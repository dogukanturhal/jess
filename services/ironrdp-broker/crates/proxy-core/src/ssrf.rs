// SPDX-License-Identifier: AGPL-3.0-or-later

//! SSRF guard for broker-side probe endpoints — Rust mirror of the
//! Go internal/rdpprobe::IsAllowedTarget from Phase 5f-2b.
//!
//! Same semantics:
//!   * target parses as host:port
//!   * port ∈ {3389, 13389}
//!   * host resolves to RFC1918 / loopback / link-local ONLY
//!
//! TOCTOU: the upstream TCP dial re-resolves the host after this
//! guard passes. Defense-in-depth lives at the broker pod's egress
//! NetworkPolicy (cluster-wide already blocks non-RFC1918 from
//! the jess ns).

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("expected host:port, got {0:?}")]
    BadFormat(String),
    #[error("port {0} not in allow-list (3389, 13389)")]
    PortDenied(u16),
    #[error("resolve {host}: {err}")]
    ResolveFailed { host: String, err: String },
    #[error("no IPs resolved for {0}")]
    NoIPs(String),
    #[error("host {host} resolves to non-private IP {ip} (SSRF guard)")]
    PublicIP { host: String, ip: IpAddr },
}

pub fn is_allowed_target(target: &str) -> Result<(), SsrfError> {
    let (host, port_str) = match target.rsplit_once(':') {
        Some(parts) => parts,
        None => return Err(SsrfError::BadFormat(target.to_owned())),
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| SsrfError::BadFormat(target.to_owned()))?;
    match port {
        3389 | 13389 => {}
        other => return Err(SsrfError::PortDenied(other)),
    }
    // Resolve via the OS resolver (matches the dialer behaviour);
    // collect all returned addresses.
    let addrs: Vec<_> = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| SsrfError::ResolveFailed {
            host: host.to_owned(),
            err: e.to_string(),
        })?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(SsrfError::NoIPs(host.to_owned()));
    }
    for ip in addrs {
        if !is_private_ip(ip) {
            return Err(SsrfError::PublicIP {
                host: host.to_owned(),
                ip,
            });
        }
    }
    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_private() || is_cgnat(v4),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || is_ula(v6),
    }
}

// CGNAT 100.64/10 (RFC 6598) — std::net::Ipv4Addr::is_private misses it.
fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] >= 64 && o[1] <= 127)
}

// Unique-Local Address fc00::/7 (RFC 4193) — std stable API doesn't
// expose this directly. Match the high 7 bits.
fn is_ula(v6: std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1918_accepted() {
        assert!(is_allowed_target("10.0.20.10:3389").is_ok());
        assert!(is_allowed_target("192.168.1.50:3389").is_ok());
        assert!(is_allowed_target("172.16.5.5:3389").is_ok());
        assert!(is_allowed_target("127.0.0.1:3389").is_ok());
        assert!(is_allowed_target("10.0.20.10:13389").is_ok());
    }

    #[test]
    fn public_ip_rejected() {
        assert!(matches!(
            is_allowed_target("1.1.1.1:3389"),
            Err(SsrfError::PublicIP { .. })
        ));
        assert!(matches!(
            is_allowed_target("8.8.8.8:3389"),
            Err(SsrfError::PublicIP { .. })
        ));
    }

    #[test]
    fn wrong_port_rejected() {
        assert!(matches!(
            is_allowed_target("10.0.20.10:22"),
            Err(SsrfError::PortDenied(22))
        ));
        assert!(matches!(
            is_allowed_target("10.0.20.10:443"),
            Err(SsrfError::PortDenied(443))
        ));
    }

    #[test]
    fn malformed_rejected() {
        assert!(matches!(
            is_allowed_target("10.0.20.10"),
            Err(SsrfError::BadFormat(_))
        ));
    }
}
