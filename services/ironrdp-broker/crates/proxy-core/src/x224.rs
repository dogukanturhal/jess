// SPDX-License-Identifier: AGPL-3.0-or-later

//! X.224 + RDP Negotiation Request/Response — minimum-viable RDP
//! reachability probe.
//!
//! Mirrors the Go impl in cmd/jessctl/rdp_probe.go byte-for-byte. The
//! two will share the same target via the upcoming `/api/admin/rdp-probe`
//! endpoint (5f-2b): operator hits jess-web → controller forwards →
//! broker uses THIS module to probe.
//!
//! No dependency on the ironrdp crates — this is just spec-driven raw
//! framing per:
//!   * RFC 905 (X.224)
//!   * MS-RDPBCGR §2.2.1.1, §2.2.1.2 (Connection Request/Confirm)
//!   * MS-RDPBCGR §2.2.1.1.1, §2.2.1.2.1, §2.2.1.2.2 (RDP Negotiation)
//!
//! When the ironrdp_connector full handshake lands in Phase 5f-2b, it
//! will USE this module for the X.224 leg, then hand off to
//! ironrdp_connector for MCS / GCC / fastpath.

use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// MS-RDPBCGR §2.2.1.1.1 requestedProtocols bitset.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RequestedProto(pub u32);

impl RequestedProto {
    pub const RDP: u32 = 0x00000000;
    pub const TLS: u32 = 0x00000001;
    pub const CRED_SSP: u32 = 0x00000002;
    pub const RDSTLS: u32 = 0x00000004;
    pub const CRED_SSP_EARLY_USER_AUTH: u32 = 0x00000008;
}

/// RDP_NEG_FAILURE selectedProtocol code → human reason.
/// MS-RDPBCGR §2.2.1.2.2.
pub const FAILURE_REASONS: &[(u32, &str)] = &[
    (1, "SSL_REQUIRED_BY_SERVER"),
    (2, "SSL_NOT_ALLOWED_BY_SERVER"),
    (3, "SSL_CERT_NOT_ON_SERVER"),
    (4, "INCONSISTENT_FLAGS"),
    (5, "HYBRID_REQUIRED_BY_SERVER (NLA required)"),
    (6, "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"),
];

// Serialize/Deserialize on NegResponse + ProbeReport so the broker's
// axum handler at handlers::rdp_probe can return Json<ProbeReport> —
// without Serialize, Json<T> doesn't impl IntoResponse, the handler
// doesn't impl Handler, and the route registration fails E0277.
// Pre-existing latent bug from Phase 5f-2c; masked until the sspi/
// picky build break (which fired earlier) was fixed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NegResponse {
    /// Server sent a Connection Confirm but no negotiation trailer
    /// — legacy RDP, no TLS/NLA negotiation supported.
    Absent,
    /// Server selected a protocol from the requested set.
    Ok { selected: u32, flags: u8 },
    /// Server rejected the request with the given failure code.
    Failure { code: u32 },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeReport {
    pub target: String,
    pub reachable: bool,
    pub negotiation: NegResponse,
    pub nla_required: bool,
    pub tls_supported: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("connect timeout to {target} after {timeout_ms}ms")]
    ConnectTimeout { target: String, timeout_ms: u64 },
    #[error("connect: {0}")]
    Connect(#[from] std::io::Error),
    #[error("bad TPKT version 0x{0:02X} (expected 0x03)")]
    BadTPKTVersion(u8),
    #[error("TPKT length {0} too short for X.224 CC")]
    TPKTShort(u16),
    #[error("not an X.224 Connection Confirm (TPDU code 0x{0:02X})")]
    NotCC(u8),
    #[error("unknown negotiation trailer type 0x{0:02X}")]
    UnknownNegType(u8),
}

/// Probe an RDP target. Opens TCP, sends X.224 CR + RDP_NEG_REQ,
/// reads CC + NEG_RSP/FAILURE, returns the parsed report.
///
/// The probe is single-shot: no retry, no keepalive — the connection
/// closes immediately after the CC is parsed. Cheap enough to run on
/// every WS handshake if the broker wants to do capability discovery
/// before the actual session bridge starts.
pub async fn probe(
    target: &str,
    requested: u32,
    cookie: Option<&str>,
    deadline: Duration,
) -> Result<ProbeReport, ProbeError> {
    let t0 = std::time::Instant::now();
    let mut stream = match timeout(deadline, TcpStream::connect(target)).await {
        Err(_) => {
            return Err(ProbeError::ConnectTimeout {
                target: target.to_owned(),
                timeout_ms: deadline.as_millis() as u64,
            })
        }
        Ok(Err(e)) => return Err(ProbeError::Connect(e)),
        Ok(Ok(s)) => s,
    };
    let cr = build_x224_connection_request(cookie, requested);
    stream.write_all(&cr).await.map_err(ProbeError::Connect)?;
    stream.flush().await.map_err(ProbeError::Connect)?;
    let nego = read_x224_connection_confirm(&mut stream).await?;
    let elapsed = t0.elapsed().as_millis() as u64;
    let (nla_required, tls_supported) = match &nego {
        NegResponse::Ok { selected, .. } => (
            (selected & RequestedProto::CRED_SSP) != 0,
            (selected & (RequestedProto::TLS | RequestedProto::CRED_SSP)) != 0,
        ),
        NegResponse::Failure { code } => (*code == 5, false),
        NegResponse::Absent => (false, false),
    };
    Ok(ProbeReport {
        target: target.to_owned(),
        reachable: true,
        negotiation: nego,
        nla_required,
        tls_supported,
        duration_ms: elapsed,
    })
}

/// Build TPKT + X.224 CR + optional cookie + RDP_NEG_REQ. Byte-for-byte
/// match to the Go impl in cmd/jessctl/rdp_probe.go writeX224ConnectionRequest.
pub fn build_x224_connection_request(cookie: Option<&str>, requested: u32) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    if let Some(c) = cookie {
        body.extend_from_slice(b"Cookie: ");
        body.extend_from_slice(c.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    // RDP_NEG_REQ (8 bytes)
    body.push(0x01); // type
    body.push(0x00); // flags
    body.extend_from_slice(&8u16.to_le_bytes()); // length
    body.extend_from_slice(&requested.to_le_bytes());

    // X.224 CR header: 7 bytes total; LI = 6 + body.len() (LI excludes itself).
    let li = (6 + body.len()) as u8;
    let mut x224 = vec![li, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
    x224.extend_from_slice(&body);

    // TPKT (4 bytes) — total length includes TPKT header.
    let total = 4 + x224.len();
    let mut tpkt = vec![0x03, 0x00];
    tpkt.extend_from_slice(&(total as u16).to_be_bytes());
    tpkt.extend_from_slice(&x224);
    tpkt
}

/// Read TPKT + X.224 CC + optional negotiation trailer from an async
/// stream. Returns the parsed NegResponse or a typed parse error.
pub async fn read_x224_connection_confirm<R>(r: &mut R) -> Result<NegResponse, ProbeError>
where
    R: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await.map_err(ProbeError::Connect)?;
    if hdr[0] != 0x03 {
        return Err(ProbeError::BadTPKTVersion(hdr[0]));
    }
    let total = u16::from_be_bytes([hdr[2], hdr[3]]);
    if total < 11 {
        return Err(ProbeError::TPKTShort(total));
    }
    let mut rest = vec![0u8; total as usize - 4];
    r.read_exact(&mut rest).await.map_err(ProbeError::Connect)?;
    if rest.len() < 7 {
        return Err(ProbeError::NotCC(0));
    }
    if rest[1] != 0xD0 {
        return Err(ProbeError::NotCC(rest[1]));
    }
    let body = &rest[7..];
    if body.is_empty() {
        return Ok(NegResponse::Absent);
    }
    if body.len() < 8 {
        return Ok(NegResponse::Absent);
    }
    match body[0] {
        0x02 => {
            let flags = body[1];
            let selected = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            Ok(NegResponse::Ok { selected, flags })
        }
        0x03 => {
            let code = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            Ok(NegResponse::Failure { code })
        }
        other => Err(ProbeError::UnknownNegType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_frame_shape_matches_spec() {
        let out = build_x224_connection_request(None, RequestedProto::TLS | RequestedProto::CRED_SSP);
        // 4 (TPKT) + 7 (X.224 CR) + 8 (NEG_REQ) = 19 bytes
        assert_eq!(out.len(), 19);
        assert_eq!(out[0], 0x03);
        assert_eq!(out[1], 0x00);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 19);
        assert_eq!(out[4], 0x0E);
        assert_eq!(out[5], 0xE0);
        // NEG_REQ
        assert_eq!(&out[11..15], &[0x01, 0x00, 0x08, 0x00]);
        assert_eq!(u32::from_le_bytes([out[15], out[16], out[17], out[18]]), 0x03);
    }

    #[test]
    fn cr_with_cookie_inflates_length() {
        let out = build_x224_connection_request(Some("mstshash=alice"), RequestedProto::TLS);
        // cookie line = "Cookie: mstshash=alice\r\n" = 24 bytes
        assert_eq!(out.len(), 4 + 7 + 24 + 8);
    }

    #[tokio::test]
    async fn parse_cc_with_neg_rsp_ok() {
        let mut body = vec![0x0E, 0xD0, 0, 0, 0, 0, 0]; // X.224 CC
        body.extend_from_slice(&[0x02, 0x01, 0x08, 0x00]); // NEG_RSP type/flags/len
        body.extend_from_slice(&RequestedProto::CRED_SSP.to_le_bytes());
        let mut frame = vec![0x03, 0x00];
        frame.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&body);
        let mut cursor = std::io::Cursor::new(frame);
        let nego = read_x224_connection_confirm(&mut cursor).await.unwrap();
        match nego {
            NegResponse::Ok { selected, .. } => assert_eq!(selected, RequestedProto::CRED_SSP),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn parse_cc_with_nla_failure() {
        let mut body = vec![0x0E, 0xD0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&[0x03, 0x00, 0x08, 0x00]); // FAILURE
        body.extend_from_slice(&5u32.to_le_bytes()); // HYBRID_REQUIRED_BY_SERVER
        let mut frame = vec![0x03, 0x00];
        frame.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&body);
        let mut cursor = std::io::Cursor::new(frame);
        let nego = read_x224_connection_confirm(&mut cursor).await.unwrap();
        assert_eq!(nego, NegResponse::Failure { code: 5 });
    }

    /// Live probe against $RDP_TARGET when set. Run with
    ///   RDP_TARGET=10.0.20.10:3389 cargo test -- --ignored live_probe
    /// from a workstation with cluster reach (WG up).
    #[tokio::test]
    #[ignore]
    async fn live_probe() {
        let target = std::env::var("RDP_TARGET")
            .expect("set RDP_TARGET=host:port to run the live probe");
        let rep = probe(
            &target,
            RequestedProto::TLS | RequestedProto::CRED_SSP,
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("probe should succeed against a reachable RDP service");
        assert!(rep.reachable);
        eprintln!("probe report: {:?}", rep);
    }
}
