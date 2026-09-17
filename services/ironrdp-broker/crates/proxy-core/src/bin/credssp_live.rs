// SPDX-License-Identifier: AGPL-3.0-or-later

//! `credssp_live` — live CredSSP/NLA handshake runner (ADR 0051,
//! `feat/rdp-credssp-live`).
//!
//! Reads the target + credentials from the environment, drives the
//! IronRDP connector all the way to `Connected` against a real Windows
//! DC, and prints each connector state transition + the negotiated
//! desktop/channels. The PASSWORD is held in `zeroize::Zeroizing` and is
//! NEVER printed.
//!
//! Build/run (whole workspace — feature-unification quirk, see
//! `proxy-core/src/spike.rs`):
//!
//! ```text
//! RDP_TARGET=10.0.20.10:3389 RDP_USER=jess-rdptest \
//! RDP_DOMAIN=HEXXLOCK RDP_PASS='…' \
//!   cargo run -p jess-ironrdp-proxy-core \
//!     --features jess-ironrdp-proxy-core/ironrdp_live --bin credssp_live
//! ```
//!
//! Exit code 0 = reached `Connected` (CredSSP completed). Non-zero =
//! the exact failure (printed) — itself the valuable diagnostic.

use jess_ironrdp_proxy_core::connect::{connect_to_connected, LiveConnectParams};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // tracing → stderr; default to debug for the connect path so every
    // state transition the driver logs is visible. RUST_LOG overrides.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "credssp_live=debug,jess_ironrdp_proxy_core=debug,ironrdp_connector=debug,\
         ironrdp_async=debug,sspi=debug,info"
            .to_owned()
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .init();

    let target = match std::env::var("RDP_TARGET") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("FATAL: set RDP_TARGET=host:port (e.g. 10.0.20.10:3389)");
            return std::process::ExitCode::from(2);
        }
    };
    let username = std::env::var("RDP_USER").unwrap_or_default();
    let domain = std::env::var("RDP_DOMAIN").ok().filter(|d| !d.is_empty());
    // Password: read once, wrap in Zeroizing so the heap buffer is wiped
    // on drop. NEVER logged.
    let password = Zeroizing::new(std::env::var("RDP_PASS").unwrap_or_default());

    if username.is_empty() || password.is_empty() {
        eprintln!("FATAL: set RDP_USER and RDP_PASS (RDP_DOMAIN optional)");
        return std::process::ExitCode::from(2);
    }

    eprintln!("=== jess RDP CredSSP live handshake ===");
    eprintln!("target  : {target}");
    eprintln!("user    : {username}");
    eprintln!(
        "domain  : {}",
        domain.as_deref().unwrap_or("<local account>")
    );
    eprintln!("password: <redacted, {} chars>", password.len());
    eprintln!("---------------------------------------");

    let params = LiveConnectParams {
        target: &target,
        username: &username,
        domain: domain.as_deref(),
        password: &password,
        // Handshake-only spike: the legacy fixed resolution is fine.
        desktop_size: jess_ironrdp_proxy_core::spike::DEFAULT_DESKTOP_SIZE,
        // Handshake-only spike — no clipboard channel.
        enable_clipboard: false,
        // Handshake-only spike — no EGFX/H.264 channel.
        enable_h264: false,
    };

    match connect_to_connected(params).await {
        Ok((_result, outcome, _framed, _clip, _egfx)) => {
            eprintln!("---------------------------------------");
            eprintln!("SUCCESS — reached ClientConnectorState::Connected");
            eprintln!("  CredSSP/NLA completed against the live DC.");
            eprintln!(
                "  desktop = {}x{}  io_channel={}  user_channel={}",
                outcome.desktop_width,
                outcome.desktop_height,
                outcome.io_channel_id,
                outcome.user_channel_id,
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("---------------------------------------");
            eprintln!("FAILED to reach Connected.");
            // Print the full error chain — the precise blocker is the
            // deliverable when the handshake doesn't complete.
            eprintln!("error: {e:#}");
            let mut src = e.source();
            while let Some(s) = src {
                eprintln!("  caused by: {s}");
                src = s.source();
            }
            std::process::ExitCode::FAILURE
        }
    }
}
