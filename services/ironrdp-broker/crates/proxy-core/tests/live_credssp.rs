// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live CredSSP/NLA handshake integration test (ADR 0051,
//! `feat/rdp-credssp-live`).
//!
//! `#[ignore]` + feature-gated: the whole file compiles to nothing unless
//! `--features ironrdp_live` is set, and even then it only runs when
//! explicitly named/`--ignored`, so default `cargo test` is unaffected.
//!
//! Run (whole workspace — feature-unification quirk):
//! ```text
//! RDP_TARGET=10.0.20.10:3389 RDP_USER=jess-rdptest \
//! RDP_DOMAIN=HEXXLOCK RDP_PASS='…' \
//!   cargo test -p jess-ironrdp-proxy-core \
//!     --features jess-ironrdp-proxy-core/ironrdp_live \
//!     --test live_credssp -- --ignored --nocapture live_credssp_handshake
//! ```
//! Asserts the connector reaches `Connected` (CredSSP completed). The
//! password is held in `zeroize::Zeroizing` and never printed.

#![cfg(feature = "ironrdp_live")]

use jess_ironrdp_proxy_core::connect::{connect_to_connected, LiveConnectParams};
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "live: needs RDP_TARGET/RDP_USER/RDP_PASS env + cluster reach (WG up)"]
async fn live_credssp_handshake() {
    let target = std::env::var("RDP_TARGET").expect("set RDP_TARGET=host:port");
    let username = std::env::var("RDP_USER").expect("set RDP_USER");
    let domain = std::env::var("RDP_DOMAIN").ok().filter(|d| !d.is_empty());
    let password = Zeroizing::new(std::env::var("RDP_PASS").expect("set RDP_PASS"));

    // Best-effort tracing init (ignore if another test already set it).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| {
            "jess_ironrdp_proxy_core=debug,ironrdp_connector=debug,info".to_owned()
        }))
        .with_test_writer()
        .try_init();

    let params = LiveConnectParams {
        target: &target,
        username: &username,
        domain: domain.as_deref(),
        password: &password,
        desktop_size: jess_ironrdp_proxy_core::spike::DEFAULT_DESKTOP_SIZE,
        // Handshake-only live test — no clipboard channel.
        enable_clipboard: false,
        // Handshake-only live test — no EGFX/H.264 channel.
        enable_h264: false,
    };

    let (result, outcome, _framed, _clip, _egfx) = connect_to_connected(params)
        .await
        .expect("CredSSP handshake should reach Connected against the live DC");

    // Reaching here means the connector hit ClientConnectorState::Connected.
    eprintln!(
        "live_credssp_handshake OK: desktop={}x{} io_ch={} user_ch={}",
        outcome.desktop_width,
        outcome.desktop_height,
        outcome.io_channel_id,
        outcome.user_channel_id
    );
    assert!(outcome.desktop_width > 0, "negotiated a desktop width");
    assert!(outcome.desktop_height > 0, "negotiated a desktop height");
    // Channel ids are assigned by MCS during finalization.
    assert!(result.io_channel_id > 0, "MCS assigned an I/O channel");
}
