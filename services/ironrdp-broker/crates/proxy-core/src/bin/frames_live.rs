// SPDX-License-Identifier: AGPL-3.0-or-later

//! `frames_live` — live desktop-decode → PNG runner (ADR 0051 P2a
//! "first pixels", `feat/rdp-p2-decode`).
//!
//! Reads the target + credentials from the environment, drives the
//! IronRDP connector to `Connected` against a real Windows DC (via
//! [`connect_to_connected`]), then drives `ironrdp_session::ActiveStage`
//! over the live stream until the desktop is painted and writes the
//! decoded RGBA framebuffer to a PNG on disk. Prints dimensions, byte
//! size, stop reason, and whether the buffer looks non-trivial (real
//! pixels vs all-black).
//!
//! The PASSWORD is held in `zeroize::Zeroizing` and is NEVER printed.
//! The PNG may contain sensitive desktop content — it is written to a
//! local path only and MUST NOT be committed.
//!
//! Build/run (whole workspace — feature-unification quirk, see
//! `proxy-core/src/spike.rs`):
//!
//! ```text
//! RDP_TARGET=10.0.20.10:3389 RDP_USER=jess-rdptest \
//! RDP_DOMAIN=HEXXLOCK RDP_PASS='…' RDP_OUT=/tmp/rdp-frame.png \
//!   cargo run -p jess-ironrdp-proxy-core \
//!     --features jess-ironrdp-proxy-core/ironrdp_live --bin frames_live
//! ```
//!
//! Exit code 0 = wrote a PNG (check the printed "non-trivial" flag +
//! stop reason to judge whether it's the real desktop). Non-zero = the
//! exact failure (printed) — itself the valuable diagnostic.

use std::time::Duration;

use jess_ironrdp_proxy_core::active::{
    capture_desktop, encode_png, looks_nontrivial, CaptureBudget, StopReason,
};
use jess_ironrdp_proxy_core::connect::{connect_to_connected, LiveConnectParams};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "frames_live=debug,jess_ironrdp_proxy_core=debug,ironrdp_session=debug,\
         ironrdp_connector=info,info"
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
    let password = Zeroizing::new(std::env::var("RDP_PASS").unwrap_or_default());
    let out_path = std::env::var("RDP_OUT").unwrap_or_else(|_| "/tmp/rdp-frame.png".to_owned());

    if username.is_empty() || password.is_empty() {
        eprintln!("FATAL: set RDP_USER and RDP_PASS (RDP_DOMAIN optional)");
        return std::process::ExitCode::from(2);
    }

    // Optional budget overrides (seconds) for live iteration. This is a one-shot
    // capture diagnostic, so it keeps a small default (unlike the long-lived
    // session_live). Accepts the canonical JESS_RDP_BUDGET_SECS name too.
    let total_secs = std::env::var("JESS_RDP_BUDGET_SECS")
        .or_else(|_| std::env::var("RDP_BUDGET_SECS"))
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20);
    let idle_secs = std::env::var("RDP_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3);
    let budget = CaptureBudget {
        total: Duration::from_secs(total_secs),
        idle_read: Duration::from_secs(idle_secs),
        ..CaptureBudget::default()
    };

    eprintln!("=== jess RDP live desktop decode → PNG ===");
    eprintln!("target  : {target}");
    eprintln!("user    : {username}");
    eprintln!(
        "domain  : {}",
        domain.as_deref().unwrap_or("<local account>")
    );
    eprintln!("password: <redacted, {} chars>", password.len());
    eprintln!("output  : {out_path}");
    eprintln!(
        "budget  : total={total_secs}s idle_read={idle_secs}s max_pdus={}",
        budget.max_pdus
    );
    eprintln!("------------------------------------------");

    // Optional requested resolution (same env contract as session_live);
    // unset ⇒ legacy 1280×1024.
    let req_w = std::env::var("RDP_DESKTOP_W")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let req_h = std::env::var("RDP_DESKTOP_H")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let params = LiveConnectParams {
        target: &target,
        username: &username,
        domain: domain.as_deref(),
        password: &password,
        desktop_size: jess_ironrdp_proxy_core::spike::desktop_size_from_request(req_w, req_h),
        // Single-frame decode spike — no clipboard channel.
        enable_clipboard: false,
        // Single-frame decode spike — no EGFX/H.264 channel.
        enable_h264: false,
    };

    // 1) handshake → Connected, hold the live framed stream.
    let (connection_result, outcome, mut framed, _clip, _egfx) =
        match connect_to_connected(params).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("------------------------------------------");
                eprintln!("FAILED at handshake (never reached Connected).");
                eprintln!("error: {e:#}");
                return std::process::ExitCode::FAILURE;
            }
        };
    eprintln!(
        "Connected: desktop={}x{} io_ch={} user_ch={}",
        outcome.desktop_width,
        outcome.desktop_height,
        outcome.io_channel_id,
        outcome.user_channel_id
    );

    // 2) drive ActiveStage → decoded framebuffer.
    let capture = match capture_desktop(connection_result, &mut framed, budget).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("------------------------------------------");
            eprintln!("FAILED in active-stage decode (reached Connected but no usable frame).");
            eprintln!("error: {e:#}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let w = capture.image.width();
    let h = capture.image.height();
    let nontrivial = looks_nontrivial(&capture.image);
    let coverage = if capture.total_pixels() > 0 {
        (capture.painted_pixels as f64 / capture.total_pixels() as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("------------------------------------------");
    eprintln!("decode: stop_reason={:?}", capture.stop_reason);
    eprintln!(
        "decode: pdus={} graphics_updates={} painted_pixels={} ({coverage:.1}% of {}x{})",
        capture.pdus, capture.graphics_updates, capture.painted_pixels, w, h
    );
    eprintln!("decode: framebuffer non-trivial (real pixels)? {nontrivial}");

    // 3) encode + write PNG.
    let png_bytes = match encode_png(&capture.image) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAILED to encode PNG: {e:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(&out_path, &png_bytes) {
        eprintln!("FAILED to write PNG to {out_path}: {e}");
        return std::process::ExitCode::FAILURE;
    }

    eprintln!("------------------------------------------");
    eprintln!("WROTE PNG: {out_path}");
    eprintln!("  dimensions : {w}x{h}");
    eprintln!("  png bytes  : {}", png_bytes.len());
    eprintln!("  non-trivial: {nontrivial}");
    match (capture.stop_reason, nontrivial) {
        (StopReason::IdleBeforePaint, _) | (_, false) => {
            eprintln!(
                "  VERDICT    : NO real pixels decoded (blank/black or server sent no paint). \
                 See stop_reason + the debug log for the exact frontier."
            );
        }
        _ => {
            eprintln!(
                "  VERDICT    : decoded real desktop pixels ({coverage:.1}% painted). \
                 Open {out_path} to view (do NOT commit it)."
            );
        }
    }
    std::process::ExitCode::SUCCESS
}
