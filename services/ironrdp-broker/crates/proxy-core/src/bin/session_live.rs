// SPDX-License-Identifier: AGPL-3.0-or-later

//! `session_live` — live RDP **streaming** session over the Go↔Rust
//! bridge wire protocol (ADR 0051 P2b "streaming session core",
//! `feat/rdp-p2b-stream`).
//!
//! Reads the target + credentials from the environment, drives the IronRDP
//! connector to `Connected` against a real Windows DC (via
//! [`connect_to_connected`]), then runs [`run_session`] over the live
//! stream:
//!
//! * **stdout** carries the server→client stream: `DESKTOP_SIZE`, then a
//!   `FRAME` per decoded dirty region (the region crop as a PNG), then
//!   `CLOSE`. This is binary — pipe it into a parser, do NOT print it.
//! * **stdin** carries the client→server stream: `MOUSE` / `KEY` TLVs that
//!   are mapped to FastPath input and injected into the live session.
//!
//! All human-readable logs go to **stderr** so they don't corrupt the
//! binary stdout stream. The PASSWORD is held in `zeroize::Zeroizing` and
//! is NEVER printed.
//!
//! Build/run (whole workspace — feature-unification quirk, see
//! `proxy-core/src/spike.rs`):
//!
//! ```text
//! RDP_TARGET=10.0.20.10:3389 RDP_USER=jess-rdptest \
//! RDP_DOMAIN=HEXXLOCK RDP_PASS='…' \
//!   cargo run -p jess-ironrdp-proxy-core \
//!     --features jess-ironrdp-proxy-core/ironrdp_live --bin session_live \
//!     > /tmp/rdp-stream.bin
//! ```

use std::time::Duration;

use jess_ironrdp_proxy_core::connect::{connect_to_connected, LiveConnectParams};
use jess_ironrdp_proxy_core::stream::{run_session, StreamBudget};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "session_live=debug,jess_ironrdp_proxy_core=debug,ironrdp_session=info,\
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

    if username.is_empty() || password.is_empty() {
        eprintln!("FATAL: set RDP_USER and RDP_PASS (RDP_DOMAIN optional)");
        return std::process::ExitCode::from(2);
    }

    // Wall-clock session budget. The legacy 30s cap auto-closed real RDP
    // sessions after 30s; the budget is now operator-configurable and defaults
    // LARGE (4h). `JESS_RDP_BUDGET_SECS` is the canonical name the Go bridge
    // forwards; `RDP_BUDGET_SECS` is kept as a back-compat alias. Unset / `0` /
    // unparseable → `DEFAULT_BUDGET_SECS` (so an explicit 0 means "use the
    // default", never "close immediately").
    const DEFAULT_BUDGET_SECS: u64 = 14_400; // 4 hours
    let total_secs = std::env::var("JESS_RDP_BUDGET_SECS")
        .or_else(|_| std::env::var("RDP_BUDGET_SECS"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_BUDGET_SECS);
    let idle_secs = std::env::var("RDP_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2);

    // Tier-1 live encoding. WebP (lossy) is the DEFAULT live frame; set
    // JESS_RDP_LOSSLESS=1 to fall back to lossless PNG live frames. When the Go
    // bridge is recording it sets JESS_RDP_RECORD_LOSSLESS=1 so we ALSO emit a
    // lossless PNG per region for the recorder feed (the bridge records the PNG,
    // forwards the WebP) — keeping the WORM bundle lossless + format-unchanged.
    let webp_live = !env_flag("JESS_RDP_LOSSLESS");
    let record_lossless = env_flag("JESS_RDP_RECORD_LOSSLESS");
    let webp_quality = std::env::var("JESS_RDP_WEBP_QUALITY")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .filter(|q| (0.0..=100.0).contains(q))
        .unwrap_or(StreamBudget::default().webp_quality);

    let budget = StreamBudget {
        total: Duration::from_secs(total_secs),
        idle_read: Duration::from_secs(idle_secs),
        webp_live,
        webp_quality,
        record_lossless,
        ..StreamBudget::default()
    };

    // QUALITY item #3 — resolution match. The browser-desired desktop size is
    // threaded in via RDP_DESKTOP_W / RDP_DESKTOP_H (the Go bridge sets these
    // from the WS query params). `0`/unset/out-of-range falls back to the
    // legacy 1280×1024 via `desktop_size_from_request`'s clamp.
    let req_w = std::env::var("RDP_DESKTOP_W")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let req_h = std::env::var("RDP_DESKTOP_H")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let desktop_size = jess_ironrdp_proxy_core::spike::desktop_size_from_request(req_w, req_h);

    // CLIPBOARD virtual channel (ADR 0054). Negotiate CLIPRDR (bidirectional
    // TEXT) when JESS_RDP_CLIPBOARD is truthy ("1"/"true"/"yes", case-
    // insensitive). DEFAULT OFF — unset/anything-else keeps the legacy
    // graphics+input-only desktop, so this work is inert until an operator/
    // policy opts in. The Go bridge forwards the env var per session.
    let enable_clipboard = std::env::var("JESS_RDP_CLIPBOARD")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false);

    // MS-RDPEGFX / AVC420 H.264 path (ADR 0053). Opt-in via JESS_RDP_H264.
    //
    // ADR 0058 LIFTS the previous "EGFX off when recording" gate: the H.264 path
    // used to be hard-gated off for recorded sessions because an H.264 frame
    // produces no RGBA bitmap for the WORM PNG track. The Go bridge now records
    // the AVC420 access units directly into the jess-rdp-recording-v2 stream (the
    // `h264` event kind), so a recorded H.264 session is fully replayable. The Go
    // bridge accordingly sets JESS_RDP_RECORD_LOSSLESS *only* for NON-H.264
    // recorded sessions (the bitmap path still needs the lossless-PNG twin), so
    // `record_lossless` is naturally false here whenever H.264 is requested. We no
    // longer AND it in — H.264 is enabled purely by the operator's request.
    // ADR 0061: the SOFTWARE H.264 path (JESS_RDP_H264_SW) wins over EGFX — when
    // we CPU-encode the framebuffer ourselves there's no point negotiating the
    // host's AVC420 graphics pipeline, so don't advertise EGFX in that case.
    // run_session also ignores any EGFX channel when sw-H.264 is on.
    let enable_h264 = jess_ironrdp_proxy_core::stream::h264_requested()
        && !jess_ironrdp_proxy_core::h264enc::sw_h264_requested();

    eprintln!("=== jess RDP live STREAMING session (Go↔Rust wire protocol) ===");
    eprintln!("target  : {target}");
    eprintln!("user    : {username}");
    eprintln!(
        "domain  : {}",
        domain.as_deref().unwrap_or("<local account>")
    );
    eprintln!("password: <redacted, {} chars>", password.len());
    eprintln!("budget  : total={total_secs}s idle_read={idle_secs}s");
    eprintln!(
        "encoding: live={} (q={webp_quality}) record_lossless={record_lossless}",
        if webp_live {
            "webp(lossy)"
        } else {
            "png(lossless)"
        }
    );
    eprintln!(
        "desktop : requesting {}x{} (req {req_w}x{req_h})",
        desktop_size.width, desktop_size.height
    );
    eprintln!(
        "clipbrd : {}",
        if enable_clipboard {
            "CLIPRDR ON (bidirectional TEXT)"
        } else {
            "off (set JESS_RDP_CLIPBOARD=1 to enable)"
        }
    );
    eprintln!(
        "h264    : {}",
        if enable_h264 && record_lossless {
            // Shouldn't happen — the Go bridge omits JESS_RDP_RECORD_LOSSLESS for
            // H.264 recorded sessions — but if both are set, H.264 wins and the AUs
            // are recorded (ADR 0058); the lossless-PNG twin is simply unused.
            "MS-RDPEGFX/AVC420 ON (Tier-2) — recording AVC420 access units (ADR 0058)"
        } else if enable_h264 {
            "MS-RDPEGFX/AVC420 ON (Tier-2)"
        } else {
            "off (set JESS_RDP_H264=1 to enable)"
        }
    );
    eprintln!("stdout  : binary server→client stream — pipe into a parser");
    eprintln!("stdin   : binary client→server MOUSE/KEY stream");
    eprintln!("----------------------------------------------------------------");

    // Run the session, with a one-shot graceful H.264 fallback: if EGFX is
    // active and the host can't encode H.264, it accepts our AVC420 advertise,
    // commits to the graphics pipeline, then its graphics subsystem fails and the
    // server tears the session down before any frame. run_session detects that
    // (egfx_fallback_recommended) and leaves the stream OPEN (no CLOSE); we then
    // reconnect ONCE without EGFX (bitmap path) and continue the same client
    // stream. So enabling JESS_RDP_H264 is safe against any host: H.264 where the
    // host supports it, automatic bitmap fallback where it doesn't.
    let mut try_h264 = enable_h264;
    loop {
        let params = LiveConnectParams {
            target: &target,
            username: &username,
            domain: domain.as_deref(),
            password: &password,
            desktop_size,
            enable_clipboard,
            enable_h264: try_h264,
        };

        // 1) handshake → Connected, hold the live framed stream + (when
        //    negotiated) the clipboard channel + the EGFX/AVC420 frame channel.
        let (connection_result, outcome, framed, clipboard, egfx) =
            match connect_to_connected(params).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("----------------------------------------------------------------");
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

        // 2) run the streaming session over stdout/stdin (+ optional clipboard).
        let stdout = tokio::io::stdout();
        let stdin = tokio::io::stdin();
        let result = run_session(
            connection_result,
            framed,
            stdout,
            stdin,
            budget,
            clipboard,
            egfx,
        )
        .await;

        // One-shot no-EGFX retry on an H.264-incapable host.
        if try_h264 {
            if let Ok(o) = &result {
                if o.egfx_fallback_recommended {
                    eprintln!("----------------------------------------------------------------");
                    eprintln!(
                        "H.264/EGFX not usable on this host (server terminated before any frame)."
                    );
                    eprintln!("Retrying WITHOUT H.264 (bitmap path)…");
                    try_h264 = false;
                    continue;
                }
            }
        }

        return handle_result(result);
    }
}

/// True when `key` is set to a truthy value (`1`/`true`/`yes`, case-insensitive).
fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Map the streaming-session result to a process exit code (kept out of `main`
/// so the encoding-config setup above reads top-to-bottom).
fn handle_result(
    result: anyhow::Result<jess_ironrdp_proxy_core::stream::StreamOutcome>,
) -> std::process::ExitCode {
    match result {
        Ok(o) => {
            eprintln!("----------------------------------------------------------------");
            eprintln!(
                "session ended: pdus={} frames_emitted={} input_applied={} terminated_by_server={}",
                o.pdus, o.frames_emitted, o.input_applied, o.terminated_by_server
            );
            if o.frames_emitted == 0 {
                eprintln!("VERDICT: NO frames emitted — see stderr log for the frontier.");
                std::process::ExitCode::FAILURE
            } else {
                eprintln!("VERDICT: streamed {} FRAME message(s).", o.frames_emitted);
                std::process::ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("----------------------------------------------------------------");
            eprintln!("FAILED in streaming session: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
