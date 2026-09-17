// SPDX-License-Identifier: AGPL-3.0-or-later

//! Active-stage desktop decode — ADR 0051 Phase 5f-8b-P2a ("first
//! pixels"), branch `feat/rdp-p2-decode`.
//!
//! ## What this is
//!
//! The first place in the broker that drives the IronRDP **active
//! session** past `Connected`: it takes the [`ConnectionResult`] +
//! upgraded [`LiveFramed`] that [`crate::connect::connect_to_connected`]
//! hands back and runs `ironrdp_session::ActiveStage` over the live TLS
//! stream until the server has painted the desktop, returning a fully
//! decoded RGBA framebuffer ([`DecodedImage`]) — the real pixels of the
//! live Windows login/desktop screen.
//!
//! This is the async counterpart of the `ActiveStage` loop in upstream
//! IronRDP's `examples/screenshot.rs` (which is blocking and breaks out
//! of the loop on a TCP read-timeout `WouldBlock`). The broker is async
//! (axum/tokio), so this version reads PDUs with a tokio per-read timeout
//! and a wall-clock budget, and stops once the desktop is painted.
//!
//! ## Gated OFF by default
//!
//! Compiled only under the `ironrdp_live` cargo feature (same as
//! `connect.rs`). The default `cargo build` / CI surface is unchanged.
//! Build/run the whole workspace, not `-p jess-ironrdp-proxy-core` (the
//! feature-unification quirk noted in `spike.rs`):
//!
//! ```text
//! cargo build --features jess-ironrdp-proxy-core/ironrdp_live
//! RDP_TARGET=… RDP_USER=… RDP_DOMAIN=… RDP_PASS=… \
//!   cargo run -p jess-ironrdp-proxy-core \
//!     --features jess-ironrdp-proxy-core/ironrdp_live --bin frames_live
//! ```
//!
//! ## Scope (honest)
//!
//! This is **P2a: decode to image** only. It produces a [`DecodedImage`]
//! (and via [`encode_png`] a PNG on disk). It does NOT stream frames to a
//! browser canvas (P2b), record decoded frames to WORM storage (P4), or
//! bridge over a WebSocket / Go subprocess — those are the remaining
//! tracks. The `ActiveStage` loop here is the exact seam those tracks
//! will reuse (replace "write PNG once painted" with "push each
//! `GraphicsUpdate` region to the consumer").

use std::time::{Duration, Instant};

use anyhow::Context as _;
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp_async::FramedWrite as _;
// `width()` / `height()` on InclusiveRectangle come from the `Rectangle`
// trait — must be in scope to call them.
use ironrdp_pdu::geometry::Rectangle as _;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use tracing::{debug, info, warn};

use crate::connect::LiveFramed;

/// Tuning for the [`capture_desktop`] decode loop.
#[derive(Debug, Clone, Copy)]
pub struct CaptureBudget {
    /// Hard wall-clock cap on the whole decode loop. Even if the server
    /// keeps streaming (e.g. a blinking cursor), we stop after this.
    pub total: Duration,
    /// Per-`read_pdu` timeout. A live desktop goes quiet between paints;
    /// once the first full-desktop area is painted AND a read times out,
    /// we treat the screen as settled and stop. Also bounds a stall on a
    /// server that goes silent without painting (reported as a blocker).
    pub idle_read: Duration,
    /// Safety cap on the number of PDUs processed, independent of timing.
    pub max_pdus: usize,
}

impl Default for CaptureBudget {
    fn default() -> Self {
        Self {
            total: Duration::from_secs(20),
            idle_read: Duration::from_secs(3),
            max_pdus: 4096,
        }
    }
}

/// Why [`capture_desktop`] stopped — surfaced for honest reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The desktop was painted (cumulative painted area covered the full
    /// framebuffer) and the stream then went idle — the happy path.
    Painted,
    /// The server gracefully terminated the session.
    Terminated,
    /// We hit the wall-clock or PDU budget. If `painted_pixels` is high
    /// this is still a usable screenshot; if near zero it's a blocker.
    BudgetExhausted,
    /// A read timed out before the desktop was ever painted (server went
    /// silent without sending paintable updates). This is the precise
    /// frontier to report when no pixels arrive.
    IdleBeforePaint,
}

/// Result of a [`capture_desktop`] run.
pub struct CaptureResult {
    /// The decoded RGBA32 framebuffer at the negotiated desktop size.
    pub image: DecodedImage,
    /// Why the loop stopped.
    pub stop_reason: StopReason,
    /// Number of PDUs processed.
    pub pdus: usize,
    /// Number of `GraphicsUpdate` regions received.
    pub graphics_updates: usize,
    /// Cumulative painted pixel count (sum of update-region areas; may
    /// exceed total pixels if regions overlap/repaint).
    pub painted_pixels: u64,
}

impl CaptureResult {
    /// Total pixels in the framebuffer.
    pub fn total_pixels(&self) -> u64 {
        u64::from(self.image.width()) * u64::from(self.image.height())
    }
}

/// Drive the active session over a live, post-`Connected` framed stream
/// until the desktop is painted, returning the decoded RGBA framebuffer.
///
/// Mirrors `screenshot.rs`'s `active_stage` loop, async-ported:
/// `ActiveStage::new(connection_result)` then repeatedly
/// `framed.read_pdu()` → `active_stage.process(&mut image, action,
/// &payload)` → for each [`ActiveStageOutput`]: write `ResponseFrame`s
/// back, accumulate `GraphicsUpdate` painted area, and break on
/// `Terminate`. `DeactivateAll` (a mid-session capability re-exchange)
/// is logged and the loop continues — re-driving the activation sequence
/// is P2b/bridge work, but in practice the initial desktop paint arrives
/// before any deactivation on a fresh connect.
///
/// Stops at the FIRST of: full desktop painted + stream idle; server
/// `Terminate`; the wall-clock / PDU budget; or an idle read before any
/// paint (the honest "no pixels" blocker).
pub async fn capture_desktop(
    connection_result: ironrdp_connector::ConnectionResult,
    framed: &mut LiveFramed,
    budget: CaptureBudget,
) -> anyhow::Result<CaptureResult> {
    let width = connection_result.desktop_size.width;
    let height = connection_result.desktop_size.height;
    info!(
        desktop = format!("{width}x{height}"),
        budget_secs = budget.total.as_secs(),
        "active stage: starting desktop decode loop"
    );

    // RGBA32 framebuffer at the negotiated desktop size — same pixel
    // format the upstream example saves as PNG.
    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    let total_pixels = u64::from(width) * u64::from(height);

    let mut active_stage = ActiveStage::new(connection_result);

    let started = Instant::now();
    let mut pdus = 0usize;
    let mut graphics_updates = 0usize;
    let mut painted_pixels = 0u64;
    let mut stop_reason: Option<StopReason> = None;

    'outer: loop {
        if started.elapsed() >= budget.total {
            stop_reason = Some(StopReason::BudgetExhausted);
            break;
        }
        if pdus >= budget.max_pdus {
            stop_reason = Some(StopReason::BudgetExhausted);
            break;
        }

        // Per-read timeout: a settled desktop stops sending. Treat a
        // timeout as "stream went idle". Whether that's success or a
        // blocker depends on whether we've painted anything yet.
        let read = tokio::time::timeout(budget.idle_read, framed.read_pdu()).await;
        let (action, payload) = match read {
            Ok(Ok(frame)) => frame,
            Ok(Err(e)) => {
                // EOF / connection reset after some paint = effectively
                // terminated; before any paint = a blocker. Either way,
                // stop and report.
                if painted_pixels > 0 {
                    debug!(error = %e, "read_pdu ended after paint — treating as session end");
                    stop_reason = Some(StopReason::Terminated);
                    break;
                }
                return Err(anyhow::Error::new(e)
                    .context("read_pdu failed before any desktop pixels were painted"));
            }
            Err(_elapsed) => {
                // Any paint (full or partial) then idle → a usable
                // frame; the report surfaces actual coverage. No paint at
                // all → the honest "server sent nothing to draw" blocker.
                stop_reason = Some(if painted_pixels > 0 {
                    StopReason::Painted
                } else {
                    StopReason::IdleBeforePaint
                });
                break;
            }
        };

        pdus += 1;
        debug!(
            ?action,
            len = payload.len(),
            pdu = pdus,
            "active stage: frame"
        );

        let outputs = active_stage
            .process(&mut image, action, &payload)
            .context("ActiveStage::process")?;

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => {
                    framed
                        .write_all(&frame)
                        .await
                        .context("write ActiveStage response frame")?;
                }
                ActiveStageOutput::GraphicsUpdate(region) => {
                    graphics_updates += 1;
                    // InclusiveRectangle: width/height helpers give the
                    // painted area. Accumulate so we know when the whole
                    // desktop has been covered at least once.
                    let w = u64::from(region.width());
                    let h = u64::from(region.height());
                    painted_pixels = painted_pixels.saturating_add(w * h);
                    debug!(
                        left = region.left,
                        top = region.top,
                        right = region.right,
                        bottom = region.bottom,
                        painted_pixels,
                        total_pixels,
                        "graphics update"
                    );
                    // Once the cumulative painted area covers the full
                    // framebuffer we have a complete first frame. Keep
                    // reading only briefly (the idle-read timeout will
                    // close us out) so late top-up paints land too.
                    if painted_pixels >= total_pixels && stop_reason.is_none() {
                        info!(
                            graphics_updates,
                            "full-desktop paint reached — draining briefly then stopping"
                        );
                    }
                }
                ActiveStageOutput::Terminate(reason) => {
                    info!(?reason, "server terminated the session");
                    stop_reason = Some(StopReason::Terminated);
                    break 'outer;
                }
                ActiveStageOutput::DeactivateAll(_seq) => {
                    // Mid-session capability re-exchange. Properly handling
                    // it means re-driving the activation sequence; that's
                    // P2b/bridge scope. For a fresh single-screenshot the
                    // first paint normally precedes any deactivate.
                    warn!(
                        "server sent DeactivateAll (capability re-exchange) — \
                         not re-activated in P2a; stopping with whatever is painted"
                    );
                    stop_reason = Some(StopReason::BudgetExhausted);
                    break 'outer;
                }
                // Pointer / multitransport / autodetect updates don't
                // affect the framebuffer pixels; ignore for the
                // screenshot path (P2b will surface pointer state).
                _other => {
                    debug!("ignoring non-graphics active-stage output");
                }
            }
        }
    }

    let stop_reason = stop_reason.unwrap_or(StopReason::BudgetExhausted);
    info!(
        ?stop_reason,
        pdus, graphics_updates, painted_pixels, total_pixels, "active stage: decode loop finished"
    );

    Ok(CaptureResult {
        image,
        stop_reason,
        pdus,
        graphics_updates,
        painted_pixels,
    })
}

/// Encode a decoded RGBA32 [`DecodedImage`] to a PNG byte buffer.
///
/// `DecodedImage::data()` is a tightly-packed `width*height*4` RGBA8
/// buffer (the `PixelFormat::RgbA32` we constructed it with), which is
/// exactly what the `png` crate's `ColorType::Rgba` / `BitDepth::Eight`
/// writer expects — no row re-stride needed.
pub fn encode_png(image: &DecodedImage) -> anyhow::Result<Vec<u8>> {
    let width = u32::from(image.width());
    let height = u32::from(image.height());
    let data = image.data();

    let expected = (width as usize) * (height as usize) * 4;
    anyhow::ensure!(
        data.len() == expected,
        "decoded image buffer is {} bytes, expected {expected} for {width}x{height} RGBA8",
        data.len()
    );

    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().context("png write_header")?;
        writer
            .write_image_data(data)
            .context("png write_image_data")?;
        writer.finish().context("png finish")?;
    }
    Ok(out)
}

/// Default quality for the LOSSY WebP live encoder (0..=100). ~80 is the
/// standard "visually lossless for desktop UI" point: crisp text, a large
/// size win over the lossless region PNG. The recording path never uses this
/// (it stays on [`encode_png`]); this is the live-stream encoder only.
pub const WEBP_LIVE_QUALITY: f32 = 80.0;

/// Encode a decoded RGBA32 [`DecodedImage`] to a LOSSY WebP byte buffer at
/// `quality` (0..=100; see [`WEBP_LIVE_QUALITY`]).
///
/// Same input contract as [`encode_png`]: `DecodedImage::data()` is a
/// tightly-packed `width*height*4` RGBA8 buffer (the `PixelFormat::RgbA32` we
/// constructed it with), which is exactly what `webp::Encoder::from_rgba`
/// expects. WebP is the LIVE-stream encoder (markedly smaller on the wire than
/// the lossless PNG, decoded off the browser main thread via
/// `createImageBitmap`); PNG remains the lossless + WORM-recording encoder.
pub fn encode_webp(image: &DecodedImage, quality: f32) -> anyhow::Result<Vec<u8>> {
    let width = u32::from(image.width());
    let height = u32::from(image.height());
    let data = image.data();

    let expected = (width as usize) * (height as usize) * 4;
    anyhow::ensure!(
        data.len() == expected,
        "decoded image buffer is {} bytes, expected {expected} for {width}x{height} RGBA8",
        data.len()
    );

    let encoder = webp::Encoder::from_rgba(data, width, height);
    // `encode` returns a `WebPMemory` (owns the libwebp output buffer); copy it
    // into an owned Vec so the caller isn't tied to the libwebp allocation.
    Ok(encoder.encode(quality.clamp(0.0, 100.0)).to_vec())
}

/// Heuristic: is the decoded framebuffer non-trivial (not all one
/// colour)? Used by the runner to report honestly whether real pixels
/// were decoded vs an all-black/blank buffer.
///
/// Returns `(distinct_first_bytes_seen, is_nontrivial)` — samples the
/// buffer and reports whether more than one distinct pixel value exists.
pub fn looks_nontrivial(image: &DecodedImage) -> bool {
    let data = image.data();
    if data.len() < 8 {
        return false;
    }
    // Compare every pixel against the first; bail early on first
    // difference. An all-black or all-one-colour buffer returns false.
    let first = &data[0..4];
    data.chunks_exact(4).any(|px| px != first)
}
