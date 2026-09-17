// SPDX-License-Identifier: AGPL-3.0-or-later

//! Software H.264 encoder for the GPU-free "native-feel" live path (ADR 0061).
//!
//! `session_live` already decodes RDP into a full RGBA framebuffer
//! ([`ironrdp_session::image::DecodedImage`]). Instead of re-encoding each dirty
//! region as a separate WebP *image* (no inter-frame compression, capped fps,
//! stutter under motion), this CPU-encodes the **whole framebuffer** as a real
//! low-latency H.264 video stream with Cisco's OpenH264. The encoded access
//! units are emitted as `MSG_H264` — the SAME wire the EGFX/AVC420 host path
//! uses — so the browser decodes them via the existing WebCodecs decoder
//! (`rdpH264.ts`), they're recorded by the existing WORM tee (ADR 0058), and
//! they ride the WebTransport datagram transport (ADR 0060). No GPU anywhere,
//! and it works against ANY RDP target (the host sends ordinary RDP graphics;
//! WE encode the H.264). Unlike the EGFX path, it does NOT depend on the Windows
//! host having an AVC hardware encoder.
//!
//! Colour: a standard BT.601 limited-range RGBA→I420 conversion (OpenH264's
//! default colour space; matches what WebCodecs assumes when the stream carries
//! no VUI). Minor colour variance vs the host is possible — see ADR 0061.

use anyhow::{Context, Result};
use openh264::encoder::{Encoder, EncoderConfig, FrameType, RateControlMode};
use openh264::formats::YUVSlices;
use openh264::OpenH264API;

/// A reusable software H.264 encoder bound to one desktop size. Recreate it
/// (via [`Self::new`]) if the RDP desktop resizes.
pub struct H264SwEncoder {
    enc: Encoder,
    width: usize,  // even (H.264 macroblock requirement); see new()
    height: usize, // even
    // Reusable I420 plane buffers so the hot path doesn't allocate per frame.
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    first: bool,
}

impl H264SwEncoder {
    /// Build an encoder for a `width`x`height` desktop at `bitrate_bps` / `fps`.
    /// Dimensions are floored to even values (H.264 needs even W/H); a 1-pixel
    /// odd edge is dropped (imperceptible, and RDP desktop sizes are even anyway).
    pub fn new(width: u16, height: u16, bitrate_bps: u32, fps: f32) -> Result<Self> {
        let w = (width as usize) & !1;
        let h = (height as usize) & !1;
        anyhow::ensure!(
            w >= 16 && h >= 16,
            "desktop {width}x{height} too small for H.264"
        );
        // Bitrate-controlled, frame-skipping low-latency config. OpenH264 emits
        // SPS+PPS before each IDR by default, so a keyframe access unit is
        // self-initialising for the browser's WebCodecs decoder.
        let cfg = EncoderConfig::new()
            .set_bitrate_bps(bitrate_bps)
            .rate_control_mode(RateControlMode::Bitrate)
            .max_frame_rate(fps)
            .enable_skip_frame(true);
        let enc = Encoder::with_api_config(OpenH264API::from_source(), cfg)
            .context("openh264: create encoder")?;
        Ok(Self {
            enc,
            width: w,
            height: h,
            y: vec![0u8; w * h],
            u: vec![0u8; (w / 2) * (h / 2)],
            v: vec![0u8; (w / 2) * (h / 2)],
            first: true,
        })
    }

    /// The (even) frame size this encoder produces — the `MSG_H264` w/h.
    pub fn dimensions(&self) -> (u16, u16) {
        (self.width as u16, self.height as u16)
    }

    /// Encode one full RGBA framebuffer (`stride` bytes per row) into an Annex-B
    /// H.264 access unit. Returns `(nal, keyframe)`; `keyframe` is true for an
    /// IDR (carries SPS+PPS). An empty `nal` (the encoder skipped this frame for
    /// rate control) returns `Ok(None)`.
    pub fn encode(&mut self, rgba: &[u8], stride: usize) -> Result<Option<(Vec<u8>, bool)>> {
        self.rgba_to_i420(rgba, stride);
        // First frame MUST be an IDR so the browser decoder can configure.
        if self.first {
            self.enc.force_intra_frame();
            self.first = false;
        }
        let yuv = YUVSlices::new(
            (&self.y, &self.u, &self.v),
            (self.width, self.height),
            (self.width, self.width / 2, self.width / 2),
        );
        let bs = self.enc.encode(&yuv).context("openh264: encode frame")?;
        match bs.frame_type() {
            FrameType::Skip => Ok(None), // rate control dropped this frame
            ft => {
                let nal = bs.to_vec();
                if nal.is_empty() {
                    return Ok(None);
                }
                let keyframe = matches!(ft, FrameType::IDR | FrameType::I);
                Ok(Some((nal, keyframe)))
            }
        }
    }

    /// BT.601 limited-range RGBA→I420 into the reusable plane buffers. Y is
    /// per-pixel; U/V are one sample per 2x2 block from the averaged RGB.
    // Indexed loops are intentional: each row writes one plane while reading a
    // strided, differently-shaped RGBA source — an iterator rewrite would be
    // less clear and no faster in this hot pixel loop.
    #[allow(clippy::needless_range_loop)]
    fn rgba_to_i420(&mut self, rgba: &[u8], stride: usize) {
        let (w, h) = (self.width, self.height);
        for row in 0..h {
            let line = &rgba[row * stride..];
            let yrow = &mut self.y[row * w..row * w + w];
            for col in 0..w {
                let p = col * 4;
                let r = line[p] as i32;
                let g = line[p + 1] as i32;
                let b = line[p + 2] as i32;
                // Y = 16 + (65.738R + 129.057G + 25.064B)/256 (BT.601, 8-bit fixed)
                yrow[col] = clamp8(16 + ((66 * r + 129 * g + 25 * b + 128) >> 8));
            }
        }
        let cw = w / 2;
        for cy in 0..h / 2 {
            let r0 = (2 * cy) * stride;
            let r1 = (2 * cy + 1) * stride;
            let urow = &mut self.u[cy * cw..cy * cw + cw];
            let vrow = &mut self.v[cy * cw..cy * cw + cw];
            for cx in 0..cw {
                let p = 2 * cx * 4;
                // Average the 2x2 RGB block for the shared chroma sample.
                let mut r = 0i32;
                let mut g = 0i32;
                let mut b = 0i32;
                for base in [r0 + p, r0 + p + 4, r1 + p, r1 + p + 4] {
                    r += rgba[base] as i32;
                    g += rgba[base + 1] as i32;
                    b += rgba[base + 2] as i32;
                }
                r /= 4;
                g /= 4;
                b /= 4;
                // U = 128 + (-38R - 74G + 112B)/256 ; V = 128 + (112R - 94G - 18B)/256
                urow[cx] = clamp8(128 + ((-38 * r - 74 * g + 112 * b + 128) >> 8));
                vrow[cx] = clamp8(128 + ((112 * r - 94 * g - 18 * b + 128) >> 8));
            }
        }
    }
}

#[inline]
fn clamp8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// Whether the operator opted into the software-H.264 path (`JESS_RDP_H264_SW`
/// truthy). Default OFF — the bitmap (WebP/PNG) path is unchanged unless set.
pub fn sw_h264_requested() -> bool {
    std::env::var("JESS_RDP_H264_SW")
        .map(|v| {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        })
        .unwrap_or(false)
}

/// Target bitrate (bits/s) for the software encoder, from `JESS_RDP_H264_SW_BITRATE`
/// (default 8 Mbit/s — a reasonable desktop default). Clamped to a sane range.
pub fn sw_h264_bitrate() -> u32 {
    std::env::var("JESS_RDP_H264_SW_BITRATE")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(8_000_000)
        .clamp(500_000, 50_000_000)
}

/// Max frame rate for the software encoder, from `JESS_RDP_H264_SW_FPS`
/// (default 30). Clamped to 1..=60.
pub fn sw_h264_fps() -> f32 {
    std::env::var("JESS_RDP_H264_SW_FPS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(30)
        .clamp(1, 60) as f32
}
