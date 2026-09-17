// SPDX-License-Identifier: AGPL-3.0-or-later

//! MS-RDPEGFX (RDP Graphics Pipeline Extension) AVC420 client handler — the
//! Tier-2 "native-feel" H.264 path (ADR 0053), implemented IN-TREE on top of
//! IronRDP 0.15's DVC framework + ZGFX decompressor (no upstream fork).
//!
//! # What this is
//!
//! IronRDP 0.15 ships the *plumbing* for the graphics pipeline — a dynamic
//! virtual channel framework ([`ironrdp::dvc`]) and a ZGFX bulk decompressor
//! ([`ironrdp::graphics::zgfx`]) — but NOT an MS-RDPEGFX command-PDU codec and
//! NOT an `ActiveStageOutput` H.264 variant. This module fills that gap with a
//! focused EGFX client (AVC420 by default; AVC444 opt-in):
//!
//! 1. Registers a [`DvcProcessor`] for the well-known `Microsoft::Windows::
//!    RDS::Graphics` channel.
//! 2. On channel open, advertises `RDPGFX_CAPVERSION_81` (8.1) with the
//!    `AVC420_ENABLED` flag. By default that's the ONLY capset, so a host can
//!    select AVC420 or fall back to bitmaps but can never pick the dual-stream
//!    AVC444 codec — keeping the browser's single-stream WebCodecs decode always
//!    valid. When `JESS_RDP_AVC444` is set, a `RDPGFX_CAPVERSION_107` (10.7)
//!    capset is ALSO advertised so a capable host may use AVC444; we then display
//!    the AVC444 **main view** (a complete 4:2:0 image). See [`Self::caps_advertise`].
//! 3. Per inbound DVC message: ZGFX-decompress, walk the RDPGFX PDU stream, and
//!    for each `WIRE_TO_SURFACE_1` (AVC420, or the AVC444 main view), locate the
//!    H.264 NAL bitstream inside the `RFX_AVC420_BITMAP_STREAM` envelope and
//!    forward it VERBATIM (Annex-B) to the browser via the [`EgfxChannel`]. The
//!    Rust side **never decodes** the H.264 — the browser's WebCodecs does.
//!    Multiple surfaces (multi-monitor) are tracked independently and painted at
//!    their absolute output origins.
//! 4. Emits the REQUIRED `FRAME_ACKNOWLEDGE` after every `END_FRAME` (a server
//!    that doesn't see acks throttles, then stalls the pipeline).
//!
//! # Honest status / safety
//!
//! - OFF by default (gated by `JESS_RDP_H264` via [`crate::stream::h264_requested`]).
//! - The caller (the broker) MUST additionally keep EGFX OFF for **recorded**
//!   sessions: an H.264 frame produces no RGBA `GraphicsUpdate`, so the WORM
//!   recorder (which feeds on the lossless PNG track) would get nothing. When
//!   recording, the connector simply does not advertise AVC420 and the server
//!   uses the bitmap path → the WebP/PNG dual-emit keeps the recording lossless.
//! - The bitmap (`ServerMsg::Frame`/`FrameWebp`) path is ALWAYS the fallback:
//!   if the server doesn't pick AVC420 (old host, GPU absent, recording on),
//!   graphics arrive as surface-command bitmaps and this channel stays idle.
//! - The wire codecs here are spec-faithful ([MS-RDPEGFX]) but end-to-end
//!   pixel correctness depends on a live AVC420-capable host (Windows with the
//!   H.264/AVC graphics codec enabled) to confirm — there is no such host in CI.

use std::collections::HashMap;

use ironrdp::dvc::{DvcClientProcessor, DvcEncode, DvcMessage, DvcProcessor};
use ironrdp::graphics::zgfx;
use ironrdp_core::{ensure_size, impl_as_any, Encode, EncodeResult, WriteCursor};
use ironrdp_pdu::PduResult;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// The well-known DVC name for the MS-RDPEGFX graphics pipeline.
pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

// --- RDPGFX command IDs (RDPGFX_CMDID_*, [MS-RDPEGFX] 2.2.1.6) ------------
const CMDID_WIRE_TO_SURFACE_1: u16 = 0x0001;
const CMDID_WIRE_TO_SURFACE_2: u16 = 0x0002;
const CMDID_CREATE_SURFACE: u16 = 0x0009;
const CMDID_DELETE_SURFACE: u16 = 0x000A;
const CMDID_START_FRAME: u16 = 0x000B;
const CMDID_END_FRAME: u16 = 0x000C;
const CMDID_FRAME_ACKNOWLEDGE: u16 = 0x000D;
const CMDID_RESET_GRAPHICS: u16 = 0x000E;
const CMDID_MAP_SURFACE_TO_OUTPUT: u16 = 0x000F;
const CMDID_MAP_SURFACE_TO_WINDOW: u16 = 0x0015;
const CMDID_MAP_SURFACE_TO_SCALED_OUTPUT: u16 = 0x0017;
const CMDID_CAPS_ADVERTISE: u16 = 0x0012;
const CMDID_CAPS_CONFIRM: u16 = 0x0013;

// --- RDPGFX codec IDs (RDPGFX_CODECID_*, [MS-RDPEGFX] 2.2.1.5) ------------
const CODECID_AVC420: u16 = 0x000B;
const CODECID_AVC444: u16 = 0x000E;
const CODECID_AVC444V2: u16 = 0x000F;

// --- Capability version / flags ([MS-RDPEGFX] 2.2.3 / 2.2.3.2) -----------
/// `RDPGFX_CAPVERSION_81` (8.1). Lowest version with the AVC420 flag; has no
/// AVC444 concept — advertising only this forces an AVC420-or-bitmap choice.
const CAPVERSION_81: u32 = 0x0008_0105;
/// `RDPGFX_CAPS_FLAG_AVC420_ENABLED` — opt into the H.264 AVC420 codec.
const CAPS_FLAG_AVC420_ENABLED: u32 = 0x0000_0010;
/// `RDPGFX_CAPVERSION_107` (10.7). A v10.x capset whose `flags` bit
/// `RDPGFX_CAPS_FLAG_AVC_DISABLED` (0x20) is CLEAR ⇒ the server may use the
/// H.264 graphics codec at AVC420 *or* AVC444. Advertised ONLY when AVC444 is
/// opted into (`JESS_RDP_AVC444`); otherwise we advertise 8.1/AVC420 alone so a
/// host can never select the dual-stream AVC444 codec.
const CAPVERSION_107: u32 = 0x000A_0701;

/// RDPGFX_HEADER size: cmdId(2) + flags(2) + pduLength(4).
const RDPGFX_HEADER_SIZE: usize = 8;
/// `WIRE_TO_SURFACE_1` fixed part after the header, in bytes: surfaceId(2),
/// codecId(2), pixelFormat(1), destRect(8), bitmapDataLength(4) — total 17. The
/// `bitmapData` (RFX_AVC420_BITMAP_STREAM for AVC420) follows at this offset.
const WTS1_FIXED: usize = 17;

/// One decoded AVC420 access unit, ready to forward to the browser's WebCodecs
/// `VideoDecoder`. The Rust side only LOCATES the NAL bitstream; it never
/// decodes it.
#[derive(Debug, Clone)]
pub struct Avc420Frame {
    /// Annex-B (start-code-delimited) H.264 NAL bytes for the access unit.
    pub nal: Vec<u8>,
    /// Destination X on the desktop (surface output origin + destRect.left).
    pub x: u16,
    /// Destination Y on the desktop (surface output origin + destRect.top).
    pub y: u16,
    /// Destination width (destRect.right - destRect.left).
    pub w: u16,
    /// Destination height (destRect.bottom - destRect.top).
    pub h: u16,
    /// `true` if the access unit carries an IDR or SPS — the browser decoder
    /// must (re)start on a keyframe.
    pub keyframe: bool,
    /// `true` if this is the MAIN view of an AVC444 4:4:4 update — an [`Avc420Frame`]
    /// with [`Self::aux`] set follows and the browser recombines them (ADR 0059).
    /// `false` for a plain AVC420 (single-stream) update.
    pub avc444: bool,
    /// `true` if this is the AVC444 AUXILIARY (chroma) view to recombine with the
    /// preceding main view; `false` for a displayable (main / plain AVC420) view.
    pub aux: bool,
}

/// The receive handle the session loop holds to drain decoded AVC420 frames
/// the [`EgfxClient`] extracts inside `ActiveStage::process()`. Drained each
/// loop iteration and turned into `ServerMsg::H264`.
pub struct EgfxChannel {
    frames: mpsc::UnboundedReceiver<Avc420Frame>,
}

impl EgfxChannel {
    /// Non-blocking pop of the next decoded frame, if any.
    pub fn try_recv(&mut self) -> Option<Avc420Frame> {
        self.frames.try_recv().ok()
    }
}

/// An already-serialised, **ZGFX-wrapped** EGFX client→server PDU (CapsAdvertise
/// from `start()`, FrameAcknowledge from `process()`). The whole client→server
/// EGFX surface is tiny and fixed-shape, so we build the RDPGFX PDU bytes by hand
/// and wrap them in the RDP8 RDP_SEGMENTED_DATA descriptor (uncompressed single
/// segment, via [`zgfx::wrap_uncompressed`]) — REQUIRED: every PDU on the
/// `Microsoft::Windows::RDS::Graphics` channel is RDP8-bulk framed in BOTH
/// directions, so a Windows host silently ignores a raw (unwrapped) PDU and
/// never sends CapsConfirm (verified live). The DVC framework then carries these
/// wrapped bytes in DRDYNVC Data PDUs.
struct RawEgfxPdu(Vec<u8>);

impl Encode for RawEgfxPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPGFX_CLIENT_PDU"
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl DvcEncode for RawEgfxPdu {}

/// Per-surface state we track to map a surface-relative destRect to absolute
/// desktop coordinates for the browser blit.
#[derive(Debug, Clone, Copy, Default)]
struct SurfaceInfo {
    /// Output origin X on the desktop (from MAP_SURFACE_TO_OUTPUT).
    origin_x: u32,
    /// Output origin Y on the desktop.
    origin_y: u32,
}

/// The MS-RDPEGFX AVC420 DVC processor. Owns the (stateful) ZGFX decompressor,
/// surface→origin map, and the sender half of the frame side-channel.
pub struct EgfxClient {
    /// ZGFX bulk decompressor — STATEFUL (≈2.5 MiB LZ77 history); MUST persist
    /// across PDUs for back-references to resolve. Hence a field, not a local.
    decompressor: zgfx::Decompressor,
    /// surfaceId → output mapping, for absolute-coordinate frame placement.
    surfaces: HashMap<u16, SurfaceInfo>,
    /// Sender half of the decoded-frame side-channel (the loop holds the rx).
    frames_tx: mpsc::UnboundedSender<Avc420Frame>,
    /// Running count of acknowledged frames, for FRAME_ACKNOWLEDGE.
    total_frames_decoded: u32,
    /// Whether to ALSO advertise AVC444 (capversion 10.7) — opt-in via
    /// `JESS_RDP_AVC444`. When a host then selects AVC444, we display the main
    /// (luma + 4:2:0 chroma) view of the dual-stream — see [`avc444_main_view`].
    advertise_avc444: bool,
}

/// Whether the operator opted into AVC444 (`JESS_RDP_AVC444` truthy). Default
/// off ⇒ AVC420-only advertise (a host can never pick the dual-stream codec).
fn avc444_requested() -> bool {
    std::env::var("JESS_RDP_AVC444")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

impl EgfxClient {
    /// Build the processor + the loop-side [`EgfxChannel`]. Move the processor
    /// into a `DrdynvcClient::with_dynamic_channel(...)`; hand the channel to
    /// the session loop.
    pub fn create() -> (Self, EgfxChannel) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                decompressor: zgfx::Decompressor::new(),
                surfaces: HashMap::new(),
                frames_tx: tx,
                total_frames_decoded: 0,
                advertise_avc444: avc444_requested(),
            },
            EgfxChannel { frames: rx },
        )
    }

    /// Build the `RDPGFX_CAPS_ADVERTISE_PDU`. Always advertises capversion 8.1
    /// with the AVC420 flag; when `avc444` is set, ALSO advertises capversion
    /// 10.7 (flags=0 ⇒ AVC enabled, AVC444 permitted) so a capable host may pick
    /// the dual-stream codec. Each RDPGFX_CAPSET = { version(4),
    /// capsDataLength(4)=4, capsData=flags(4) }; the body is capsSetCount(2) then
    /// the capsets.
    fn caps_advertise(avc444: bool) -> RawEgfxPdu {
        let caps_set_count: u16 = if avc444 { 2 } else { 1 };
        let body_len = 2 + 12 * usize::from(caps_set_count);
        let pdu_len = (RDPGFX_HEADER_SIZE + body_len) as u32;
        let mut b = Vec::with_capacity(pdu_len as usize);
        // RDPGFX_HEADER
        b.extend_from_slice(&CMDID_CAPS_ADVERTISE.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // flags
        b.extend_from_slice(&pdu_len.to_le_bytes());
        // body
        b.extend_from_slice(&caps_set_count.to_le_bytes());
        // capset 1: 8.1 / AVC420
        b.extend_from_slice(&CAPVERSION_81.to_le_bytes());
        b.extend_from_slice(&4u32.to_le_bytes()); // capsDataLength
        b.extend_from_slice(&CAPS_FLAG_AVC420_ENABLED.to_le_bytes());
        if avc444 {
            // capset 2: 10.7 with flags=0 (AVC enabled, AVC444 permitted).
            b.extend_from_slice(&CAPVERSION_107.to_le_bytes());
            b.extend_from_slice(&4u32.to_le_bytes()); // capsDataLength
            b.extend_from_slice(&0u32.to_le_bytes()); // flags = 0 (AVC not disabled)
        }
        RawEgfxPdu(zgfx::wrap_uncompressed(&b))
    }

    /// Build a `RDPGFX_FRAME_ACKNOWLEDGE_PDU` { queueDepth, frameId,
    /// totalFramesDecoded }. We report `queueDepth = 0` ("no backlog — keep
    /// sending") because we forward NAL units to the browser immediately and do
    /// not gate the server on browser-side display.
    fn frame_acknowledge(frame_id: u32, total: u32) -> RawEgfxPdu {
        let body_len = 12; // queueDepth(4) + frameId(4) + totalFramesDecoded(4)
        let pdu_len = (RDPGFX_HEADER_SIZE + body_len) as u32;
        let mut b = Vec::with_capacity(pdu_len as usize);
        b.extend_from_slice(&CMDID_FRAME_ACKNOWLEDGE.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // flags
        b.extend_from_slice(&pdu_len.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // queueDepth = 0
        b.extend_from_slice(&frame_id.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        RawEgfxPdu(zgfx::wrap_uncompressed(&b))
    }

    /// Walk one decompressed RDPGFX PDU stream, dispatching each command and
    /// collecting any client→server replies (frame acks).
    fn handle_pdu_stream(&mut self, data: &[u8]) -> Vec<DvcMessage> {
        let mut msgs: Vec<DvcMessage> = Vec::new();
        let mut off = 0usize;
        while off + RDPGFX_HEADER_SIZE <= data.len() {
            let cmd_id = u16::from_le_bytes([data[off], data[off + 1]]);
            // data[off+2..off+4] = flags (unused by us)
            let pdu_len =
                u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]])
                    as usize;
            // pduLength includes the 8-byte header; guard against a bogus length.
            if pdu_len < RDPGFX_HEADER_SIZE || off + pdu_len > data.len() {
                warn!(
                    cmd_id,
                    pdu_len,
                    remaining = data.len() - off,
                    "EGFX: bad RDPGFX pduLength — stopping stream walk"
                );
                break;
            }
            let body = &data[off + RDPGFX_HEADER_SIZE..off + pdu_len];
            self.dispatch(cmd_id, body, &mut msgs);
            off += pdu_len;
        }
        msgs
    }

    /// Dispatch one RDPGFX command. Only AVC420 graphics + the few surface /
    /// frame bookkeeping commands are acted on; everything else is tracked or
    /// ignored (the bitmap path is unaffected — these are EGFX-only commands).
    fn dispatch(&mut self, cmd_id: u16, body: &[u8], msgs: &mut Vec<DvcMessage>) {
        match cmd_id {
            CMDID_WIRE_TO_SURFACE_1 => self.handle_wire_to_surface_1(body),
            CMDID_CREATE_SURFACE => {
                // surfaceId(2), width(2), height(2), pixelFormat(1)
                if body.len() >= 2 {
                    let sid = u16::from_le_bytes([body[0], body[1]]);
                    self.surfaces.entry(sid).or_default();
                    trace!(surface = sid, "EGFX: CREATE_SURFACE");
                }
            }
            CMDID_DELETE_SURFACE => {
                if body.len() >= 2 {
                    let sid = u16::from_le_bytes([body[0], body[1]]);
                    self.surfaces.remove(&sid);
                    trace!(surface = sid, "EGFX: DELETE_SURFACE");
                }
            }
            CMDID_MAP_SURFACE_TO_OUTPUT | CMDID_MAP_SURFACE_TO_SCALED_OUTPUT => {
                // surfaceId(2), reserved(2), outputOriginX(4), outputOriginY(4)
                // [SCALED adds targetWidth(4)+targetHeight(4) — scaling is ignored;
                // we place the surface at its output origin]. MULTI-MONITOR: each
                // surface maps to its own output origin, tracked independently in
                // `surfaces`, so several monitors paint at their absolute desktop
                // coordinates.
                if body.len() >= 12 {
                    let sid = u16::from_le_bytes([body[0], body[1]]);
                    let ox = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                    let oy = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
                    let info = self.surfaces.entry(sid).or_default();
                    info.origin_x = ox;
                    info.origin_y = oy;
                    trace!(
                        surface = sid,
                        ox,
                        oy,
                        scaled = cmd_id == CMDID_MAP_SURFACE_TO_SCALED_OUTPUT,
                        "EGFX: MAP_SURFACE_TO_OUTPUT"
                    );
                }
            }
            CMDID_MAP_SURFACE_TO_WINDOW => {
                trace!("EGFX: MAP_SURFACE_TO_WINDOW (RemoteApp — not used for full desktop)")
            }
            CMDID_START_FRAME => {
                // timestamp(4), frameId(4) — nothing to do until END_FRAME.
                trace!("EGFX: START_FRAME");
            }
            CMDID_END_FRAME => {
                // frameId(4) — acknowledge it (REQUIRED for continued flow).
                if body.len() >= 4 {
                    let frame_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    self.total_frames_decoded = self.total_frames_decoded.wrapping_add(1);
                    msgs.push(Box::new(Self::frame_acknowledge(
                        frame_id,
                        self.total_frames_decoded,
                    )));
                    trace!(frame_id, "EGFX: END_FRAME → FRAME_ACKNOWLEDGE");
                }
            }
            CMDID_CAPS_CONFIRM => {
                // version(4), capsDataLength(4), capsData
                if body.len() >= 4 {
                    let version = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    debug!(version = format!("{version:#010x}"), "EGFX: CAPS_CONFIRM");
                }
            }
            CMDID_RESET_GRAPHICS => {
                // width(4), height(4), monitorCount(4), then the monitor array +
                // padding. We don't drive layout from this (frames carry their own
                // absolute coords via surface origin + destRect), but log the
                // desktop dimensions + monitor count for multi-monitor diagnostics.
                if body.len() >= 12 {
                    let w = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    let h = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                    let monitors = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
                    trace!(w, h, monitors, "EGFX: RESET_GRAPHICS");
                }
            }
            CMDID_WIRE_TO_SURFACE_2 => trace!("EGFX: WIRE_TO_SURFACE_2 (cached — ignored)"),
            other => trace!(cmd_id = other, "EGFX: unhandled command (ignored)"),
        }
    }

    /// Parse a `RDPGFX_WIRE_TO_SURFACE_PDU_1`; if it carries codec AVC420,
    /// extract the NAL bitstream + dest rect and forward an [`Avc420Frame`].
    fn handle_wire_to_surface_1(&mut self, body: &[u8]) {
        if body.len() < WTS1_FIXED {
            warn!(len = body.len(), "EGFX: short WIRE_TO_SURFACE_1");
            return;
        }
        let surface_id = u16::from_le_bytes([body[0], body[1]]);
        let codec_id = u16::from_le_bytes([body[2], body[3]]);
        // body[4] = pixelFormat (unused — AVC420 output is YUV→RGB in the browser)
        let dest_left = u16::from_le_bytes([body[5], body[6]]);
        let dest_top = u16::from_le_bytes([body[7], body[8]]);
        let dest_right = u16::from_le_bytes([body[9], body[10]]);
        let dest_bottom = u16::from_le_bytes([body[11], body[12]]);
        // bitmapDataLength(u32 LE) at offset 13; bitmapData starts at offset 17.
        // Honour the declared length (FreeRDP `rdpgfx_recv_wire_to_surface_1_pdu`)
        // but fall back to end-of-PDU if it overruns, so a slightly-off length
        // never drops an otherwise-valid frame.
        let bitmap_data_len = u32::from_le_bytes([body[13], body[14], body[15], body[16]]) as usize;
        let bitmap_data = body
            .get(WTS1_FIXED..WTS1_FIXED + bitmap_data_len)
            .unwrap_or(&body[WTS1_FIXED..]);

        // Resolve the RFX_AVC420_BITMAP_STREAM(s) to forward. For AVC420 the
        // bitmap data IS that stream — a plain single-stream update. AVC444/v2
        // wraps TWO of them — a main (luma + 4:2:0 chroma) view and an auxiliary
        // (chroma residual) view. We forward the MAIN view (a complete 4:2:0
        // image with correct colour) AND, when present, the AUXILIARY view, so a
        // capable browser can recombine them into true 4:4:4 (ADR 0059, the
        // MS-RDPEGFX YUV420→YUV444 mapping in a WebGL shader). A browser that
        // can't recombine simply displays the main view (4:2:0) — see the SPA.
        match codec_id {
            CODECID_AVC420 => self.emit_frame(
                surface_id, dest_left, dest_top, dest_right, dest_bottom, bitmap_data, false, false,
            ),
            CODECID_AVC444 | CODECID_AVC444V2 => {
                let Some(main_stream) = avc444_main_view(bitmap_data) else {
                    // LC==2 (chroma-only) update — no main view to display, and
                    // this stateless emit can't correlate it to a prior main. Drop
                    // it; the next full frame restores fidelity (prior behaviour).
                    warn!("EGFX: chroma-only RFX_AVC444_BITMAP_STREAM — dropping frame");
                    return;
                };
                let aux_stream = avc444_aux_view(bitmap_data);
                // Mark the main view `avc444` ONLY when an aux frame follows, so a
                // luma-only (LC==1) update stays a plain AVC420 frame for the SPA.
                self.emit_frame(
                    surface_id,
                    dest_left,
                    dest_top,
                    dest_right,
                    dest_bottom,
                    main_stream,
                    aux_stream.is_some(),
                    false,
                );
                if let Some(aux_stream) = aux_stream {
                    self.emit_frame(
                        surface_id, dest_left, dest_top, dest_right, dest_bottom, aux_stream, false,
                        true,
                    );
                }
            }
            other => {
                // A non-AVC EGFX codec (RemoteFX progressive / ClearCodec /
                // planar / uncompressed) — not decoded server-side; the bitmap
                // path covers those. A host honouring our caps shouldn't send them.
                trace!(codec_id = other, "EGFX: non-AVC WIRE_TO_SURFACE_1 — ignored");
            }
        }
    }

    /// Extract the NAL bitstream from an `RFX_AVC420_BITMAP_STREAM`, map the dest
    /// rect to absolute desktop coordinates via the surface's output origin, and
    /// forward an [`Avc420Frame`]. Shared by the AVC420 and AVC444 (main-view)
    /// paths.
    #[allow(clippy::too_many_arguments)]
    fn emit_frame(
        &mut self,
        surface_id: u16,
        dest_left: u16,
        dest_top: u16,
        dest_right: u16,
        dest_bottom: u16,
        avc420_stream: &[u8],
        avc444: bool,
        aux: bool,
    ) {
        let Some(nal) = avc420_nal(avc420_stream) else {
            warn!("EGFX: malformed RFX_AVC420_BITMAP_STREAM — dropping frame");
            return;
        };
        if nal.is_empty() {
            return;
        }

        let origin = self.surfaces.get(&surface_id).copied().unwrap_or_default();
        let x =
            u16::try_from(u32::from(dest_left).saturating_add(origin.origin_x)).unwrap_or(u16::MAX);
        let y =
            u16::try_from(u32::from(dest_top).saturating_add(origin.origin_y)).unwrap_or(u16::MAX);
        let w = dest_right.saturating_sub(dest_left);
        let h = dest_bottom.saturating_sub(dest_top);
        let keyframe = nal_has_keyframe(nal);

        let frame = Avc420Frame {
            nal: nal.to_vec(),
            x,
            y,
            w,
            h,
            keyframe,
            avc444,
            aux,
        };
        // Unbounded send never blocks; the only error is a closed receiver
        // (session ending) — safe to drop the frame then.
        if self.frames_tx.send(frame).is_err() {
            trace!("EGFX: frame receiver gone — session ending");
        }
    }
}

impl_as_any!(EgfxClient);

impl DvcProcessor for EgfxClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        if self.advertise_avc444 {
            debug!("EGFX: channel open — advertising AVC420 (8.1) + AVC444 (10.7)");
        } else {
            debug!("EGFX: channel open — advertising AVC420-only (capversion 8.1)");
        }
        Ok(vec![Box::new(Self::caps_advertise(self.advertise_avc444))])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        // `payload` is one COMPLETE (DVC-reassembled) EGFX message: a ZGFX
        // bulk-compressed blob. Decompress, then walk the RDPGFX PDU stream.
        let mut decompressed = Vec::new();
        if let Err(e) = self.decompressor.decompress(payload, &mut decompressed) {
            warn!(error = %e, "EGFX: ZGFX decompress failed — dropping segment");
            return Ok(Vec::new());
        }
        Ok(self.handle_pdu_stream(&decompressed))
    }
}

impl DvcClientProcessor for EgfxClient {}

/// Locate the AVC420 NAL bitstream inside a `RFX_AVC420_BITMAP_STREAM`
/// ([MS-RDPEGFX] 2.2.4.4): an `RFX_AVC420_METABLOCK` header then the raw H.264
/// access unit. The metablock is `numRegionRects(4)` then, per rect, an
/// `RDPGFX_RECT16` (8 bytes) and an `RDPGFX_AVC420_QUANTIZATION_QUALITY`
/// (2 bytes) — i.e. `4 + numRegionRects * 10` bytes. The remainder is the NAL
/// bitstream we forward verbatim. Returns `None` on a malformed header.
fn avc420_nal(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    let num_rects = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    // 10 bytes per rect (8 rect + 2 quant) — checked-mul guards a bogus count.
    let meta_size = 4usize.checked_add(num_rects.checked_mul(10)?)?;
    if meta_size > data.len() {
        return None;
    }
    Some(&data[meta_size..])
}

/// Locate the MAIN (luma + 4:2:0 chroma) view inside an `RFX_AVC444_BITMAP_STREAM`
/// ([MS-RDPEGFX] 2.2.4.5). Layout: a `UINT32` whose low 30 bits are
/// `cbAvc420EncodedBitstream1` (the byte length of view 1) and whose top 2 bits
/// are `LC` (the "luma/chroma" selector), then view 1 (an `RFX_AVC420_BITMAP_STREAM`,
/// the main view) and optionally view 2 (the auxiliary chroma view). `LC`:
/// `0` = both views present, `1` = view 1 (luma) only, `2` = view 2 (chroma) only.
/// We return view 1 (the displayable 4:2:0 image) for `LC` 0/1; for `LC` 2 there
/// is no luma view to display, so `None`. The returned slice is itself an
/// `RFX_AVC420_BITMAP_STREAM` that [`avc420_nal`] then parses. The auxiliary
/// chroma view (full 4:4:4 recombine) is intentionally not used here.
fn avc444_main_view(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    let info = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let lc = info >> 30;
    if lc == 2 {
        return None; // chroma-only update — no luma view to display
    }
    let cb1 = (info & 0x3FFF_FFFF) as usize; // low 30 bits = view-1 byte length
    let rest = &data[4..];
    // LC==1 ⇒ view 1 is the whole remainder; LC==0 ⇒ first cb1 bytes. A bogus
    // cb1 falls back to the whole remainder rather than dropping the frame.
    Some(rest.get(..cb1).unwrap_or(rest))
}

/// Locate the AUXILIARY (chroma) view inside an `RFX_AVC444_BITMAP_STREAM`
/// ([MS-RDPEGFX] 2.2.4.5) — the second `RFX_AVC420_BITMAP_STREAM` (view 2),
/// which carries the chroma samples needed to upgrade the main view's 4:2:0 to
/// 4:4:4. The header `UINT32` low 30 bits are `cbAvc420EncodedBitstream1`
/// (view-1 length) and the top 2 bits are `LC`: `0` = both views present
/// (view 2 = the bytes after view 1), `1` = luma only (NO aux view → `None`),
/// `2` = chroma only (the whole remainder IS view 2; not reached here because
/// [`avc444_main_view`] returns `None` for `LC==2` and the caller drops it).
/// The returned slice is itself an `RFX_AVC420_BITMAP_STREAM` that
/// [`avc420_nal`] then parses. The browser recombines it with the main view
/// into true 4:4:4 (ADR 0059); browsers that can't simply ignore it.
fn avc444_aux_view(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    let info = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let lc = info >> 30;
    let cb1 = (info & 0x3FFF_FFFF) as usize; // low 30 bits = view-1 byte length
    let rest = &data[4..];
    match lc {
        0 => rest.get(cb1..).filter(|s| !s.is_empty()), // both views — aux follows view 1
        2 => Some(rest),                                // chroma-only — remainder is the aux view
        _ => None,                                      // LC==1 (luma only) — no aux view
    }
}

/// Scan an Annex-B H.264 access unit for a keyframe indicator: an IDR slice
/// (nal_unit_type 5) or an SPS (7) means the browser decoder can (re)start
/// here. Walks 3-byte (`00 00 01`) and 4-byte (`00 00 00 01`) start codes.
fn nal_has_keyframe(nal: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 3 < nal.len() {
        if nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 1 {
            let nal_unit_type = nal[i + 3] & 0x1F;
            if nal_unit_type == 5 || nal_unit_type == 7 {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}
