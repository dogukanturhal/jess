// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming active session + the Go↔Rust bridge wire protocol — ADR 0051
//! Phase 5f-8b-P2b ("streaming session core"), branch `feat/rdp-p2b-stream`.
//!
//! ## What this is
//!
//! Turns the one-shot [`crate::active::capture_desktop`] decode into a
//! **live streaming session**: it drives `ironrdp_session::ActiveStage`
//! over the post-`Connected` [`crate::connect::LiveFramed`] stream and,
//! instead of accumulating one framebuffer and writing a single PNG, it
//!
//! * emits a `DESKTOP_SIZE` message once, then one `FRAME` message per
//!   decoded dirty region (the region crop re-encoded with the P2a `png`
//!   encoder), and a `CLOSE` message on session end — written to an
//!   arbitrary [`AsyncWrite`] sink (stdout in the `session_live` bin); and
//! * reads `MOUSE` / `KEY` messages from an arbitrary [`AsyncRead`] source
//!   (stdin in the bin), maps them to IronRDP FastPath input events, and
//!   feeds them into the live session via `ActiveStage::process_fastpath_input`.
//!
//! This is the exact length-prefixed TLV wire format a later talon Go
//! bridge + browser canvas will speak — see [the protocol](#wire-protocol).
//!
//! ## Concurrency model
//!
//! The [`LiveFramed`] is split once (`ironrdp_tokio::split_tokio_framed`)
//! into a read-half and a write-half:
//!
//! * a **stdin-reader task** owns the input source: it decodes inbound
//!   TLVs, maps each to a `FastPathInputEvent`, encodes it through the
//!   shared `ActiveStage` encoder (behind a `Mutex`, used only briefly for
//!   the pure CPU encode — never across an await on the socket), and sends
//!   the resulting wire bytes over an `mpsc` channel; it NEVER touches the
//!   socket;
//! * the **main loop** owns BOTH the read-half and the write-half. It
//!   `tokio::select!`s between `read_pdu()` (a server PDU) and
//!   `rx.recv()` (an outbound input PDU). Both branches are cancel-safe
//!   (documented so upstream). The actual `write_all` to the write-half
//!   happens AFTER the select resolves, never inside a select arm — so the
//!   non-cancel-safe `write_all` future is never raced or dropped
//!   mid-flight. The write-half therefore has a single owner and inbound
//!   input + outbound server-response frames are serialised through it.
//!
//! This is the "mpsc of outbound PDUs merged into the read loop" option
//! from the task brief: the framed sink is never shared across tasks.
//!
//! ## Wire protocol
//!
//! All integers **big-endian**. Every message is
//! `[u32 total_len][u8 msg_type][payload]` where `total_len` counts
//! `msg_type` + `payload` (i.e. `1 + payload.len()`).
//!
//! Server→client ([`ServerMsg`], written to the sink):
//! * `1` `DESKTOP_SIZE` — `[u16 width][u16 height]`. Emitted once at start.
//! * `2` `FRAME` — `[u16 x][u16 y][u16 w][u16 h][PNG bytes]`. One per
//!   decoded dirty region; the PNG is that sub-rectangle of the
//!   framebuffer. LOSSLESS — retained as the lossless mode AND as the
//!   recorder feed (the Go tee inlines it into jess-rdp-recording-v2).
//! * `3` `CLOSE` — empty payload. On session end.
//! * `4` `FRAME_WEBP` — `[u16 x][u16 y][u16 w][u16 h][WebP bytes]`. The
//!   Tier-1 LOSSY live frame (same geometry header as `FRAME`, WebP body
//!   instead of PNG). This is the DEFAULT live frame the browser renders
//!   off-thread via `createImageBitmap`; it is markedly smaller than the
//!   lossless PNG. When recording is on, the session emits a `FRAME_WEBP`
//!   for the browser AND a lossless `FRAME` (PNG) for the recorder — the Go
//!   bridge forwards the WebP to the browser and records only the PNG, so
//!   the WORM bundle stays lossless + format-unchanged.
//!
//! Client→server ([`ClientMsg`], read from the source):
//! * `1` `MOUSE` — `[u16 x][u16 y][u8 button_mask][i8 wheel]`
//!   (button_mask bit0=left, 1=right, 2=middle).
//! * `2` `KEY` — `[u8 is_down][u32 scancode]` (RDP scancode).
//!
//! ## Gated OFF by default
//!
//! Compiled only under the `ironrdp_live` cargo feature (same as
//! `connect.rs` / `active.rs`). Default `cargo build` / CI surface is
//! unchanged. The TLV codec itself has no live deps, so its roundtrip
//! unit tests run under `cargo test --features …/ironrdp_live`.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp_async::{FramedRead, FramedWrite as _};
use ironrdp_pdu::geometry::InclusiveRectangle;
// `width()` / `height()` on InclusiveRectangle come from the `Rectangle` trait —
// must be in scope to call them (used by the EGFX H.264 emit seam, ADR 0053).
use ironrdp_pdu::geometry::Rectangle as _;
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags as FpKeyboardFlags};
use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use ironrdp_tokio::split_tokio_framed;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::clipboard::{ClipboardChannel, ClipboardCommand};
use crate::connect::LiveFramed;
use crate::egfx::EgfxChannel;
use ironrdp::cliprdr::pdu::{ClipboardFormat, ClipboardFormatId, FormatDataResponse};
use ironrdp::cliprdr::CliprdrClient;
// `IntoOwned` provides `.into_owned()` on the borrowed `FormatDataResponse<'_>`
// the cliprdr text helpers return, to the `OwnedFormatDataResponse` that
// `submit_format_data` requires.
use ironrdp_core::IntoOwned as _;

// --- Wire-protocol message-type bytes ------------------------------------

/// Server→client `DESKTOP_SIZE` message type.
pub const MSG_DESKTOP_SIZE: u8 = 1;
/// Server→client `FRAME` (LOSSLESS PNG) message type.
pub const MSG_FRAME: u8 = 2;
/// Server→client `CLOSE` message type.
pub const MSG_CLOSE: u8 = 3;
/// Server→client `FRAME_WEBP` (Tier-1 LOSSY WebP) message type.
pub const MSG_FRAME_WEBP: u8 = 4;
/// Server→client `H264` message type — the Tier-2 "native-feel" H.264
/// access-unit path (ADR 0053). This is an **additive, parallel** codepath to
/// the [`MSG_FRAME`] PNG bitmap path; it never replaces it.
///
/// Payload: `[u8 flags][u16 x][u16 y][u16 w][u16 h][AVC NAL bytes (Annex-B)]`.
/// `flags` bit0 = keyframe (the access unit is an IDR carrying SPS+PPS),
/// bit1 = AVC444 (a second chroma plane the client must composite; AVC420 4:2:0
/// when clear). The browser feeds the NAL bytes to a WebCodecs `VideoDecoder`.
///
/// **STATUS (ADR 0053):** the broker NOW emits this — the in-tree MS-RDPEGFX
/// AVC420 handler ([`crate::egfx`]) registers a DRDYNVC channel, ZGFX-
/// decompresses the graphics stream, extracts AVC420 NAL units, and the
/// [`run_session`] loop drains them into `MSG_H264`. It is gated by
/// `JESS_RDP_H264` and kept OFF for recorded sessions (the WORM PNG track needs
/// the bitmap path). The legacy RGBA→WebP/PNG path remains the unconditional
/// fallback for any session/region the server doesn't send as AVC420. The byte
/// layout is shared with the Go bridge + browser and verified by
/// [`tests::server_h264_roundtrip`]. (End-to-end pixels need a live AVC420 host
/// to confirm — none in CI.)
pub const MSG_H264: u8 = 5;

/// [`MSG_H264`] flag bit: the access unit is a keyframe (IDR + SPS/PPS).
pub const H264_FLAG_KEYFRAME: u8 = 0b0000_0001;
/// [`MSG_H264`] flag bit: AVC444 (dual-plane). Set on the MAIN view of an
/// AVC444 4:4:4 update to signal "a chroma ([`H264_FLAG_AUX`]) frame follows —
/// buffer this one and recombine". Clear ⇒ plain AVC420 4:2:0 (single stream).
pub const H264_FLAG_AVC444: u8 = 0b0000_0010;
/// [`MSG_H264`] flag bit: this access unit is the AVC444 AUXILIARY (chroma)
/// view — the second `RFX_AVC420_BITMAP_STREAM` of an `RFX_AVC444_BITMAP_STREAM`
/// (ADR 0059). The browser decodes it on a SECOND `VideoDecoder` and recombines
/// its planes with the preceding [`H264_FLAG_AVC444`] main view into true 4:4:4
/// (MS-RDPEGFX YUV420→YUV444 mapping) in a WebGL shader. The Go WORM tee does
/// NOT record aux frames — a recording stays the AVC420 main view (4:2:0), so
/// this never ripples into the ADR 0058 recording format.
pub const H264_FLAG_AUX: u8 = 0b0000_0100;

/// Client→server `MOUSE` message type.
pub const MSG_MOUSE: u8 = 1;
/// Client→server `KEY` message type.
pub const MSG_KEY: u8 = 2;

/// `CLIPBOARD` message type — BIDIRECTIONAL (both client→server and
/// server→client, the subtype byte disambiguates the direction's meaning).
/// ADR 0054, Tier-3 virtual-channel work. A deliberately HIGH number so it
/// never collides with the graphics/input types (1/2/3) nor the render-path
/// types siblings add in the 4/5 range. See [`crate::clipboard`] for the
/// `[u8 subtype][payload]` body layout.
pub const MSG_CLIPBOARD: u8 = crate::clipboard::MSG_CLIPBOARD;

/// Button-mask bit: left button (bit 0).
pub const BUTTON_LEFT: u8 = 0b001;
/// Button-mask bit: right button (bit 1).
pub const BUTTON_RIGHT: u8 = 0b010;
/// Button-mask bit: middle button (bit 2).
pub const BUTTON_MIDDLE: u8 = 0b100;

/// Hard cap on a single TLV payload we will read from the (untrusted)
/// client source — defends the stdin-reader against a bogus length prefix.
/// A MOUSE is 6 bytes and a KEY is 5; 64 KiB is generous headroom for any
/// future client message without enabling an allocation DoS.
const MAX_CLIENT_PAYLOAD: usize = 64 * 1024;

// --- Server→client codec -------------------------------------------------

/// A decoded server→client message. Constructed by the session loop and
/// serialised with [`ServerMsg::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMsg {
    /// `DESKTOP_SIZE` — the negotiated desktop dimensions, emitted once.
    DesktopSize {
        /// Desktop width in pixels.
        width: u16,
        /// Desktop height in pixels.
        height: u16,
    },
    /// `FRAME` — a decoded dirty region as a standalone LOSSLESS PNG of the
    /// sub-rectangle `(x, y, w, h)` of the framebuffer.
    Frame {
        /// Left edge of the dirty region (px).
        x: u16,
        /// Top edge of the dirty region (px).
        y: u16,
        /// Region width (px).
        w: u16,
        /// Region height (px).
        h: u16,
        /// PNG-encoded RGBA of the `w*h` sub-rectangle.
        png: Vec<u8>,
    },
    /// `FRAME_WEBP` — a decoded dirty region as a standalone LOSSY WebP of the
    /// sub-rectangle `(x, y, w, h)`. Same geometry header as [`ServerMsg::Frame`];
    /// the Tier-1 live frame the browser renders off-thread.
    FrameWebp {
        /// Left edge of the dirty region (px).
        x: u16,
        /// Top edge of the dirty region (px).
        y: u16,
        /// Region width (px).
        w: u16,
        /// Region height (px).
        h: u16,
        /// WebP-encoded RGBA of the `w*h` sub-rectangle.
        webp: Vec<u8>,
    },
    /// `H264` — one H.264 access unit for a framebuffer sub-rectangle (ADR
    /// 0053, Tier-2 native-feel path). Carried in parallel with [`Self::Frame`];
    /// see [`MSG_H264`] for the wire layout. Emitted by the in-tree EGFX/AVC420
    /// handler ([`crate::egfx`]) when active. The browser feeds `nal` to a
    /// WebCodecs `VideoDecoder`.
    H264 {
        /// `true` = keyframe (IDR carrying SPS+PPS); `false` = delta.
        keyframe: bool,
        /// `true` = the MAIN view of an AVC444 4:4:4 update (an [`Self::H264`]
        /// with [`Self::H264::aux`] set follows); `false` = plain AVC420 4:2:0.
        avc444: bool,
        /// `true` = this is the AVC444 AUXILIARY (chroma) view to recombine with
        /// the preceding main view (ADR 0059); `false` = a displayable view.
        aux: bool,
        /// Left edge of the surface region this AU paints (px).
        x: u16,
        /// Top edge of the surface region (px).
        y: u16,
        /// Region width (px).
        w: u16,
        /// Region height (px).
        h: u16,
        /// Annex-B (start-code-delimited) H.264 NAL bytes for the access unit.
        nal: Vec<u8>,
    },
    /// `CLOSE` — the session ended.
    Close,
}

impl ServerMsg {
    /// Serialise to the `[u32 total_len][u8 msg_type][payload]` wire form
    /// (`total_len` counts `msg_type` + `payload`, all big-endian).
    pub fn encode(&self) -> Vec<u8> {
        // Build the [msg_type][payload] body first, then frame it.
        let mut body = Vec::new();
        match self {
            ServerMsg::DesktopSize { width, height } => {
                body.push(MSG_DESKTOP_SIZE);
                body.extend_from_slice(&width.to_be_bytes());
                body.extend_from_slice(&height.to_be_bytes());
            }
            ServerMsg::Frame { x, y, w, h, png } => {
                body.push(MSG_FRAME);
                body.extend_from_slice(&x.to_be_bytes());
                body.extend_from_slice(&y.to_be_bytes());
                body.extend_from_slice(&w.to_be_bytes());
                body.extend_from_slice(&h.to_be_bytes());
                body.extend_from_slice(png);
            }
            ServerMsg::FrameWebp { x, y, w, h, webp } => {
                body.push(MSG_FRAME_WEBP);
                body.extend_from_slice(&x.to_be_bytes());
                body.extend_from_slice(&y.to_be_bytes());
                body.extend_from_slice(&w.to_be_bytes());
                body.extend_from_slice(&h.to_be_bytes());
                body.extend_from_slice(webp);
            }
            ServerMsg::H264 {
                keyframe,
                avc444,
                aux,
                x,
                y,
                w,
                h,
                nal,
            } => {
                body.push(MSG_H264);
                let mut flags = 0u8;
                if *keyframe {
                    flags |= H264_FLAG_KEYFRAME;
                }
                if *avc444 {
                    flags |= H264_FLAG_AVC444;
                }
                if *aux {
                    flags |= H264_FLAG_AUX;
                }
                body.push(flags);
                body.extend_from_slice(&x.to_be_bytes());
                body.extend_from_slice(&y.to_be_bytes());
                body.extend_from_slice(&w.to_be_bytes());
                body.extend_from_slice(&h.to_be_bytes());
                body.extend_from_slice(nal);
            }
            ServerMsg::Close => {
                body.push(MSG_CLOSE);
            }
        }
        let total_len = u32::try_from(body.len()).expect("server message body fits in u32");
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one server message from a full `[u32 total_len][body]` frame
    /// — the inverse of [`ServerMsg::encode`]. Used by tests / a Go bridge
    /// reference and the live verification parser. `buf` must contain
    /// exactly one framed message.
    pub fn decode(buf: &[u8]) -> anyhow::Result<ServerMsg> {
        let (msg_type, payload) = split_frame(buf)?;
        match msg_type {
            MSG_DESKTOP_SIZE => {
                anyhow::ensure!(payload.len() == 4, "DESKTOP_SIZE payload must be 4 bytes");
                Ok(ServerMsg::DesktopSize {
                    width: u16::from_be_bytes([payload[0], payload[1]]),
                    height: u16::from_be_bytes([payload[2], payload[3]]),
                })
            }
            MSG_FRAME => {
                anyhow::ensure!(payload.len() >= 8, "FRAME payload must be >= 8 bytes");
                Ok(ServerMsg::Frame {
                    x: u16::from_be_bytes([payload[0], payload[1]]),
                    y: u16::from_be_bytes([payload[2], payload[3]]),
                    w: u16::from_be_bytes([payload[4], payload[5]]),
                    h: u16::from_be_bytes([payload[6], payload[7]]),
                    png: payload[8..].to_vec(),
                })
            }
            MSG_FRAME_WEBP => {
                anyhow::ensure!(payload.len() >= 8, "FRAME_WEBP payload must be >= 8 bytes");
                Ok(ServerMsg::FrameWebp {
                    x: u16::from_be_bytes([payload[0], payload[1]]),
                    y: u16::from_be_bytes([payload[2], payload[3]]),
                    w: u16::from_be_bytes([payload[4], payload[5]]),
                    h: u16::from_be_bytes([payload[6], payload[7]]),
                    webp: payload[8..].to_vec(),
                })
            }
            MSG_H264 => {
                anyhow::ensure!(payload.len() >= 9, "H264 payload must be >= 9 bytes");
                let flags = payload[0];
                Ok(ServerMsg::H264 {
                    keyframe: flags & H264_FLAG_KEYFRAME != 0,
                    avc444: flags & H264_FLAG_AVC444 != 0,
                    aux: flags & H264_FLAG_AUX != 0,
                    x: u16::from_be_bytes([payload[1], payload[2]]),
                    y: u16::from_be_bytes([payload[3], payload[4]]),
                    w: u16::from_be_bytes([payload[5], payload[6]]),
                    h: u16::from_be_bytes([payload[7], payload[8]]),
                    nal: payload[9..].to_vec(),
                })
            }
            MSG_CLOSE => {
                anyhow::ensure!(payload.is_empty(), "CLOSE payload must be empty");
                Ok(ServerMsg::Close)
            }
            other => anyhow::bail!("unknown server msg_type {other}"),
        }
    }
}

// --- Client→server codec -------------------------------------------------

/// A decoded client→server input message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientMsg {
    /// `MOUSE` — absolute position, a button-mask snapshot, and a wheel
    /// delta (positive = up/away).
    Mouse {
        /// Absolute X (px).
        x: u16,
        /// Absolute Y (px).
        y: u16,
        /// Pressed-button bitmask (bit0=left, 1=right, 2=middle).
        button_mask: u8,
        /// Wheel delta (positive = up/away, negative = down/toward).
        wheel: i8,
    },
    /// `KEY` — a key transition for an RDP scancode.
    Key {
        /// `true` = key down, `false` = key up (release).
        is_down: bool,
        /// RDP scancode (0xE0-prefixed in the high byte for extended keys).
        scancode: u32,
    },
}

impl ClientMsg {
    /// Serialise to the `[u32 total_len][u8 msg_type][payload]` wire form.
    /// (Primarily for tests + the live input-injection helper; a real
    /// client/browser produces these bytes.)
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match *self {
            ClientMsg::Mouse {
                x,
                y,
                button_mask,
                wheel,
            } => {
                body.push(MSG_MOUSE);
                body.extend_from_slice(&x.to_be_bytes());
                body.extend_from_slice(&y.to_be_bytes());
                body.push(button_mask);
                body.push(wheel as u8);
            }
            ClientMsg::Key { is_down, scancode } => {
                body.push(MSG_KEY);
                body.push(u8::from(is_down));
                body.extend_from_slice(&scancode.to_be_bytes());
            }
        }
        let total_len = u32::try_from(body.len()).expect("client message body fits in u32");
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one client message from a `[u8 msg_type][payload]` body
    /// (the length prefix already stripped by the stdin reader).
    fn decode_body(msg_type: u8, payload: &[u8]) -> anyhow::Result<ClientMsg> {
        match msg_type {
            MSG_MOUSE => {
                anyhow::ensure!(payload.len() == 6, "MOUSE payload must be 6 bytes");
                Ok(ClientMsg::Mouse {
                    x: u16::from_be_bytes([payload[0], payload[1]]),
                    y: u16::from_be_bytes([payload[2], payload[3]]),
                    button_mask: payload[4],
                    wheel: payload[5] as i8,
                })
            }
            MSG_KEY => {
                anyhow::ensure!(payload.len() == 5, "KEY payload must be 5 bytes");
                Ok(ClientMsg::Key {
                    is_down: payload[0] != 0,
                    scancode: u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]),
                })
            }
            other => anyhow::bail!("unknown client msg_type {other}"),
        }
    }

    /// Map this input message to the IronRDP FastPath input events that
    /// realise it on the wire.
    ///
    /// A MOUSE always carries an absolute MOVE; button-mask bits add
    /// `LEFT/RIGHT/MIDDLE_BUTTON` with `DOWN`, and a non-zero wheel adds a
    /// `VERTICAL_WHEEL` event. A KEY maps to one `KeyboardEvent`: the low
    /// scancode byte plus the `EXTENDED` flag when the RDP scancode has the
    /// 0xE0 extended prefix (high byte 0xE0), and `RELEASE` when `is_down`
    /// is false.
    pub fn to_fastpath_events(self, prev_mask: u8) -> Vec<FastPathInputEvent> {
        match self {
            ClientMsg::Mouse {
                x,
                y,
                button_mask,
                wheel,
            } => mouse_events(prev_mask, x, y, button_mask, wheel),
            ClientMsg::Key { is_down, scancode } => vec![key_event(is_down, scancode)],
        }
    }
}

/// Build the FastPath mouse event(s) for a MOUSE message. The browser sends the
/// absolute position + the CURRENT button mask (state, not edges); we diff it
/// against `prev_mask` so a click becomes a real button DOWN then UP and a held
/// button isn't re-pressed on every move. RDP signals a release as the button
/// flag WITHOUT `DOWN`. Order: MOVE first (anchors the position), then any
/// button edges, then an optional wheel — the previous stateless version never
/// emitted the release, so clicks pressed but never released.
fn mouse_events(
    prev_mask: u8,
    x: u16,
    y: u16,
    button_mask: u8,
    wheel: i8,
) -> Vec<FastPathInputEvent> {
    let mv = |flags: PointerFlags| {
        FastPathInputEvent::MouseEvent(MousePdu {
            flags,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        })
    };
    let mut events = vec![mv(PointerFlags::MOVE)];

    for (bit, button) in [
        (BUTTON_LEFT, PointerFlags::LEFT_BUTTON),
        (BUTTON_RIGHT, PointerFlags::RIGHT_BUTTON),
        (BUTTON_MIDDLE, PointerFlags::MIDDLE_BUTTON_OR_WHEEL),
    ] {
        let was = prev_mask & bit != 0;
        let now = button_mask & bit != 0;
        if now && !was {
            events.push(mv(button | PointerFlags::DOWN)); // press
        } else if was && !now {
            events.push(mv(button)); // release: button flag without DOWN
        }
    }

    if wheel != 0 {
        events.push(FastPathInputEvent::MouseEvent(MousePdu {
            flags: PointerFlags::VERTICAL_WHEEL,
            // The MousePdu encoder packs the low byte as the rotation
            // magnitude and sets WHEEL_NEGATIVE for negatives.
            number_of_wheel_rotation_units: i16::from(wheel) * 120,
            x_position: x,
            y_position: y,
        }));
    }

    events
}

/// Map an RDP scancode + transition to a FastPath keyboard event.
fn key_event(is_down: bool, scancode: u32) -> FastPathInputEvent {
    let mut flags = FpKeyboardFlags::empty();
    if !is_down {
        flags |= FpKeyboardFlags::RELEASE;
    }
    // RDP "extended" scancodes carry a 0xE0 prefix in the high byte; the
    // FastPath event encodes the low byte + the EXTENDED flag.
    if (scancode >> 8) & 0xFF == 0xE0 {
        flags |= FpKeyboardFlags::EXTENDED;
    }
    let code = (scancode & 0xFF) as u8;
    FastPathInputEvent::KeyboardEvent(flags, code)
}

// --- Shared frame helpers ------------------------------------------------

/// Split a full `[u32 total_len][u8 msg_type][payload]` frame into its
/// `msg_type` + `payload`, validating the length prefix.
fn split_frame(buf: &[u8]) -> anyhow::Result<(u8, &[u8])> {
    anyhow::ensure!(buf.len() >= 5, "frame must be >= 5 bytes (len+type)");
    let total_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    anyhow::ensure!(
        total_len >= 1,
        "total_len must cover at least the msg_type byte"
    );
    anyhow::ensure!(
        buf.len() == 4 + total_len,
        "frame length {} != 4 + total_len {}",
        buf.len(),
        4 + total_len
    );
    Ok((buf[4], &buf[5..]))
}

/// Crop a dirty `region` out of the full RGBA32 framebuffer into a tightly
/// packed `w*h*4` buffer, row by row (the framebuffer rows are full-width;
/// `DecodedImage::data_for_rect` returns a stride-spanning slice, so we
/// copy each region row individually). Returns `(w, h, packed_rgba)`.
fn crop_region(image: &DecodedImage, region: &InclusiveRectangle) -> (u16, u16, Vec<u8>) {
    let bpp = image.bytes_per_pixel();
    let stride = image.stride();
    let data = image.data();

    // Clamp the region to the framebuffer in case the server reports a
    // rectangle on the inclusive edge.
    let img_w = image.width();
    let img_h = image.height();
    let left = region.left.min(img_w.saturating_sub(1));
    let top = region.top.min(img_h.saturating_sub(1));
    let right = region.right.min(img_w.saturating_sub(1));
    let bottom = region.bottom.min(img_h.saturating_sub(1));
    let w = right.saturating_sub(left) + 1;
    let h = bottom.saturating_sub(top) + 1;

    let row_bytes = usize::from(w) * bpp;
    let mut packed = Vec::with_capacity(usize::from(h) * row_bytes);
    for row in 0..usize::from(h) {
        let src_y = usize::from(top) + row;
        let src_off = src_y * stride + usize::from(left) * bpp;
        packed.extend_from_slice(&data[src_off..src_off + row_bytes]);
    }
    (w, h, packed)
}

/// Encode a tightly-packed `w*h*4` RGBA8 buffer to a PNG (the region
/// crop). Mirrors [`crate::active::encode_png`] but over an explicit
/// buffer + dimensions rather than a whole [`DecodedImage`].
fn encode_region_png(w: u16, h: u16, rgba: &[u8]) -> anyhow::Result<Vec<u8>> {
    let expected = usize::from(w) * usize::from(h) * 4;
    anyhow::ensure!(
        rgba.len() == expected,
        "region buffer is {} bytes, expected {expected} for {w}x{h} RGBA8",
        rgba.len()
    );
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, u32::from(w), u32::from(h));
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().context("png write_header")?;
        writer
            .write_image_data(rgba)
            .context("png write_image_data")?;
        writer.finish().context("png finish")?;
    }
    Ok(out)
}

/// Encode a tightly-packed `w*h*4` RGBA8 buffer to a LOSSY WebP at `quality`
/// (0..=100; see [`crate::active::WEBP_LIVE_QUALITY`]). The region-crop
/// counterpart of [`crate::active::encode_webp`]. This is the Tier-1 live
/// frame encoder; the lossless [`encode_region_png`] feeds the recorder.
fn encode_region_webp(w: u16, h: u16, rgba: &[u8], quality: f32) -> anyhow::Result<Vec<u8>> {
    let expected = usize::from(w) * usize::from(h) * 4;
    anyhow::ensure!(
        rgba.len() == expected,
        "region buffer is {} bytes, expected {expected} for {w}x{h} RGBA8",
        rgba.len()
    );
    let encoder = webp::Encoder::from_rgba(rgba, u32::from(w), u32::from(h));
    Ok(encoder.encode(quality.clamp(0.0, 100.0)).to_vec())
}

// --- EGFX / H.264 (ADR 0053) ---------------------------------------------

/// Whether the operator has REQUESTED the Tier-2 H.264 (MS-RDPEGFX / AVC420)
/// path via `JESS_RDP_H264=1`. The caller ANDs this with "not recording" to
/// decide whether to advertise the EGFX/AVC420 channel ([`crate::egfx`]) on the
/// connector: when on (and not recording), the broker negotiates AVC420 and the
/// in-tree handler forwards NAL units as [`ServerMsg::H264`]; when off, graphics
/// arrive as the RGBA→WebP/PNG bitmap path. The flag NEVER disables or degrades
/// the bitmap path — the bitmap path is always the fallback.
pub fn h264_requested() -> bool {
    std::env::var("JESS_RDP_H264")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Build a [`ServerMsg::H264`] from a decoded EGFX H.264 access unit, given the
/// destination rectangle. A pure constructor so the wire encoding is locked in
/// and roundtrip-tested; [`crate::egfx`] forwards extracted access units via the
/// `EgfxChannel` and the [`run_session`] loop constructs the message directly,
/// so this helper is primarily the tested reference. `nal` must be Annex-B
/// (start-code) bytes; `avc444` selects the dual-plane layout (we advertise
/// AVC420-only, so it is always `false` in practice).
pub fn h264_message(
    region: &InclusiveRectangle,
    nal: Vec<u8>,
    keyframe: bool,
    avc444: bool,
    aux: bool,
) -> ServerMsg {
    let w = region.width();
    let h = region.height();
    ServerMsg::H264 {
        keyframe,
        avc444,
        aux,
        x: region.left,
        y: region.top,
        w,
        h,
        nal,
    }
}

// --- Session tuning ------------------------------------------------------

/// Tuning for [`run_session`].
#[derive(Debug, Clone, Copy)]
pub struct StreamBudget {
    /// Hard wall-clock cap on the whole streaming loop.
    pub total: Duration,
    /// Per-`read_pdu` timeout. Unlike P2a we do NOT stop on idle — a live
    /// session stays open through quiet periods; the timeout just lets the
    /// select loop wake to re-check the wall-clock budget and pump any
    /// queued input.
    pub idle_read: Duration,
    /// Safety cap on the number of server PDUs processed.
    pub max_pdus: usize,
    /// Tier-1 live encoding. When `true` (the default), each dirty region is
    /// emitted as a LOSSY `FRAME_WEBP` (the browser frame). When `false`, the
    /// session emits the LOSSLESS `FRAME` (PNG) as the live frame instead — a
    /// lossless-mode escape hatch (e.g. `JESS_RDP_LOSSLESS=1`).
    pub webp_live: bool,
    /// WebP quality (0..=100) for the live `FRAME_WEBP` frames.
    pub webp_quality: f32,
    /// When `true`, also emit a LOSSLESS `FRAME` (PNG) alongside each live
    /// `FRAME_WEBP`, for the WORM recorder feed. The Go bridge records only the
    /// PNG and forwards only the WebP, so the recording stays lossless +
    /// format-unchanged while the browser still gets the smaller WebP. Set by
    /// the bridge (via `JESS_RDP_RECORD_LOSSLESS`) only when a session is being
    /// recorded. No-op when `webp_live` is false (the PNG is already the live
    /// frame then).
    pub record_lossless: bool,
}

impl Default for StreamBudget {
    fn default() -> Self {
        Self {
            // Large wall-clock cap (4h) so a live RDP session is NOT auto-closed
            // mid-use. The previous 30s default was a streaming-spike value that
            // leaked into the live session path; `session_live` makes the cap
            // operator-configurable via JESS_RDP_BUDGET_SECS.
            total: Duration::from_secs(14_400),
            idle_read: Duration::from_secs(2),
            max_pdus: 100_000,
            webp_live: true,
            webp_quality: crate::active::WEBP_LIVE_QUALITY,
            record_lossless: false,
        }
    }
}

/// Outcome of a [`run_session`] run — surfaced for honest reporting.
#[derive(Debug, Clone, Copy)]
pub struct StreamOutcome {
    /// Server PDUs processed.
    pub pdus: usize,
    /// `FRAME` messages emitted to the sink.
    pub frames_emitted: usize,
    /// Inbound input messages applied (mapped to FastPath + written).
    pub input_applied: usize,
    /// Whether the server gracefully terminated (vs budget / EOF).
    pub terminated_by_server: bool,
    /// The EGFX/AVC420 (H.264) path was active AND the server terminated the
    /// session before a single frame was emitted — the signature of a host that
    /// can't encode H.264 (no GPU / no AVC encoder): it accepts our AVC420
    /// advertise, commits to the graphics pipeline, then its graphics subsystem
    /// fails. A healthy host always paints the initial desktop immediately, so
    /// "EGFX active + server-terminated + zero frames" is a reliable, codec-
    /// agnostic signal to retry the session WITHOUT EGFX (the bitmap path). When
    /// this is true, [`run_session`] deliberately does NOT emit the trailing
    /// `CLOSE`, so the caller can reconnect and continue the same client stream.
    pub egfx_fallback_recommended: bool,
}

/// Per-region live-frame encoding policy, derived from [`StreamBudget`] once
/// per session and passed to [`pump_pdu`]. Keeps the hot loop's frame-emit
/// logic in one place (WebP for the browser, optional lossless PNG for the
/// recorder).
#[derive(Debug, Clone, Copy)]
struct FrameEncoding {
    webp_live: bool,
    webp_quality: f32,
    record_lossless: bool,
}

// --- The streaming session core ------------------------------------------

/// Drive the active session over the post-`Connected` framed stream as a
/// live bidirectional stream: emit `DESKTOP_SIZE` then a `FRAME` per dirty
/// region to `out`, while reading `MOUSE`/`KEY` from `inp` and injecting
/// them as FastPath input. Writes `CLOSE` at the end.
///
/// See the [module docs](crate::stream) for the wire protocol and the
/// read/write concurrency model.
pub async fn run_session<W, R>(
    connection_result: ironrdp_connector::ConnectionResult,
    framed: LiveFramed,
    out: W,
    inp: R,
    budget: StreamBudget,
    clipboard: Option<ClipboardChannel>,
    egfx: Option<EgfxChannel>,
) -> anyhow::Result<StreamOutcome>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let width = connection_result.desktop_size.width;
    let height = connection_result.desktop_size.height;
    info!(
        desktop = format!("{width}x{height}"),
        budget_secs = budget.total.as_secs(),
        "stream: starting live streaming session"
    );
    // ADR 0053 Tier-2: the MS-RDPEGFX/AVC420 channel is now built in-tree
    // (`crate::egfx`). It is ACTIVE iff the caller handed us an `EgfxChannel`
    // (the connector advertised AVC420). The caller keeps it OFF for recorded
    // sessions (the WORM PNG track needs the bitmap path) and when
    // `JESS_RDP_H264` is unset. When inactive, this loop takes the RGBA→WebP/PNG
    // bitmap path exactly as before. A server that doesn't select AVC420 also
    // falls back to bitmaps — the H.264 channel simply stays idle.
    if egfx.is_some() {
        info!("stream: MS-RDPEGFX/AVC420 H.264 path ACTIVE (Tier-2); bitmap path is the fallback");
    } else if h264_requested() {
        debug!(
            "stream: JESS_RDP_H264 set but EGFX not active for this session \
             (recording on, or AVC420 not negotiated) — using the bitmap path"
        );
    }

    // Tier-1 live frame encoding policy, captured once from the budget.
    let enc_cfg = FrameEncoding {
        webp_live: budget.webp_live,
        webp_quality: budget.webp_quality,
        record_lossless: budget.record_lossless,
    };
    info!(
        webp_live = enc_cfg.webp_live,
        webp_quality = enc_cfg.webp_quality,
        record_lossless = enc_cfg.record_lossless,
        "stream: live frame encoding policy"
    );

    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);

    // Software H.264 path (ADR 0061): CPU-encode the WHOLE framebuffer as a
    // low-latency H.264 stream instead of per-region WebP — native-feel
    // smoothness with NO GPU and ANY RDP host. When active it REPLACES the
    // WebP/PNG bitmap emit and DISABLES the EGFX (host-AVC) drain (we are the
    // encoder, not a forwarder). OFF unless JESS_RDP_H264_SW is set.
    let mut sw_enc = if crate::h264enc::sw_h264_requested() {
        match crate::h264enc::H264SwEncoder::new(
            width,
            height,
            crate::h264enc::sw_h264_bitrate(),
            crate::h264enc::sw_h264_fps(),
        ) {
            Ok(e) => {
                info!(
                    desktop = format!("{width}x{height}"),
                    bitrate = crate::h264enc::sw_h264_bitrate(),
                    fps = crate::h264enc::sw_h264_fps(),
                    "stream: SOFTWARE H.264 path ACTIVE (ADR 0061) — CPU encode, no GPU, any host"
                );
                Some(e)
            }
            Err(e) => {
                warn!(error = %e, "stream: software H.264 encoder init failed — using bitmap path");
                None
            }
        }
    } else {
        None
    };
    // sw-H.264 wins over EGFX: if we're encoding, ignore any host-AVC channel.
    let egfx = if sw_enc.is_some() { None } else { egfx };
    let sw_frame_interval =
        std::time::Duration::from_secs_f32(1.0 / crate::h264enc::sw_h264_fps().max(1.0));
    // Wake the read loop at least once per frame interval when sw-H.264 is on, so
    // a trailing frame (updates that stopped mid-interval) flushes promptly
    // rather than waiting the full idle_read.
    let read_idle = if sw_enc.is_some() {
        sw_frame_interval.min(budget.idle_read)
    } else {
        budget.idle_read
    };
    let mut sw_dirty = false;
    let mut sw_last = std::time::Instant::now();
    let active_stage = Arc::new(Mutex::new(ActiveStage::new(connection_result)));

    // Split the framed stream: the main loop owns both halves, but the
    // input task only ever produces *bytes* (over the channel), never
    // touches the socket — see module docs.
    let (mut framed_read, mut framed_write) = split_tokio_framed(framed);

    // Outbound input PDUs (already encoded to wire bytes) flow from the
    // stdin task to the main loop, which is the sole writer of the socket.
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);

    // CLIPBOARD commands (browser → remote) flow from the stdin task to the
    // main loop too, but as decoded `ClipboardCommand`s rather than wire bytes:
    // servicing them needs the `ActiveStage` SVC processor (to encode the
    // CLIPRDR PDUs) which the main loop owns. A `None` clipboard ⇒ the channel
    // wasn't negotiated; the stdin task then drops clipboard frames. The
    // bounded channel applies natural backpressure.
    let (clip_tx, mut clip_rx) = mpsc::channel::<ClipboardCommand>(64);
    let clipboard_enabled = clipboard.is_some();
    let mut clipboard = clipboard;
    // EGFX/AVC420 frame side-channel (Some iff the H.264 path is active). Drained
    // each loop iteration into `ServerMsg::H264` — see the drain after the
    // clipboard drain below.
    let egfx_active = egfx.is_some();
    let mut egfx = egfx;

    // --- stdin-reader task -----------------------------------------------
    // Spawned now, but it does NOT touch stdin until the session is proven
    // viable (the first frame is emitted) — see `input_gate`. A session the
    // server tears down before any frame (the signature of an EGFX/AVC420 host
    // that can't encode H.264) therefore leaves stdin pristine, so the caller
    // can cleanly reconnect WITHOUT EGFX over the same stdin.
    let input_stage = Arc::clone(&active_stage);
    let input_gate = Arc::new(tokio::sync::Notify::new());
    let input_gate_task = Arc::clone(&input_gate);
    let input_task = tokio::spawn(async move {
        // Park until the main loop opens the gate (first frame emitted). On an
        // EGFX teardown-before-first-frame the gate never opens and the task is
        // aborted still parked here — `reader` (stdin) is never polled.
        input_gate_task.notified().await;
        let mut reader = inp;
        let mut applied = 0usize;
        // Last button-mask state, so a MOUSE message can emit RDP button
        // DOWN/UP on the press/release EDGE (the browser sends the current
        // mask, not discrete press/release events).
        let mut prev_mask: u8 = 0;
        loop {
            // Length prefix.
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!("stdin closed — input task exiting");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "stdin read error — input task exiting");
                    break;
                }
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;
            if total_len == 0 || total_len > MAX_CLIENT_PAYLOAD {
                warn!(
                    total_len,
                    "rejecting client frame with bad length — closing input"
                );
                break;
            }
            // msg_type + payload.
            let mut body = vec![0u8; total_len];
            if let Err(e) = reader.read_exact(&mut body).await {
                warn!(error = %e, "stdin truncated mid-frame — input task exiting");
                break;
            }
            let msg_type = body[0];
            let payload = &body[1..];

            // CLIPBOARD (0x20) is routed to the main loop as a decoded command
            // (servicing it needs the SVC processor the main loop owns). When
            // the channel wasn't negotiated, drop the frame quietly.
            if msg_type == MSG_CLIPBOARD {
                if clipboard_enabled {
                    // `payload` is `[u8 subtype][payload]` (the MSG_CLIPBOARD
                    // type byte already split off above).
                    if let Some(cmd) = crate::clipboard::decode_client_clipboard(payload) {
                        if clip_tx.send(cmd).await.is_err() {
                            debug!("main loop gone — input task exiting (clipboard)");
                            return applied;
                        }
                    }
                }
                continue;
            }

            let msg = match ClientMsg::decode_body(msg_type, payload) {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "dropping malformed client message");
                    continue;
                }
            };

            // Map to FastPath events and encode through the shared
            // ActiveStage. The lock is held only for the synchronous
            // encode (no await inside) so it can never block the socket.
            // Capture the new button mask BEFORE consuming msg so we can
            // diff against prev_mask for button DOWN/UP edges, then advance.
            let new_mask = match &msg {
                ClientMsg::Mouse { button_mask, .. } => *button_mask,
                _ => prev_mask,
            };
            let events = msg.to_fastpath_events(prev_mask);
            prev_mask = new_mask;
            let frames = {
                let mut stage = input_stage.lock().await;
                // A throwaway image: process_fastpath_input only mutates
                // the image for client-side pointer rendering, which the
                // broker leaves to the browser; the response frames are
                // what we need on the wire.
                let mut scratch = DecodedImage::new(PixelFormat::RgbA32, 1, 1);
                match stage.process_fastpath_input(&mut scratch, &events) {
                    Ok(outputs) => outputs,
                    Err(e) => {
                        warn!(error = %e, "failed to encode fastpath input — dropping");
                        continue;
                    }
                }
            };
            for out in frames {
                if let ActiveStageOutput::ResponseFrame(bytes) = out {
                    if in_tx.send(bytes).await.is_err() {
                        debug!("main loop gone — input task exiting");
                        return applied;
                    }
                    applied += 1;
                }
            }
        }
        applied
    });

    // --- main loop -------------------------------------------------------
    let mut out = out;
    // 1) DESKTOP_SIZE, once.
    write_msg(&mut out, &ServerMsg::DesktopSize { width, height })
        .await
        .context("write DESKTOP_SIZE")?;

    let started = Instant::now();
    let mut pdus = 0usize;
    let mut frames_emitted = 0usize;
    let mut input_applied = 0usize;
    let mut terminated_by_server = false;
    // Opened once the first frame is emitted, releasing the stdin reader task
    // from its gate (see `input_gate`). Until then stdin is untouched.
    let mut input_started = false;
    // Once the input task's channel closes (stdin EOF), stop selecting on
    // it — a closed `recv()` returns `None` immediately and would otherwise
    // busy-spin the biased select. We then read server PDUs unconditionally.
    let mut input_open = true;
    // Same for the clipboard-command channel: when the input task exits it
    // drops `clip_tx`, so `clip_rx.recv()` returns `None` forever. Latch it
    // closed so the select stops polling it (no busy-spin). Independent of
    // `clipboard_enabled` (which records whether the channel was negotiated).
    let mut clip_open = clipboard_enabled;

    'outer: loop {
        if started.elapsed() >= budget.total {
            info!("stream: wall-clock budget reached — closing");
            break;
        }
        if pdus >= budget.max_pdus {
            info!("stream: max-pdus budget reached — closing");
            break;
        }

        // Resolve an outbound input PDU, a browser CLIPBOARD command, OR a
        // server PDU. All three source futures are cancel-safe (mpsc::recv +
        // Framed::read_pdu, both documented so); whichever loses is simply
        // dropped and rebuilt next iteration. Crucially, the non-cancel-safe
        // `write_all`s happen AFTER the select resolves — never inside a select
        // arm — so the single-owner write-half is never raced or torn.
        enum Event {
            Input(Option<Vec<u8>>),
            Clipboard(Option<ClipboardCommand>),
            Server(anyhow::Result<Option<(ironrdp_pdu::Action, bytes::BytesMut)>>),
        }
        let event = match (input_open, clip_open) {
            (true, true) => tokio::select! {
                biased;
                maybe_input = in_rx.recv() => Event::Input(maybe_input),
                maybe_clip = clip_rx.recv() => Event::Clipboard(maybe_clip),
                read = read_pdu_timeout(&mut framed_read, read_idle) => Event::Server(read),
            },
            (true, false) => tokio::select! {
                biased;
                maybe_input = in_rx.recv() => Event::Input(maybe_input),
                read = read_pdu_timeout(&mut framed_read, read_idle) => Event::Server(read),
            },
            (false, true) => tokio::select! {
                biased;
                maybe_clip = clip_rx.recv() => Event::Clipboard(maybe_clip),
                read = read_pdu_timeout(&mut framed_read, read_idle) => Event::Server(read),
            },
            (false, false) => Event::Server(read_pdu_timeout(&mut framed_read, read_idle).await),
        };

        match event {
            Event::Input(Some(bytes)) => {
                framed_write
                    .write_all(&bytes)
                    .await
                    .context("write inbound input PDU to server")?;
                input_applied += 1;
            }
            Event::Input(None) => {
                // stdin EOF → stop selecting on the channel; keep streaming.
                debug!("input channel closed — continuing server→client frames only");
                input_open = false;
            }
            Event::Clipboard(Some(cmd)) => {
                // Browser → remote clipboard op. May write CLIPRDR PDUs to the
                // server (write-half) — done here, outside any select arm.
                if let Some(ch) = clipboard.as_ref() {
                    apply_browser_clipboard(&active_stage, &mut framed_write, ch, cmd).await?;
                }
            }
            Event::Clipboard(None) => {
                // Input task gone (stdin EOF) — its clipboard sender dropped.
                // Stop selecting on the closed channel; server→client clipboard
                // events still flow via the per-iteration drain below.
                debug!("clipboard command channel closed — server→client only");
                clip_open = false;
            }
            Event::Server(read) => match read? {
                Some((action, payload)) => {
                    if pump_pdu(
                        &active_stage,
                        &mut image,
                        action,
                        &payload,
                        &mut framed_write,
                        &mut out,
                        &mut pdus,
                        &mut frames_emitted,
                        &enc_cfg,
                        sw_enc.is_some(),
                        &mut sw_dirty,
                    )
                    .await?
                    {
                        terminated_by_server = true;
                        break 'outer;
                    }
                }
                None => {
                    // idle read timeout — flush any pending sw-H.264 frame (the
                    // trailing frame after updates stopped mid-interval), then
                    // re-check budget on the next iteration.
                    if let Some(enc) = sw_enc.as_mut() {
                        if sw_dirty {
                            emit_sw_frame(enc, &image, &mut out, &mut frames_emitted).await?;
                            sw_dirty = false;
                            sw_last = std::time::Instant::now();
                        }
                    }
                    continue;
                }
            },
        }

        // After every iteration, drain the clipboard backend: emit any
        // remote→browser events (FormatList availability / pasted TEXT) as
        // CLIPBOARD TLVs, and service any remote format-data request the
        // backend recorded during `pump_pdu`'s `process()`.
        if let Some(ch) = clipboard.as_mut() {
            drain_clipboard(ch, &active_stage, &mut framed_write, &mut out).await?;
        }

        // Drain any AVC420 access units the EGFX DVC processor extracted during
        // this iteration's `pump_pdu` → `ActiveStage::process()`, emitting one
        // `ServerMsg::H264` per frame. The processor pushes frames onto its
        // side-channel synchronously inside `process()`; we forward them here
        // (the sole socket/sink writer). The bitmap path is untouched: a session
        // is either EGFX-driven (frames here) or bitmap-driven (FRAME/FRAME_WEBP
        // in `pump_pdu`), never double-painted.
        if let Some(ch) = egfx.as_mut() {
            while let Some(frame) = ch.try_recv() {
                // `avc444`/`aux` are set by the EGFX handler: a 4:4:4 update emits
                // the MAIN view (`avc444`) then the AUXILIARY chroma view (`aux`);
                // a plain AVC420 update emits one frame with both clear (ADR 0059).
                let msg = ServerMsg::H264 {
                    keyframe: frame.keyframe,
                    avc444: frame.avc444,
                    aux: frame.aux,
                    x: frame.x,
                    y: frame.y,
                    w: frame.w,
                    h: frame.h,
                    nal: frame.nal,
                };
                write_msg(&mut out, &msg).await.context("write H264")?;
                frames_emitted += 1;
            }
        }

        // Software H.264 (ADR 0061): if the framebuffer changed this iteration and
        // a frame interval has elapsed, encode the WHOLE framebuffer as one paced
        // H.264 access unit and emit it as MSG_H264 (coalescing sub-interval
        // bursts into ≤ fps frames). The browser decodes it via the same WebCodecs
        // path as the EGFX host-AVC frames; the WORM tee records it (ADR 0058).
        if let Some(enc) = sw_enc.as_mut() {
            if sw_dirty && sw_last.elapsed() >= sw_frame_interval {
                emit_sw_frame(enc, &image, &mut out, &mut frames_emitted).await?;
                sw_dirty = false;
                sw_last = std::time::Instant::now();
            }
        }

        // The session is viable once the first frame is emitted — open the gate
        // so the parked stdin reader task starts (it was held back to keep stdin
        // pristine for a possible no-EGFX retry). Fires exactly once.
        if !input_started && frames_emitted > 0 {
            input_gate.notify_one();
            input_started = true;
        }
    }

    // The signature of an EGFX/AVC420 host that can't encode H.264: the path was
    // active and the server terminated the session before a single frame. A
    // healthy host always paints immediately, so this is a reliable signal to
    // retry WITHOUT EGFX.
    let egfx_fallback_recommended = egfx_active && terminated_by_server && frames_emitted == 0;

    // 3) CLOSE, once — UNLESS we're recommending a no-EGFX retry, in which case
    // we deliberately leave the stream open so the caller can reconnect and
    // continue the SAME client stream (no spurious CLOSE reaches the browser).
    if egfx_fallback_recommended {
        warn!(
            "stream: EGFX/H.264 host terminated before any frame — suppressing CLOSE so the \
             caller can retry without EGFX (bitmap path)"
        );
    } else {
        write_msg(&mut out, &ServerMsg::Close)
            .await
            .context("write CLOSE")?;
    }
    let _ = out.flush().await;

    // Stop the stdin reader task. ABORT rather than await: once released from its
    // gate it may be parked on a blocking stdin read that won't return until the
    // operator disconnects (so awaiting would hang the teardown), and if never
    // released it's parked on the gate. The main loop's `input_applied` is the
    // authoritative tally of what hit the socket, so the task's count isn't
    // needed. `drop(in_rx)` first so any in-flight send() the task has also fails.
    drop(in_rx);
    input_task.abort();

    let outcome = StreamOutcome {
        pdus,
        frames_emitted,
        input_applied,
        terminated_by_server,
        egfx_fallback_recommended,
    };
    info!(?outcome, "stream: session ended");
    Ok(outcome)
}

/// Read one server PDU with a per-read idle timeout. `Ok(None)` = the read
/// timed out (the loop should re-check its budget and keep going — a live
/// session is allowed to be quiet); `Ok(Some(..))` = a PDU; `Err` = a real
/// I/O error (EOF/reset). Generic over the read-half so it isn't pinned to
/// the concrete TLS stream type. `read_pdu` is cancel-safe under select.
async fn read_pdu_timeout<S>(
    framed_read: &mut ironrdp_async::Framed<S>,
    idle: Duration,
) -> anyhow::Result<Option<(ironrdp_pdu::Action, bytes::BytesMut)>>
where
    S: FramedRead,
{
    match tokio::time::timeout(idle, framed_read.read_pdu()).await {
        Ok(Ok(frame)) => Ok(Some(frame)),
        Ok(Err(e)) => Err(anyhow::Error::new(e).context("read_pdu")),
        Err(_elapsed) => Ok(None),
    }
}

/// Encode the WHOLE current framebuffer as one software-H.264 access unit
/// (ADR 0061) and emit it as `MSG_H264`. The browser decodes it via the same
/// WebCodecs path as the EGFX host-AVC frames, and the WORM tee records it
/// (ADR 0058). A frame the encoder skipped for rate control — or a framebuffer
/// smaller than the encoder (a not-yet-applied desktop resize) — emits nothing.
async fn emit_sw_frame<W>(
    enc: &mut crate::h264enc::H264SwEncoder,
    image: &DecodedImage,
    out: &mut W,
    frames_emitted: &mut usize,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let (ew, eh) = enc.dimensions();
    if image.width() < ew || image.height() < eh {
        return Ok(()); // pending resize — never read past the framebuffer
    }
    if let Some((nal, keyframe)) = enc
        .encode(image.data(), image.stride())
        .context("software H.264 encode")?
    {
        write_msg(
            out,
            &ServerMsg::H264 {
                keyframe,
                avc444: false,
                aux: false,
                x: 0,
                y: 0,
                w: ew,
                h: eh,
                nal,
            },
        )
        .await
        .context("write software H264")?;
        *frames_emitted += 1;
    }
    Ok(())
}

/// Process one server PDU through `ActiveStage`, writing any response
/// frames back to the server and emitting a `FRAME` message per graphics
/// update. Returns `Ok(true)` if the server terminated the session.
/// Generic over both the write-half and the sink.
#[expect(clippy::too_many_arguments, reason = "internal loop-body helper")]
async fn pump_pdu<SW, W>(
    active_stage: &Arc<Mutex<ActiveStage>>,
    image: &mut DecodedImage,
    action: ironrdp_pdu::Action,
    payload: &[u8],
    framed_write: &mut ironrdp_async::Framed<SW>,
    out: &mut W,
    pdus: &mut usize,
    frames_emitted: &mut usize,
    enc: &FrameEncoding,
    // Software H.264 (ADR 0061): when true, a GraphicsUpdate does NOT emit a
    // WebP/PNG region — it just marks the framebuffer dirty (`sw_dirty`); the
    // run_session loop encodes the whole framebuffer as paced H.264 instead.
    sw_h264: bool,
    sw_dirty: &mut bool,
) -> anyhow::Result<bool>
where
    SW: ironrdp_async::FramedWrite,
    W: AsyncWrite + Unpin,
{
    *pdus += 1;
    // Process under the lock (synchronous) and collect outputs; release the
    // lock before any await on the socket.
    let outputs = {
        let mut stage = active_stage.lock().await;
        stage
            .process(image, action, payload)
            .context("ActiveStage::process")?
    };

    for output in outputs {
        match output {
            ActiveStageOutput::ResponseFrame(frame) => {
                framed_write
                    .write_all(&frame)
                    .await
                    .context("write ActiveStage response frame")?;
            }
            ActiveStageOutput::GraphicsUpdate(region) => {
                // The RGBA bitmap path: `GraphicsUpdate` is `ironrdp-session`'s
                // already-decoded output. The Tier-2 H.264 path does NOT branch
                // here — EGFX/AVC420 frames arrive on a separate DRDYNVC channel
                // ([`crate::egfx`]) and are emitted as `ServerMsg::H264` from the
                // EgfxChannel drain in the main loop. When EGFX is active the
                // server sends graphics over that channel instead of as surface
                // bitmaps, so this arm naturally only fires for non-EGFX regions
                // — it is the unconditional fallback (and the only path when
                // recording, which gates EGFX off).
                //
                // Software H.264 (ADR 0061): the region was already applied to
                // `image` by `process()` above; we encode the WHOLE framebuffer as
                // paced H.264 in the run_session loop, so here we just mark it
                // dirty and skip the per-region WebP/PNG entirely.
                if sw_h264 {
                    *sw_dirty = true;
                    continue;
                }
                let (w, h, rgba) = crop_region(image, &region);
                let x = region.left;
                let y = region.top;
                if enc.webp_live {
                    // LIVE frame = lossy WebP (the browser frame).
                    let webp = encode_region_webp(w, h, &rgba, enc.webp_quality)
                        .context("encode region WebP")?;
                    debug!(
                        x,
                        y,
                        w,
                        h,
                        webp_bytes = webp.len(),
                        "stream: emitting FRAME_WEBP"
                    );
                    write_msg(out, &ServerMsg::FrameWebp { x, y, w, h, webp })
                        .await
                        .context("write FRAME_WEBP")?;
                    // When recording, ALSO emit a lossless PNG for the recorder
                    // feed. The Go bridge records the PNG and forwards only the
                    // WebP, keeping the WORM bundle lossless + format-unchanged.
                    if enc.record_lossless {
                        let png = encode_region_png(w, h, &rgba).context("encode region PNG")?;
                        write_msg(out, &ServerMsg::Frame { x, y, w, h, png })
                            .await
                            .context("write recorder FRAME")?;
                    }
                } else {
                    // Lossless mode: the live frame is the PNG itself.
                    let png = encode_region_png(w, h, &rgba).context("encode region PNG")?;
                    debug!(
                        x,
                        y,
                        w,
                        h,
                        png_bytes = png.len(),
                        "stream: emitting FRAME (lossless)"
                    );
                    write_msg(out, &ServerMsg::Frame { x, y, w, h, png })
                        .await
                        .context("write FRAME")?;
                }
                *frames_emitted += 1;
            }
            ActiveStageOutput::Terminate(reason) => {
                info!(?reason, "stream: server terminated the session");
                return Ok(true);
            }
            ActiveStageOutput::DeactivateAll(_seq) => {
                // Mid-session capability re-exchange. Re-driving the
                // activation sequence is follow-up work (the Go-bridge
                // track); for the streaming core we stop cleanly so the
                // browser sees CLOSE rather than a stalled canvas.
                warn!("stream: server sent DeactivateAll — stopping (re-activation not wired)");
                return Ok(true);
            }
            _other => {
                debug!("stream: ignoring non-graphics active-stage output");
            }
        }
    }
    Ok(false)
}

/// Frame + write one server message to the sink.
async fn write_msg<W>(out: &mut W, msg: &ServerMsg) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = msg.encode();
    out.write_all(&bytes).await?;
    out.flush().await
}

// --- CLIPBOARD virtual channel (ADR 0054) --------------------------------

/// Apply one browser→remote clipboard command by driving the CLIPRDR SVC
/// processor (which the `ActiveStage` owns) and writing the resulting PDUs to
/// the server (the single-owner write-half). Runs in the main loop only,
/// outside any select arm.
///
/// * `LocalText` — stage the text for the remote, then `initiate_copy`
///   advertising `CF_UNICODETEXT`. The remote later issues a format-data
///   request, serviced by [`drain_clipboard`].
/// * `RequestRemoteText` — `initiate_paste(CF_UNICODETEXT)` against the format
///   id the remote advertised; the answer arrives as `on_format_data_response`
///   and is forwarded to the browser by [`drain_clipboard`].
async fn apply_browser_clipboard<SW>(
    active_stage: &Arc<Mutex<ActiveStage>>,
    framed_write: &mut ironrdp_async::Framed<SW>,
    clipboard: &ClipboardChannel,
    cmd: ClipboardCommand,
) -> anyhow::Result<()>
where
    SW: ironrdp_async::FramedWrite,
{
    let bytes = {
        // Hold the ActiveStage lock only for the synchronous SVC encode — never
        // across the socket await below.
        let mut stage = active_stage.lock().await;
        let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else {
            warn!("clipboard: CLIPRDR processor missing — dropping browser command");
            return Ok(());
        };
        match cmd {
            ClipboardCommand::LocalText(text) => {
                // Stage the text so a remote format-data request is answered
                // with it (drain_clipboard), then advertise CF_UNICODETEXT.
                clipboard.set_pending_paste(text);
                let formats = [ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
                match cliprdr.initiate_copy(&formats) {
                    Ok(msgs) => stage
                        .process_svc_processor_messages(msgs)
                        .context("encode CLIPRDR initiate_copy")?,
                    Err(e) => {
                        warn!(error = %e, "clipboard: initiate_copy failed");
                        return Ok(());
                    }
                }
            }
            ClipboardCommand::RequestRemoteText => {
                // Paste remote → browser: ask the remote for the format id it
                // advertised (CF_UNICODETEXT preferred, else CF_TEXT).
                let Some(fmt_id) = clipboard.remote_text_format_id() else {
                    debug!("clipboard: paste requested but remote has no TEXT");
                    return Ok(());
                };
                clipboard.set_last_paste_format(fmt_id);
                match cliprdr.initiate_paste(ClipboardFormatId::new(fmt_id)) {
                    Ok(msgs) => stage
                        .process_svc_processor_messages(msgs)
                        .context("encode CLIPRDR initiate_paste")?,
                    Err(e) => {
                        warn!(error = %e, "clipboard: initiate_paste failed");
                        return Ok(());
                    }
                }
            }
            ClipboardCommand::LocalImage(png) => {
                // Stage the PNG (converted to DIB on a remote request), then
                // advertise CF_DIB.
                clipboard.set_pending_image_paste(png);
                let formats = [ClipboardFormat::new(ClipboardFormatId::CF_DIB)];
                match cliprdr.initiate_copy(&formats) {
                    Ok(msgs) => stage
                        .process_svc_processor_messages(msgs)
                        .context("encode CLIPRDR initiate_copy (image)")?,
                    Err(e) => {
                        warn!(error = %e, "clipboard: initiate_copy (image) failed");
                        return Ok(());
                    }
                }
            }
            ClipboardCommand::RequestRemoteImage => {
                // Paste remote IMAGE → browser: request the DIB format the remote
                // advertised; record it so the response is routed image→PNG.
                let Some(fmt_id) = clipboard.remote_image_format_id() else {
                    debug!("clipboard: image paste requested but remote has no IMAGE");
                    return Ok(());
                };
                clipboard.set_last_paste_format(fmt_id);
                match cliprdr.initiate_paste(ClipboardFormatId::new(fmt_id)) {
                    Ok(msgs) => stage
                        .process_svc_processor_messages(msgs)
                        .context("encode CLIPRDR initiate_paste (image)")?,
                    Err(e) => {
                        warn!(error = %e, "clipboard: initiate_paste (image) failed");
                        return Ok(());
                    }
                }
            }
        }
    };
    framed_write
        .write_all(&bytes)
        .await
        .context("write CLIPRDR PDU to server")?;
    Ok(())
}

/// Drain the clipboard backend once per loop iteration:
///  1. emit any remote→browser [`crate::clipboard::ClipboardEvent`]s as
///     `CLIPBOARD` TLVs on the sink; and
///  2. service any remote format-data request the backend recorded during the
///     last `process()` — answer with the browser-staged TEXT (CF_UNICODETEXT)
///     or an error response (any other format, or no text staged).
async fn drain_clipboard<SW, W>(
    clipboard: &mut ClipboardChannel,
    active_stage: &Arc<Mutex<ActiveStage>>,
    framed_write: &mut ironrdp_async::Framed<SW>,
    out: &mut W,
) -> anyhow::Result<()>
where
    SW: ironrdp_async::FramedWrite,
    W: AsyncWrite + Unpin,
{
    // 1) remote → browser events.
    while let Some(ev) = clipboard.try_recv_event() {
        let body = ev.encode();
        let total_len = u32::try_from(body.len()).expect("clipboard body fits u32");
        out.write_all(&total_len.to_be_bytes())
            .await
            .context("write CLIPBOARD len")?;
        out.write_all(&body).await.context("write CLIPBOARD body")?;
        out.flush().await.context("flush CLIPBOARD")?;
        debug!("clipboard: emitted server→client CLIPBOARD TLV");
    }

    // 2) service a recorded remote format-data request.
    if let Some(fmt_id) = clipboard.take_remote_request() {
        let bytes = {
            let mut stage = active_stage.lock().await;
            let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                return Ok(());
            };
            // Answer CF_UNICODETEXT with our staged text and CF_DIB/CF_DIBV5
            // with our staged image (PNG→DIB); everything else gets an error.
            let response = if fmt_id == ClipboardFormatId::CF_UNICODETEXT.value() {
                match clipboard.take_pending_paste() {
                    Some(text) => FormatDataResponse::new_unicode_string(&text).into_owned(),
                    None => FormatDataResponse::new_error().into_owned(),
                }
            } else if fmt_id == ClipboardFormatId::CF_DIB.value()
                || fmt_id == ClipboardFormatId::CF_DIBV5.value()
            {
                match clipboard
                    .take_pending_image_paste()
                    .and_then(|png| crate::clipboard::png_to_dib(&png))
                {
                    Some(dib) => FormatDataResponse::new_data(dib).into_owned(),
                    None => FormatDataResponse::new_error().into_owned(),
                }
            } else {
                FormatDataResponse::new_error().into_owned()
            };
            match cliprdr.submit_format_data(response) {
                Ok(msgs) => stage
                    .process_svc_processor_messages(msgs)
                    .context("encode CLIPRDR submit_format_data")?,
                Err(e) => {
                    warn!(error = %e, "clipboard: submit_format_data failed");
                    return Ok(());
                }
            }
        };
        framed_write
            .write_all(&bytes)
            .await
            .context("write CLIPRDR format-data response to server")?;
        debug!("clipboard: answered remote format-data request");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_desktop_size_roundtrip() {
        let msg = ServerMsg::DesktopSize {
            width: 1280,
            height: 1024,
        };
        let wire = msg.encode();
        // [u32 total_len=5][type=1][w:2][h:2]
        assert_eq!(&wire[0..4], &5u32.to_be_bytes());
        assert_eq!(wire[4], MSG_DESKTOP_SIZE);
        assert_eq!(wire.len(), 4 + 5);
        assert_eq!(ServerMsg::decode(&wire).unwrap(), msg);
    }

    #[test]
    fn server_frame_roundtrip() {
        let msg = ServerMsg::Frame {
            x: 10,
            y: 20,
            w: 64,
            h: 48,
            png: vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5],
        };
        let wire = msg.encode();
        assert_eq!(wire[4], MSG_FRAME);
        // total_len = 1 (type) + 8 (rect) + 9 (png)
        assert_eq!(&wire[0..4], &18u32.to_be_bytes());
        assert_eq!(ServerMsg::decode(&wire).unwrap(), msg);
    }

    #[test]
    fn server_h264_roundtrip() {
        // Keyframe AVC420 access unit (ADR 0053 Tier-2 path).
        let msg = ServerMsg::H264 {
            keyframe: true,
            avc444: false,
            aux: false,
            x: 0,
            y: 0,
            w: 1280,
            h: 1024,
            nal: vec![0, 0, 0, 1, 0x67, 0x42, 0, 0x1f], // start code + SPS NAL stub
        };
        let wire = msg.encode();
        assert_eq!(wire[4], MSG_H264);
        // total_len = 1 (type) + 1 (flags) + 8 (rect) + 8 (nal) = 18.
        assert_eq!(&wire[0..4], &18u32.to_be_bytes());
        // flags byte: keyframe set, avc444 clear.
        assert_eq!(wire[5], H264_FLAG_KEYFRAME);
        assert_eq!(ServerMsg::decode(&wire).unwrap(), msg);

        // Delta AVC444 access unit — flags differ, roundtrips intact.
        let delta = ServerMsg::H264 {
            keyframe: false,
            avc444: true,
            aux: false,
            x: 10,
            y: 20,
            w: 64,
            h: 48,
            nal: vec![0, 0, 1, 0x41, 0x9a],
        };
        let wire = delta.encode();
        assert_eq!(wire[5], H264_FLAG_AVC444);
        assert_eq!(ServerMsg::decode(&wire).unwrap(), delta);
    }

    #[test]
    fn server_close_roundtrip() {
        let msg = ServerMsg::Close;
        let wire = msg.encode();
        assert_eq!(&wire[0..4], &1u32.to_be_bytes());
        assert_eq!(wire[4], MSG_CLOSE);
        assert_eq!(wire.len(), 5);
        assert_eq!(ServerMsg::decode(&wire).unwrap(), msg);
    }

    #[test]
    fn client_mouse_roundtrip() {
        let msg = ClientMsg::Mouse {
            x: 300,
            y: 400,
            button_mask: BUTTON_LEFT | BUTTON_MIDDLE,
            wheel: -3,
        };
        let wire = msg.encode();
        // [u32 total_len=7][type=1][x:2][y:2][mask:1][wheel:1]
        assert_eq!(&wire[0..4], &7u32.to_be_bytes());
        assert_eq!(wire[4], MSG_MOUSE);
        let (mt, payload) = split_frame(&wire).unwrap();
        assert_eq!(ClientMsg::decode_body(mt, payload).unwrap(), msg);
    }

    #[test]
    fn client_key_roundtrip() {
        let msg = ClientMsg::Key {
            is_down: true,
            scancode: 0xE05B, // extended (left meta)
        };
        let wire = msg.encode();
        // [u32 total_len=6][type=2][is_down:1][scancode:4]
        assert_eq!(&wire[0..4], &6u32.to_be_bytes());
        assert_eq!(wire[4], MSG_KEY);
        let (mt, payload) = split_frame(&wire).unwrap();
        assert_eq!(ClientMsg::decode_body(mt, payload).unwrap(), msg);
    }

    #[test]
    fn client_key_maps_extended_flag() {
        // 0xE0-prefixed scancode → EXTENDED flag set, low byte preserved.
        let ev = key_event(true, 0xE05B);
        match ev {
            FastPathInputEvent::KeyboardEvent(flags, code) => {
                assert!(flags.contains(FpKeyboardFlags::EXTENDED));
                assert!(!flags.contains(FpKeyboardFlags::RELEASE));
                assert_eq!(code, 0x5B);
            }
            _ => panic!("expected KeyboardEvent"),
        }
        // Plain scancode, key up → RELEASE, no EXTENDED.
        let ev = key_event(false, 0x1E); // 'A'
        match ev {
            FastPathInputEvent::KeyboardEvent(flags, code) => {
                assert!(flags.contains(FpKeyboardFlags::RELEASE));
                assert!(!flags.contains(FpKeyboardFlags::EXTENDED));
                assert_eq!(code, 0x1E);
            }
            _ => panic!("expected KeyboardEvent"),
        }
    }

    #[test]
    fn mouse_emits_press_and_release_edges() {
        // Press edge (prev=0, now=LEFT): MOVE then LEFT|DOWN.
        let down = mouse_events(0, 100, 200, BUTTON_LEFT, 0);
        assert_eq!(down.len(), 2, "move + press");
        match &down[0] {
            FastPathInputEvent::MouseEvent(p) => {
                assert!(p.flags.contains(PointerFlags::MOVE));
                assert_eq!(p.x_position, 100);
                assert_eq!(p.y_position, 200);
            }
            _ => panic!("expected MouseEvent"),
        }
        match &down[1] {
            FastPathInputEvent::MouseEvent(p) => {
                assert!(p.flags.contains(PointerFlags::LEFT_BUTTON));
                assert!(p.flags.contains(PointerFlags::DOWN));
            }
            _ => panic!("expected MouseEvent"),
        }
        // Release edge (prev=LEFT, now=0): MOVE then LEFT WITHOUT DOWN.
        let up = mouse_events(BUTTON_LEFT, 100, 200, 0, 0);
        assert_eq!(up.len(), 2, "move + release");
        match &up[1] {
            FastPathInputEvent::MouseEvent(p) => {
                assert!(p.flags.contains(PointerFlags::LEFT_BUTTON));
                assert!(
                    !p.flags.contains(PointerFlags::DOWN),
                    "release must not set DOWN"
                );
            }
            _ => panic!("expected MouseEvent"),
        }
        // Held (prev=LEFT, now=LEFT): no edge → MOVE only, no re-press.
        let held = mouse_events(BUTTON_LEFT, 50, 60, BUTTON_LEFT, 0);
        assert_eq!(held.len(), 1, "held button must not re-press");
    }

    #[test]
    fn mouse_wheel_emits_second_event() {
        let events = mouse_events(0, 0, 0, 0, 2);
        assert_eq!(events.len(), 2, "move + wheel");
        match &events[1] {
            FastPathInputEvent::MouseEvent(pdu) => {
                assert!(pdu.flags.contains(PointerFlags::VERTICAL_WHEEL));
            }
            _ => panic!("expected wheel MouseEvent"),
        }
    }

    #[test]
    fn split_frame_rejects_bad_length() {
        // total_len claims 10 but only 5 bytes follow the prefix.
        let mut buf = 10u32.to_be_bytes().to_vec();
        buf.push(MSG_CLOSE);
        assert!(split_frame(&buf).is_err());
    }

    #[test]
    fn decode_body_rejects_wrong_size() {
        assert!(ClientMsg::decode_body(MSG_MOUSE, &[0; 3]).is_err());
        assert!(ClientMsg::decode_body(MSG_KEY, &[0; 2]).is_err());
        assert!(ClientMsg::decode_body(99, &[]).is_err());
    }
}
