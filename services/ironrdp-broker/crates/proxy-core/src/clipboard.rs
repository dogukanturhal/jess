// SPDX-License-Identifier: AGPL-3.0-or-later

//! CLIPBOARD virtual channel (MS-RDPECLIP / cliprdr) — Tier-3 virtual-channel
//! work, ADR 0054 (`feat/rdp-rdp-tier3-clipboard-features`).
//!
//! ## What this is
//!
//! Bidirectional **TEXT** clipboard sync between the browser and the remote
//! Windows desktop, layered on IronRDP 0.15's [`ironrdp::cliprdr`] CLIPRDR
//! static-virtual-channel implementation. It is the channel-side counterpart
//! to the graphics/input stream in [`crate::stream`]: where that module owns
//! `DESKTOP_SIZE`/`FRAME`/`MOUSE`/`KEY`, this module owns the `CLIPBOARD`
//! TLV (msg-type `0x20`) and the CLIPRDR SVC processor that backs it.
//!
//! ## IronRDP seam
//!
//! `ironrdp_cliprdr::Cliprdr<Client>` (alias `CliprdrClient`) is a
//! `SvcClientProcessor`. We:
//!
//!  1. register it on the connector with
//!     `ClientConnector::with_static_channel(CliprdrClient::new(backend))`
//!     (see [`crate::connect`]), so CLIPRDR is negotiated during the
//!     connection-initiation / channel-join sequence; and
//!  2. let `ironrdp_session::ActiveStage::process` route inbound CLIPRDR PDUs
//!     to the processor automatically (the x224 processor dispatches by MCS
//!     channel id and auto-sends the processor's reply PDUs as a
//!     `ResponseFrame`); and
//!  3. drive OUTBOUND clipboard ops by fetching the processor back out with
//!     `ActiveStage::get_svc_processor_mut::<CliprdrClient>()`, calling
//!     `initiate_copy` / `initiate_paste` / `submit_format_data`, and encoding
//!     the returned `CliprdrSvcMessages` with
//!     `ActiveStage::process_svc_processor_messages`.
//!
//! The bridge between IronRDP's **synchronous** [`CliprdrBackend`] callbacks
//! (which fire inside `ActiveStage::process`, on the session thread) and the
//! async stream loop is [`ChannelBackend`] + the [`ClipboardChannel`] handle:
//! the backend pushes [`ClipboardEvent`]s onto an `mpsc` the stream loop
//! drains, and the stream loop pushes browser-originated text in via a shared
//! "pending paste" slot the backend reads when the remote requests our data.
//!
//! ## Scope (TEXT only)
//!
//! Only `CF_UNICODETEXT` is wired end-to-end. File transfer (`cliprdr` also
//! implements the full file-list / file-contents / lock state machine) is
//! intentionally NOT surfaced to the browser — the backend advertises no file
//! formats and ignores remote file lists. RDP image-format paste (`CF_DIB`)
//! is likewise out of scope. See ADR 0054 for the rationale and the
//! file/audio/multimon/drive follow-ups.
//!
//! ## Gated OFF by default
//!
//! Compiled only under the `ironrdp_live` cargo feature (same as
//! `connect`/`active`/`stream`). The CLIPRDR negotiation is additionally
//! gated at runtime by the `JESS_RDP_CLIPBOARD` env flag in `session_live`,
//! so an operator/policy can disable the channel entirely (the connector then
//! never advertises CLIPRDR and the desktop runs graphics+input only, exactly
//! as before this work).

use std::sync::{Arc, Mutex};

use ironrdp::cliprdr::backend::CliprdrBackend;
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
// `CliprdrBackend` requires `AsAny` (for the SVC processor's downcast).
// `impl_as_any!` is the canonical way IronRDP's own backends satisfy it.
use ironrdp_core::impl_as_any;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// --- Wire protocol: the CLIPBOARD TLV (msg-type 0x20) --------------------

/// Server→client / client→server `CLIPBOARD` message type.
///
/// Deliberately a HIGH number (`0x20`) so it never collides with the
/// graphics/input message types (`DESKTOP_SIZE`/`FRAME`/`CLOSE` = 1/2/3,
/// `MOUSE`/`KEY` = 1/2) nor with the render-path types siblings add in the
/// 4/5 range. The body is `[u8 msg_type=0x20][u8 subtype][payload]`; the
/// stream loop frames it with the usual `[u32 total_len]` prefix.
pub const MSG_CLIPBOARD: u8 = 0x20;

// Server→client subtypes (remote → browser).
/// The remote advertised that TEXT is available on its clipboard (a
/// FormatList carrying `CF_UNICODETEXT`/`CF_TEXT`). Payload: empty. The
/// browser may now offer to paste the remote clipboard locally.
pub const CLIP_SUB_REMOTE_TEXT_AVAILABLE: u8 = 1;
/// The remote's clipboard TEXT, as a response to a browser
/// [`CLIP_SUB_REQUEST_REMOTE_TEXT`]. Payload: UTF-8 text bytes.
pub const CLIP_SUB_REMOTE_TEXT_DATA: u8 = 2;
/// The remote advertised that an IMAGE is available (a FormatList carrying
/// `CF_DIB`/`CF_DIBV5`). Payload: empty.
pub const CLIP_SUB_REMOTE_IMAGE_AVAILABLE: u8 = 3;
/// The remote's clipboard IMAGE, as a response to a browser
/// [`CLIP_SUB_REQUEST_REMOTE_IMAGE`]. Payload: PNG bytes (the remote's DIB
/// converted to PNG broker-side).
pub const CLIP_SUB_REMOTE_IMAGE_DATA: u8 = 4;

// Client→server subtypes (browser → remote).
/// The browser's clipboard changed; advertise + supply this TEXT to the
/// remote. Payload: UTF-8 text bytes (the browser-side clipboard contents).
pub const CLIP_SUB_LOCAL_TEXT: u8 = 1;
/// The browser wants the remote clipboard TEXT (user is pasting remote
/// content into the browser tab). Payload: empty. The remote answers with a
/// [`CLIP_SUB_REMOTE_TEXT_DATA`].
pub const CLIP_SUB_REQUEST_REMOTE_TEXT: u8 = 2;
/// The browser's clipboard contains an IMAGE; advertise + supply it (as
/// `CF_DIB`) to the remote. Payload: PNG bytes (converted to DIB broker-side).
pub const CLIP_SUB_LOCAL_IMAGE: u8 = 3;
/// The browser wants the remote clipboard IMAGE. Payload: empty. The remote
/// answers with a [`CLIP_SUB_REMOTE_IMAGE_DATA`].
pub const CLIP_SUB_REQUEST_REMOTE_IMAGE: u8 = 4;

/// A decoded client→server clipboard command (browser → remote), produced by
/// [`decode_client_clipboard`] from a `[u8 subtype][payload]` body (the
/// `MSG_CLIPBOARD` type byte already stripped by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardCommand {
    /// Browser clipboard contains this TEXT; advertise it to the remote.
    LocalText(String),
    /// Browser is requesting the remote clipboard TEXT.
    RequestRemoteText,
    /// Browser clipboard contains this IMAGE (PNG bytes); advertise it to the
    /// remote as `CF_DIB` (converted broker-side).
    LocalImage(Vec<u8>),
    /// Browser is requesting the remote clipboard IMAGE.
    RequestRemoteImage,
}

/// Decode one client clipboard body (`[u8 subtype][payload]`, the leading
/// `MSG_CLIPBOARD` byte already consumed by the stream loop). Returns `None`
/// for an unknown subtype or invalid UTF-8 (dropped, not fatal).
pub fn decode_client_clipboard(body: &[u8]) -> Option<ClipboardCommand> {
    let (&subtype, payload) = body.split_first()?;
    match subtype {
        CLIP_SUB_LOCAL_TEXT => match String::from_utf8(payload.to_vec()) {
            Ok(text) => Some(ClipboardCommand::LocalText(text)),
            Err(_) => {
                warn!("clipboard: dropping LOCAL_TEXT with invalid UTF-8");
                None
            }
        },
        CLIP_SUB_REQUEST_REMOTE_TEXT => Some(ClipboardCommand::RequestRemoteText),
        CLIP_SUB_LOCAL_IMAGE => {
            if payload.is_empty() {
                warn!("clipboard: dropping empty LOCAL_IMAGE");
                None
            } else {
                Some(ClipboardCommand::LocalImage(payload.to_vec()))
            }
        }
        CLIP_SUB_REQUEST_REMOTE_IMAGE => Some(ClipboardCommand::RequestRemoteImage),
        other => {
            debug!(
                subtype = other,
                "clipboard: ignoring unknown client subtype"
            );
            None
        }
    }
}

/// Encode a server→client `CLIPBOARD` message BODY (`[u8 MSG_CLIPBOARD][u8
/// subtype][payload]`) — the stream loop frames it with the `[u32 len]` prefix.
/// `payload` is empty for the *_AVAILABLE subtypes, the UTF-8 text for
/// `CLIP_SUB_REMOTE_TEXT_DATA`, and the PNG bytes for `CLIP_SUB_REMOTE_IMAGE_DATA`.
fn encode_server_clipboard(subtype: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + payload.len());
    body.push(MSG_CLIPBOARD);
    body.push(subtype);
    body.extend_from_slice(payload);
    body
}

// --- CF_DIB <-> PNG conversion (clipboard images) ------------------------
//
// The browser speaks PNG; RDP clipboard images are CF_DIB (a BMP without the
// 14-byte file header: a BITMAPINFOHEADER then BGR(A) rows). We convert at the
// broker so the browser path stays PNG-only. Only uncompressed 24/32-bpp DIBs
// (the common screenshot case) are handled; exotic formats (palettized, RLE,
// JPEG/PNG-in-DIB) are declined (None) rather than mis-rendered.

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i32le(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Convert a CF_DIB (BITMAPINFOHEADER + pixels) to PNG. Returns `None` for
/// formats we don't handle.
fn dib_to_png(dib: &[u8]) -> Option<Vec<u8>> {
    if dib.len() < 40 {
        return None;
    }
    let bi_size = u32le(dib, 0) as usize;
    if bi_size < 40 || bi_size > dib.len() {
        return None;
    }
    let width = i32le(dib, 4);
    let height_raw = i32le(dib, 8);
    let bit_count = u16le(dib, 14);
    let compression = u32le(dib, 16);
    // BI_RGB (0) or BI_BITFIELDS (3) only; 24/32 bpp only.
    if compression != 0 && compression != 3 {
        return None;
    }
    if bit_count != 24 && bit_count != 32 {
        return None;
    }
    let w = width.unsigned_abs() as usize;
    let h = height_raw.unsigned_abs() as usize;
    if w == 0 || h == 0 || w > 16384 || h > 16384 {
        return None;
    }
    let bottom_up = height_raw > 0;
    let bpp = (bit_count / 8) as usize;
    // Pixels follow the header (+ 3 DWORD masks for BI_BITFIELDS).
    let mut off = bi_size;
    if compression == 3 {
        off += 12;
    }
    let row_stride = (w * bpp + 3) & !3; // 4-byte aligned
    if off.checked_add(row_stride.checked_mul(h)?)? > dib.len() {
        return None;
    }
    let mut rgba = vec![0u8; w * h * 4];
    for y in 0..h {
        let src_row = if bottom_up { h - 1 - y } else { y };
        let row = &dib[off + src_row * row_stride..];
        for x in 0..w {
            let p = &row[x * bpp..];
            let o = (y * w + x) * 4;
            // DIB is BGR(A); CF_DIB 32-bpp alpha is undefined → force opaque.
            rgba[o] = p[2];
            rgba[o + 1] = p[1];
            rgba[o + 2] = p[0];
            rgba[o + 3] = 255;
        }
    }
    encode_png_rgba(w, h, &rgba)
}

/// Convert a browser PNG to a bottom-up 32-bpp BI_RGB CF_DIB.
pub(crate) fn png_to_dib(png_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut reader = png::Decoder::new(png_bytes).read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (info.width as usize, info.height as usize);
    let rgba: Vec<u8> = match info.color_type {
        png::ColorType::Rgba => buf[..w * h * 4].to_vec(),
        png::ColorType::Rgb => {
            let mut v = vec![0u8; w * h * 4];
            for i in 0..w * h {
                v[i * 4] = buf[i * 3];
                v[i * 4 + 1] = buf[i * 3 + 1];
                v[i * 4 + 2] = buf[i * 3 + 2];
                v[i * 4 + 3] = 255;
            }
            v
        }
        _ => return None, // grayscale/palette: declined
    };
    let mut dib = Vec::with_capacity(40 + w * h * 4);
    dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
    dib.extend_from_slice(&(w as i32).to_le_bytes()); // biWidth
    dib.extend_from_slice(&(h as i32).to_le_bytes()); // biHeight (+ = bottom-up)
    dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    dib.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
    dib.extend_from_slice(&((w * h * 4) as u32).to_le_bytes()); // biSizeImage
    dib.extend_from_slice(&[0u8; 16]); // ppm x/y + clrUsed/clrImportant
    for y in (0..h).rev() {
        for x in 0..w {
            let o = (y * w + x) * 4;
            dib.push(rgba[o + 2]); // B
            dib.push(rgba[o + 1]); // G
            dib.push(rgba[o]); // R
            dib.push(255); // A (undefined in CF_DIB)
        }
    }
    Some(dib)
}

fn encode_png_rgba(w: usize, h: usize, rgba: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w as u32, h as u32);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().ok()?;
        writer.write_image_data(rgba).ok()?;
        writer.finish().ok()?;
    }
    Some(out)
}

/// A clipboard event flowing remote → browser, drained from the backend by
/// the stream loop and serialised to the `CLIPBOARD` TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// The remote advertised TEXT availability (FormatList with a text
    /// format). → `CLIP_SUB_REMOTE_TEXT_AVAILABLE`.
    RemoteTextAvailable,
    /// The remote returned its clipboard TEXT (answer to our paste request).
    /// → `CLIP_SUB_REMOTE_TEXT_DATA`.
    RemoteText(String),
    /// The remote advertised IMAGE availability (FormatList with `CF_DIB`/
    /// `CF_DIBV5`). → `CLIP_SUB_REMOTE_IMAGE_AVAILABLE`.
    RemoteImageAvailable,
    /// The remote returned its clipboard IMAGE as PNG (its DIB converted
    /// broker-side). → `CLIP_SUB_REMOTE_IMAGE_DATA`.
    RemoteImage(Vec<u8>),
}

impl ClipboardEvent {
    /// Serialise to a server→client `CLIPBOARD` message body (unframed).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ClipboardEvent::RemoteTextAvailable => {
                encode_server_clipboard(CLIP_SUB_REMOTE_TEXT_AVAILABLE, &[])
            }
            ClipboardEvent::RemoteText(text) => {
                encode_server_clipboard(CLIP_SUB_REMOTE_TEXT_DATA, text.as_bytes())
            }
            ClipboardEvent::RemoteImageAvailable => {
                encode_server_clipboard(CLIP_SUB_REMOTE_IMAGE_AVAILABLE, &[])
            }
            ClipboardEvent::RemoteImage(png) => {
                encode_server_clipboard(CLIP_SUB_REMOTE_IMAGE_DATA, png)
            }
        }
    }
}

/// The browser-side text the backend should hand to the remote on the next
/// `on_format_data_request` for `CF_UNICODETEXT`. Shared between the stream
/// loop (writer, on a `LocalText` command) and the backend (reader, inside a
/// synchronous SVC callback). A plain `Mutex<Option<String>>` is enough — the
/// callback is brief and never awaits.
type PendingPaste = Arc<Mutex<Option<String>>>;

/// A remote→us format-data request the backend recorded inside its
/// synchronous callback, for the stream loop to service AFTER
/// `ActiveStage::process` returns (the loop owns the SVC processor, so only it
/// can call `submit_format_data`). `Some(format_id)` ⇒ the remote asked for
/// that format; the loop answers with our staged text (text format) or an
/// error (anything else).
type PendingRemoteRequest = Arc<Mutex<Option<u32>>>;

/// Handle the stream loop holds to talk to the CLIPRDR channel. Created by
/// [`ChannelBackend::new`]; the matching [`ChannelBackend`] is moved into the
/// `CliprdrClient` SVC processor.
#[derive(Debug)]
pub struct ClipboardChannel {
    /// Remote → browser events (drained by the stream loop each poll).
    events: mpsc::UnboundedReceiver<ClipboardEvent>,
    /// Browser → remote text staged for the next remote format-data request.
    pending_paste: PendingPaste,
    /// `CF_UNICODETEXT` format-id the remote most recently advertised, if any.
    /// Set by the backend when the remote copies text; read by the stream loop
    /// to drive `initiate_paste`. `None` ⇒ the remote has no text to paste.
    remote_text_format: Arc<Mutex<Option<u32>>>,
    /// A remote format-data request the loop must answer (see
    /// [`PendingRemoteRequest`]).
    pending_remote_request: PendingRemoteRequest,
    /// Browser → remote IMAGE (PNG) staged for the next remote `CF_DIB`
    /// request; converted to DIB on supply. Channel-only, like `pending_paste`.
    pending_image_paste: Arc<Mutex<Option<Vec<u8>>>>,
    /// `CF_DIB`/`CF_DIBV5` format id the remote most recently advertised, if any
    /// (set by the backend on a remote copy; read by the loop to `initiate_paste`).
    remote_image_format: Arc<Mutex<Option<u32>>>,
    /// Format id of OUR last `initiate_paste`, so the backend routes the
    /// format-data response to the text vs image path. Shared with the backend.
    last_paste_format: Arc<Mutex<Option<u32>>>,
}

impl ClipboardChannel {
    /// Non-blocking drain of the next remote→browser event, if any.
    pub fn try_recv_event(&mut self) -> Option<ClipboardEvent> {
        self.events.try_recv().ok()
    }

    /// Stage browser clipboard IMAGE (PNG) for the remote, fetched as `CF_DIB`.
    pub fn set_pending_image_paste(&self, png: Vec<u8>) {
        if let Ok(mut slot) = self.pending_image_paste.lock() {
            *slot = Some(png);
        }
    }

    /// Take (clear) the browser-staged IMAGE (PNG) to answer a remote `CF_DIB`
    /// request. `None` ⇒ nothing staged (the loop sends an error response).
    pub fn take_pending_image_paste(&self) -> Option<Vec<u8>> {
        self.pending_image_paste
            .lock()
            .ok()
            .and_then(|mut s| s.take())
    }

    /// The `CF_DIB`/`CF_DIBV5` format id the remote last advertised, or `None`.
    pub fn remote_image_format_id(&self) -> Option<u32> {
        self.remote_image_format.lock().ok().and_then(|g| *g)
    }

    /// Record the format id of an `initiate_paste` we're about to issue so the
    /// backend can route the eventual format-data response (text vs image).
    pub fn set_last_paste_format(&self, id: u32) {
        if let Ok(mut slot) = self.last_paste_format.lock() {
            *slot = Some(id);
        }
    }

    /// Stage browser clipboard TEXT for the remote. The remote will fetch it
    /// via `on_format_data_request` after we advertise (`initiate_copy`).
    pub fn set_pending_paste(&self, text: String) {
        if let Ok(mut slot) = self.pending_paste.lock() {
            *slot = Some(text);
        }
    }

    /// The `CF_UNICODETEXT` format id the remote last advertised (for
    /// `initiate_paste`), or `None` when the remote has no text available.
    pub fn remote_text_format_id(&self) -> Option<u32> {
        self.remote_text_format.lock().ok().and_then(|g| *g)
    }

    /// Take (clear) a remote format-data request the backend recorded, if any.
    /// The stream loop calls this after `ActiveStage::process` and replies via
    /// `CliprdrClient::submit_format_data`.
    pub fn take_remote_request(&self) -> Option<u32> {
        self.pending_remote_request
            .lock()
            .ok()
            .and_then(|mut s| s.take())
    }

    /// The text the stream loop should send in answer to a remote request (the
    /// browser-staged paste), taking + clearing it. `None` ⇒ nothing staged
    /// (the loop sends an error response).
    pub fn take_pending_paste(&self) -> Option<String> {
        self.pending_paste.lock().ok().and_then(|mut s| s.take())
    }
}

/// IronRDP [`CliprdrBackend`] that bridges the synchronous CLIPRDR callbacks
/// to the async stream loop via channels. TEXT-only: it advertises only
/// `CF_UNICODETEXT`, serves the staged browser text on a remote request, and
/// forwards remote text availability + data to the stream loop as
/// [`ClipboardEvent`]s. File/image/lock callbacks are accepted (so the channel
/// stays spec-correct) but produce no browser-visible effect.
#[derive(Debug)]
pub struct ChannelBackend {
    /// Remote → browser events (the stream loop's receiver lives in
    /// [`ClipboardChannel`]).
    events: mpsc::UnboundedSender<ClipboardEvent>,
    /// The `CF_UNICODETEXT` format id the remote advertised, mirrored into
    /// [`ClipboardChannel`] so the stream loop can `initiate_paste`.
    remote_text_format: Arc<Mutex<Option<u32>>>,
    /// A remote format-data request recorded for the stream loop to answer.
    pending_remote_request: PendingRemoteRequest,
    /// `CF_DIB`/`CF_DIBV5` format id the remote advertised (mirrored to the
    /// channel for `initiate_paste`).
    remote_image_format: Arc<Mutex<Option<u32>>>,
    /// Format id of the loop's last `initiate_paste` — read here to route the
    /// format-data response (text vs image).
    last_paste_format: Arc<Mutex<Option<u32>>>,
    // NOTE: the browser→remote staged text/image (`PendingPaste`) lives ONLY on
    // the `ClipboardChannel` side — the backend never reads it (the stream loop
    // owns the SVC processor and supplies the staged data on a remote request).
}

impl ChannelBackend {
    /// Build the backend (to register on the connector) + the matching
    /// [`ClipboardChannel`] handle (held by the stream loop). Not named `new`
    /// because it returns a `(backend, channel)` pair rather than `Self`.
    pub fn create() -> (Box<dyn CliprdrBackend>, ClipboardChannel) {
        let (tx, rx) = mpsc::unbounded_channel();
        let pending_paste: PendingPaste = Arc::new(Mutex::new(None));
        let remote_text_format = Arc::new(Mutex::new(None));
        let pending_remote_request: PendingRemoteRequest = Arc::new(Mutex::new(None));
        let remote_image_format = Arc::new(Mutex::new(None));
        let last_paste_format = Arc::new(Mutex::new(None));
        let backend = ChannelBackend {
            events: tx,
            remote_text_format: Arc::clone(&remote_text_format),
            pending_remote_request: Arc::clone(&pending_remote_request),
            remote_image_format: Arc::clone(&remote_image_format),
            last_paste_format: Arc::clone(&last_paste_format),
        };
        let channel = ClipboardChannel {
            events: rx,
            pending_paste,
            remote_text_format,
            pending_remote_request,
            pending_image_paste: Arc::new(Mutex::new(None)),
            remote_image_format,
            last_paste_format,
        };
        (Box::new(backend), channel)
    }

    /// Does this format list carry a TEXT format we understand?
    /// Returns the preferred text format id (`CF_UNICODETEXT` if present, else
    /// `CF_TEXT`), or `None` when the list has no text.
    fn preferred_text_format(formats: &[ClipboardFormat]) -> Option<ClipboardFormatId> {
        let mut ansi = None;
        for f in formats {
            if f.id() == ClipboardFormatId::CF_UNICODETEXT {
                return Some(ClipboardFormatId::CF_UNICODETEXT);
            }
            if f.id() == ClipboardFormatId::CF_TEXT {
                ansi = Some(ClipboardFormatId::CF_TEXT);
            }
        }
        ansi
    }

    /// Does this format list carry an IMAGE format we convert? Prefers `CF_DIB`
    /// (we decode 24/32-bpp BI_RGB), else `CF_DIBV5`. `None` when no DIB.
    fn preferred_image_format(formats: &[ClipboardFormat]) -> Option<ClipboardFormatId> {
        let mut v5 = None;
        for f in formats {
            if f.id() == ClipboardFormatId::CF_DIB {
                return Some(ClipboardFormatId::CF_DIB);
            }
            if f.id() == ClipboardFormatId::CF_DIBV5 {
                v5 = Some(ClipboardFormatId::CF_DIBV5);
            }
        }
        v5
    }
}

impl_as_any!(ChannelBackend);

impl CliprdrBackend for ChannelBackend {
    fn temporary_directory(&self) -> &str {
        // No file transfer in TEXT-only mode; a sane placeholder satisfies the
        // ClientTemporaryDirectory PDU the initiation batch sends.
        ".jess-cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        // TEXT-only: advertise NO extra capabilities. We deliberately do NOT
        // set STREAM_FILECLIP_ENABLED / CAN_LOCK_CLIPDATA — the broker brokers
        // text, not files, so the file-transfer state machine stays dormant.
        // (`Cliprdr` always ORs in USE_LONG_FORMAT_NAMES itself.)
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {
        info!("clipboard: CLIPRDR channel ready");
    }

    fn on_request_format_list(&mut self) {
        // Called once during init (after Monitor Ready) so the client can
        // advertise its initial clipboard. We have nothing to advertise yet
        // (the browser pushes text via a LocalText command, which the stream
        // loop turns into an explicit initiate_copy). No-op.
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        capabilities: ClipboardGeneralCapabilityFlags,
    ) {
        debug!(?capabilities, "clipboard: negotiated capabilities");
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // The remote performed a copy. Remember which formats it offers (for a
        // later initiate_paste) and tell the browser what's available. We do NOT
        // auto-fetch — fetching happens only when the user pastes into the
        // browser (delayed rendering), per the cliprdr backend contract. TEXT
        // and IMAGE are surfaced independently (a copy may offer both).
        let text = Self::preferred_text_format(available_formats);
        if let Ok(mut slot) = self.remote_text_format.lock() {
            *slot = text.map(|id| id.value());
        }
        if let Some(id) = text {
            let _ = self.events.send(ClipboardEvent::RemoteTextAvailable);
            debug!(format_id = id.value(), "clipboard: remote copied TEXT");
        }

        let image = Self::preferred_image_format(available_formats);
        if let Ok(mut slot) = self.remote_image_format.lock() {
            *slot = image.map(|id| id.value());
        }
        if let Some(id) = image {
            let _ = self.events.send(ClipboardEvent::RemoteImageAvailable);
            debug!(format_id = id.value(), "clipboard: remote copied IMAGE");
        }
        if text.is_none() && image.is_none() {
            debug!("clipboard: remote copied unsupported formats — ignored");
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        // The remote wants OUR clipboard data in `request.format`. The response
        // must be sent by the stream loop (it owns the SVC processor and calls
        // `submit_format_data`), which only runs AFTER this synchronous callback
        // returns. So record the requested format id; the loop drains it via
        // `ClipboardChannel::take_remote_request` and answers with the staged
        // browser text (text format) or an error response (anything else).
        debug!(
            format_id = request.format.value(),
            "clipboard: remote requested our format data"
        );
        if let Ok(mut slot) = self.pending_remote_request.lock() {
            *slot = Some(request.format.value());
        }
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        // The remote answered our paste request (initiate_paste). Route by the
        // format the loop last requested (recorded in `last_paste_format`): a DIB
        // format → convert to PNG for the browser; otherwise UNICODE text.
        if response.is_error() {
            warn!("clipboard: remote format-data response is an error");
            return;
        }
        let requested = self.last_paste_format.lock().ok().and_then(|g| *g);
        let is_image = matches!(
            requested,
            Some(id) if id == ClipboardFormatId::CF_DIB.value()
                || id == ClipboardFormatId::CF_DIBV5.value()
        );
        if is_image {
            match dib_to_png(response.data()) {
                Some(png) => {
                    debug!(
                        bytes = png.len(),
                        "clipboard: received remote IMAGE (DIB→PNG)"
                    );
                    let _ = self.events.send(ClipboardEvent::RemoteImage(png));
                }
                None => warn!("clipboard: remote IMAGE (DIB) unsupported/failed to convert"),
            }
            return;
        }
        match response.to_unicode_string() {
            Ok(text) => {
                debug!(len = text.len(), "clipboard: received remote TEXT");
                let _ = self.events.send(ClipboardEvent::RemoteText(text));
            }
            Err(e) => warn!(error = %e, "clipboard: remote TEXT decode failed"),
        }
    }

    // --- File transfer: TEXT-only mode declines everything ---------------

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        // We never advertise files, so this should not arrive; if it does, the
        // SVC processor already answers with an error response. No-op here.
        debug!(
            stream_id = request.stream_id,
            "clipboard: ignoring file-contents request (text-only)"
        );
    }

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {
        // We never request files. No-op.
    }

    fn on_lock(&mut self, _data_id: LockDataId) {
        // No file streams to protect in text-only mode. No-op.
    }

    fn on_unlock(&mut self, _data_id: LockDataId) {
        // No file streams to protect in text-only mode. No-op.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_local_text_roundtrips() {
        let mut body = vec![CLIP_SUB_LOCAL_TEXT];
        body.extend_from_slice("héllo".as_bytes());
        assert_eq!(
            decode_client_clipboard(&body),
            Some(ClipboardCommand::LocalText("héllo".to_owned()))
        );
    }

    #[test]
    fn decode_request_remote_text() {
        assert_eq!(
            decode_client_clipboard(&[CLIP_SUB_REQUEST_REMOTE_TEXT]),
            Some(ClipboardCommand::RequestRemoteText)
        );
    }

    #[test]
    fn decode_rejects_unknown_subtype_and_bad_utf8() {
        assert_eq!(decode_client_clipboard(&[0x99]), None);
        // Lone continuation byte 0x80 is invalid UTF-8.
        assert_eq!(decode_client_clipboard(&[CLIP_SUB_LOCAL_TEXT, 0x80]), None);
        assert_eq!(decode_client_clipboard(&[]), None);
    }

    #[test]
    fn event_encode_shapes() {
        let avail = ClipboardEvent::RemoteTextAvailable.encode();
        assert_eq!(avail, vec![MSG_CLIPBOARD, CLIP_SUB_REMOTE_TEXT_AVAILABLE]);

        let data = ClipboardEvent::RemoteText("hi".to_owned()).encode();
        assert_eq!(data[0], MSG_CLIPBOARD);
        assert_eq!(data[1], CLIP_SUB_REMOTE_TEXT_DATA);
        assert_eq!(&data[2..], b"hi");
    }

    #[test]
    fn pending_paste_flows_through_channel() {
        let (_backend_box, channel) = ChannelBackend::create();
        channel.set_pending_paste("clip".to_owned());
        assert_eq!(channel.take_pending_paste(), Some("clip".to_owned()));
        // Second take is empty (taken).
        assert_eq!(channel.take_pending_paste(), None);
    }

    #[test]
    fn remote_format_request_recorded_for_loop() {
        let (backend_box, channel) = ChannelBackend::create();
        let mut backend = backend_box;
        let b = backend
            .as_any_mut()
            .downcast_mut::<ChannelBackend>()
            .expect("ChannelBackend");
        b.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        });
        assert_eq!(
            channel.take_remote_request(),
            Some(ClipboardFormatId::CF_UNICODETEXT.value())
        );
        assert_eq!(channel.take_remote_request(), None);
    }

    #[test]
    fn remote_copy_text_sets_format_and_emits_event() {
        let (backend_box, mut channel) = ChannelBackend::create();
        let mut backend = backend_box;
        let b = backend
            .as_any_mut()
            .downcast_mut::<ChannelBackend>()
            .expect("ChannelBackend");
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert_eq!(
            channel.remote_text_format_id(),
            Some(ClipboardFormatId::CF_UNICODETEXT.value())
        );
        assert_eq!(
            channel.try_recv_event(),
            Some(ClipboardEvent::RemoteTextAvailable)
        );
    }

    #[test]
    fn remote_copy_nontext_clears_format() {
        let (backend_box, channel) = ChannelBackend::create();
        let mut backend = backend_box;
        let b = backend
            .as_any_mut()
            .downcast_mut::<ChannelBackend>()
            .expect("ChannelBackend");
        // CF_BITMAP only → no text.
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_BITMAP)]);
        assert_eq!(channel.remote_text_format_id(), None);
    }
}
