// SPDX-License-Identifier: AGPL-3.0-or-later

//! jess-ironrdp-proxy-core — RDP framing + grant-lookup primitives.
//!
//! Phase 5f-1 SCOPE: types + grant client only. The RDP framing path
//! re-exports the bits of `ironrdp` we will wire up in Phase 5f-2:
//! `ironrdp_connector::ClientConnector` for the X.224 / MCS / GCC
//! handshake, `ironrdp_pdu::Action` for fastpath dispatch. None of that
//! is exercised yet — keeping the dependency in `Cargo.toml` so the
//! workspace builds and link-time gotchas surface now, not later.
//!
//! Tests against the controller's admin port use the same wire shape
//! jess-web uses: GET /grants?subject=...&target=... → array of Grant.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod grant;
pub mod ssrf;
pub mod target;
pub mod x224;

// ADR 0051 IronRDP first spike — OFF by default (see Cargo.toml feature
// `ironrdp_spike`). This is the first module that `use`s a real
// ironrdp_connector symbol; the default build stays the 5f-8a
// handshake-only broker with no extra direct deps.
#[cfg(feature = "ironrdp_spike")]
pub mod spike;

// ADR 0051 LIVE CredSSP/NLA handshake — OFF by default (feature
// `ironrdp_live`, which implies `ironrdp_spike`). Drives the connector
// all the way to `Connected` against a real Windows DC: TLS upgrade +
// CredSSP token exchange. This is the gating-risk resolver for the RDP
// track and the reusable transport seam for the production bridge.
#[cfg(feature = "ironrdp_live")]
pub mod connect;

// ADR 0051 P2a "first pixels" — OFF by default (feature `ironrdp_live`).
// Drives `ironrdp_session::ActiveStage` over the live post-Connected
// stream from `connect`, decoding the desktop into an RGBA framebuffer
// and encoding it to PNG. The server-side-decode seam the production
// bridge (P2b) + WORM recording (P4) will reuse.
#[cfg(feature = "ironrdp_live")]
pub mod active;

// ADR 0051 P2b "streaming session core" — OFF by default (feature
// `ironrdp_live`). Turns the one-shot `active::capture_desktop` decode
// into a live bidirectional stream over the Go↔Rust bridge wire protocol:
// emits DESKTOP_SIZE + a FRAME per dirty region to a sink and injects
// MOUSE/KEY from a source as FastPath input. The exact length-prefixed TLV
// protocol a later talon Go bridge + browser canvas will speak.
#[cfg(feature = "ironrdp_live")]
pub mod stream;

// CLIPBOARD virtual channel (MS-RDPECLIP / cliprdr) — Tier-3 virtual-channel
// work, ADR 0054. OFF by default (feature `ironrdp_live`). The CLIPRDR SVC
// processor backend + the `CLIPBOARD` (0x20) TLV codec; `connect` registers it
// on the connector and `stream` drives it. Bidirectional TEXT only. The
// channel is additionally runtime-gated by `JESS_RDP_CLIPBOARD` in the
// `session_live` bin, so it can be turned off without rebuilding.
#[cfg(feature = "ironrdp_live")]
pub mod clipboard;

// MS-RDPEGFX graphics pipeline (AVC420 / H.264) — Tier-2 "native-feel" path,
// ADR 0053. OFF by default (feature `ironrdp_live`). The in-tree EGFX DVC
// processor advertises AVC420-only caps, ZGFX-decompresses the graphics stream,
// and forwards raw H.264 NAL units to the browser's WebCodecs decoder; `connect`
// registers it on a DRDYNVC channel and `stream` drains its frames into
// `ServerMsg::H264`. Additionally runtime-gated by `JESS_RDP_H264` in the
// `session_live` bin, and kept OFF for recorded sessions (the WORM PNG track
// needs the bitmap path). See `egfx.rs`.
#[cfg(feature = "ironrdp_live")]
pub mod egfx;

// Software H.264 encoder (ADR 0061) — the GPU-free "native-feel" live path:
// CPU-encode the decoded RGBA framebuffer as H.264 → MSG_H264 (no host AVC
// encoder / GPU needed). OFF by default (JESS_RDP_H264_SW).
#[cfg(feature = "ironrdp_live")]
pub mod h264enc;

pub use grant::{Grant, GrantClient, GrantLookupError};
pub use ssrf::{is_allowed_target, SsrfError};
pub use target::{Target, TargetKind};
pub use x224::{probe, NegResponse, ProbeError, ProbeReport, RequestedProto, FAILURE_REASONS};

/// Crate version pinned for `/healthz` and Prometheus `build_info`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
