// SPDX-License-Identifier: AGPL-3.0-or-later

//! IronRDP first spike — ADR 0051, Phase 5f-8b kickoff (R&D).
//!
//! ## What this is
//!
//! The FIRST place in the broker that actually `use`s a real IronRDP
//! connector symbol. Up to now `ironrdp*` has been a pinned-but-unused
//! dependency (see `Cargo.toml` + the `lib.rs` Phase 5f-1 header): the
//! live session path is still the handshake-only `x224::probe` raw
//! framing (`handlers::handle_socket` closes with
//! `"phase 5f-8a handshake-only"`).
//!
//! This module constructs an [`ironrdp_connector::ClientConnector`] and
//! drives it through its FIRST state — `ConnectionInitiationSendRequest`
//! — which encodes the X.224 / connection-initiation PDU
//! (TPKT + X.224 CR + RDP_NEG_REQ) into an output buffer and advances
//! the state machine to `ConnectionInitiationWaitConfirm`. It does this
//! with NO network I/O: `Sequence::step_no_input` is pure
//! encode-into-buffer, so the spike is a deterministic unit test of the
//! real connector, not a live dial.
//!
//! ## Why gated behind a feature
//!
//! The `pub mod spike;` declaration in `lib.rs` is
//! `#[cfg(feature = "ironrdp_spike")]`. The default `cargo build` /
//! `cargo test` surface is UNCHANGED — the broker still ships the 5f-8a
//! handshake-only behaviour and pulls in no extra direct dependency.
//! Enable the spike with (NOTE: build the whole workspace, not `-p
//! jess-ironrdp-proxy-core`; in isolation Cargo doesn't unify the
//! `time/parsing` feature that `grant.rs` needs — a pre-existing
//! workspace feature-resolution quirk, unrelated to the spike):
//!
//! ```text
//! cargo build --features jess-ironrdp-proxy-core/ironrdp_spike
//! cargo test  --features jess-ironrdp-proxy-core/ironrdp_spike
//! ```
//!
//! ## Honest status
//!
//! This is a SPIKE, not the bridge. It proves exactly one thing: the
//! pinned `ironrdp_connector` 0.9 API can be constructed and driven one
//! step from this codebase, against this toolchain, producing real
//! on-the-wire X.224 bytes. The connection-initiation step is the
//! cheapest real connector step (no TLS, no creds, no MCS), which is
//! why it's the spike target per ADR 0051's week-1 plan.
//!
//! Everything past the first step is NOT here — see the
//! `=== CONNECTOR FRONTIER ===` marker below for exactly where the
//! state machine stops and what each remaining phase must wire.

use ironrdp_connector::{
    BitmapConfig, ClientConnector, Config, Credentials, DesktopSize, Sequence, Written,
};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::{BitmapCodecs, MajorPlatformType};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};

/// Build the broker's quality-first [`BitmapConfig`].
///
/// QUALITY (ADR 0051 — text-crispness fix): the connector's `bitmap: None`
/// default *does* already negotiate 32-bit colour (`connection.rs`
/// `max_color_depth` defaults to 32 + `WANT_32_BPP_SESSION`), but it also
/// advertises the **RemoteFX** codec by default
/// (`client_codecs_capabilities(&[])` enables `remotefx` with RLGR3 entropy
/// coding). RemoteFX is a *lossy* wavelet codec — it visibly blurs text and
/// fine UI edges, which is exactly the artefact the operator reported.
///
/// Setting an explicit `BitmapConfig` with `color_depth = 32` (full colour,
/// explicit where it was implicit), `lossy_compression = false` (no lossy
/// bitmap drawing flags), and `codecs = BitmapCodecs(vec![])` (advertise NO
/// RemoteFX codec) forces the server onto the **lossless** path: RDP 6.0
/// 32-bit bitmap updates / `CODEC_ID_NONE` surface bits, both of which
/// `ironrdp_session`'s decoder handles (see `fast_path.rs`
/// `process_bitmap_update` / `process_surface_commands`). The result is
/// pixel-exact text instead of wavelet-blurred text.
fn lossless_bitmap_config() -> BitmapConfig {
    BitmapConfig {
        // Full 32-bit colour. Explicit — the connector's implicit default is
        // also 32 here, but we no longer rely on it.
        color_depth: 32,
        // No lossy bitmap drawing flags (no chroma subsampling / dynamic
        // colour fidelity).
        lossy_compression: false,
        // Empty codec set ⇒ do NOT advertise RemoteFX (the default
        // `client_codecs_capabilities(&[])` would). The server then falls
        // back to lossless RDP 6.0 bitmaps / uncompressed surface bits.
        codecs: BitmapCodecs(Vec::new()),
    }
}

/// The legacy fixed desktop resolution (the value this Config hard-coded
/// before the resolution-match work). Used when the caller doesn't request
/// a specific size.
pub const DEFAULT_DESKTOP_SIZE: DesktopSize = DesktopSize {
    width: 1280,
    height: 1024,
};

/// Lower/upper bounds for a *requested* desktop resolution. A browser-
/// supplied size is clamped into this range so a hostile or buggy client
/// can't ask for a 1×1 or a multi-gigapixel framebuffer (the server-side
/// `DecodedImage` allocates `w*h*4` bytes). The wire fields are `u16`, so
/// the hard ceiling is already 65535; we keep a saner 8K-ish cap.
const MIN_DESKTOP_DIM: u16 = 640;
const MAX_DESKTOP_DIM: u16 = 8192;

/// Build a [`DesktopSize`] from a browser-requested width/height, clamping
/// each axis into `[MIN_DESKTOP_DIM, MAX_DESKTOP_DIM]`. `0` on either axis
/// (the "unset" sentinel) falls back to [`DEFAULT_DESKTOP_SIZE`] for that
/// axis, so a partial/legacy request still yields a sane size.
pub fn desktop_size_from_request(width: u16, height: u16) -> DesktopSize {
    let clamp = |v: u16, fallback: u16| -> u16 {
        if v == 0 {
            fallback
        } else {
            v.clamp(MIN_DESKTOP_DIM, MAX_DESKTOP_DIM)
        }
    };
    DesktopSize {
        width: clamp(width, DEFAULT_DESKTOP_SIZE.width),
        height: clamp(height, DEFAULT_DESKTOP_SIZE.height),
    }
}

/// Build a minimal non-NLA connector [`Config`].
///
/// `enable_tls = true`, `enable_credssp = false` selects the legacy
/// TLS-only (PROTOCOL_SSL) security path: the connector advertises
/// PROTOCOL_SSL in the X.224 RDP_NEG_REQ and does NOT request CredSSP /
/// NLA. This is the same posture ADR 0033's slice 5f-8b-1 targets first
/// (lab Windows VMs with NLA disabled) and what ADR 0051 picks for the
/// gating week-1 spike — it exercises the connector's connection-
/// initiation encode without dragging in the sspi CredSSP stack.
///
/// Field values mirror the canonical `ironrdp` `screenshot.rs` example
/// (the upstream reference for a headless client Config) so the spike
/// stays faithful to a known-good construction rather than guessing.
pub fn spike_config_non_nla() -> Config {
    Config {
        // Non-NLA: TLS graphical-login only, NO CredSSP. The frontier
        // marker below explains what flipping `enable_credssp = true`
        // would require (the whole sspi CredSSP path, ADR 0051 §CredSSP).
        enable_tls: true,
        enable_credssp: false,
        // Empty creds: legacy TLS shows winlogon; the operator types
        // into the rendered login screen. NLA targets would need real
        // credentials threaded here (5f-8b-2 typed-password /
        // 5f-8b-3 smart-card).
        credentials: Credentials::UsernamePassword {
            username: String::new(),
            password: String::new(),
        },
        domain: None,

        desktop_size: DesktopSize {
            width: 1280,
            height: 1024,
        },
        desktop_scale_factor: 0,

        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),

        bitmap: None,
        client_build: 0,
        client_name: "jess-ironrdp-broker-spike".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        dig_product_id: String::new(),

        // The broker runs on Linux; advertise UNIX like the upstream
        // example does for non-Windows builds.
        platform: MajorPlatformType::UNIX,

        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// Build a full **NLA / CredSSP** connector [`Config`] from real
/// credentials.
///
/// This is the live-handshake counterpart to [`spike_config_non_nla`]:
/// `enable_tls = false`, `enable_credssp = true` is exactly the posture
/// the upstream `screenshot.rs` example uses for an NLA target (the
/// connector advertises PROTOCOL_HYBRID, performs the TLS enhanced-
/// security upgrade, then drives the CredSSP token exchange). It is the
/// only posture that can reach a session on a DC that mandates
/// PROTOCOL_HYBRID_EX (our live target `10.0.20.10:3389`).
///
/// `enable_tls = false` is NOT "no TLS" — with `enable_credssp = true`
/// the connector still performs the enhanced-security TLS upgrade; the
/// flag selects the *legacy direct-TLS-graphical-login* path (PROTOCOL_
/// SSL) which is mutually exclusive with CredSSP. Mirrors the example.
///
/// `domain` is the NetBIOS domain (e.g. `HEXXLOCK`). Connecting by IP
/// (no SPN) forces NTLM client-side — sspi performs NTLM in-process on
/// Linux, no KDC round-trip needed.
///
/// `desktop_size` is the resolution to REQUEST from the server (item #3 —
/// resolution match). The server normally honours it for a fresh connect,
/// so a browser that asks for a size matching its viewport renders close to
/// 1:1 (no upscaling blur). Pass [`DEFAULT_DESKTOP_SIZE`] for the legacy
/// fixed 1280×1024.
///
/// SECURITY: `username`/`domain` are logged at the call site for
/// diagnostics; `password` is moved into the connector's `Credentials`
/// and MUST originate from a `zeroize::Zeroizing` buffer at the caller.
/// It is never logged here.
pub fn live_config_nla(
    username: String,
    password: String,
    domain: Option<String>,
    desktop_size: DesktopSize,
) -> Config {
    Config {
        // NLA target: TLS enhanced-security upgrade + CredSSP token
        // exchange (NOT the legacy direct-TLS login path).
        enable_tls: false,
        enable_credssp: true,
        credentials: Credentials::UsernamePassword { username, password },
        domain,

        desktop_size,
        desktop_scale_factor: 0,

        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),

        // QUALITY: full-colour, lossless bitmaps, NO RemoteFX (see
        // `lossless_bitmap_config`). Was `None` ⇒ RemoteFX-on-by-default,
        // which is a lossy wavelet codec that blurred text.
        bitmap: Some(lossless_bitmap_config()),
        client_build: 0,
        client_name: "jess-ironrdp-broker-credssp".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        dig_product_id: String::new(),

        // Broker runs on Linux; advertise UNIX like the upstream example.
        platform: MajorPlatformType::UNIX,

        request_data: None,
        // AUTOLOGON: inject the credential into the Windows logon so the session
        // single-signs-on straight to the desktop. Without it, NLA/CredSSP
        // authenticates the connection but Windows still presents the interactive
        // "Other user" logon — a dead end here, because the per-session ephemeral
        // password is Vault-generated and never shown to the operator (the
        // passwordless-injection model, like Boundary). The credentials are
        // already in `credentials` above; this sets ClientInfoFlags::AUTOLOGON so
        // they're delivered in the Client Info PDU for SSO straight to the desktop.
        autologon: true,
        enable_audio_playback: false,
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// Outcome of the connection-initiation spike step.
#[derive(Debug)]
pub struct InitiationStepResult {
    /// Number of bytes the connector encoded for the X.224 CR PDU.
    pub bytes_written: usize,
    /// `State::name()` AFTER the step (expected:
    /// `"ConnectionInitiationWaitResponse"`).
    pub next_state: &'static str,
}

/// Construct a real [`ClientConnector`] and drive its FIRST step.
///
/// Returns the encoded X.224 connection-request bytes plus the
/// post-step state name. No socket is opened — `step_no_input` is a
/// pure encode-into-buffer for the initiation state (its
/// `next_pdu_hint()` is `None`, i.e. it consumes no input).
///
/// This is the load-bearing proof: it links and runs against the pinned
/// `ironrdp_connector` 0.9 / `ironrdp_pdu` 0.8 / `ironrdp_core` 0.2
/// surface from inside this workspace.
pub fn drive_connection_initiation() -> Result<(Vec<u8>, InitiationStepResult), String> {
    let config = spike_config_non_nla();

    // The connector wants the CLIENT socket address (it's embedded in
    // GCC client data later). For the offline initiation step the value
    // is irrelevant — a loopback placeholder keeps the spike I/O-free.
    let client_addr = "127.0.0.1:0".parse().expect("static loopback addr parses");

    let mut connector = ClientConnector::new(config, client_addr);

    // Sanity: a fresh connector starts in the initiation-send state.
    debug_assert_eq!(connector.state().name(), "ConnectionInitiationSendRequest");

    let mut output = WriteBuf::new();
    let written = connector
        .step_no_input(&mut output)
        .map_err(|e| format!("connector initiation step failed: {e}"))?;

    let bytes_written = match written {
        Written::Size(n) => n.get(),
        Written::Nothing => {
            return Err("connection-initiation step wrote nothing (expected an X.224 CR)".into())
        }
    };

    let next_state = connector.state().name();

    // ────────────────────────────────────────────────────────────────
    // === CONNECTOR FRONTIER ===  (ADR 0051 phased build)
    //
    // The state machine is now parked at:
    //     ClientConnectorState::ConnectionInitiationWaitConfirm
    // i.e. it has SENT the X.224 CR and is waiting for the server's
    // Connection Confirm. EVERYTHING below is NOT wired by this spike:
    //
    //  1. TCP + read-loop driver. Real progress needs a transport that
    //     feeds `connector.step(input, &mut output)` whenever
    //     `connector.next_pdu_hint()` says a PDU is available, and
    //     writes `output` back to the socket. Upstream provides
    //     `ironrdp_blocking::connect_begin / connect_finalize` and an
    //     async `ironrdp_async` equivalent — the bridge will use the
    //     async one (tokio). (ADR 0051 §Phase connector/MCS)
    //
    //  2. TLS enhanced-security upgrade. After the CR/CC exchange the
    //     connector enters `EnhancedSecurityUpgrade`; the driver must
    //     `should_perform_security_upgrade()` → wrap the TCP stream in
    //     rustls → `mark_security_upgrade_as_done()`. (§Phase fastpath
    //     prereq)
    //
    //  3. CredSSP / NLA. With `enable_credssp = true` the connector
    //     enters `ClientConnectorState::Credssp` and needs the sspi
    //     CredSSP token exchange driven (NTLM/Kerberos/smart-card).
    //     This is the GATING RISK called out in ADR 0051 — the week-1
    //     spike against real AD lives in a SEPARATE harness, not here.
    //     (§CredSSP approach, §Risk)
    //
    //  4. MCS / GCC / channel join / capability + finalization. The
    //     long tail of `BasicSettingsExchange* → ChannelConnection →
    //     SecureSettingsExchange → LicensingExchange →
    //     CapabilitiesExchange → ConnectionFinalization → Connected`.
    //     On `Connected` the connector yields a `ConnectionResult` and
    //     the session enters the active (fastpath) stage. (§Phase MCS)
    //
    //  5. Fastpath + SERVER-SIDE DECODE. ADR 0051 resolves the raw-vs-
    //     decoded frame-model fork in favour of server-side decode
    //     (via `ironrdp_session::ActiveStage` → `DecodedImage`), because
    //     WORM recording requires decoded frames. This spike emits NONE
    //     of that. (§Frame-model decision, §Recording)
    // ────────────────────────────────────────────────────────────────

    Ok((
        output.filled().to_vec(),
        InitiationStepResult {
            bytes_written,
            next_state,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_connector::ClientConnectorState;

    #[test]
    fn config_is_non_nla() {
        let c = spike_config_non_nla();
        assert!(c.enable_tls, "spike config must select legacy TLS");
        assert!(!c.enable_credssp, "spike must NOT request CredSSP/NLA");
    }

    #[test]
    fn live_config_requests_lossless_full_color_bitmaps() {
        // QUALITY (item #2): the NLA config must pin an explicit BitmapConfig
        // that is 32-bit, non-lossy, and advertises NO codecs (so RemoteFX —
        // the lossy default — is never offered, forcing lossless bitmaps).
        let c = live_config_nla("u".to_owned(), "p".to_owned(), None, DEFAULT_DESKTOP_SIZE);
        let bitmap = c
            .bitmap
            .expect("live config must set an explicit BitmapConfig");
        assert_eq!(bitmap.color_depth, 32, "must request 32-bit colour");
        assert!(
            !bitmap.lossy_compression,
            "must NOT enable lossy compression"
        );
        assert!(
            bitmap.codecs.0.is_empty(),
            "must advertise NO codecs (no lossy RemoteFX), got {} codec(s)",
            bitmap.codecs.0.len()
        );
    }

    #[test]
    fn live_config_passes_requested_desktop_size_through() {
        let c = live_config_nla(
            "u".to_owned(),
            "p".to_owned(),
            None,
            DesktopSize {
                width: 1920,
                height: 1080,
            },
        );
        assert_eq!(c.desktop_size.width, 1920);
        assert_eq!(c.desktop_size.height, 1080);
    }

    #[test]
    fn desktop_size_request_clamps_and_falls_back() {
        // Unset (0) on both axes → the legacy default.
        let d = desktop_size_from_request(0, 0);
        assert_eq!(d.width, DEFAULT_DESKTOP_SIZE.width);
        assert_eq!(d.height, DEFAULT_DESKTOP_SIZE.height);

        // A sane in-range request passes through unchanged.
        let d = desktop_size_from_request(1600, 900);
        assert_eq!((d.width, d.height), (1600, 900));

        // Out-of-range values are clamped, not rejected.
        let d = desktop_size_from_request(10, 60000);
        assert_eq!(d.width, MIN_DESKTOP_DIM, "tiny width clamps up");
        assert_eq!(d.height, MAX_DESKTOP_DIM, "huge height clamps down");

        // A partial request (one axis unset) fills the unset axis from the
        // default and keeps/clamps the other.
        let d = desktop_size_from_request(1440, 0);
        assert_eq!(d.width, 1440);
        assert_eq!(d.height, DEFAULT_DESKTOP_SIZE.height);
    }

    #[test]
    fn initiation_step_emits_x224_cr_and_advances() {
        let (bytes, res) =
            drive_connection_initiation().expect("connection-initiation step should succeed");

        // The connector emitted a real PDU.
        assert!(res.bytes_written > 0, "expected non-empty X.224 CR");
        assert_eq!(bytes.len(), res.bytes_written, "buffer/len agree");

        // TPKT header: version 0x03, reserved 0x00, then a 16-bit BE
        // total length covering the whole packet. This asserts the
        // connector produced spec-shaped X.224-over-TPKT bytes
        // (MS-RDPBCGR §2.2.1.1), matching our hand-rolled `x224.rs`
        // framing — proof the real connector and our probe agree on
        // the wire format.
        assert_eq!(bytes[0], 0x03, "TPKT version");
        assert_eq!(bytes[1], 0x00, "TPKT reserved");
        let tpkt_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(tpkt_len, bytes.len(), "TPKT length covers the packet");

        // State machine advanced past the initial send state.
        assert_eq!(
            res.next_state, "ConnectionInitiationWaitResponse",
            "connector should be waiting for the Connection Confirm"
        );
    }

    /// Belt-and-braces: the state name helper distinguishes the two
    /// initiation states, so a future refactor that accidentally
    /// re-runs the send step is caught.
    #[test]
    fn fresh_connector_starts_in_send_state() {
        let client_addr = "127.0.0.1:0".parse().unwrap();
        let connector = ClientConnector::new(spike_config_non_nla(), client_addr);
        assert_eq!(
            <ClientConnector as Sequence>::state(&connector).name(),
            "ConnectionInitiationSendRequest"
        );
        // Reference the state enum so the import is load-bearing and the
        // spike fails to compile if upstream renames the variant.
        let _ = ClientConnectorState::Consumed;
    }
}
