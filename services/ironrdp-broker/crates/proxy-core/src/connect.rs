// SPDX-License-Identifier: AGPL-3.0-or-later

//! LIVE CredSSP/NLA RDP connection driver — ADR 0051, the gating-risk
//! spike (`feat/rdp-credssp-live`).
//!
//! ## What this is
//!
//! The first place in the broker that drives the IronRDP connector state
//! machine **all the way to `Connected` against a real Windows host** —
//! TLS enhanced-security upgrade + the full CredSSP/NLA token exchange —
//! rather than the encode-only first step of [`crate::spike`].
//!
//! It is the async counterpart of upstream IronRDP's `screenshot.rs`
//! example: where that example uses the *blocking* helpers
//! (`ironrdp_blocking::{connect_begin, mark_as_upgraded,
//! connect_finalize}`), this uses the **official async helpers**
//! (`ironrdp_async::{connect_begin, mark_as_upgraded, connect_finalize}`,
//! re-exported through `ironrdp_tokio`) over a tokio `TcpStream` wrapped
//! in `ironrdp_tokio::TokioFramed`, with `tokio_rustls` for the async TLS
//! upgrade. The async path is the one the real broker needs (it lives in
//! an axum/tokio process and bridges a WebSocket), so the spike is built
//! on the transport the production bridge will reuse — not a throwaway
//! blocking dial.
//!
//! ## Gated OFF by default
//!
//! Compiled only under the `ironrdp_live` cargo feature (see
//! `Cargo.toml`). The default `cargo build` / CI surface is unchanged.
//! Build/run the whole workspace, not `-p jess-ironrdp-proxy-core` (the
//! same feature-unification quirk noted in `spike.rs`):
//!
//! ```text
//! cargo build --features jess-ironrdp-proxy-core/ironrdp_live
//! cargo run -p jess-ironrdp-proxy-core --features jess-ironrdp-proxy-core/ironrdp_live --bin credssp_live
//! cargo test --features jess-ironrdp-proxy-core/ironrdp_live -- --ignored live_credssp_handshake
//! ```
//!
//! ## TLS trust — SPIKE ONLY
//!
//! The DC presents a self-signed RDP cert, so this uses a rustls
//! "accept-any-cert" verifier ([`danger`]). CredSSP does NOT rely on
//! TLS chain trust for its security — it channel-binds to the server's
//! TLS public key (lifted from the presented leaf cert) and the NTLM/
//! Kerberos exchange authenticates the peer. But a passive MITM that
//! could terminate TLS would still be a downgrade risk, so PRODUCTION
//! MUST pin/verify the DC cert (jess already runs a device-cert CA — the
//! broker can pin the DC's SPKI or issue from an internal CA). Tracked
//! in ADR 0047 (RDP TLS CA scope note).

use std::net::SocketAddr;
use std::sync::Arc;

use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    ClientConnector, ConnectionResult, ConnectorResult, Sequence as _, ServerName,
};
use ironrdp_tokio::{NetworkClient, TokioFramed};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tracing::{debug, info, warn};

/// The live, post-CredSSP, TLS-upgraded framed RDP stream the active
/// session reads/writes over.
///
/// This is the exact type `connect_to_connected` hands back alongside the
/// [`ConnectionResult`]: an `ironrdp_tokio::TokioFramed` over the
/// `tokio_rustls` client TLS stream that wraps the original TCP socket.
/// `ironrdp_session::ActiveStage` drives the session by `read_pdu`-ing
/// from it and `write_all`-ing response frames back — see
/// [`crate::active::capture_desktop`].
pub type LiveFramed = TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>;

/// `NetworkClient` for the CredSSP generator.
///
/// IronRDP's `connect_finalize` only calls `NetworkClient::send` when the
/// CredSSP generator suspends on an **out-of-band KDC round-trip** — i.e.
/// Kerberos. Our live target is reached **by IP with no SPN**, which
/// forces **NTLM**; NTLM is computed entirely in-process by sspi and
/// never suspends the generator, so `send` is never hit on this path.
///
/// If it ever IS hit (a future Kerberos-by-hostname target), failing
/// loudly is the honest behaviour for the spike — wiring a real async KDC
/// client (sspi's `ReqwestNetworkClient` is blocking; the async bridge
/// would need an async resolver) is out of scope here. Production
/// Kerberos brokering will replace this.
struct NtlmOnlyNetworkClient;

impl NetworkClient for NtlmOnlyNetworkClient {
    async fn send(&mut self, request: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        warn!(
            url = %request.url,
            "CredSSP generator suspended on a KDC network request — this path \
             is NTLM-only (IP target); Kerberos KDC brokering is not wired in \
             the spike"
        );
        Err(ironrdp_connector::general_err!(
            "CredSSP requested a KDC round-trip but the spike is NTLM-only \
             (connect by IP forces NTLM; provide an SPN/hostname + async KDC \
             client for Kerberos)"
        ))
    }
}

/// Everything the driver needs to reach a session, minus the password
/// (kept in a `zeroize::Zeroizing` buffer owned by the caller and only
/// borrowed for the connector `Config`).
pub struct LiveConnectParams<'a> {
    /// `host:port`, e.g. `10.0.20.10:3389`.
    pub target: &'a str,
    /// Sign-in user (sAMAccountName), e.g. `jess-rdptest`.
    pub username: &'a str,
    /// NetBIOS domain, e.g. `HEXXLOCK`. `None` for a local account.
    pub domain: Option<&'a str>,
    /// Password — borrowed; the driver clones it once into the connector
    /// `Config` and never logs it.
    pub password: &'a str,
    /// Desktop resolution to REQUEST from the server (item #3 — resolution
    /// match). Use [`crate::spike::DEFAULT_DESKTOP_SIZE`] for the legacy
    /// fixed 1280×1024, or [`crate::spike::desktop_size_from_request`] to
    /// build a clamped size from a browser-supplied width/height.
    pub desktop_size: ironrdp_connector::DesktopSize,
    /// Negotiate the CLIPRDR (clipboard) static virtual channel (ADR 0054,
    /// Tier-3 virtual-channel work). When `true`, the connector advertises
    /// CLIPRDR and [`connect_to_connected`] returns a
    /// [`crate::clipboard::ClipboardChannel`] handle the session loop drives
    /// for bidirectional TEXT sync. When `false` (the legacy default), CLIPRDR
    /// is never advertised and the channel handle is `None` — the desktop runs
    /// graphics + input only, byte-for-byte as before this work.
    pub enable_clipboard: bool,
    /// Negotiate the MS-RDPEGFX graphics pipeline with AVC420 (H.264) — the
    /// Tier-2 "native-feel" path (ADR 0053). When `true`, the connector
    /// registers a DRDYNVC channel hosting the in-tree [`crate::egfx::EgfxClient`]
    /// (AVC420-only caps) and [`connect_to_connected`] returns an
    /// [`crate::egfx::EgfxChannel`] the session loop drains into
    /// `ServerMsg::H264`. When `false` (the legacy default), EGFX is never
    /// advertised and the server uses the bitmap path (WebP/PNG).
    ///
    /// MUST be left `false` for **recorded** sessions: an H.264 frame produces
    /// no RGBA bitmap, so the WORM recorder (PNG track) would capture nothing.
    /// The caller is responsible for that gate (see the `session_live` bin).
    pub enable_h264: bool,
}

/// Result of a successful drive-to-`Connected`.
#[derive(Debug)]
pub struct LiveConnectOutcome {
    /// The negotiated security protocol bitset the server selected in the
    /// X.224 Connection Confirm (8 = PROTOCOL_HYBRID_EX on our DC).
    pub selected_protocol: u32,
    /// Negotiated desktop width (px) after capability exchange.
    pub desktop_width: u16,
    /// Negotiated desktop height (px) after capability exchange.
    pub desktop_height: u16,
    /// MCS I/O channel id from the finalized connection.
    pub io_channel_id: u16,
    /// MCS user channel id from the finalized connection.
    pub user_channel_id: u16,
}

/// Drive a real `ClientConnector` from a cold TCP socket all the way to
/// `ClientConnectorState::Connected` against a live RDP host, performing
/// the TLS enhanced-security upgrade and the **CredSSP/NLA** token
/// exchange in between.
///
/// Returns the finalized [`ConnectionResult`] (which carries the MCS
/// channel set the active session needs), a [`LiveConnectOutcome`]
/// summary for logging, AND the live upgraded [`LiveFramed`] stream. This
/// is the reusable seam: the caller hands the `ConnectionResult` + the
/// `LiveFramed` to `ironrdp_session::ActiveStage` for the live session
/// (server-side decode → PNG / WORM recording). P2 (`crate::active`)
/// consumes exactly this tuple; the `credssp_live` spike bin just logs
/// the outcome and drops the stream.
///
/// The flow mirrors `ironrdp` `examples/screenshot.rs` exactly, async-
/// ported:
/// 1. `connect_begin` drives X.224 CR/CC (`ConnectionInitiation*`) and
///    parks at `EnhancedSecurityUpgrade`, returning a `ShouldUpgrade`.
/// 2. We rip the raw TCP stream out, async-TLS-upgrade it, and lift the
///    server's TLS public key from the presented leaf cert.
/// 3. `mark_as_upgraded` advances the connector past the upgrade.
/// 4. `connect_finalize` drives `Credssp{..}` (the gating sub-sequence),
///    the HYBRID_EX Early User Authorization Result PDU, then MCS / GCC /
///    channel-join / licensing / capabilities / finalization →
///    `Connected`, yielding the `ConnectionResult`.
pub async fn connect_to_connected(
    params: LiveConnectParams<'_>,
) -> anyhow::Result<(
    ConnectionResult,
    LiveConnectOutcome,
    LiveFramed,
    Option<crate::clipboard::ClipboardChannel>,
    Option<crate::egfx::EgfxChannel>,
)> {
    use anyhow::Context as _;

    let config = crate::spike::live_config_nla(
        params.username.to_owned(),
        params.password.to_owned(),
        params.domain.map(str::to_owned),
        params.desktop_size,
    );

    info!(
        target = params.target,
        username = params.username,
        domain = params.domain.unwrap_or("<none>"),
        clipboard = params.enable_clipboard,
        h264 = params.enable_h264,
        "RDP/CredSSP live connect: dialing"
    );

    // --- TCP ---------------------------------------------------------
    let tcp = TcpStream::connect(params.target)
        .await
        .with_context(|| format!("TCP connect to {}", params.target))?;
    let client_addr: SocketAddr = tcp.local_addr().context("local_addr")?;
    debug!(%client_addr, "TCP connected");

    let mut framed = TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config, client_addr);

    // CLIPRDR static virtual channel (ADR 0054). Register the cliprdr SVC
    // processor on the connector BEFORE the handshake so it's advertised in the
    // GCC client channel list + joined during channel-connection. The matching
    // ClipboardChannel handle is returned to the caller (the session loop) to
    // drive bidirectional TEXT. Skipped entirely when disabled — the connector
    // then never advertises CLIPRDR.
    let clipboard_channel = if params.enable_clipboard {
        let (backend, channel) = crate::clipboard::ChannelBackend::create();
        connector = connector.with_static_channel(ironrdp::cliprdr::CliprdrClient::new(backend));
        info!("RDP clipboard: CLIPRDR channel registered (bidirectional TEXT)");
        Some(channel)
    } else {
        None
    };

    // MS-RDPEGFX graphics pipeline (ADR 0053). Register a DRDYNVC static
    // channel hosting the in-tree AVC420 EGFX processor BEFORE the handshake so
    // DRDYNVC is advertised + the dynamic channel opens during the session. The
    // EgfxChannel handle is returned to the session loop, which drains decoded
    // H.264 NAL units into `ServerMsg::H264`. Skipped entirely when disabled —
    // the connector then never advertises DRDYNVC/EGFX and graphics arrive as
    // bitmaps (the WebP/PNG path). The caller keeps this OFF when recording.
    let egfx_channel = if params.enable_h264 {
        let (egfx, channel) = crate::egfx::EgfxClient::create();
        let drdynvc = ironrdp::dvc::DrdynvcClient::new().with_dynamic_channel(egfx);
        connector = connector.with_static_channel(drdynvc);
        info!("RDP graphics: MS-RDPEGFX/AVC420 channel registered (Tier-2 H.264)");
        Some(channel)
    } else {
        None
    };
    debug!(state = connector.state().name(), "connector constructed");

    // --- Phase 1: X.224 CR/CC up to the TLS-upgrade boundary ----------
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .context("connect_begin (X.224 connection initiation)")?;
    info!(
        state = connector.state().name(),
        "connect_begin done — parked at security upgrade"
    );

    // --- Phase 2: TLS enhanced-security upgrade -----------------------
    // ServerName strips any :port and is what CredSSP binds the SPN/
    // channel-binding name to. The DC is reached by IP → NTLM.
    let server_name = ServerName::new(params.target);
    let initial_stream = framed.into_inner_no_leftover();
    let (tls_stream, server_public_key) = tls_upgrade(initial_stream, server_name.as_str())
        .await
        .context("TLS enhanced-security upgrade")?;
    info!(
        server_public_key_len = server_public_key.len(),
        "TLS upgrade done — lifted server SPKI for CredSSP channel binding"
    );

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = TokioFramed::new(tls_stream);
    debug!(state = connector.state().name(), "marked upgraded");

    // --- Phase 3: CredSSP + MCS/GCC/licensing/caps → Connected --------
    // network_client satisfies the NetworkClient bound connect_finalize
    // requires; for an IP target CredSSP runs NTLM in-process (no KDC),
    // so `send` is never called — see NtlmOnlyNetworkClient.
    let mut network_client = NtlmOnlyNetworkClient;
    info!("driving connect_finalize (CredSSP token exchange + MCS/caps)…");
    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        server_name,
        server_public_key,
        None, // KerberosConfig — None ⇒ NTLM (IP target, no SPN/KDC).
    )
    .await
    .context("connect_finalize (CredSSP / MCS / capabilities)")?;

    let outcome = LiveConnectOutcome {
        selected_protocol: 0, // filled by caller from the probe if needed
        desktop_width: connection_result.desktop_size.width,
        desktop_height: connection_result.desktop_size.height,
        io_channel_id: connection_result.io_channel_id,
        user_channel_id: connection_result.user_channel_id,
    };

    info!(
        desktop = format!("{}x{}", outcome.desktop_width, outcome.desktop_height),
        io_channel_id = outcome.io_channel_id,
        user_channel_id = outcome.user_channel_id,
        "RDP/CredSSP live connect: reached Connected — session is LIVE"
    );

    // Hand back the still-live upgraded TLS framed stream so the caller
    // can drive `ActiveStage` over it (no re-handshake; the connector
    // left it positioned exactly after the connection-finalization PDUs),
    // plus the optional clipboard channel handle (Some iff CLIPRDR was
    // negotiated) for the session loop to drive.
    Ok((
        connection_result,
        outcome,
        upgraded_framed,
        clipboard_channel,
        egfx_channel,
    ))
}

/// Async TLS enhanced-security upgrade over the already-X.224-negotiated
/// TCP stream. Returns the TLS stream + the server's
/// SubjectPublicKeyInfo bytes (CredSSP channel-binding material).
///
/// SPIKE: accepts ANY server cert (the DC self-signs). See the module
/// doc — production MUST pin/verify.
async fn tls_upgrade(
    stream: TcpStream,
    server_name: &str,
) -> anyhow::Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>)> {
    use anyhow::Context as _;

    // Both `ring` and `aws-lc-rs` are in the dep tree (sspi defaults to
    // aws-lc-rs). Install a process-default provider explicitly so
    // `ClientConfig::builder()` can't panic on an ambiguous default;
    // idempotent + ignore the "already set" error.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();
    // CredSSP needs the raw cert; TLS resumption can skip presenting it.
    config.resumption = rustls::client::Resumption::disabled();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    // rustls wants a DNS-ish ServerName; an IP literal is fine for SNI
    // here since we don't verify the name. Fall back to a placeholder if
    // it somehow won't parse (verifier ignores it anyway).
    let dns_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("rdp").unwrap());

    let tls_stream = connector
        .connect(dns_name, stream)
        .await
        .context("rustls async handshake")?;

    // Lift the server leaf certificate's SubjectPublicKeyInfo bit-string.
    let server_public_key = {
        let (_io, conn) = tls_stream.get_ref();
        let cert = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .context("server presented no TLS certificate")?;
        extract_tls_server_public_key(cert).context("extract server SPKI")?
    };

    Ok((tls_stream, server_public_key))
}

/// Parse the leaf cert DER and return the SubjectPublicKeyInfo public-key
/// BIT STRING bytes — the value CredSSP channel-binds to. Verbatim port
/// of the upstream `screenshot.rs` helper.
fn extract_tls_server_public_key(cert: &[u8]) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context as _;
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert).context("parse leaf cert DER")?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not byte-aligned")?
        .to_owned();
    Ok(spki)
}

/// rustls "accept any certificate" verifier — SPIKE ONLY. Verbatim port
/// of the upstream `screenshot.rs` `danger` module. See module doc for
/// the production-trust requirement.
mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::{pki_types, DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &pki_types::CertificateDer<'_>,
            _intermediates: &[pki_types::CertificateDer<'_>],
            _server_name: &pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}
