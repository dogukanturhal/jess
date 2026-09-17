// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-wide state Arc'd into every Axum handler. Holds the JWKS
//! verifier, the controller grant client, and the path to the broker's
//! own outbound bearer (sidecar-rotated).

use jess_ironrdp_proxy_core::GrantClient;

use crate::auth::JwksVerifier;

/// Shared across all handlers. Cheap to clone — `JwksVerifier` and
/// `GrantClient` both hold `Arc`s internally.
pub struct AppState {
    /// Falcon-ID JWT verifier (rotating JWKS cache).
    pub verifier: JwksVerifier,
    /// HTTP client against the jess-controller admin port.
    pub grants: GrantClient,
    /// Filesystem path to the broker's own bearer JWT — read fresh on
    /// each outbound call to pick up sidecar rotation without restart.
    pub broker_bearer_path: String,
}

impl AppState {
    /// Read the current bearer from disk. Errors propagate as a 502 to
    /// the browser — by the time we're calling this, the WS handshake
    /// already accepted, so we close the socket with a useful reason.
    pub async fn read_bearer(&self) -> std::io::Result<String> {
        let bytes = tokio::fs::read(&self.broker_bearer_path).await?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_string())
    }
}
