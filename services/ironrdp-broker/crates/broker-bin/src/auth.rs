// SPDX-License-Identifier: AGPL-3.0-or-later

//! Falcon-ID JWT verification.
//!
//! Same JWKS jess-web uses (the Go side hits the OIDC issuer's
//! `/.well-known/jwks.json` directly). We cache the JWKS in memory
//! and refresh every `refresh_interval` — matches the kid-rotation
//! cadence Falcon-ID uses (rotate every 24h, valid for 48h overlap).
//!
//! Two failure modes worth narrating:
//!   * `kid` not in cache → forced refresh + retry once. Covers the
//!     window between Falcon-ID publishing a new kid and our next
//!     scheduled refresh.
//!   * JWKS endpoint unreachable on startup → broker refuses to boot.
//!     A broker without a verifier silently accepts every JWT, which
//!     is the wrong failure mode for an IAP-protected upstream.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Clone, Debug, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub exp: usize,
    pub iss: String,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("missing or invalid Authorization header")]
    MissingBearer,
    #[error("token kid not in JWKS")]
    UnknownKid,
    #[error("token verification failed: {0}")]
    Invalid(String),
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),
}

#[derive(Clone)]
pub struct JwksVerifier {
    inner: Arc<Inner>,
}

struct Inner {
    jwks_url: String,
    issuer: String,
    audience: String,
    refresh_interval: Duration,
    cache: RwLock<JwksCache>,
    http: reqwest::Client,
}

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

impl JwksVerifier {
    pub async fn new(
        jwks_url: String,
        issuer: String,
        audience: String,
        refresh_interval: Duration,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let inner = Arc::new(Inner {
            jwks_url,
            issuer,
            audience,
            refresh_interval,
            cache: RwLock::new(JwksCache {
                keys: HashMap::new(),
                fetched_at: Instant::now() - Duration::from_secs(3600),
            }),
            http,
        });
        // Forced first fetch — fail-closed if JWKS unreachable on boot.
        let v = Self { inner };
        v.refresh().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(v)
    }

    /// Verify a raw Bearer token. Returns the verified `Claims` or a
    /// typed error that handlers can map to (401 Unauthorized, 502
    /// Bad Gateway for JWKS reach failures).
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        let header = decode_header(token).map_err(|e| VerifyError::Invalid(e.to_string()))?;
        let kid = header.kid.ok_or(VerifyError::Invalid("no kid".into()))?;

        // Cache-hit path.
        if let Some(claims) = self.try_decode(&kid, token).await? {
            return Ok(claims);
        }
        // Cache-miss path: forced refresh, retry once.
        debug!(%kid, "kid not in JWKS cache, forcing refresh");
        self.refresh()
            .await
            .map_err(|e| VerifyError::JwksFetch(format!("{e}")))?;
        match self.try_decode(&kid, token).await? {
            Some(claims) => Ok(claims),
            None => Err(VerifyError::UnknownKid),
        }
    }

    async fn try_decode(&self, kid: &str, token: &str) -> Result<Option<Claims>, VerifyError> {
        let cache = self.inner.cache.read().await;
        let Some(key) = cache.keys.get(kid) else {
            return Ok(None);
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.inner.issuer]);
        validation.set_audience(&[&self.inner.audience]);
        let data = decode::<Claims>(token, key, &validation)
            .map_err(|e| VerifyError::Invalid(e.to_string()))?;
        Ok(Some(data.claims))
    }

    async fn refresh(&self) -> Result<(), VerifyError> {
        let resp = self
            .inner
            .http
            .get(&self.inner.jwks_url)
            .send()
            .await
            .map_err(|e| VerifyError::JwksFetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(VerifyError::JwksFetch(format!("status {}", resp.status())));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| VerifyError::JwksFetch(format!("decode: {e}")))?;
        let mut keys = HashMap::with_capacity(set.keys.len());
        for jwk in &set.keys {
            let kid = jwk.common.key_id.clone().unwrap_or_default();
            if kid.is_empty() {
                warn!("jwks key without kid skipped");
                continue;
            }
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    keys.insert(kid, key);
                }
                Err(e) => warn!(error = %e, %kid, "failed to load jwk into DecodingKey"),
            }
        }
        let mut cache = self.inner.cache.write().await;
        info!(count = keys.len(), "JWKS refreshed");
        cache.keys = keys;
        cache.fetched_at = Instant::now();
        Ok(())
    }

    /// Refresh-if-stale helper a background task can call on a timer.
    /// Returns true if a refresh actually happened. Phase 5f-1 doesn't
    /// spawn the timer yet — handlers call refresh on cache-miss which
    /// is enough until production volume warrants the timer.
    pub async fn maybe_refresh(&self) -> Result<bool, VerifyError> {
        let stale = {
            let cache = self.inner.cache.read().await;
            cache.fetched_at.elapsed() > self.inner.refresh_interval
        };
        if stale {
            self.refresh().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Extract a Bearer token from an Axum-style header map. Accepts
/// `Bearer <token>` case-insensitively on the scheme keyword (real
/// browsers and reverse proxies are inconsistent here).
pub fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Result<&str, VerifyError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(VerifyError::MissingBearer)?
        .to_str()
        .map_err(|_| VerifyError::MissingBearer)?;
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token = parts.next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(VerifyError::MissingBearer);
    }
    Ok(token)
}
