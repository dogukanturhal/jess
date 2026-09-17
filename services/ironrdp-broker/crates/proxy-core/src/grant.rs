// SPDX-License-Identifier: AGPL-3.0-or-later

//! Grant-lookup client for the jess-controller admin port.
//!
//! Wire shape mirrors what jess-web's grants client does today:
//! `GET /grants?subject={sub}&target={target_id}` returns a JSON array
//! of grant rows; we filter for an unexpired one and use its `id` as
//! the session anchor the controller will then bind to a `jit_session`
//! row.
//!
//! Auth: outbound JWT minted via the broker's SA token + Falcon-ID
//! self-issued service-token endpoint, exactly the same handshake
//! jess-web does. The token plumbing lives in `broker-bin/src/auth.rs`
//! — this crate just consumes a Bearer string.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{debug, warn};

/// One row in the controller's grants table — fields kept narrow to
/// what the broker actually checks. Extra fields the controller may
/// add later are ignored by serde without breaking the deserialise.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Grant {
    /// Stable grant id; becomes the asciicast/RDP recording prefix.
    pub id: String,
    /// Operator subject (must match the WS caller's verified JWT `sub`).
    pub subject: String,
    /// Target host id (e.g. `win-bastion-01`).
    pub target_id: String,
    /// RFC3339 expiry — broker rejects when this is in the past.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl Grant {
    /// True when the grant is still inside its TTL.
    pub fn is_active(&self) -> bool {
        self.expires_at > OffsetDateTime::now_utc()
    }
}

/// Errors the broker surfaces back to the WebSocket client. All
/// variants map cleanly to a close-frame `(code, reason)` pair so
/// the operator's browser sees a useful message instead of a generic
/// "1000".
#[derive(Debug, Error)]
pub enum GrantLookupError {
    /// Controller admin port unreachable / TLS failure.
    #[error("controller admin port unreachable: {0}")]
    Transport(String),
    /// Controller returned non-2xx; status + body propagated for logs.
    #[error("controller responded {status}: {body}")]
    Upstream {
        /// HTTP status from the controller.
        status: u16,
        /// First 256 bytes of body for diagnosis.
        body: String,
    },
    /// No unexpired grant matching subject + target.
    #[error("no active grant for subject={subject} target={target}")]
    NoGrant {
        /// Subject the lookup ran for.
        subject: String,
        /// Target id the lookup ran for.
        target: String,
    },
}

/// Thin HTTP client against the controller admin port.
///
/// Construct once at process start (Arc-clone into every request
/// handler). The inner `reqwest::Client` pools TLS connections by
/// default which is what we want — admin-port latency under high
/// concurrent open is dominated by handshake.
#[derive(Clone, Debug)]
pub struct GrantClient {
    http: Client,
    base_url: String,
}

impl GrantClient {
    /// Build a client pointing at `<base_url>/grants?...`. base_url
    /// MUST include the scheme (`https://jess-controller-admin:443`)
    /// and MUST NOT end with `/grants` — the path is appended here so
    /// the same client can grow more endpoints (sessions, requests)
    /// without ambiguity.
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> anyhow::Result<Self> {
        let http = Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(8)
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    /// Returns the first active grant matching (`subject`, `target`),
    /// or `NoGrant` if none exists. `bearer` is the broker's outbound
    /// JWT — the controller authorises this call exactly like
    /// jess-web's admin lookups.
    pub async fn lookup_active(
        &self,
        subject: &str,
        target: &str,
        bearer: &str,
    ) -> Result<Grant, GrantLookupError> {
        let url = format!(
            "{}/grants?subject={}&target={}",
            self.base_url,
            urlencoding::encode(subject),
            urlencoding::encode(target)
        );
        debug!(%subject, %target, "ironrdp grant lookup");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|e| GrantLookupError::Transport(e.to_string()))?;
        let status = resp.status();
        if status == StatusCode::OK {
            let grants: Vec<Grant> = resp
                .json()
                .await
                .map_err(|e| GrantLookupError::Transport(format!("decode: {e}")))?;
            match grants.into_iter().find(|g| g.is_active()) {
                Some(g) => Ok(g),
                None => Err(GrantLookupError::NoGrant {
                    subject: subject.to_owned(),
                    target: target.to_owned(),
                }),
            }
        } else {
            let body = resp.text().await.unwrap_or_default();
            let trimmed = body.chars().take(256).collect::<String>();
            warn!(%status, %trimmed, "ironrdp grant lookup non-2xx");
            Err(GrantLookupError::Upstream {
                status: status.as_u16(),
                body: trimmed,
            })
        }
    }
}

// Tiny URL-encoder vendored to avoid pulling the full `url` crate just
// for query-string escaping. Only handles the four characters that
// actually appear in subject/target ids in jess (`:` `@` `+` ` `).
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }
}
