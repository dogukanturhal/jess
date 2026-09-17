// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP + WebSocket handlers.
//!
//! Phase 5f-1: WS auth + grant lookup, stub close-frame.
//! Phase 5f-2c: GET /api/admin/rdp-probe?target= using proxy_core::x224.
//! Phase 5f-8a: WS replaces session_ready_stub with real upstream TCP
//!              + X.224 handshake against the grant's target. Proves
//!              the broker can REACH the upstream RDP service through
//!              the operator's WS session before bridging frames.
//!
//! Phase 5f-8b (deferred): replace handshake-only with full ironrdp_connector
//! flow (MCS + GCC + SecurityExchange) and bridge fastpath I/O between WS
//! and TCP. Needs CredSSP relay for NLA targets — operator credentials
//! arrive via the WS first frame.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use jess_ironrdp_proxy_core::{
    is_allowed_target, probe as x224_probe, Grant, GrantLookupError, NegResponse, ProbeReport,
    RequestedProto, VERSION,
};

use crate::{
    auth::{bearer_from_headers, Claims, VerifyError},
    state::AppState,
};

#[derive(Serialize)]
struct VersionResp {
    version: &'static str,
    component: &'static str,
}

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn readyz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn version() -> impl IntoResponse {
    Json(VersionResp {
        version: VERSION,
        component: "jess-ironrdp-broker",
    })
}

// pub so axum's Handler trait resolution at the route-registration
// site (main.rs::Router::route("/api/me", get(me))) can see the
// concrete return type. Private response types in a pub-fn signature
// fail with `error: type `MeResp` is private`. Earlier builds didn't
// reach this because the sspi/picky compile failure fired first in
// proxy-core.
#[derive(Serialize)]
pub struct MeResp {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
    pub amr: Vec<String>,
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<MeResp>, ApiError> {
    let claims = verify(&state, &headers).await?;
    Ok(Json(MeResp {
        sub: claims.sub,
        email: claims.email,
        roles: claims.roles,
        amr: claims.amr,
    }))
}

// ────────────────────────────────────────────────────────────────────
// Phase 5f-2c — GET /api/admin/rdp-probe?target=HOST:PORT
//
// Broker-side mirror of the Go controller's /rdp-probe endpoint
// (5f-2b). Uses proxy_core::x224::probe under the same RFC1918 SSRF
// guard. The admin SPA's "Test reachability" button can hit EITHER
// the controller OR the broker — useful for verifying broker-side
// network reach independently when debugging WS handshake issues.
// ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ProbeParams {
    target: String,
    /// Comma-separated subset of "tls,credssp,rdp". Default tls,credssp.
    protocols: Option<String>,
    /// Optional X.224 routing cookie (mstshash=user) for load-balancers.
    cookie: Option<String>,
}

pub async fn rdp_probe(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ProbeParams>,
) -> Result<Json<ProbeReport>, ApiError> {
    // Admin role required — broker probe MAY be more permissive than
    // the controller (no role gate would let any operator scan), but
    // we keep parity for principle-of-least-surprise.
    let claims = verify(&state, &headers).await?;
    if !claims.roles.iter().any(|r| r == "platform_admin") {
        return Err(ApiError::Unauthorized("role platform_admin required".into()));
    }
    if let Err(e) = is_allowed_target(&params.target) {
        return Err(ApiError::BadRequest(format!("ssrf guard: {e}")));
    }
    let requested = parse_protocols(params.protocols.as_deref().unwrap_or("tls,credssp"))
        .map_err(ApiError::BadRequest)?;
    let report = x224_probe(
        &params.target,
        requested,
        params.cookie.as_deref(),
        Duration::from_secs(5),
    )
    .await
    .map_err(|e| ApiError::Upstream(e.to_string()))?;
    Ok(Json(report))
}

fn parse_protocols(s: &str) -> Result<u32, String> {
    let mut v: u32 = 0;
    for tok in s.split(',') {
        match tok.trim().to_ascii_lowercase().as_str() {
            "" | "rdp" => {} // requestedProtocols=0
            "tls" => v |= RequestedProto::TLS,
            "credssp" | "nla" => v |= RequestedProto::CRED_SSP,
            "rdstls" => v |= RequestedProto::RDSTLS,
            "credssp-eua" => v |= RequestedProto::CRED_SSP_EARLY_USER_AUTH,
            other => return Err(format!("unknown protocol {other:?}")),
        }
    }
    Ok(v)
}

// ────────────────────────────────────────────────────────────────────
// WS session — Phase 5f-1 + 5f-8a
// ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WsParams {
    target: String,
    #[allow(dead_code)]
    grant: Option<String>,
}

pub async fn ws_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<WsParams>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    let claims = match verify(&state, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let bearer = match state.read_bearer().await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "broker bearer unreadable");
            return ApiError::Bearer.into_response();
        }
    };
    let target = params.target.clone();
    let grant = match state.grants.lookup_active(&claims.sub, &target, &bearer).await {
        Ok(g) => g,
        Err(GrantLookupError::NoGrant { subject, target }) => {
            warn!(%subject, %target, "ironrdp WS rejected — no active grant");
            return ApiError::NoGrant.into_response();
        }
        Err(e) => {
            warn!(error = %e, %target, "ironrdp grant lookup failed");
            return ApiError::Controller(e.to_string()).into_response();
        }
    };
    info!(
        sub = %claims.sub, target = %target, grant = %grant.id, peer = %peer,
        "ironrdp WS accepted"
    );
    ws.on_upgrade(move |socket| handle_socket(socket, claims, grant))
}

async fn handle_socket(mut socket: WebSocket, claims: Claims, grant: Grant) {
    // Phase 5f-8a: real upstream-connect leg. The grant carries the
    // target_id (operator-facing handle); the broker resolves that to
    // an address via the controller-supplied catalog. Today's grant
    // shape doesn't include the resolved address — for the 5f-8a
    // milestone we use grant.target_id assuming it's already a
    // host:port (true for the Phase 5f-2d catalog entries
    // rdp-host-a / rdp-host-b). Phase 5f-8b lifts this to a
    // proper catalog lookup against the controller admin port.
    let upstream_addr = if grant.target_id.contains(':') {
        grant.target_id.clone()
    } else {
        // Default RDP port if the operator passed a bare host.
        format!("{}:3389", grant.target_id)
    };

    // Apply SSRF guard at the broker side too — defence-in-depth on
    // top of the controller's grant gate. A compromised grant with
    // a public-IP target_id is rejected here.
    if let Err(e) = is_allowed_target(&upstream_addr) {
        let _ = socket
            .send(Message::Text(
                serde_json::json!({
                    "type": "error",
                    "stage": "ssrf_guard",
                    "msg": format!("ssrf guard rejected target {upstream_addr}: {e}"),
                })
                .to_string(),
            ))
            .await;
        let _ = socket
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1008, // policy violation
                reason: "ssrf guard".into(),
            })))
            .await;
        return;
    }

    // First WS frame from broker → SPA: handshake-in-progress receipt.
    // Lets the renderer show "connecting to <target>" before the
    // upstream probe completes.
    let connecting = serde_json::json!({
        "type": "upstream_connecting",
        "sub": claims.sub,
        "target_id": grant.target_id,
        "upstream_addr": upstream_addr,
        "grant_id": grant.id,
        "broker_version": VERSION,
    });
    if let Err(e) = socket.send(Message::Text(connecting.to_string())).await {
        warn!(error = %e, "ironrdp WS send_connecting failed");
        return;
    }

    // Run the X.224 + Negotiation handshake. Reuses proxy_core::probe.
    // 5s deadline matches the controller-side endpoint; well above
    // typical sub-second response times for in-cluster RDP services.
    let probe_result = x224_probe(
        &upstream_addr,
        RequestedProto::TLS | RequestedProto::CRED_SSP,
        None,
        Duration::from_secs(5),
    )
    .await;

    let frame = match probe_result {
        Ok(rep) => match &rep.negotiation {
            NegResponse::Ok { selected, .. } => serde_json::json!({
                "type": "upstream_ready",
                "stage": "x224_complete",
                "target_id": grant.target_id,
                "negotiated_protocol_bits": selected,
                "tls_supported": rep.tls_supported,
                "nla_required": rep.nla_required,
                "duration_ms": rep.duration_ms,
                "note": "Phase 5f-8a: handshake complete; fastpath bridge not yet wired (5f-8b)",
            }),
            NegResponse::Failure { code } => serde_json::json!({
                "type": "upstream_nego_failure",
                "stage": "x224_neg_failure",
                "target_id": grant.target_id,
                "failure_code": code,
                "duration_ms": rep.duration_ms,
            }),
            NegResponse::Absent => serde_json::json!({
                "type": "upstream_ready",
                "stage": "x224_legacy",
                "target_id": grant.target_id,
                "note": "legacy RDP server (no negotiation extension)",
                "duration_ms": rep.duration_ms,
            }),
        },
        Err(e) => serde_json::json!({
            "type": "upstream_unreachable",
            "stage": "x224_failed",
            "target_id": grant.target_id,
            "msg": e.to_string(),
        }),
    };
    if let Err(e) = socket.send(Message::Text(frame.to_string())).await {
        warn!(error = %e, "ironrdp WS send_result failed");
    }

    // 5f-8a stops here. 5f-8b will: ironrdp_connector to complete
    // MCS+GCC+SecurityExchange (with CredSSP relay for NLA), then
    // bridge fastpath frames between WS and TCP. Until then, close
    // cleanly so the SPA's test-pattern renderer can show
    // "handshake complete — bridge pending".
    let _ = socket
        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
            code: 1000,
            reason: "phase 5f-8a handshake-only".into(),
        })))
        .await;
}

async fn verify(state: &Arc<AppState>, headers: &HeaderMap) -> Result<Claims, ApiError> {
    let token = bearer_from_headers(headers).map_err(ApiError::from)?;
    state.verifier.verify(token).await.map_err(ApiError::from)
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    BadRequest(String),
    NoGrant,
    Bearer,
    Controller(String),
    Upstream(String),
}

impl From<VerifyError> for ApiError {
    fn from(e: VerifyError) -> Self {
        ApiError::Unauthorized(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": msg}).to_string(),
            ),
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": msg}).to_string(),
            ),
            ApiError::NoGrant => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "no active grant"}).to_string(),
            ),
            ApiError::Bearer => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({"error": "broker bearer unavailable"}).to_string(),
            ),
            ApiError::Controller(msg) => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({"error": format!("controller: {msg}")}).to_string(),
            ),
            ApiError::Upstream(msg) => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({"error": format!("upstream: {msg}")}).to_string(),
            ),
        };
        let mut resp = Response::new(body.into());
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        resp
    }
}
