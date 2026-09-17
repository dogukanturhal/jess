// SPDX-License-Identifier: AGPL-3.0-or-later

//! jess-ironrdp-broker — Axum HTTP/WebSocket server.
//!
//! Phase 5f-1 (this file) wires:
//!   * /healthz, /readyz, /version            — k8s liveness/readiness
//!   * /api/me                                — same shape as jess-web
//!   * /ws/session?target=...&grant=...       — WS upgrade, auth-gated
//!   * Falcon-ID JWT verify via JWKS (rotating cache)
//!   * Grant lookup against jess-controller admin port (proxy-core)
//!
//! Phase 5f-2 will add: RDP framing through `ironrdp_connector`,
//! browser-side canvas messages (mouse/keyboard/clipboard), WORM
//! recording (`ironrdp-replay` format → MinIO same bucket as asciicast).
//!
//! Process model: single Axum process per pod; tokio multi-thread
//! runtime; one task per connected operator. Backpressure via the
//! channel between the WS read half and the RDP write half — bound
//! at 256 frames so a slow upstream can't OOM the broker.

mod auth;
mod handlers;
mod state;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    routing::{any, get},
    Router,
};
use tokio::net::TcpListener;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{info, warn};
use tracing_subscriber::{prelude::*, EnvFilter};

use jess_ironrdp_proxy_core::{GrantClient, VERSION};

use crate::{auth::JwksVerifier, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env().context("config")?;
    info!(
        version = VERSION,
        addr = %cfg.listen_addr,
        jwks = %cfg.jwks_url,
        controller = %cfg.controller_admin_url,
        "jess-ironrdp-broker starting"
    );

    let verifier = JwksVerifier::new(
        cfg.jwks_url.clone(),
        cfg.issuer.clone(),
        cfg.audience.clone(),
        Duration::from_secs(cfg.jwks_refresh_secs),
    )
    .await
    .context("jwks verifier init")?;

    let grants = GrantClient::new(cfg.controller_admin_url.clone(), Duration::from_secs(5))
        .context("grant client init")?;

    let state = Arc::new(AppState {
        verifier,
        grants,
        broker_bearer_path: cfg.broker_bearer_path.clone(),
    });

    let app = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .route("/version", get(handlers::version))
        .route("/api/me", get(handlers::me))
        // Phase 5f-2c — broker-side mirror of controller /rdp-probe
        .route("/api/admin/rdp-probe", get(handlers::rdp_probe))
        .route("/ws/session", any(handlers::ws_session))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state);

    let listener = TcpListener::bind(&cfg.listen_addr)
        .await
        .with_context(|| format!("bind {}", cfg.listen_addr))?;
    info!(addr = %cfg.listen_addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("axum serve")?;

    info!("jess-ironrdp-broker stopped");
    Ok(())
}

fn init_tracing() {
    // Default to info, allow override via RUST_LOG. JSON format in prod;
    // keep humanised fallback for `cargo run` ergonomics.
    let json = std::env::var("LOG_FORMAT").as_deref() == Ok("json");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    }
}

async fn shutdown_signal() {
    // SIGINT (Ctrl-C) for local dev; SIGTERM for k8s rolling restart.
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "ctrl_c listener failed");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => warn!(error = %e, "SIGTERM listener init failed"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => info!("ctrl-c received, shutting down"),
        _ = terminate => info!("SIGTERM received, shutting down"),
    }
}

struct Config {
    listen_addr: SocketAddr,
    jwks_url: String,
    issuer: String,
    audience: String,
    jwks_refresh_secs: u64,
    controller_admin_url: String,
    /// File path to the broker's own Falcon-ID JWT (sidecar-rotated).
    /// Read on each outbound controller call so rotation is picked up
    /// without a process restart — same pattern jess-web uses for the
    /// svc-cert path.
    broker_bearer_path: String,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            listen_addr: env_or("JESS_IRONRDP_LISTEN", "0.0.0.0:7102").parse()?,
            jwks_url: env_required("JESS_IRONRDP_JWKS_URL")?,
            issuer: env_required("JESS_IRONRDP_OIDC_ISSUER")?,
            audience: env_required("JESS_IRONRDP_OIDC_AUDIENCE")?,
            jwks_refresh_secs: env_or("JESS_IRONRDP_JWKS_REFRESH_SECS", "300").parse()?,
            controller_admin_url: env_required("JESS_IRONRDP_CONTROLLER_ADMIN_URL")?,
            broker_bearer_path: env_or(
                "JESS_IRONRDP_BEARER_PATH",
                "/var/run/secrets/jess/bearer.jwt",
            ),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_required(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("env {} must be set", key))
}
