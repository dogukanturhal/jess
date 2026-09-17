// SPDX-License-Identifier: AGPL-3.0-or-later

//! Target identity + transport descriptor for the RDP upstream.
//!
//! Phase 5f-1 SCOPE: just the type. Phase 5f-2 will add the controller
//! lookup that resolves a `target_id` (operator-friendly handle) to a
//! `(host, port, security)` tuple — same lookup the SSH bridge does,
//! mirroring `internal/spine/target.go` on the Go side.

use serde::{Deserialize, Serialize};

/// Discriminator for which kind of broker handles this target. The
/// broker rejects any target whose `kind` isn't `rdp` early in the WS
/// handshake — keeps SSH targets from being accidentally routed here
/// when the SPA URL gets typo'd.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    /// Microsoft RDP — this broker's only supported kind.
    Rdp,
    /// SSH — handled by jess-web's bridge, not here. Listed so a
    /// JSON mismatch surfaces as a typed error not a "unknown variant".
    Ssh,
    /// Database brokers (Postgres / MySQL / Redis) — same reason.
    Db,
}

/// A resolved RDP target — what the controller hands back when the
/// broker asks "where is `win-bastion-01`?".
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Target {
    /// Operator-facing id (`win-bastion-01`).
    pub id: String,
    /// Broker kind — MUST be `Rdp` for this binary.
    pub kind: TargetKind,
    /// Resolved upstream host (IP or DNS name, NOT the operator-facing id).
    pub host: String,
    /// RDP TCP port (3389 default, but explicit in case targets re-map).
    pub port: u16,
    /// Whether to enforce NLA on the connector. Defaults to true at the
    /// controller — only flipped off for targets that can't speak it
    /// (very old XP-era machines), and even then the controller
    /// requires an operator note explaining why.
    pub require_nla: bool,
}
