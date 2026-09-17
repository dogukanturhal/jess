// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

// Phase 7a — Dynamic catalog substrate.
//
// DiscoveryProvider is the additive seam: every source of targets
// (static JSON ConfigMap, Kubernetes Node watch, Proxmox API,
// AWS/Azure cloud APIs, GitOps JessTarget CRDs, ad-hoc admin REST)
// implements this single interface. The Aggregator below merges
// them into a single catalog.Catalog the rest of jess consumes
// unchanged.
//
// Design rationale + the 3-pattern industry survey that drove it:
// docs/adr/0030-phase-7-dynamic-catalog.md.

import (
	"context"
	"time"
)

// DiscoveryProvider surfaces targets from a single upstream source.
//
//   - Discover MUST be context-aware. A long-running discovery (e.g. a
//     k8s Node watch primed at startup) should still return promptly
//     from each call — providers cache internally; Discover returns
//     the current snapshot.
//   - A nil error with an empty slice is a VALID result ("nothing here
//     now") and the aggregator WILL evict targets previously known to
//     this provider. Providers that can't be certain should return a
//     non-nil error instead.
//   - A non-nil error means the provider is degraded; aggregator keeps
//     the last-known-good snapshot (fail-closed eviction).
//   - Discover MUST be safe to call concurrently with itself. The
//     aggregator serialises calls per provider but the contract is
//     defensive.
type DiscoveryProvider interface {
	// Name returns a stable provider identifier used as Target.Source,
	// the audit attribution field, and the metric label. Conventional
	// names: "static", "k8s-nodes", "proxmox", "aws-ec2", "azure-vm",
	// "jess-target-crd", "admin-api". Keep them DNS-label-safe so
	// Prometheus label hygiene holds.
	Name() string

	// Discover returns the current set of targets visible to this
	// provider. The aggregator stamps Target.Source = Name() and
	// Target.LastSeen = time.Now() on every returned target before
	// caching, so providers don't need to set those themselves.
	Discover(ctx context.Context) ([]Target, error)
}

// DiffEvent is one entry in the diff produced when the aggregator
// reconciles a provider's old snapshot against a new one. Audit
// emitters and metric collectors consume these.
type DiffEvent struct {
	Provider   string    // provider name
	ChangeType string    // "added" | "removed" | "changed"
	TargetID   string    // canonical id (must be unique across providers — collisions logged separately)
	Before     *Target   // nil on "added"
	After      *Target   // nil on "removed"
	At         time.Time // when the diff was observed (== aggregator refresh tick)
}

// AuditEmitter is the narrow interface the aggregator uses to emit
// per-target diff events. internal/audit.Sink satisfies this with a
// thin adapter; tests can mock it.
type AuditEmitter interface {
	EmitCatalogDiff(ctx context.Context, ev DiffEvent)
}

// MetricsEmitter is optional. Implemented by *metrics.Metrics in
// production; nil-safe (the aggregator no-ops when nil).
type MetricsEmitter interface {
	CatalogProviderRefresh(provider string, duration time.Duration, ok bool)
	CatalogProviderTargets(provider string, count int)
	CatalogProviderError(provider string, reason string)
	CatalogDiff(provider, changeType string)
}
