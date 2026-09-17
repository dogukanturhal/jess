// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

// Phase 7a — Static JSON ConfigMap provider.
//
// Wraps an existing MemoryCatalog (loaded from JESS_TARGETS file on
// startup) as a DiscoveryProvider so the aggregator can merge the
// static set with dynamic providers. The wrapping is zero-cost —
// MemoryCatalog already keeps everything in memory; this is just an
// interface adaptation.
//
// Convention: this provider is named "static" and the aggregator gives
// it precedence over cloud providers but yields to "admin-api" (Phase
// 7f). This means an operator's intentional ConfigMap entry wins
// against a same-id cloud-discovered entry — useful for pinning host
// keys or required_roles that the cloud doesn't model.

import (
	"context"
)

// StaticProvider is a DiscoveryProvider backed by a MemoryCatalog.
// Discover() returns the entire seed set verbatim — the catalog file
// is the source of truth, no refresh needed (operators redeploy the
// ConfigMap to make changes, just like before).
type StaticProvider struct {
	cat *MemoryCatalog
}

// NewStaticProvider wraps the MemoryCatalog as a DiscoveryProvider.
// The aggregator's AddProvider should typically use interval=-1 for
// the static provider — no cron needed; the snapshot is computed once
// at startup and reflected on every Lookup/List. (Pre-7a behavior is
// preserved exactly.)
func NewStaticProvider(cat *MemoryCatalog) *StaticProvider {
	return &StaticProvider{cat: cat}
}

// Name implements DiscoveryProvider.
func (*StaticProvider) Name() string { return "static" }

// Discover implements DiscoveryProvider. Returns a snapshot of every
// target in the underlying MemoryCatalog.
func (s *StaticProvider) Discover(ctx context.Context) ([]Target, error) {
	all, err := s.cat.List(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(all))
	for _, t := range all {
		out = append(out, *t)
	}
	return out, nil
}
