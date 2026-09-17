// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

// Phase 7a — Aggregator: the single catalog.Catalog implementation
// fronted by N DiscoveryProviders, with fail-closed last-known-good
// caching, periodic refresh, and diff-then-audit on every change.
//
// Design (docs/adr/0030-phase-7-dynamic-catalog.md):
//
//   - Each provider gets a refresh goroutine. Per-provider snapshot lives
//     in memory keyed by Target.ID. The aggregator's exposed view is the
//     merge of all per-provider snapshots, with explicit precedence to
//     resolve cross-provider id collisions.
//
//   - Provider error => keep last-known-good snapshot (fail-closed
//     eviction). A successful empty result IS allowed to evict targets
//     (the provider is asserting "nothing here right now"). This matches
//     Teleport's discovery_group safety + Boundary's sync_interval=0
//     semantics — deletion is the highest-risk path.
//
//   - Precedence: providers earlier in the slice win on id collision.
//     Convention: admin-api > static > cloud providers. Collisions are
//     logged + audited; the higher-precedence Target is returned.
//
//   - Refresh cadence: per-provider, defaults to 5min (Teleport's
//     poll_interval baseline). Each provider can opt out of the cron
//     and refresh itself (event-driven providers like the K8s Node
//     watch).
//
//   - WORM audit on every diff: one DiffEvent per add/remove/change
//     into the existing audit.Sink (5e-16 chain). The aggregator
//     fingerprints each Target (excluding LastSeen) so unchanged
//     entries don't emit spurious "changed" events on every refresh.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// ErrTargetNotFound is the canonical Lookup() miss. Distinct from
// generic errors so the controller's deny path can stamp a precise
// audit reason.
var ErrTargetNotFound = errors.New("catalog: target not found")

// ErrTargetRetired is returned by Lookup when a target exists in the
// snapshot but its LastSeen is older than the provider's configured
// RetirementTTL (Phase D — auto-discovery program). Distinct from
// ErrTargetNotFound so audit can attribute the deny to "the source
// stopped listing this target" rather than "it never existed".
var ErrTargetRetired = errors.New("catalog: target retired (source has not re-listed it within retention TTL)")

// DefaultRefreshInterval is the per-provider poll cadence when the
// operator doesn't override. Matches Teleport's discovery_service
// poll_interval default — validated industry baseline (see
// docs/adr/0030-phase-7-dynamic-catalog.md §Industry survey).
const DefaultRefreshInterval = 5 * time.Minute

// providerSnapshot is the aggregator's per-provider cached view.
type providerSnapshot struct {
	mu             sync.RWMutex
	targets        map[string]Target // keyed by Target.ID
	lastRefresh    time.Time
	lastSuccessful time.Time // wall-clock of last error-free Discover
	lastErr        error     // last refresh error (nil on success)
}

// Aggregator implements Catalog. Construct with NewAggregator; add
// providers via AddProvider before Run.
type Aggregator struct {
	mu             sync.RWMutex
	providers      []DiscoveryProvider
	snapshots      map[string]*providerSnapshot   // keyed by provider name
	intervals      map[string]time.Duration       // optional per-provider override
	retirementTTLs map[string]time.Duration       // Phase D — per-provider TTL beyond which targets are retired
	retiredAudited map[string]map[string]struct{} // [provider][targetID]: one-shot dedup so we audit a retirement once
	audit          AuditEmitter
	metrics        MetricsEmitter
	logger         *log.Logger
}

// NewAggregator constructs an empty aggregator. The audit emitter is
// required for production use (every diff produces a row); pass nil in
// tests that don't care.
func NewAggregator(audit AuditEmitter, m MetricsEmitter) *Aggregator {
	return &Aggregator{
		providers:      nil,
		snapshots:      map[string]*providerSnapshot{},
		intervals:      map[string]time.Duration{},
		retirementTTLs: map[string]time.Duration{},
		retiredAudited: map[string]map[string]struct{}{},
		audit:          audit,
		metrics:        m,
	}
}

// SetRetirementTTL opts a provider into the Phase D retirement layer:
// any target whose LastSeen is older than ttl is treated as retired —
// Lookup() returns ErrTargetRetired (sessions deny with a precise audit
// reason) and List() filters the target out. The first time a target
// crosses the threshold, the aggregator emits one `catalog.diff.retired`
// audit event (further checks are no-op until the source re-lists the
// target, which resets LastSeen and re-arms the audit).
//
// ttl=0 (the default) disables retirement for the provider — targets
// persist in the snapshot until their source explicitly removes them.
// Use case for tying retirement to provider type:
//
//   - Poll-based providers (proxmox, ldap): TTL should be a small
//     multiple of PollInterval (e.g. 15min when interval=5min) so a
//     missed poll doesn't drop targets, but a sustained outage does.
//   - Event-driven providers (k8s informers, jess-target-crd): TTL is
//     usually NOT desirable — informers re-list on resync, so a healthy
//     watch keeps LastSeen fresh. Set ttl=0 unless you want defensive
//     auto-retirement on a half-broken informer.
//   - admin-api: never set TTL — operator-added targets are sticky
//     until explicit Delete.
//   - static (ConfigMap): never set TTL — the operator's MR is the
//     source of truth.
func (a *Aggregator) SetRetirementTTL(providerName string, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ttl > 0 {
		a.retirementTTLs[providerName] = ttl
		if _, ok := a.retiredAudited[providerName]; !ok {
			a.retiredAudited[providerName] = map[string]struct{}{}
		}
	} else {
		delete(a.retirementTTLs, providerName)
		delete(a.retiredAudited, providerName)
	}
}

// AddProvider registers a provider. Precedence follows insertion order:
// the first AddProvider'd provider wins on id collision (convention:
// admin-api first, then static, then cloud providers).
//
// Optional refresh interval — pass 0 to use DefaultRefreshInterval.
// Pass -1 (i.e. <0) for "no cron — provider refreshes itself" (e.g. a
// k8s watch handler that calls aggregator.IngestSnapshot directly).
func (a *Aggregator) AddProvider(p DiscoveryProvider, interval time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.providers = append(a.providers, p)
	a.snapshots[p.Name()] = &providerSnapshot{targets: map[string]Target{}}
	if interval > 0 {
		a.intervals[p.Name()] = interval
	} else if interval == 0 {
		a.intervals[p.Name()] = DefaultRefreshInterval
	}
	// interval < 0 → not stored, Run() skips spawning a refresh loop
}

// SetLogger lets the caller wire structured logging. Optional; nil
// uses the default package logger.
func (a *Aggregator) SetLogger(l *log.Logger) { a.logger = l }

// Run blocks until ctx cancels. Spawns one refresh goroutine per
// provider that has a positive interval, plus one initial sync.
// Returns ctx.Err() on shutdown.
func (a *Aggregator) Run(ctx context.Context) error {
	a.mu.RLock()
	providers := append([]DiscoveryProvider(nil), a.providers...)
	a.mu.RUnlock()

	var wg sync.WaitGroup
	for _, p := range providers {
		interval, has := a.intervals[p.Name()]
		// Initial sync — pull once before any timer fires so the
		// catalog isn't empty for the first refresh-interval window.
		a.refreshOne(ctx, p)
		if !has {
			continue // event-driven provider; nothing to schedule
		}
		wg.Add(1)
		go func(p DiscoveryProvider, interval time.Duration) {
			defer wg.Done()
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					a.refreshOne(ctx, p)
				}
			}
		}(p, interval)
	}
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

// IngestSnapshot is the entry point for event-driven providers (e.g.
// the K8s Node watch). Treats the slice as the current authoritative
// view; aggregator computes the diff against the previous snapshot
// and applies it identically to the cron path.
func (a *Aggregator) IngestSnapshot(ctx context.Context, providerName string, targets []Target) {
	snap, ok := a.snapshotFor(providerName)
	if !ok {
		a.warnf("IngestSnapshot for unknown provider %q (forgot AddProvider?)", providerName)
		return
	}
	a.applySnapshot(ctx, providerName, snap, targets)
}

// Lookup implements Catalog. Walks providers in precedence order so
// the first match wins. Phase D — when a match has retired (LastSeen
// older than the provider's RetirementTTL), the first time the check
// fires per target emits one `catalog.diff.retired` audit event;
// subsequent checks return ErrTargetRetired silently.
func (a *Aggregator) Lookup(ctx context.Context, id string) (*Target, error) {
	a.mu.RLock()
	providers := a.providers
	a.mu.RUnlock()
	for _, p := range providers {
		snap, _ := a.snapshotFor(p.Name())
		snap.mu.RLock()
		t, ok := snap.targets[id]
		snap.mu.RUnlock()
		if ok {
			if a.isRetired(p.Name(), t) {
				a.emitRetiredOnce(ctx, p.Name(), t)
				return nil, fmt.Errorf("%w: %s (source=%s, last_seen=%s)", ErrTargetRetired, id, p.Name(), t.LastSeen.Format(time.RFC3339))
			}
			out := t // copy
			return &out, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrTargetNotFound, id)
}

// List implements Catalog. Merges across providers in precedence
// order — the first provider's view of a given id wins. region=""
// returns everything; non-empty filters server-side. Phase D — retired
// targets are silently excluded.
func (a *Aggregator) List(ctx context.Context, region string) ([]*Target, error) {
	a.mu.RLock()
	providers := a.providers
	a.mu.RUnlock()
	seen := map[string]struct{}{}
	var out []*Target
	for _, p := range providers {
		snap, _ := a.snapshotFor(p.Name())
		snap.mu.RLock()
		for id, t := range snap.targets {
			if _, dup := seen[id]; dup {
				continue
			}
			if region != "" && t.Region != "" && t.Region != region {
				continue
			}
			if a.isRetired(p.Name(), t) {
				// First List() observation of a retired target emits the
				// one-shot audit + metric. Subsequent List() calls are
				// silent until the source re-lists.
				a.emitRetiredOnce(ctx, p.Name(), t)
				continue
			}
			seen[id] = struct{}{}
			row := t // copy
			out = append(out, &row)
		}
		snap.mu.RUnlock()
	}
	// Stable ordering for determinism in tests + admin UIs.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// isRetired reports whether t's LastSeen is older than the provider's
// configured RetirementTTL. Returns false if no TTL is configured
// (provider opted out of Phase D).
func (a *Aggregator) isRetired(providerName string, t Target) bool {
	a.mu.RLock()
	ttl, has := a.retirementTTLs[providerName]
	a.mu.RUnlock()
	if !has || ttl <= 0 {
		return false
	}
	if t.LastSeen.IsZero() {
		return false // shouldn't happen post-applySnapshot, but defensive
	}
	return time.Since(t.LastSeen) > ttl
}

// emitRetiredOnce sends a single audit event the first time a target
// crosses its retirement threshold. Dedup is per (provider, target.ID);
// the slot is cleared in applySnapshot when the source re-lists.
func (a *Aggregator) emitRetiredOnce(ctx context.Context, providerName string, t Target) {
	a.mu.Lock()
	audited, ok := a.retiredAudited[providerName]
	if !ok {
		audited = map[string]struct{}{}
		a.retiredAudited[providerName] = audited
	}
	if _, already := audited[t.ID]; already {
		a.mu.Unlock()
		return
	}
	audited[t.ID] = struct{}{}
	a.mu.Unlock()
	a.metricsDiff(providerName, "retired")
	if a.audit != nil {
		row := t // copy
		a.audit.EmitCatalogDiff(ctx, DiffEvent{
			Provider:   providerName,
			ChangeType: "retired",
			TargetID:   t.ID,
			Before:     &row,
			At:         time.Now(),
		})
	}
}

// ProviderStatus is the snapshot of a provider's health for the
// admin API + Prometheus exposure (Phase 7f surface).
type ProviderStatus struct {
	Name             string
	LastRefresh      time.Time
	LastSuccessful   time.Time
	LastErr          string // empty when LastErr is nil
	TargetCount      int
	HealthyForLookup bool
}

// Status returns one entry per provider for admin observability.
func (a *Aggregator) Status() []ProviderStatus {
	a.mu.RLock()
	providers := append([]DiscoveryProvider(nil), a.providers...)
	a.mu.RUnlock()
	out := make([]ProviderStatus, 0, len(providers))
	for _, p := range providers {
		snap, _ := a.snapshotFor(p.Name())
		snap.mu.RLock()
		st := ProviderStatus{
			Name:           p.Name(),
			LastRefresh:    snap.lastRefresh,
			LastSuccessful: snap.lastSuccessful,
			TargetCount:    len(snap.targets),
			// Lookups serve from the last-known-good cache, so a provider with
			// a recent error but a non-empty snapshot is still useful.
			HealthyForLookup: len(snap.targets) > 0,
		}
		if snap.lastErr != nil {
			st.LastErr = snap.lastErr.Error()
		}
		snap.mu.RUnlock()
		out = append(out, st)
	}
	return out
}

// --- internals -------------------------------------------------------

func (a *Aggregator) snapshotFor(name string) (*providerSnapshot, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	snap, ok := a.snapshots[name]
	return snap, ok
}

func (a *Aggregator) refreshOne(ctx context.Context, p DiscoveryProvider) {
	start := time.Now()
	targets, err := p.Discover(ctx)
	duration := time.Since(start)
	snap, _ := a.snapshotFor(p.Name())
	if err != nil {
		// Fail-closed eviction posture: keep last-known-good. Bump
		// metrics + log, then return without diffing.
		snap.mu.Lock()
		snap.lastRefresh = time.Now()
		snap.lastErr = err
		snap.mu.Unlock()
		a.metricsRefresh(p.Name(), duration, false)
		a.metricsError(p.Name(), "discover_failed")
		a.warnf("provider %s: Discover failed: %v (keeping last-known-good %d targets)", p.Name(), err, len(snap.targets))
		return
	}
	a.applySnapshot(ctx, p.Name(), snap, targets)
	a.metricsRefresh(p.Name(), duration, true)
}

// applySnapshot is the diff-and-commit core. Shared between the cron
// refresh and the event-driven IngestSnapshot paths.
func (a *Aggregator) applySnapshot(ctx context.Context, providerName string, snap *providerSnapshot, newTargets []Target) {
	now := time.Now()

	// Stamp source + last-seen on every entry. Providers don't need
	// to set these themselves — the aggregator is the source of truth
	// for provenance.
	next := make(map[string]Target, len(newTargets))
	for _, t := range newTargets {
		t.Source = providerName
		t.LastSeen = now
		next[t.ID] = t
	}

	snap.mu.Lock()
	old := snap.targets
	snap.targets = next
	snap.lastRefresh = now
	snap.lastSuccessful = now
	snap.lastErr = nil
	snap.mu.Unlock()

	// Phase D — clear retirement-audit dedup for any target we just re-listed.
	// If the source removes it again later, it's a brand-new retirement that
	// deserves its own audit event.
	a.mu.Lock()
	if audited, ok := a.retiredAudited[providerName]; ok {
		for id := range next {
			delete(audited, id)
		}
	}
	a.mu.Unlock()

	// Diff outside the snapshot lock — audit.Emit may be slow.
	diffs := diffSnapshots(providerName, old, next, now)
	for _, ev := range diffs {
		a.metricsDiff(providerName, ev.ChangeType)
		if a.audit != nil {
			a.audit.EmitCatalogDiff(ctx, ev)
		}
	}
	a.metricsTargets(providerName, len(next))
}

// diffSnapshots computes the per-target change set. Order is stable
// (ID-sorted) so tests can assert event sequences.
func diffSnapshots(providerName string, old, next map[string]Target, at time.Time) []DiffEvent {
	allIDs := map[string]struct{}{}
	for id := range old {
		allIDs[id] = struct{}{}
	}
	for id := range next {
		allIDs[id] = struct{}{}
	}
	ids := make([]string, 0, len(allIDs))
	for id := range allIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []DiffEvent
	for _, id := range ids {
		oldT, hadOld := old[id]
		newT, hadNew := next[id]
		switch {
		case !hadOld && hadNew:
			row := newT // copy
			out = append(out, DiffEvent{
				Provider: providerName, ChangeType: "added",
				TargetID: id, After: &row, At: at,
			})
		case hadOld && !hadNew:
			row := oldT // copy
			out = append(out, DiffEvent{
				Provider: providerName, ChangeType: "removed",
				TargetID: id, Before: &row, At: at,
			})
		case hadOld && hadNew:
			// LastSeen is updated every refresh; exclude from
			// fingerprint so unchanged entries don't emit noise.
			if targetFingerprint(oldT) == targetFingerprint(newT) {
				continue
			}
			b := oldT
			a := newT
			out = append(out, DiffEvent{
				Provider: providerName, ChangeType: "changed",
				TargetID: id, Before: &b, After: &a, At: at,
			})
		}
	}
	return out
}

// targetFingerprint canonicalises a Target for change detection.
// Excludes LastSeen (always changes on refresh) and Source (set by
// aggregator, identical for both sides of any same-provider diff).
func targetFingerprint(t Target) string {
	t.LastSeen = time.Time{}
	t.Source = ""
	b, _ := json.Marshal(t)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (a *Aggregator) warnf(format string, args ...any) {
	if a.logger != nil {
		a.logger.Printf("aggregator: "+format, args...)
		return
	}
	log.Printf("catalog/aggregator: "+format, args...)
}

func (a *Aggregator) metricsRefresh(provider string, d time.Duration, ok bool) {
	if a.metrics != nil {
		a.metrics.CatalogProviderRefresh(provider, d, ok)
	}
}
func (a *Aggregator) metricsTargets(provider string, n int) {
	if a.metrics != nil {
		a.metrics.CatalogProviderTargets(provider, n)
	}
}
func (a *Aggregator) metricsError(provider, reason string) {
	if a.metrics != nil {
		a.metrics.CatalogProviderError(provider, reason)
	}
}
func (a *Aggregator) metricsDiff(provider, changeType string) {
	if a.metrics != nil {
		a.metrics.CatalogDiff(provider, changeType)
	}
}
