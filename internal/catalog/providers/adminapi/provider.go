// SPDX-License-Identifier: AGPL-3.0-or-later

// Package adminapi is the Phase 7f discovery provider for ad-hoc
// operator-added targets.
//
// Background: 7c (Kubernetes Node watch) and 7b (Proxmox API) cover
// the steady-state fleet. But operators occasionally need to surface
// a target IMMEDIATELY — during an incident, for an unattested
// one-off VM, when a discovery upstream is degraded — without waiting
// for a ConfigMap MR + Argo sync cycle.
//
// AdminProvider is the break-glass + sandbox surface:
//
//   - HTTP routes on the controller admin port (POST/GET/PATCH/DELETE
//     /admin/targets) let any platform_admin add, edit, or remove a
//     target. internal/admin/targets.go wires those routes.
//
//   - jessctl admin target add/edit/delete/list subcommands give the
//     same CRUD from the CLI (Phase 7f-2 will ship those).
//
// Precedence: registered FIRST on the Aggregator so admin-api entries
// WIN against same-id discoveries from cloud / static / k8s providers.
// Operator intent is the highest signal we have.
//
// Storage:
//
//   - v1 (this commit): in-memory map. Restart-fragile by design —
//     the admin-API surface is for break-glass, not the steady-state
//     catalog. Operators promote permanent entries to the static
//     ConfigMap (or, when 7e lands, a JessTarget CR).
//
//   - v2 (Phase 7f-2): Postgres-backed for restart durability +
//     audit trail of who added what. New table jit_target_overrides
//     keyed by id with target_json, added_by, added_at, deleted_at.
//
// Audit: the Aggregator's existing diff-then-emit path (Phase 7a)
// stamps every add/update/delete to the audit Sink as a
// catalog.diff.{added,changed,removed} row. No extra audit hook
// here — the substrate already covers it.
package adminapi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// ErrAlreadyExists is returned by Create when the id is already in
// use. Callers translate to HTTP 409.
var ErrAlreadyExists = errors.New("adminapi: target with this id already exists")

// ErrNotFound is returned by Update / Delete / Get when the id isn't
// in the store. Callers translate to HTTP 404.
var ErrNotFound = errors.New("adminapi: target not found")

// Sink receives a notification any time the store mutates. The
// Aggregator's IngestSnapshot is the production wiring; tests mock
// it. Sink may be nil — the provider still works, just without the
// event-driven push (Aggregator falls back to its cron Discover).
type Sink interface {
	IngestSnapshot(ctx context.Context, providerName string, targets []catalog.Target)
}

// AddedBy records who created or last updated each entry. Reads from
// the verified JWT subject of the API caller. Surfaces in the
// audit-event err string + the SPA admin panel (Phase 7h).
type AddedBy string

// entry is the in-memory row. Mirrors what Phase 7f-2 will persist
// to Postgres.
type entry struct {
	target    catalog.Target
	addedBy   AddedBy
	addedAt   time.Time
	updatedAt time.Time
}

// Provider is the in-memory ad-hoc target store + discovery provider.
type Provider struct {
	mu      sync.RWMutex
	entries map[string]entry
	sink    Sink
}

// New constructs an empty Provider. The Sink (typically the
// Aggregator) MAY be nil — without it, the Aggregator's cron pulls
// the snapshot on its own cadence (default 5min).
func New(sink Sink) *Provider {
	return &Provider{entries: map[string]entry{}, sink: sink}
}

// Name implements catalog.DiscoveryProvider.
func (*Provider) Name() string { return "admin-api" }

// Discover implements catalog.DiscoveryProvider. Returns a snapshot
// of the in-memory store. Concurrent-safe; no lock held during the
// return slice's lifetime.
func (p *Provider) Discover(_ context.Context) ([]catalog.Target, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]catalog.Target, 0, len(p.entries))
	for _, e := range p.entries {
		t := e.target // copy
		out = append(out, t)
	}
	return out, nil
}

// Create inserts a new target. Returns ErrAlreadyExists if the id is
// taken — callers should treat this as 409 Conflict; trying to Create
// over an existing id is almost always a mistake, NOT an upsert
// signal. (Operators who want upsert should PATCH explicitly.)
//
// After the insert, the Sink is notified with a full snapshot so the
// Aggregator's diff-and-audit path runs synchronously. Failure of
// the Sink notification is NOT propagated as an error from Create —
// the in-memory store has already accepted the new entry; the
// Aggregator will pick it up on the next cron tick at the latest.
func (p *Provider) Create(ctx context.Context, t catalog.Target, addedBy AddedBy) error {
	if t.ID == "" {
		return fmt.Errorf("adminapi: Target.ID is required")
	}
	now := time.Now()
	p.mu.Lock()
	if _, exists := p.entries[t.ID]; exists {
		p.mu.Unlock()
		return ErrAlreadyExists
	}
	p.entries[t.ID] = entry{target: t, addedBy: addedBy, addedAt: now, updatedAt: now}
	snapshot := p.snapshotLocked()
	p.mu.Unlock()
	p.notify(ctx, snapshot)
	return nil
}

// Update replaces an existing entry. The id is taken from the
// existing row, not from the body — callers can't rename a target by
// PATCH (would break grant_id references). Returns ErrNotFound when
// the id is unknown.
func (p *Provider) Update(ctx context.Context, id string, t catalog.Target, by AddedBy) error {
	p.mu.Lock()
	e, exists := p.entries[id]
	if !exists {
		p.mu.Unlock()
		return ErrNotFound
	}
	t.ID = id // pin
	e.target = t
	e.updatedAt = time.Now()
	e.addedBy = by // last-toucher attribution
	p.entries[id] = e
	snapshot := p.snapshotLocked()
	p.mu.Unlock()
	p.notify(ctx, snapshot)
	return nil
}

// Delete removes an entry. Idempotent — deleting a missing id returns
// ErrNotFound but callers may treat as success (the post-condition
// "id is not in the store" already holds).
func (p *Provider) Delete(ctx context.Context, id string) error {
	p.mu.Lock()
	if _, exists := p.entries[id]; !exists {
		p.mu.Unlock()
		return ErrNotFound
	}
	delete(p.entries, id)
	snapshot := p.snapshotLocked()
	p.mu.Unlock()
	p.notify(ctx, snapshot)
	return nil
}

// Get returns the entry for an id. Read-only convenience for the
// GET /admin/targets/{id} handler.
func (p *Provider) Get(id string) (catalog.Target, AddedBy, time.Time, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.entries[id]
	if !ok {
		return catalog.Target{}, "", time.Time{}, false
	}
	return e.target, e.addedBy, e.updatedAt, true
}

// ListWithMeta returns every entry with its metadata. Backs the
// GET /admin/targets list endpoint and `jessctl admin target list`.
type Entry struct {
	Target    catalog.Target `json:"target"`
	AddedBy   AddedBy        `json:"added_by"`
	AddedAt   time.Time      `json:"added_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// ListWithMeta returns a stable snapshot of every entry. Order is
// not specified; callers that need deterministic order should sort
// by id.
func (p *Provider) ListWithMeta() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Entry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, Entry{
			Target:    e.target,
			AddedBy:   e.addedBy,
			AddedAt:   e.addedAt,
			UpdatedAt: e.updatedAt,
		})
	}
	return out
}

// snapshotLocked returns a fresh slice of targets. Caller must hold
// at least the read lock. Used by Create/Update/Delete to feed the
// Sink notification under the write lock (cheap; no I/O while
// locked).
func (p *Provider) snapshotLocked() []catalog.Target {
	out := make([]catalog.Target, 0, len(p.entries))
	for _, e := range p.entries {
		t := e.target
		out = append(out, t)
	}
	return out
}

// notify pushes the snapshot to the Sink, if any. Errors swallowed —
// the store has already accepted the mutation; the Aggregator's
// cron will catch up if the synchronous push misses.
func (p *Provider) notify(ctx context.Context, snapshot []catalog.Target) {
	if p.sink == nil {
		return
	}
	p.sink.IngestSnapshot(ctx, "admin-api", snapshot)
}
