// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeProvider lets each test feed a sequence of Discover results.
type fakeProvider struct {
	name string
	mu   sync.Mutex
	idx  int
	runs [][]Target
	errs []error
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Discover(_ context.Context) ([]Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.idx
	if i >= len(f.runs) {
		i = len(f.runs) - 1
	}
	f.idx++
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	return append([]Target(nil), f.runs[i]...), nil
}

type recAudit struct {
	mu     sync.Mutex
	events []DiffEvent
}

func (r *recAudit) EmitCatalogDiff(_ context.Context, ev DiffEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}
func (r *recAudit) snapshot() []DiffEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DiffEvent, len(r.events))
	copy(out, r.events)
	return out
}

type recMetrics struct {
	mu      sync.Mutex
	refresh []struct {
		p  string
		ok bool
	}
	targets map[string]int
	errors  []struct{ p, reason string }
	diffs   []struct{ p, c string }
}

func newRecMetrics() *recMetrics { return &recMetrics{targets: map[string]int{}} }

func (r *recMetrics) CatalogProviderRefresh(p string, _ time.Duration, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh = append(r.refresh, struct {
		p  string
		ok bool
	}{p, ok})
}
func (r *recMetrics) CatalogProviderTargets(p string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[p] = n
}
func (r *recMetrics) CatalogProviderError(p, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, struct{ p, reason string }{p, reason})
}
func (r *recMetrics) CatalogDiff(p, c string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.diffs = append(r.diffs, struct{ p, c string }{p, c})
}

func tgt(id, addr, region string) Target {
	return Target{ID: id, Protocol: ProtoSSH, Address: addr, Region: region}
}

func TestAggregator_InitialSyncAddsTargets(t *testing.T) {
	a := NewAggregator(nil, nil)
	a.AddProvider(&fakeProvider{
		name: "p1",
		runs: [][]Target{{tgt("a", "10.0.0.1:22", "eu"), tgt("b", "10.0.0.2:22", "eu")}},
	}, -1) // event-driven; no cron — we drive it via Run's initial sync
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go a.Run(ctx)
	// initial sync runs synchronously in Run; give it a tick to settle
	time.Sleep(30 * time.Millisecond)
	all, err := a.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(all))
	}
	for _, x := range all {
		if x.Source != "p1" {
			t.Errorf("source = %q, want p1", x.Source)
		}
		if x.LastSeen.IsZero() {
			t.Errorf("LastSeen not stamped on %s", x.ID)
		}
	}
}

func TestAggregator_FailClosedKeepsLastKnownGood(t *testing.T) {
	audit := &recAudit{}
	m := newRecMetrics()
	p := &fakeProvider{
		name: "p1",
		runs: [][]Target{
			{tgt("a", "10.0.0.1:22", "eu"), tgt("b", "10.0.0.2:22", "eu")},
			nil, // second call errors
		},
		errs: []error{nil, errors.New("upstream down")},
	}
	a := NewAggregator(audit, m)
	a.AddProvider(p, -1)
	ctx := context.Background()
	a.refreshOne(ctx, p)
	a.refreshOne(ctx, p) // this one errors

	all, _ := a.List(ctx, "")
	if len(all) != 2 {
		t.Fatalf("fail-closed broken: post-error List returned %d targets, want 2 (last-known-good)", len(all))
	}
	// Only the FIRST refresh emits add events; the failing second one emits nothing.
	got := audit.snapshot()
	adds := 0
	for _, e := range got {
		if e.ChangeType == "added" {
			adds++
		}
	}
	if adds != 2 {
		t.Errorf("adds = %d, want 2 (only initial)", adds)
	}
	// And metrics should record one error
	m.mu.Lock()
	errs := append([]struct{ p, reason string }{}, m.errors...)
	m.mu.Unlock()
	if len(errs) != 1 || errs[0].reason != "discover_failed" {
		t.Errorf("metrics errors = %+v, want one discover_failed", errs)
	}
}

func TestAggregator_DiffOnlyOnChange(t *testing.T) {
	audit := &recAudit{}
	p := &fakeProvider{
		name: "p1",
		runs: [][]Target{
			{tgt("a", "10.0.0.1:22", "eu")},
			{tgt("a", "10.0.0.1:22", "eu")}, // identical
			{tgt("a", "10.0.0.2:22", "eu")}, // address changed
		},
	}
	a := NewAggregator(audit, nil)
	a.AddProvider(p, -1)
	ctx := context.Background()
	a.refreshOne(ctx, p)
	a.refreshOne(ctx, p)
	a.refreshOne(ctx, p)

	got := audit.snapshot()
	if len(got) != 2 {
		t.Fatalf("diff events = %d, want 2 (1 added + 1 changed; 0 from identical re-list)\nevents=%+v", len(got), got)
	}
	if got[0].ChangeType != "added" || got[1].ChangeType != "changed" {
		t.Errorf("event sequence = %v, want [added, changed]", []string{got[0].ChangeType, got[1].ChangeType})
	}
}

func TestAggregator_EmptySuccessfulSnapshotEvictsTargets(t *testing.T) {
	audit := &recAudit{}
	p := &fakeProvider{
		name: "p1",
		runs: [][]Target{
			{tgt("a", "10.0.0.1:22", "eu")},
			{}, // empty SUCCESS — caller is asserting "nothing here now"
		},
	}
	a := NewAggregator(audit, nil)
	a.AddProvider(p, -1)
	a.refreshOne(context.Background(), p)
	a.refreshOne(context.Background(), p)
	all, _ := a.List(context.Background(), "")
	if len(all) != 0 {
		t.Errorf("empty-success eviction failed: %d targets", len(all))
	}
	got := audit.snapshot()
	// one added, one removed
	if len(got) != 2 || got[1].ChangeType != "removed" {
		t.Errorf("expected add+remove sequence, got %+v", got)
	}
}

func TestAggregator_PrecedenceFirstProviderWins(t *testing.T) {
	// p1 = static (precedence), p2 = cloud — same id, different address
	p1 := &fakeProvider{name: "static", runs: [][]Target{{tgt("a", "10.0.0.1:22", "eu")}}}
	p2 := &fakeProvider{name: "cloud", runs: [][]Target{{tgt("a", "172.16.0.1:22", "us")}}}
	a := NewAggregator(nil, nil)
	a.AddProvider(p1, -1) // static first → wins on collision
	a.AddProvider(p2, -1)
	a.refreshOne(context.Background(), p1)
	a.refreshOne(context.Background(), p2)
	tgt, err := a.Lookup(context.Background(), "a")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if tgt.Source != "static" || tgt.Address != "10.0.0.1:22" {
		t.Errorf("collision resolution = %+v, want static/10.0.0.1:22", tgt)
	}
}

func TestAggregator_RegionFilter(t *testing.T) {
	p := &fakeProvider{name: "p1", runs: [][]Target{{
		tgt("eu-a", "10.0.0.1:22", "eu"),
		tgt("us-a", "172.16.0.1:22", "us"),
	}}}
	a := NewAggregator(nil, nil)
	a.AddProvider(p, -1)
	a.refreshOne(context.Background(), p)
	eu, _ := a.List(context.Background(), "eu")
	if len(eu) != 1 || eu[0].ID != "eu-a" {
		t.Errorf("region=eu filter = %+v, want only eu-a", eu)
	}
}

func TestAggregator_LookupMissReturnsNotFoundSentinel(t *testing.T) {
	a := NewAggregator(nil, nil)
	_, err := a.Lookup(context.Background(), "nope")
	if !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("err = %v, want ErrTargetNotFound", err)
	}
}

func TestAggregator_IngestSnapshotPathIdenticalToCron(t *testing.T) {
	// Event-driven providers (e.g. k8s watch) call IngestSnapshot;
	// behavior must match the cron path. Use a no-op provider so the
	// aggregator has a registered name but Run won't poll.
	noop := &fakeProvider{name: "k8s-nodes", runs: [][]Target{nil}}
	audit := &recAudit{}
	a := NewAggregator(audit, nil)
	a.AddProvider(noop, -1)
	ctx := context.Background()
	a.IngestSnapshot(ctx, "k8s-nodes", []Target{tgt("a", "10.0.0.1:22", "eu")})
	a.IngestSnapshot(ctx, "k8s-nodes", []Target{tgt("a", "10.0.0.1:22", "eu")}) // identical, no diff
	a.IngestSnapshot(ctx, "k8s-nodes", []Target{})                              // remove
	got := audit.snapshot()
	if len(got) != 2 {
		t.Fatalf("diff events = %d, want 2 (add + remove)\n%+v", len(got), got)
	}
	if got[0].ChangeType != "added" || got[1].ChangeType != "removed" {
		t.Errorf("event sequence = %v, want [added, removed]", []string{got[0].ChangeType, got[1].ChangeType})
	}
}

func TestAggregator_StaticProviderWrapsMemoryCatalog(t *testing.T) {
	cat := NewMemoryCatalog(&Target{ID: "a", Protocol: ProtoSSH, Address: "10.0.0.1:22"})
	sp := NewStaticProvider(cat)
	if sp.Name() != "static" {
		t.Errorf("name = %q, want static", sp.Name())
	}
	out, err := sp.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(out) != 1 || out[0].ID != "a" {
		t.Errorf("Discover = %+v, want one target id=a", out)
	}
}

func TestAggregator_StatusSurfacesProviderHealth(t *testing.T) {
	p1 := &fakeProvider{name: "p1", runs: [][]Target{{tgt("a", "10.0.0.1:22", "eu")}}}
	p2 := &fakeProvider{
		name: "p2",
		runs: [][]Target{nil},
		errs: []error{errors.New("boom")},
	}
	a := NewAggregator(nil, nil)
	a.AddProvider(p1, -1)
	a.AddProvider(p2, -1)
	a.refreshOne(context.Background(), p1)
	a.refreshOne(context.Background(), p2)
	st := a.Status()
	if len(st) != 2 {
		t.Fatalf("status entries = %d, want 2", len(st))
	}
	byName := map[string]ProviderStatus{}
	for _, s := range st {
		byName[s.Name] = s
	}
	if byName["p1"].LastErr != "" {
		t.Errorf("p1 LastErr = %q, want empty", byName["p1"].LastErr)
	}
	if byName["p2"].LastErr == "" {
		t.Errorf("p2 LastErr empty, want non-empty")
	}
	if byName["p1"].TargetCount != 1 {
		t.Errorf("p1 TargetCount = %d, want 1", byName["p1"].TargetCount)
	}
}

// --- Phase D — retirement TTL tests ----------------------------------

func TestAggregator_RetirementTTL_LookupAfterStaleReturnsRetired(t *testing.T) {
	a := NewAggregator(nil, nil)
	p := &fakeProvider{name: "p", runs: [][]Target{{tgt("x", "10.0.0.1:22", "eu")}}}
	a.AddProvider(p, -1)
	// Very short TTL so we can observe retirement within the test window.
	a.SetRetirementTTL("p", 10*time.Millisecond)
	a.refreshOne(context.Background(), p)
	// Fresh sighting → Lookup succeeds.
	if got, err := a.Lookup(context.Background(), "x"); err != nil || got == nil {
		t.Fatalf("expected live Lookup, got err=%v target=%v", err, got)
	}
	// Wait past TTL — provider doesn't re-list.
	time.Sleep(30 * time.Millisecond)
	got, err := a.Lookup(context.Background(), "x")
	if !errors.Is(err, ErrTargetRetired) {
		t.Fatalf("expected ErrTargetRetired, got err=%v target=%v", err, got)
	}
}

func TestAggregator_RetirementTTL_ListExcludesRetired(t *testing.T) {
	a := NewAggregator(nil, nil)
	p := &fakeProvider{name: "p", runs: [][]Target{{
		tgt("live", "10.0.0.1:22", ""),
		tgt("stale", "10.0.0.2:22", ""),
	}}}
	a.AddProvider(p, -1)
	a.SetRetirementTTL("p", 10*time.Millisecond)
	a.refreshOne(context.Background(), p)
	time.Sleep(30 * time.Millisecond)
	got, err := a.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Both targets share the same LastSeen — once we sleep past TTL both
	// should be filtered.
	if len(got) != 0 {
		t.Fatalf("expected 0 (all retired), got %d: %v", len(got), got)
	}
}

func TestAggregator_RetirementTTL_AuditEmittedOnce(t *testing.T) {
	rec := &recAudit{}
	a := NewAggregator(rec, nil)
	p := &fakeProvider{name: "p", runs: [][]Target{{tgt("x", "10.0.0.1:22", "")}}}
	a.AddProvider(p, -1)
	a.SetRetirementTTL("p", 5*time.Millisecond)
	a.refreshOne(context.Background(), p)
	time.Sleep(20 * time.Millisecond)
	// First Lookup observes retirement → 1 audit event.
	_, _ = a.Lookup(context.Background(), "x")
	// Repeat — should NOT re-emit (one-shot dedup).
	_, _ = a.Lookup(context.Background(), "x")
	_, _ = a.Lookup(context.Background(), "x")
	got := rec.snapshot()
	retired := 0
	for _, ev := range got {
		if ev.ChangeType == "retired" && ev.TargetID == "x" {
			retired++
		}
	}
	if retired != 1 {
		t.Fatalf("expected 1 retired audit event, got %d (all events: %+v)", retired, got)
	}
}

func TestAggregator_RetirementTTL_ResetAfterRelist(t *testing.T) {
	rec := &recAudit{}
	a := NewAggregator(rec, nil)
	p := &fakeProvider{name: "p", runs: [][]Target{
		{tgt("x", "10.0.0.1:22", "")},
		{tgt("x", "10.0.0.1:22", "")}, // 2nd refresh re-lists x
	}}
	a.AddProvider(p, -1)
	a.SetRetirementTTL("p", 10*time.Millisecond)
	a.refreshOne(context.Background(), p)
	time.Sleep(25 * time.Millisecond)
	_, _ = a.Lookup(context.Background(), "x") // observe retirement → 1 audit event
	// Source re-lists; LastSeen reset to now.
	a.refreshOne(context.Background(), p)
	if got, err := a.Lookup(context.Background(), "x"); err != nil || got == nil {
		t.Fatalf("expected fresh sighting after re-list, got err=%v target=%v", err, got)
	}
	// Wait for retirement window again — must emit a NEW retired audit
	// because we re-listed in between.
	time.Sleep(25 * time.Millisecond)
	_, _ = a.Lookup(context.Background(), "x")
	got := rec.snapshot()
	retired := 0
	for _, ev := range got {
		if ev.ChangeType == "retired" && ev.TargetID == "x" {
			retired++
		}
	}
	if retired != 2 {
		t.Fatalf("expected 2 retired audit events across the lifecycle, got %d", retired)
	}
}

func TestAggregator_RetirementTTL_ZeroDisables(t *testing.T) {
	a := NewAggregator(nil, nil)
	p := &fakeProvider{name: "p", runs: [][]Target{{tgt("x", "10.0.0.1:22", "")}}}
	a.AddProvider(p, -1)
	// Don't call SetRetirementTTL — default = 0 = disabled.
	a.refreshOne(context.Background(), p)
	time.Sleep(50 * time.Millisecond)
	got, err := a.Lookup(context.Background(), "x")
	if err != nil || got == nil {
		t.Fatalf("expected live Lookup with TTL disabled, got err=%v", err)
	}
}
