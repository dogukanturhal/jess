// SPDX-License-Identifier: AGPL-3.0-or-later

package offlinecreds

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ---- test doubles ----

type fakeMinter struct {
	mu      sync.Mutex
	calls   int
	payload []byte
	ttl     time.Duration
	leaseID string
	err     error
}

func (f *fakeMinter) Mint(_ context.Context, _ string) (MintResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return MintResult{}, f.err
	}
	return MintResult{Payload: f.payload, TTL: f.ttl, LeaseID: f.leaseID}, nil
}

type captureAuditor struct {
	mu     sync.Mutex
	events []Event
}

func (a *captureAuditor) Emit(_ context.Context, ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *captureAuditor) find(action string) (Event, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Action == action {
			return e, true
		}
	}
	return Event{}, false
}

type fakeRevoker struct {
	mu      sync.Mutex
	revoked []string
}

func (r *fakeRevoker) Revoke(_ context.Context, leaseID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, leaseID)
	return nil
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestManager(t *testing.T, m Minter, clk *fakeClock, aud Auditor, rev Revoker) *Manager {
	t.Helper()
	mgr, err := New(Config{
		Minter:  m,
		Auditor: aud,
		Revoker: rev,
		Caps:    DefaultCaps(),
		Now:     clk.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return mgr
}

func mustRegisterEnabled(t *testing.T, mgr *Manager, id, crit string, ttl time.Duration, uses int) {
	t.Helper()
	if err := mgr.Register(TargetPolicy{
		TargetID:    id,
		Criticality: crit,
		Policy:      Policy{Enabled: true, MaxTTL: ttl, MaxUses: uses},
	}); err != nil {
		t.Fatalf("Register(%s): %v", id, err)
	}
}

// ---- required tests ----

// TestNotEligibleByDefault: a target with no opt-in (Enabled=false) is never
// registered and Contingency fails closed — the default posture is unchanged.
func TestNotEligibleByDefault(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("secret")}, clk, &captureAuditor{}, nil)

	// A bare target (no OfflineCredentials policy ⇒ Enabled=false).
	err := mgr.Register(TargetPolicy{TargetID: "app-01", Criticality: "medium"})
	if !errors.Is(err, ErrNotEligible) {
		t.Fatalf("Register default target = %v, want ErrNotEligible", err)
	}
	if mgr.Registered("app-01") {
		t.Fatal("default target must NOT be registered")
	}
	// Even with Vault 'down', a non-opted-in target has no pre-positioned cred.
	if _, _, cerr := mgr.Contingency(context.Background(), "app-01", "op@test"); !errors.Is(cerr, ErrNoPrepositioned) {
		t.Fatalf("Contingency default target = %v, want ErrNoPrepositioned (fail closed)", cerr)
	}
}

// TestTier0NeverEligibleEvenIfOptedIn: a Tier-0 (criticality=critical) target is
// refused registration even with Enabled=true; a target reclassified UP to
// Tier-0 loses its registration AND cached credential; contingency fails closed.
func TestTier0NeverEligibleEvenIfOptedIn(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rev := &fakeRevoker{}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("secret"), ttl: time.Hour, leaseID: "lease-dc"}, clk, &captureAuditor{}, rev)

	// (1) Opt-in on a critical target is hard-refused.
	err := mgr.Register(TargetPolicy{
		TargetID: "dc-01", Criticality: "critical",
		Policy: Policy{Enabled: true, MaxTTL: time.Hour, MaxUses: 3},
	})
	if !errors.Is(err, ErrTier0Excluded) {
		t.Fatalf("Register Tier-0 opted-in = %v, want ErrTier0Excluded", err)
	}
	if mgr.Registered("dc-01") {
		t.Fatal("Tier-0 target must NEVER be registered")
	}
	// Prewarm refuses it too (backstop): never mints for a DC.
	if perr := mgr.Prewarm(context.Background(), "dc-01"); perr == nil {
		t.Fatal("Prewarm Tier-0 must fail (no mint for a DC)")
	}
	if mgr.HasPrepositioned("dc-01") {
		t.Fatal("Tier-0 target must never have a pre-positioned credential")
	}

	// (2) Reclassification safety: a target legitimately pre-positioned while
	// non-critical must be evicted the moment it becomes critical.
	mustRegisterEnabled(t, mgr, "srv-9", "high", time.Hour, 3)
	if perr := mgr.Prewarm(context.Background(), "srv-9"); perr != nil {
		t.Fatalf("Prewarm srv-9: %v", perr)
	}
	if !mgr.HasPrepositioned("srv-9") {
		t.Fatal("srv-9 should be pre-positioned before reclassification")
	}
	rerr := mgr.Register(TargetPolicy{
		TargetID: "srv-9", Criticality: "critical",
		Policy: Policy{Enabled: true, MaxTTL: time.Hour, MaxUses: 3},
	})
	if !errors.Is(rerr, ErrTier0Excluded) {
		t.Fatalf("re-Register srv-9 as critical = %v, want ErrTier0Excluded", rerr)
	}
	if mgr.Registered("srv-9") || mgr.HasPrepositioned("srv-9") {
		t.Fatal("reclassified-to-Tier-0 target must lose its registration AND cached credential")
	}
	// The evicted lease should have been revoked.
	if len(rev.revoked) != 1 || rev.revoked[0] != "lease-dc" {
		t.Fatalf("reclassification should revoke the cached lease, got %v", rev.revoked)
	}
	// And it now fails closed offline.
	if _, _, cerr := mgr.Contingency(context.Background(), "srv-9", "op"); errors.Is(cerr, nil) {
		t.Fatal("reclassified Tier-0 target must fail closed offline")
	}
}

// TestCachedCredUsedWhenVaultDownWithinBudget: a pre-positioned credential is
// served (with its plaintext intact) for an eligible target while within budget,
// TTL, and max-uses.
func TestCachedCredUsedWhenVaultDownWithinBudget(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	want := []byte(`{"Username":"v-ldap-eph","Password":"s3cret"}`)
	mgr := newTestManager(t, &fakeMinter{payload: want, ttl: time.Hour, leaseID: "l1"}, clk, &captureAuditor{}, nil)

	mustRegisterEnabled(t, mgr, "app-01", "high", 4*time.Hour, 3)
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}

	// 10 minutes later, Vault is unreachable — the cached cred is still valid.
	clk.advance(10 * time.Minute)
	got, meta, err := mgr.Contingency(context.Background(), "app-01", "op@test")
	if err != nil {
		t.Fatalf("Contingency within budget = %v, want served", err)
	}
	if string(got) != string(want) {
		t.Fatalf("served payload = %q, want %q (sealed round-trip must be byte-exact)", got, want)
	}
	if meta.Use != 1 || meta.MaxUses != 3 {
		t.Errorf("meta use=%d/%d, want 1/3", meta.Use, meta.MaxUses)
	}
	if meta.CacheID == "" || meta.PrepositionedAt.IsZero() {
		t.Error("meta must carry the cache id + pre-position timestamp")
	}
}

// TestExpiredBudgetFailsClosed: past the signed MaxTTL budget, contingency
// denies even though a cached cred exists.
func TestExpiredBudgetFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: 10 * time.Hour}, clk, &captureAuditor{}, nil)

	mustRegisterEnabled(t, mgr, "app-01", "high", time.Hour, 3) // MaxTTL 1h
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	clk.advance(2 * time.Hour) // past the 1h budget
	if _, _, err := mgr.Contingency(context.Background(), "app-01", "op"); !errors.Is(err, ErrBudgetExpired) {
		t.Fatalf("Contingency past budget = %v, want ErrBudgetExpired (fail closed)", err)
	}
}

// TestCredLeaseExpiredFailsClosed: past the credential's own lease TTL (but still
// within the MaxTTL budget), contingency denies.
func TestCredLeaseExpiredFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: 30 * time.Minute}, clk, &captureAuditor{}, nil)

	mustRegisterEnabled(t, mgr, "app-01", "high", 4*time.Hour, 3) // budget 4h, lease 30m
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	clk.advance(45 * time.Minute) // lease (30m) expired, budget (4h) not
	if _, _, err := mgr.Contingency(context.Background(), "app-01", "op"); !errors.Is(err, ErrCredExpired) {
		t.Fatalf("Contingency past lease = %v, want ErrCredExpired (fail closed)", err)
	}
}

// TestOverMaxUsesFailsClosed: the (N+1)th offline use of one pre-positioned
// credential fails closed.
func TestOverMaxUsesFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: time.Hour}, clk, &captureAuditor{}, nil)

	mustRegisterEnabled(t, mgr, "app-01", "high", time.Hour, 2) // MaxUses 2
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	for i := 1; i <= 2; i++ {
		if _, _, err := mgr.Contingency(context.Background(), "app-01", "op"); err != nil {
			t.Fatalf("Contingency use %d = %v, want served", i, err)
		}
	}
	if _, _, err := mgr.Contingency(context.Background(), "app-01", "op"); !errors.Is(err, ErrMaxUsesExceeded) {
		t.Fatalf("Contingency 3rd use = %v, want ErrMaxUsesExceeded (fail closed)", err)
	}
}

// TestAuditMarkerPresent: every offline-cred moment carries OfflineCredential=true
// plus the pre-position timestamp + cache id; a served credential emits a "used"
// event bound to the operator subject.
func TestAuditMarkerPresent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	aud := &captureAuditor{}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: time.Hour}, clk, aud, nil)

	mustRegisterEnabled(t, mgr, "app-01", "high", time.Hour, 3)
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	if _, _, err := mgr.Contingency(context.Background(), "app-01", "op@test"); err != nil {
		t.Fatalf("Contingency: %v", err)
	}

	pre, ok := aud.find("preposition")
	if !ok || !pre.OfflineCredential || pre.PrepositionedAt.IsZero() || pre.CacheID == "" {
		t.Fatalf("preposition audit missing/incomplete: %+v", pre)
	}
	used, ok := aud.find("used")
	if !ok {
		t.Fatal("no 'used' audit event for the served offline credential")
	}
	if !used.OfflineCredential {
		t.Error("used event must carry offline_credential=true marker")
	}
	if used.Subject != "op@test" {
		t.Errorf("used event subject = %q, want the operator sub", used.Subject)
	}
	if used.PrepositionedAt.IsZero() || used.CacheID == "" {
		t.Error("used event must carry the pre-position timestamp + cache id (which cached cred)")
	}
}

// TestTamperedBudgetFailsClosed: a cached budget whose signature is corrupted is
// rejected — no unsigned local trust.
func TestTamperedBudgetFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: time.Hour}, clk, &captureAuditor{}, nil)

	mustRegisterEnabled(t, mgr, "app-01", "high", time.Hour, 3)
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	// Corrupt the signed budget in the cached entry (white-box).
	mgr.mu.Lock()
	e := mgr.entries["app-01"]
	if len(e.budget.Sig) == 0 {
		mgr.mu.Unlock()
		t.Fatal("expected a signed budget")
	}
	e.budget.Sig[0] ^= 0xFF
	mgr.mu.Unlock()

	if _, _, err := mgr.Contingency(context.Background(), "app-01", "op"); !errors.Is(err, ErrTamperedBudget) {
		t.Fatalf("Contingency tampered budget = %v, want ErrTamperedBudget (fail closed)", err)
	}
}

// TestPolicyNormalizeClampsToCaps: a permissive CRD cannot widen the window
// beyond the global caps, and absent values fall back to defaults.
func TestPolicyNormalizeClampsToCaps(t *testing.T) {
	caps := Caps{MaxTTL: 2 * time.Hour, MaxUses: 2}
	got := Policy{Enabled: true, MaxTTL: 30 * 24 * time.Hour, MaxUses: 999}.normalize(caps)
	if got.MaxTTL != 2*time.Hour {
		t.Errorf("MaxTTL not clamped: got %s, want 2h", got.MaxTTL)
	}
	if got.MaxUses != 2 {
		t.Errorf("MaxUses not clamped: got %d, want 2", got.MaxUses)
	}
	def := Policy{Enabled: true}.normalize(Caps{})
	if def.MaxTTL != DefaultMaxTTL || def.MaxUses != DefaultMaxUses {
		t.Errorf("defaults not applied: got %s/%d, want %s/%d", def.MaxTTL, def.MaxUses, DefaultMaxTTL, DefaultMaxUses)
	}
}

// TestReconnectRotationRevokesAndDiscards: on reconnect (InvalidateAll) every
// pre-positioned credential's lease is best-effort revoked and the cache is
// cleared.
func TestReconnectRotationRevokesAndDiscards(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rev := &fakeRevoker{}
	aud := &captureAuditor{}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: time.Hour, leaseID: "lease-42"}, clk, aud, rev)

	mustRegisterEnabled(t, mgr, "app-01", "high", time.Hour, 3)
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	mgr.InvalidateAll(context.Background())

	if mgr.HasPrepositioned("app-01") {
		t.Fatal("InvalidateAll must clear the cache")
	}
	if len(rev.revoked) != 1 || rev.revoked[0] != "lease-42" {
		t.Fatalf("rotation should revoke the lease, got %v", rev.revoked)
	}
	if _, ok := aud.find("rotated"); !ok {
		t.Error("rotation must audit a 'rotated' event")
	}
}

// TestNotifyReachableSchedulesRotation: a down→up transition after an offline
// use schedules a rotation the next tick performs.
func TestNotifyReachableSchedulesRotation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rev := &fakeRevoker{}
	mgr := newTestManager(t, &fakeMinter{payload: []byte("x"), ttl: time.Hour, leaseID: "lz"}, clk, &captureAuditor{}, rev)

	mustRegisterEnabled(t, mgr, "app-01", "high", time.Hour, 3)
	if err := mgr.Prewarm(context.Background(), "app-01"); err != nil {
		t.Fatalf("Prewarm: %v", err)
	}
	// Serve one offline cred, then Vault comes back.
	if _, _, err := mgr.Contingency(context.Background(), "app-01", "op"); err != nil {
		t.Fatalf("Contingency: %v", err)
	}
	mgr.NotifyReachable(false)
	mgr.NotifyReachable(true) // down→up after offline use ⇒ rotation owed
	mgr.tick(context.Background())

	if len(rev.revoked) == 0 {
		t.Fatal("reconnect after offline use must rotate (revoke) the pre-positioned lease")
	}
}
