// SPDX-License-Identifier: AGPL-3.0-or-later

package offlinecreds

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
)

// Minter pre-fetches a fresh short-TTL credential for a target while ONLINE. The
// payload is opaque bytes — protocol-specific marshaling (RDP NLA secret, SSH
// cert, DB creds) lives in the caller's adapter, so the manager stays
// credential-shape agnostic. A Minter call goes to Vault; the manager only ever
// calls it while Vault is reachable (from the refresh loop), never on the
// contingency path.
type Minter interface {
	Mint(ctx context.Context, targetID string) (MintResult, error)
}

// MintResult is one freshly-minted, not-yet-sealed credential plus the lease
// metadata the manager needs to bound and later revoke it.
type MintResult struct {
	Payload []byte        // opaque credential bytes (the manager seals these at rest)
	TTL     time.Duration // Vault lease TTL of the minted credential (0 ⇒ unknown)
	LeaseID string        // Vault lease id for emergency revoke on reconnect (optional)
}

// Revoker best-effort revokes a pre-positioned credential's lease on reconnect
// (P3.8 item 7). Optional: when nil, rotation is discard-and-let-expire (the
// short lease TTL is the safety net either way).
type Revoker interface {
	Revoke(ctx context.Context, leaseID string) error
}

// Auditor receives the WORM audit events. Implementations forward into the
// tamper-evident hash-chain (or, in jess-web which has no local audit sink, a
// structured log). Every event carries OfflineCredential=true.
type Auditor interface {
	Emit(ctx context.Context, ev Event) error
}

// Config constructs a Manager. Only Minter is required; everything else has a
// secure default.
type Config struct {
	Minter          Minter
	Auditor         Auditor              // default: LogAuditor(Logger)
	Revoker         Revoker              // optional (nil ⇒ discard-and-expire on rotate)
	Sealer          *Sealer              // default: NewEphemeralSealer()
	Signer          govdecision.Signer   // default: fresh ed25519 (co-located issuer)
	Verifier        govdecision.Verifier // default: matching ed25519 verifier
	Guard           Tier0Guard
	Caps            Caps          // default: DefaultCaps()
	RefreshInterval time.Duration // Run() tick; default 60s
	Logger          *log.Logger
	Now             func() time.Time // test seam; default time.Now
}

// Manager owns the pre-position cache and the online/contingency credential
// paths. It is safe for concurrent use.
type Manager struct {
	minter   Minter
	auditor  Auditor
	revoker  Revoker
	sealer   *Sealer
	signer   govdecision.Signer
	verifier govdecision.Verifier
	guard    Tier0Guard
	caps     Caps
	refresh  time.Duration
	log      *log.Logger
	now      func() time.Time

	mu         sync.Mutex
	registered map[string]TargetPolicy // eligible, opted-in targets (normalized)
	entries    map[string]*entry       // pre-positioned creds, keyed by targetID
	reachable  bool                    // last-known Vault reachability
	offlineHit bool                    // an offline cred has been served since last rotate
	pendingRot bool                    // reconnect rotation owed
}

// entry is one sealed, budgeted pre-positioned credential.
type entry struct {
	tp            TargetPolicy
	sealed        []byte
	credExpiry    time.Time
	leaseID       string
	budget        govdecision.Decision
	prepositionAt time.Time
	uses          int
	cacheID       string
}

// New builds a Manager, filling secure defaults for every optional field.
func New(cfg Config) (*Manager, error) {
	if cfg.Minter == nil {
		return nil, fmt.Errorf("offlinecreds: Minter is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	sealer := cfg.Sealer
	if sealer == nil {
		s, err := NewEphemeralSealer()
		if err != nil {
			return nil, err
		}
		sealer = s
	}
	signer, verifier := cfg.Signer, cfg.Verifier
	if signer == nil || verifier == nil {
		s, v, err := govdecision.GenerateEd25519()
		if err != nil {
			return nil, err
		}
		signer, verifier = s, v
	}
	auditor := cfg.Auditor
	if auditor == nil {
		auditor = LogAuditor{Logger: logger}
	}
	caps := cfg.Caps
	if caps.MaxTTL <= 0 || caps.MaxUses <= 0 {
		def := DefaultCaps()
		if caps.MaxTTL <= 0 {
			caps.MaxTTL = def.MaxTTL
		}
		if caps.MaxUses <= 0 {
			caps.MaxUses = def.MaxUses
		}
	}
	refresh := cfg.RefreshInterval
	if refresh <= 0 {
		refresh = 60 * time.Second
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Manager{
		minter:     cfg.Minter,
		auditor:    auditor,
		revoker:    cfg.Revoker,
		sealer:     sealer,
		signer:     signer,
		verifier:   verifier,
		guard:      cfg.Guard,
		caps:       caps,
		refresh:    refresh,
		log:        logger,
		now:        nowFn,
		registered: map[string]TargetPolicy{},
		entries:    map[string]*entry{},
		reachable:  true,
	}, nil
}

// Register records a target's opt-in so the refresh loop will pre-position a
// credential for it. It is the SOURCE-LAYER eligibility gate AND the
// un-overridable Tier-0 rejection:
//
//   - Tier-0 (criticality=="critical" / deny-listed) ⇒ ErrTier0Excluded and NO
//     registration, even when Policy.Enabled=true (crown-jewels rule);
//   - not opted in (Enabled=false) ⇒ ErrNotEligible and no registration;
//   - eligible ⇒ registered (idempotent; re-registration refreshes the policy).
//
// Callers treat both errors as "do nothing" — they exist so a caller can log the
// crown-jewels rejection distinctly. Registration alone mints nothing; the Run
// loop (or Prewarm) performs the online mint.
func (m *Manager) Register(tp TargetPolicy) error {
	if m.guard.IsTier0(tp) {
		// Crown-jewels rule + reclassification safety: if a target that was
		// previously registered as non-Tier-0 is now Tier-0 (criticality raised /
		// added to the deny set), immediately evict its registration AND any
		// cached credential (best-effort revoke) so it can never be served offline.
		m.mu.Lock()
		delete(m.registered, tp.TargetID)
		e := m.entries[tp.TargetID]
		delete(m.entries, tp.TargetID)
		m.mu.Unlock()
		if e != nil {
			m.revoke(context.Background(), e, "reclassified-tier0")
		}
		return ErrTier0Excluded
	}
	if !tp.Policy.Enabled {
		// Opt-out (or never opted in): drop any stale registration + cached cred.
		m.mu.Lock()
		_, had := m.registered[tp.TargetID]
		if had {
			delete(m.registered, tp.TargetID)
			e := m.entries[tp.TargetID]
			delete(m.entries, tp.TargetID)
			m.mu.Unlock()
			if e != nil {
				m.revoke(context.Background(), e, "opted-out")
			}
		} else {
			m.mu.Unlock()
		}
		return ErrNotEligible
	}
	if !m.guard.IsTier1(tp) {
		// Highest-assurance-tier-only rule (2026-07-23 decision): only Tier-1
		// ("high") targets may hold pre-positioned offline creds; Tier-2+
		// ("medium"/"low") are excluded. A target that was Tier-1 but is now
		// reclassified DOWN evicts its registration + cached credential, mirroring
		// the Tier-0 reclassification path above.
		m.mu.Lock()
		_, had := m.registered[tp.TargetID]
		if had {
			delete(m.registered, tp.TargetID)
			e := m.entries[tp.TargetID]
			delete(m.entries, tp.TargetID)
			m.mu.Unlock()
			if e != nil {
				m.revoke(context.Background(), e, "reclassified-below-tier1")
			}
		} else {
			m.mu.Unlock()
		}
		return ErrNotEligible
	}
	tp.Policy = tp.Policy.normalize(m.caps)
	m.mu.Lock()
	m.registered[tp.TargetID] = tp
	m.mu.Unlock()
	return nil
}

// Deregister drops a target's opt-in and any cached credential (best-effort
// revoke). Used when a JessTarget is retired or its opt-in removed.
func (m *Manager) Deregister(ctx context.Context, targetID string) {
	m.mu.Lock()
	delete(m.registered, targetID)
	e := m.entries[targetID]
	delete(m.entries, targetID)
	m.mu.Unlock()
	if e != nil {
		m.revoke(ctx, e, "deregistered")
	}
}

// Prewarm mints (online), seals, budgets, and caches a fresh pre-positioned
// credential for a registered target. It re-applies the Tier-0 backstop (a
// registered target can never be Tier-0, but the check is defence in depth) and
// fails if the target is not registered/eligible. Safe to call repeatedly — it
// replaces any prior entry (and best-effort revokes the one it supersedes).
func (m *Manager) Prewarm(ctx context.Context, targetID string) error {
	m.mu.Lock()
	tp, ok := m.registered[targetID]
	m.mu.Unlock()
	if !ok {
		return ErrNotEligible
	}
	if m.guard.IsTier0(tp) { // backstop — must never mint for Tier-0
		return ErrTier0Excluded
	}

	res, err := m.minter.Mint(ctx, targetID)
	if err != nil {
		// Online mint failed (Vault down/blip). Keep any existing still-valid
		// entry as last-known-good; the loop retries next tick.
		return fmt.Errorf("offlinecreds: prewarm mint %s: %w", targetID, err)
	}

	now := m.now()
	sealed, err := m.sealer.Seal(res.Payload)
	if err != nil {
		return err
	}
	// (b) the signed, time-boxed budget: valid for MaxTTL from now, independent
	// of the credential's own lease TTL.
	budget, err := govdecision.Sign(m.signer, govdecision.Decision{
		Subject:    offlineCredSubject,
		Resource:   targetID,
		Verdict:    govdecision.Allow,
		IssuedAt:   now,
		ValidUntil: now.Add(tp.Policy.MaxTTL),
		Claims: map[string]string{
			"criticality": tp.Criticality,
			"max_uses":    fmt.Sprintf("%d", tp.Policy.MaxUses),
		},
	})
	if err != nil {
		return err
	}
	// (a) the credential's own lease TTL. Unknown lease (TTL 0) collapses into
	// the budget end so the cred can never outlive the budget.
	credExpiry := now.Add(tp.Policy.MaxTTL)
	if res.TTL > 0 && now.Add(res.TTL).Before(credExpiry) {
		credExpiry = now.Add(res.TTL)
	}
	e := &entry{
		tp:            tp,
		sealed:        sealed,
		credExpiry:    credExpiry,
		leaseID:       res.LeaseID,
		budget:        budget,
		prepositionAt: now,
		cacheID:       fmt.Sprintf("%s@%d", targetID, now.UnixNano()),
	}

	m.mu.Lock()
	old := m.entries[targetID]
	m.entries[targetID] = e
	m.mu.Unlock()
	if old != nil {
		m.revoke(ctx, old, "superseded-by-refresh")
	}

	m.emit(ctx, Event{
		Time:              now,
		Action:            "preposition",
		TargetID:          targetID,
		OfflineCredential: true,
		PrepositionedAt:   now,
		CacheID:           e.cacheID,
		Criticality:       tp.Criticality,
		BudgetValidUntil:  e.budget.ValidUntil,
		MaxUses:           tp.Policy.MaxUses,
	})
	return nil
}

// Contingency is the OFFLINE credential path: it returns the sealed-then-opened
// pre-positioned credential payload for an already-authorized session to an
// eligible target IFF all three governed conditions hold, else fails closed.
// The caller MUST have already passed authorization (JIT grant + grant re-check
// + recording gate) — this method has no authz and never grants access; it only
// swaps the credential source.
//
// Conditions (each a hard gate; any failure ⇒ deny + audit):
//  0. Tier-0 backstop (registered criticality is not "critical");
//  1. a pre-positioned entry exists;
//  2. its govdecision budget signature verifies (no unsigned local trust);
//  3. now is within the signed budget window (MaxTTL);
//  4. now is within the credential's own lease TTL;
//  5. uses < MaxUses.
func (m *Manager) Contingency(ctx context.Context, targetID, subject string) ([]byte, ContingencyMeta, error) {
	now := m.now()

	m.mu.Lock()
	tp, reg := m.registered[targetID]
	e := m.entries[targetID]
	// Backstop: a Tier-0 target is never served, even if an entry somehow exists.
	if reg && m.guard.IsTier0(tp) {
		m.mu.Unlock()
		m.emitDeny(ctx, targetID, subject, e, "tier0-excluded", ErrTier0Excluded)
		return nil, ContingencyMeta{}, ErrTier0Excluded
	}
	if e == nil {
		m.mu.Unlock()
		m.emitDeny(ctx, targetID, subject, nil, "no-prepositioned", ErrNoPrepositioned)
		return nil, ContingencyMeta{}, ErrNoPrepositioned
	}
	// Verify the signed budget BEFORE trusting any of its fields.
	if err := govdecision.Verify(m.verifier, e.budget); err != nil {
		m.mu.Unlock()
		m.emitDeny(ctx, targetID, subject, e, "tampered-budget", ErrTamperedBudget)
		return nil, ContingencyMeta{}, ErrTamperedBudget
	}
	switch {
	case now.After(e.budget.ValidUntil):
		m.mu.Unlock()
		m.emitDeny(ctx, targetID, subject, e, "budget-expired", ErrBudgetExpired)
		return nil, ContingencyMeta{}, ErrBudgetExpired
	case now.After(e.credExpiry):
		m.mu.Unlock()
		m.emitDeny(ctx, targetID, subject, e, "cred-expired", ErrCredExpired)
		return nil, ContingencyMeta{}, ErrCredExpired
	case e.uses >= e.tp.Policy.MaxUses:
		m.mu.Unlock()
		m.emitDeny(ctx, targetID, subject, e, "max-uses-exceeded", ErrMaxUsesExceeded)
		return nil, ContingencyMeta{}, ErrMaxUsesExceeded
	}
	// Consume one use under the lock so concurrent contingency opens can't
	// exceed MaxUses.
	e.uses++
	useOrdinal := e.uses
	sealed := e.sealed
	meta := ContingencyMeta{
		PrepositionedAt:  e.prepositionAt,
		CacheID:          e.cacheID,
		Use:              useOrdinal,
		MaxUses:          e.tp.Policy.MaxUses,
		BudgetValidUntil: e.budget.ValidUntil,
		CredExpiry:       e.credExpiry,
	}
	m.offlineHit = true // a reconnect must now rotate this cred
	crit := e.tp.Criticality
	m.mu.Unlock()

	payload, err := m.sealer.Open(sealed)
	if err != nil {
		m.emitDeny(ctx, targetID, subject, e, "unseal-failed", err)
		return nil, ContingencyMeta{}, fmt.Errorf("offlinecreds: %w", err)
	}

	m.emit(ctx, Event{
		Time:              now,
		Action:            "used",
		TargetID:          targetID,
		Subject:           subject,
		OfflineCredential: true,
		PrepositionedAt:   meta.PrepositionedAt,
		CacheID:           meta.CacheID,
		Criticality:       crit,
		BudgetValidUntil:  meta.BudgetValidUntil,
		Use:               useOrdinal,
		MaxUses:           meta.MaxUses,
	})
	return payload, meta, nil
}

// NotifyReachable records the last-observed Vault reachability from the caller's
// online mint attempts. A down→up transition AFTER an offline credential was
// served schedules an emergency rotation (item 7) on the next Run tick.
func (m *Manager) NotifyReachable(reachable bool) {
	m.mu.Lock()
	was := m.reachable
	m.reachable = reachable
	if reachable && !was && m.offlineHit {
		m.pendingRot = true
	}
	m.mu.Unlock()
}

// Run drives the background lifecycle until ctx is cancelled: it pre-positions
// registered targets, refreshes them before expiry, and performs the
// reconnect rotation when one is owed. Bind it to the process lifetime
// (go mgr.Run(ctx)), mirroring the recording store-and-forward reconciler.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.refresh)
	defer t.Stop()
	m.tick(ctx) // prewarm promptly at startup rather than after one interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// tick performs one maintenance pass: reconnect rotation first (so a rotated
// cred is immediately re-positioned), then prewarm/refresh of every registered
// target that lacks a current, unexpired-enough credential.
func (m *Manager) tick(ctx context.Context) {
	m.mu.Lock()
	doRotate := m.pendingRot
	m.pendingRot = false
	ids := make([]string, 0, len(m.registered))
	for id := range m.registered {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	if doRotate {
		m.InvalidateAll(ctx)
	}
	now := m.now()
	for _, id := range ids {
		m.mu.Lock()
		e := m.entries[id]
		m.mu.Unlock()
		if e == nil || refreshDue(e, now) {
			if err := m.Prewarm(ctx, id); err != nil {
				// Expected while Vault is down — keep last-known-good, retry next tick.
				m.log.Printf("offlinecreds: prewarm %s deferred: %v", id, err)
			}
		}
	}
}

// refreshDue reports whether e is past its half-life and should be re-minted
// while Vault is (presumably) still reachable, so a fresh cred is pre-positioned
// well before the current one expires.
func refreshDue(e *entry, now time.Time) bool {
	life := e.credExpiry.Sub(e.prepositionAt)
	if life <= 0 {
		return true
	}
	return now.After(e.prepositionAt.Add(life / 2))
}

// InvalidateAll emergency-rotates every pre-positioned credential: best-effort
// lease revoke, discard the sealed entry, and audit. Called on reconnect after
// offline use (item 7) and available for a manual break-glass reset. The next
// Run tick re-positions fresh credentials for still-registered targets.
func (m *Manager) InvalidateAll(ctx context.Context) {
	m.mu.Lock()
	old := m.entries
	m.entries = map[string]*entry{}
	m.offlineHit = false
	m.mu.Unlock()
	for _, e := range old {
		m.revoke(ctx, e, "reconnect-rotate")
	}
}

// revoke best-effort revokes a superseded/rotated entry's lease and audits it.
func (m *Manager) revoke(ctx context.Context, e *entry, reason string) {
	if e == nil {
		return
	}
	if m.revoker != nil && e.leaseID != "" {
		if err := m.revoker.Revoke(ctx, e.leaseID); err != nil {
			m.log.Printf("offlinecreds: revoke lease %s (%s): %v", e.leaseID, reason, err)
		}
	}
	m.emit(ctx, Event{
		Time:              m.now(),
		Action:            "rotated",
		TargetID:          e.tp.TargetID,
		OfflineCredential: true,
		PrepositionedAt:   e.prepositionAt,
		CacheID:           e.cacheID,
		Criticality:       e.tp.Criticality,
		Reason:            reason,
	})
}

// emit forwards an audit event, logging (never failing the caller) on sink error.
func (m *Manager) emit(ctx context.Context, ev Event) {
	if err := m.auditor.Emit(ctx, ev); err != nil {
		m.log.Printf("offlinecreds: audit emit (%s target=%s): %v", ev.Action, ev.TargetID, err)
	}
}

// emitDeny is the audit for a fail-closed contingency decision.
func (m *Manager) emitDeny(ctx context.Context, targetID, subject string, e *entry, reason string, cause error) {
	ev := Event{
		Time:              m.now(),
		Action:            "denied",
		TargetID:          targetID,
		Subject:           subject,
		OfflineCredential: true,
		Reason:            reason,
	}
	if cause != nil {
		ev.Err = cause.Error()
	}
	if e != nil {
		ev.PrepositionedAt = e.prepositionAt
		ev.CacheID = e.cacheID
		ev.Criticality = e.tp.Criticality
		ev.BudgetValidUntil = e.budget.ValidUntil
		ev.MaxUses = e.tp.Policy.MaxUses
	}
	m.emit(ctx, ev)
}

// Registered reports whether a target is currently opted in + eligible (test /
// diagnostic helper).
func (m *Manager) Registered(targetID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.registered[targetID]
	return ok
}

// HasPrepositioned reports whether a valid-shaped cached credential exists (test
// / readiness helper; does not evaluate the budget/TTL).
func (m *Manager) HasPrepositioned(targetID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[targetID]
	return ok
}

// LogAuditor is the default Auditor for processes without a wired audit sink
// (jess-web). It writes a structured, secret-free line per event so the WORM/
// log pipeline still captures the offline_credential marker.
type LogAuditor struct{ Logger *log.Logger }

// Emit writes the event as a single structured line.
func (a LogAuditor) Emit(_ context.Context, ev Event) error {
	l := a.Logger
	if l == nil {
		l = log.Default()
	}
	l.Printf("offline_credential=%t action=%s target=%s subject=%s cache=%s prepositioned_at=%s criticality=%s use=%d/%d budget_until=%s reason=%s err=%s",
		ev.OfflineCredential, ev.Action, ev.TargetID, ev.Subject, ev.CacheID,
		fmtTime(ev.PrepositionedAt), ev.Criticality, ev.Use, ev.MaxUses,
		fmtTime(ev.BudgetValidUntil), ev.Reason, ev.Err)
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
