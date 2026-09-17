// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/offlinecreds"
)

// fakeInnerCreds is a stand-in for the online Vault per-session mint.
type fakeInnerCreds struct {
	calls int
	sec   RDPSecret
	ttl   time.Duration
	err   error
}

func (f *fakeInnerCreds) IssueForOperator(_ context.Context, _, _ string) (RDPSecret, time.Duration, error) {
	f.calls++
	if f.err != nil {
		return RDPSecret{}, 0, f.err
	}
	return f.sec, f.ttl, nil
}

// staticOfflineMinter returns a fixed RDPSecret as the pre-positioned payload.
type staticOfflineMinter struct {
	sec RDPSecret
	ttl time.Duration
}

func (m staticOfflineMinter) Mint(_ context.Context, _ string) (offlinecreds.MintResult, error) {
	p, _ := json.Marshal(m.sec)
	return offlinecreds.MintResult{Payload: p, TTL: m.ttl, LeaseID: "l"}, nil
}

func newPrewarmedMgr(t *testing.T, targetID, crit string, prepos RDPSecret) *offlinecreds.Manager {
	t.Helper()
	mgr, err := offlinecreds.New(offlinecreds.Config{
		Minter: staticOfflineMinter{sec: prepos, ttl: time.Hour},
		Caps:   offlinecreds.DefaultCaps(),
	})
	if err != nil {
		t.Fatalf("offlinecreds.New: %v", err)
	}
	if rerr := mgr.Register(offlinecreds.TargetPolicy{
		TargetID: targetID, Criticality: crit,
		Policy: offlinecreds.Policy{Enabled: true, MaxTTL: time.Hour, MaxUses: 3},
	}); rerr != nil {
		t.Fatalf("Register: %v", rerr)
	}
	if perr := mgr.Prewarm(context.Background(), targetID); perr != nil {
		t.Fatalf("Prewarm: %v", perr)
	}
	return mgr
}

// TestOfflineRDP_OnlinePassthrough: while Vault is reachable the wrapper is a
// transparent pass-through — the online mint is returned and no pre-positioned
// credential is consulted.
func TestOfflineRDP_OnlinePassthrough(t *testing.T) {
	online := RDPSecret{Kind: RDPSecretADCredential, Username: "online-eph", Password: "p"}
	inner := &fakeInnerCreds{sec: online, ttl: 15 * time.Minute}
	mgr := newPrewarmedMgr(t, "app-01", "high", RDPSecret{Username: "prepositioned"})

	b, err := NewOfflineRDPCredBroker(inner, mgr)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := b.IssueForOperator(context.Background(), "app-01", "op")
	if err != nil {
		t.Fatalf("online passthrough err = %v", err)
	}
	if got.Username != "online-eph" {
		t.Fatalf("got %q, want the ONLINE mint (not the pre-positioned cred)", got.Username)
	}
}

// TestOfflineRDP_ContingencyWhenUnreachable: on an unreachable Vault the wrapper
// serves the pre-positioned credential.
func TestOfflineRDP_ContingencyWhenUnreachable(t *testing.T) {
	inner := &fakeInnerCreds{err: errors.New("dial tcp: connection refused")} // no HTTP status ⇒ unreachable
	mgr := newPrewarmedMgr(t, "app-01", "high", RDPSecret{Kind: RDPSecretADCredential, Username: "prepositioned", Password: "s"})

	b, err := NewOfflineRDPCredBroker(inner, mgr)
	if err != nil {
		t.Fatal(err)
	}
	got, ttl, err := b.IssueForOperator(context.Background(), "app-01", "op")
	if err != nil {
		t.Fatalf("contingency err = %v, want served", err)
	}
	if got.Username != "prepositioned" {
		t.Fatalf("got %q, want the pre-positioned credential", got.Username)
	}
	if ttl <= 0 {
		t.Errorf("served TTL = %s, want the remaining lease > 0", ttl)
	}
}

// TestOfflineRDP_GenuineRejectionFailsClosed: a genuine (4xx) Vault rejection
// must fail closed and NEVER be masked by a pre-positioned credential.
func TestOfflineRDP_GenuineRejectionFailsClosed(t *testing.T) {
	sentinel := errors.New("vault 403: permission denied")
	inner := &fakeInnerCreds{err: sentinel}
	mgr := newPrewarmedMgr(t, "app-01", "high", RDPSecret{Username: "prepositioned"})

	b, err := NewOfflineRDPCredBroker(inner, mgr)
	if err != nil {
		t.Fatal(err)
	}
	// Force the classifier to call this a genuine rejection (not a partition).
	b.unreachable = func(error) bool { return false }

	got, _, err := b.IssueForOperator(context.Background(), "app-01", "op")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the genuine rejection propagated (fail closed)", err)
	}
	if got.Username == "prepositioned" {
		t.Fatal("a 4xx rejection must NOT be served the pre-positioned credential")
	}
}

// TestOfflineRDP_Tier0NeverServed: a Tier-0 target is never pre-positioned, so an
// unreachable Vault fails closed even though the operator opted it in.
func TestOfflineRDP_Tier0NeverServed(t *testing.T) {
	inner := &fakeInnerCreds{err: errors.New("connection refused")}
	mgr, err := offlinecreds.New(offlinecreds.Config{
		Minter: staticOfflineMinter{sec: RDPSecret{Username: "prepositioned"}, ttl: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewOfflineRDPCredBroker(inner, mgr)
	if err != nil {
		t.Fatal(err)
	}
	// Operator opts a DC in via its CRD — the wrapper refuses it un-overridably.
	b.RegisterTarget(&catalog.Target{ID: "dc-01", Criticality: "critical",
		OfflineCredentials: &catalog.OfflineCredentialsPolicy{Enabled: true, MaxTTL: time.Hour, MaxUses: 3}})
	if mgr.Registered("dc-01") || mgr.HasPrepositioned("dc-01") {
		t.Fatal("Tier-0 target must never be registered/pre-positioned")
	}
	if _, _, cerr := b.IssueForOperator(context.Background(), "dc-01", "op"); cerr == nil {
		t.Fatal("Tier-0 target with Vault down must FAIL CLOSED (no offline cred)")
	}
}

// TestOfflineRDP_RegisterTargetEligibility: RegisterTarget honours the CRD opt-in
// and the default-not-eligible + Tier-0 rules.
func TestOfflineRDP_RegisterTargetEligibility(t *testing.T) {
	mgr, err := offlinecreds.New(offlinecreds.Config{Minter: staticOfflineMinter{ttl: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewOfflineRDPCredBroker(&fakeInnerCreds{}, mgr)
	if err != nil {
		t.Fatal(err)
	}

	// No policy ⇒ not eligible.
	b.RegisterTarget(&catalog.Target{ID: "app-nopol", Criticality: "medium"})
	if mgr.Registered("app-nopol") {
		t.Error("target with no OfflineCredentials must NOT be registered")
	}
	// Enabled + non-Tier-0 ⇒ registered.
	b.RegisterTarget(&catalog.Target{ID: "app-ok", Criticality: "high",
		OfflineCredentials: &catalog.OfflineCredentialsPolicy{Enabled: true}})
	if !mgr.Registered("app-ok") {
		t.Error("opted-in non-Tier-0 target must be registered")
	}
	// Enabled=false ⇒ not eligible.
	b.RegisterTarget(&catalog.Target{ID: "app-off", Criticality: "low",
		OfflineCredentials: &catalog.OfflineCredentialsPolicy{Enabled: false}})
	if mgr.Registered("app-off") {
		t.Error("explicitly disabled target must NOT be registered")
	}
}
