// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// DDIL P3.8 handler-level test: pre-positioned offline credentials must NOT
// bypass the JIT grant gate. The grant assertion runs BEFORE credentialFor (the
// only entry to the offline path), so a session with no active grant is denied
// even when a valid pre-positioned credential is sitting ready and Vault is
// unreachable.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/broker"
	"github.com/dogukanturhal/jess/internal/offlinecreds"
)

// prepositionedMinter yields one fixed pre-positioned RDP credential.
type prepositionedMinter struct{ sec broker.RDPSecret }

func (m prepositionedMinter) Mint(_ context.Context, _ string) (offlinecreds.MintResult, error) {
	p, _ := json.Marshal(m.sec)
	return offlinecreds.MintResult{Payload: p, TTL: time.Hour, LeaseID: "l"}, nil
}

func TestRDPLiveOfflineCredStillRequiresGrant(t *testing.T) {
	// A manager with a pre-positioned credential ready to serve offline.
	mgr, err := offlinecreds.New(offlinecreds.Config{
		Minter: prepositionedMinter{sec: broker.RDPSecret{Kind: broker.RDPSecretADCredential, Username: "prepositioned", Password: "p"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mgr.Register(offlinecreds.TargetPolicy{
		TargetID: "win-dc-01", Criticality: "high",
		Policy: offlinecreds.Policy{Enabled: true, MaxTTL: time.Hour, MaxUses: 3},
	}); rerr != nil {
		t.Fatalf("Register: %v", rerr)
	}
	if perr := mgr.Prewarm(context.Background(), "win-dc-01"); perr != nil {
		t.Fatalf("Prewarm: %v", perr)
	}

	// inner online mint would "succeed" if ever reached — proving the denial is
	// the grant gate, not a mint failure. calls must stay 0.
	inner := &fakeSessionCreds{sec: broker.RDPSecret{Kind: broker.RDPSecretADCredential, Username: "online", Password: "p"}, ttl: time.Minute}
	wrapper, err := broker.NewOfflineRDPCredBroker(inner, mgr)
	if err != nil {
		t.Fatal(err)
	}

	srv, cookie := newTestRDPLiveServerVault(t, &fakeLiveEngine{}, wrapper)

	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01") // NO grant
	defer ws.Close()

	mt, payload := readWSBinary(t, ws)
	if mt != liveMsgError {
		t.Fatalf("first frame type = %d, want error(0xFF) for missing grant", mt)
	}
	if !strings.Contains(string(payload), "not authorized") {
		t.Errorf("error payload = %q, want the stable not-authorized message", payload)
	}
	// The security-relevant proof: the credential path (online OR offline) was
	// never reached — the grant gate fired first.
	if inner.calls != 0 {
		t.Errorf("credential path reached despite missing grant (inner.calls=%d) — offline creds must NOT bypass the JIT grant gate", inner.calls)
	}
}
