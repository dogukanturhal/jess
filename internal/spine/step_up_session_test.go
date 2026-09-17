// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/stepup"
	"github.com/dogukanturhal/jess/internal/tunnel"
	"github.com/dogukanturhal/jess/internal/wire"
)

// mintStepUpToken mints a signed operator token carrying amr + auth_time so the
// P2.5 per-session step-up gate can be exercised end-to-end through the spine.
func mintStepUpToken(t *testing.T, key *rsa.PrivateKey, sub string, roles, amr []string, authTime time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   testIssuer,
		"sub":   sub,
		"aud":   testClientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"roles": roles,
	}
	if amr != nil {
		claims["amr"] = amr
	}
	if !authTime.IsZero() {
		claims["auth_time"] = authTime.Unix()
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPerSessionStepUpGate proves the P2.5 session-open step-up enforcement on
// an `elevated` target: an unsatisfied step-up is DENIED with step_up_required;
// a satisfied one PASSES the gate (reaching the later "no worker available"
// deny, which proves the step-up gate let it through). The gate composes with —
// never weakens — the existing role/grant checks.
func TestPerSessionStepUpGate(t *testing.T) {
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := pdp.NewVerifierFromKeySet(testIssuer, testClientID, []crypto.PublicKey{&signKey.PublicKey})

	// Fresh controller + listener + audit buffer per run (audit accumulates).
	run := func(t *testing.T, target *catalog.Target, token string) string {
		cat := catalog.NewMemoryCatalog(target)
		jb := jit.NewMemoryBroker()
		var buf safeBuffer
		ctrl := &Controller{
			Pool: tunnel.NewYamuxPool(), Cat: cat, JIT: jb,
			PDP: pdp.RoleAuthorizer{}, Verifier: verifier, Audit: audit.NewJSONSink(&buf),
		}
		ol, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ol.Close()
		go func() { _ = ctrl.ServeOperators(ol) }()

		g := jb.Issue("op@hexxlock", target.ID, time.Minute)
		c, err := net.Dial("tcp", ol.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		b, _ := json.Marshal(wire.OperatorRequest{Token: token, TargetID: target.ID, GrantID: g.ID})
		_, _ = c.Write(b)

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			s := buf.String()
			if strings.Contains(s, "step_up_required") || strings.Contains(s, "no worker available") {
				return s
			}
			time.Sleep(20 * time.Millisecond)
		}
		return buf.String()
	}

	elevated := func() *catalog.Target {
		return &catalog.Target{
			ID: "proddb", Protocol: catalog.ProtoTCP, Address: "127.0.0.1:1", Region: "eu-tr",
			RequiredRoles: []string{"platform_admin"}, RequireSessionMFA: "elevated",
		}
	}
	roles := []string{"platform_admin"}
	now := time.Now()

	t.Run("satisfied-fresh-webauthn-passes-gate", func(t *testing.T) {
		tok := mintStepUpToken(t, signKey, "op@hexxlock", roles, []string{"pwd", "webauthn"}, now.Add(-1*time.Minute))
		out := run(t, elevated(), tok)
		if strings.Contains(out, "step_up_required") {
			t.Fatalf("fresh phishing-resistant step-up should PASS the gate, got: %s", out)
		}
		if !strings.Contains(out, "no worker available") {
			t.Fatalf("expected flow to reach worker lookup (gate passed), got: %s", out)
		}
	})

	t.Run("unsatisfied-totp-denied", func(t *testing.T) {
		// elevated rejects TOTP even though fresh.
		tok := mintStepUpToken(t, signKey, "op@hexxlock", roles, []string{"pwd", "totp"}, now.Add(-1*time.Minute))
		out := run(t, elevated(), tok)
		if !strings.Contains(out, "step_up_required") {
			t.Fatalf("TOTP on an elevated target must be DENIED, got: %s", out)
		}
	})

	t.Run("unsatisfied-stale-denied", func(t *testing.T) {
		// phishing-resistant factor but auth_time older than the 5min window.
		tok := mintStepUpToken(t, signKey, "op@hexxlock", roles, []string{"webauthn"}, now.Add(-30*time.Minute))
		out := run(t, elevated(), tok)
		if !strings.Contains(out, "step_up_required") {
			t.Fatalf("a stale step-up assertion must be DENIED, got: %s", out)
		}
	})

	t.Run("unsatisfied-no-authtime-denied", func(t *testing.T) {
		// no auth_time claim → freshness unprovable → deny (closes the static-amr gap).
		tok := mintStepUpToken(t, signKey, "op@hexxlock", roles, []string{"webauthn"}, time.Time{})
		out := run(t, elevated(), tok)
		if !strings.Contains(out, "step_up_required") {
			t.Fatalf("a token with no auth_time must be DENIED for a step-up tier, got: %s", out)
		}
	})

	t.Run("none-tier-not-gated", func(t *testing.T) {
		// A target with no step-up tier proceeds regardless of amr/auth_time.
		tgt := &catalog.Target{
			ID: "lowrisk", Protocol: catalog.ProtoTCP, Address: "127.0.0.1:1", Region: "eu-tr",
			RequiredRoles: []string{"platform_admin"},
		}
		tok := mintStepUpToken(t, signKey, "op@hexxlock", roles, nil, time.Time{})
		out := run(t, tgt, tok)
		if strings.Contains(out, "step_up_required") {
			t.Fatalf("a none-tier target must not be step-up gated, got: %s", out)
		}
		if !strings.Contains(out, "no worker available") {
			t.Fatalf("expected none-tier flow to reach worker lookup, got: %s", out)
		}
	})
}

// TestStepUpWatchStale unit-tests the mid-session freshness re-check the
// continuous grant-watch runs each tick (P2.5): an assertion that has aged out
// of the tier window reports stale (→ session torn down), a fresh one does not.
func TestStepUpWatchStale(t *testing.T) {
	now := time.Now()
	fresh := &stepUpWatch{amr: []string{"webauthn"}, authTime: now.Add(-1 * time.Minute), policy: stepup.PolicyElevated, maxAge: 5 * time.Minute}
	if stale, _ := fresh.stale(now); stale {
		t.Error("a fresh elevated assertion must not be stale")
	}
	aged := &stepUpWatch{amr: []string{"webauthn"}, authTime: now.Add(-30 * time.Minute), policy: stepup.PolicyElevated, maxAge: 5 * time.Minute}
	if stale, reason := aged.stale(now); !stale || reason == "" {
		t.Errorf("an aged-out elevated assertion must be stale with a reason, got stale=%v reason=%q", stale, reason)
	}
	var none *stepUpWatch
	if stale, _ := none.stale(now); stale {
		t.Error("a nil watch (none tier) is never stale")
	}
}
