// SPDX-License-Identifier: AGPL-3.0-or-later

package stepup

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    Policy
		wantErr bool
	}{
		{"", PolicyNone, false},
		{"none", PolicyNone, false},
		{"None", PolicyNone, false},
		{"standard", PolicyStandard, false},
		{" ELEVATED ", PolicyElevated, false},
		{"elevatd", PolicyNone, true}, // typo → error (fail-closed at caller)
		{"strict", PolicyNone, true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("Parse(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultMaxAgeAndOverride(t *testing.T) {
	t.Parallel()
	if PolicyStandard.DefaultMaxAge() != time.Hour {
		t.Errorf("standard default max-age = %s want 1h", PolicyStandard.DefaultMaxAge())
	}
	if PolicyElevated.DefaultMaxAge() != 5*time.Minute {
		t.Errorf("elevated default max-age = %s want 5m", PolicyElevated.DefaultMaxAge())
	}
	if got := PolicyElevated.EffectiveMaxAge(300); got != 5*time.Minute {
		t.Errorf("override 300s = %s want 5m", got)
	}
	if got := PolicyElevated.EffectiveMaxAge(0); got != 5*time.Minute {
		t.Errorf("zero override should fall back to default, got %s", got)
	}
}

func TestPhishingResistant(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"hwk", "webauthn", "piv", "cac", "WebAuthn"} {
		if !IsPhishingResistant(v) {
			t.Errorf("expected %q phishing-resistant", v)
		}
	}
	for _, v := range []string{"mfa", "otp", "totp", "pwd", "sms", ""} {
		if IsPhishingResistant(v) {
			t.Errorf("expected %q NOT phishing-resistant", v)
		}
	}
	if !PolicyElevated.PhishingResistantOnly() || PolicyStandard.PhishingResistantOnly() {
		t.Error("only elevated must be phishing-resistant-only")
	}
}

func TestSatisfied(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-2 * time.Minute)   // within both windows
	old1h := now.Add(-90 * time.Minute)  // beyond 1h + skew
	old10m := now.Add(-10 * time.Minute) // beyond 5m + skew, within 1h

	cases := []struct {
		name     string
		amr      []string
		authTime time.Time
		policy   Policy
		maxAge   time.Duration
		wantOK   bool
	}{
		// none: always satisfied.
		{"none-always-ok", nil, time.Time{}, PolicyNone, 0, true},

		// standard: fresh + acceptable factor (TOTP allowed).
		{"standard-fresh-totp-ok", []string{"pwd", "totp"}, fresh, PolicyStandard, time.Hour, true},
		{"standard-fresh-webauthn-ok", []string{"webauthn"}, fresh, PolicyStandard, time.Hour, true},
		// standard: missing auth_time → deny (freshness unprovable).
		{"standard-no-authtime-deny", []string{"totp"}, time.Time{}, PolicyStandard, time.Hour, false},
		// standard: stale → deny.
		{"standard-stale-deny", []string{"totp"}, old1h, PolicyStandard, time.Hour, false},
		// standard: fresh but no acceptable factor → deny.
		{"standard-no-factor-deny", []string{"pwd"}, fresh, PolicyStandard, time.Hour, false},

		// elevated: fresh + phishing-resistant factor → allow.
		{"elevated-fresh-hwk-ok", []string{"hwk"}, fresh, PolicyElevated, 5 * time.Minute, true},
		{"elevated-fresh-piv-ok", []string{"pwd", "piv"}, fresh, PolicyElevated, 5 * time.Minute, true},
		// elevated: TOTP is NOT accepted even if fresh.
		{"elevated-totp-rejected", []string{"totp", "mfa"}, fresh, PolicyElevated, 5 * time.Minute, false},
		// elevated: PR factor but stale (older than 5m window) → deny.
		{"elevated-stale-deny", []string{"webauthn"}, old10m, PolicyElevated, 5 * time.Minute, false},
		// elevated: future-dated beyond skew → deny.
		{"elevated-future-deny", []string{"webauthn"}, now.Add(5 * time.Minute), PolicyElevated, 5 * time.Minute, false},
		// elevated: within skew freshness edge → allow (auth_time exactly at window+skew boundary).
		{"elevated-within-skew-ok", []string{"webauthn"}, now.Add(-6 * time.Minute), PolicyElevated, 5 * time.Minute, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ok, reason := Satisfied(c.amr, c.authTime, now, c.maxAge, c.policy)
			if ok != c.wantOK {
				t.Fatalf("Satisfied(%v, authTime=%v, %s) = %v (%q), want %v",
					c.amr, c.authTime, c.policy, ok, reason, c.wantOK)
			}
			if !ok && reason == "" {
				t.Error("a denial must carry a reason")
			}
		})
	}
}

func TestAcrValues(t *testing.T) {
	t.Parallel()
	if PolicyNone.AcrValues() != nil {
		t.Error("none has no acr_values")
	}
	got := PolicyElevated.AcrValues()
	want := map[string]bool{"urn:falcon-id:hwk": true, "urn:falcon-id:webauthn": true, "urn:falcon-id:piv": true, "urn:falcon-id:cac": true}
	if len(got) != len(want) {
		t.Fatalf("elevated acr_values = %v", got)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected acr value %q", v)
		}
	}
}
