// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import "testing"

// Gap audit #3 — NIST SP 800-63B-4 §3.2.5 phishing-resistant
// authenticator enforcement. The unified gate (signature includes
// phishingResistantOnly) MUST reject AMR values like otp/totp/mfa
// even when they appear in the require-any list, when the flag is
// true.
func TestSatisfiesStepUpPhishingResistantOnly(t *testing.T) {
	t.Parallel()
	type tc struct {
		name              string
		tokenAMR          []string
		requireAny        []string
		phishingResistant bool
		want              bool
	}
	cases := []tc{
		{
			name:              "legacy-mode-otp-matches",
			tokenAMR:          []string{"otp"},
			requireAny:        []string{"otp", "totp", "hwk"},
			phishingResistant: false,
			want:              true,
		},
		{
			name:              "pr-mode-otp-blocked",
			tokenAMR:          []string{"otp"},
			requireAny:        []string{"otp", "totp", "hwk"},
			phishingResistant: true,
			want:              false,
		},
		{
			name:              "pr-mode-webauthn-passes",
			tokenAMR:          []string{"webauthn"},
			requireAny:        []string{"otp", "totp", "hwk", "webauthn"},
			phishingResistant: true,
			want:              true,
		},
		{
			name:              "pr-mode-hwk-passes",
			tokenAMR:          []string{"hwk"},
			requireAny:        []string{"hwk", "webauthn"},
			phishingResistant: true,
			want:              true,
		},
		{
			name:              "pr-mode-piv-passes",
			tokenAMR:          []string{"piv"},
			requireAny:        []string{"piv", "cac", "hwk", "webauthn"},
			phishingResistant: true,
			want:              true,
		},
		{
			name:              "pr-mode-mfa-bare-blocked",
			tokenAMR:          []string{"mfa"},
			requireAny:        []string{"mfa"},
			phishingResistant: true,
			want:              false,
		},
		{
			name:              "empty-require-fails-closed",
			tokenAMR:          []string{"webauthn"},
			requireAny:        nil,
			phishingResistant: true,
			want:              false,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := satisfiesStepUp(c.tokenAMR, c.requireAny, c.phishingResistant)
			if got != c.want {
				t.Fatalf("satisfiesStepUp(%v, %v, pr=%v) = %v, want %v",
					c.tokenAMR, c.requireAny, c.phishingResistant, got, c.want)
			}
		})
	}
}

// TestIsPhishingResistantAMRValue locks the allowlist content to the
// NIST §3.2.5 four-method set. If this fails because the allowlist
// grew, update both the test AND the gap-audit ADR memo to document
// the new addition's NIST-compliance reasoning.
func TestIsPhishingResistantAMRValue(t *testing.T) {
	t.Parallel()
	pr := []string{"hwk", "webauthn", "piv", "cac"}
	non := []string{"mfa", "otp", "totp", "pwd", "pin", "sms", "voice", "email", ""}
	for _, v := range pr {
		if !isPhishingResistantAMRValue(v) {
			t.Errorf("expected %q to be phishing-resistant", v)
		}
	}
	for _, v := range non {
		if isPhishingResistantAMRValue(v) {
			t.Errorf("expected %q NOT to be phishing-resistant", v)
		}
	}
}
