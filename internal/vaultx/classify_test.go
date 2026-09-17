// SPDX-License-Identifier: AGPL-3.0-or-later

package vaultx

import (
	"errors"
	"fmt"
	"testing"
)

// TestIsUnreachableClassification proves the DDIL fail-direction gate: a
// partition/availability failure (transport, 5xx, 429) is "unreachable" (⇒ the
// offline-creds path may engage), while a genuine 4xx rejection is NOT (⇒ fail
// closed, never masked as a partition).
func TestIsUnreachableClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transport error (no status)", errors.New("dial tcp: connection refused"), true},
		{"wrapped transport error", fmt.Errorf("vaultx: ldap creds: %w", errors.New("timeout")), true},
		{"500", &vaultError{status: 500, msg: "internal"}, true},
		{"503 throttle", &vaultError{status: 503, msg: "unavailable"}, true},
		{"429 rate limited", &vaultError{status: 429, msg: "slow down"}, true},
		{"wrapped 502", fmt.Errorf("vaultx: mint: %w", &vaultError{status: 502}), true},
		{"400 bad request", &vaultError{status: 400, msg: "bad"}, false},
		{"401 unauthorized", &vaultError{status: 401, msg: "no token"}, false},
		{"403 permission denied", &vaultError{status: 403, msg: "denied"}, false},
		{"404 unknown role", &vaultError{status: 404, msg: "no role"}, false},
		{"wrapped 403", fmt.Errorf("vaultx: mint: %w", &vaultError{status: 403}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUnreachable(tc.err); got != tc.want {
				t.Fatalf("IsUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestStatusCodeUnwraps confirms StatusCode reaches the underlying *vaultError
// through %w wrapping.
func TestStatusCodeUnwraps(t *testing.T) {
	if st, ok := StatusCode(fmt.Errorf("outer: %w", &vaultError{status: 503})); !ok || st != 503 {
		t.Fatalf("StatusCode = (%d,%v), want (503,true)", st, ok)
	}
	if _, ok := StatusCode(errors.New("plain")); ok {
		t.Fatal("StatusCode of a non-vault error must be (_, false)")
	}
}
