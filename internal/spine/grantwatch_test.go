// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dogukanturhal/jess/internal/jit"
)

// TestClassifyGrantError pins the permanent-vs-transient split that drives
// the Phase 5g-6 transient-error tolerance. Every entry here corresponds
// to a real error AssertActiveID can return; if the upstream error shape
// drifts, this test catches it and the operator is forced to re-classify.
func TestClassifyGrantError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantReason string
		wantPerm   bool
	}{
		{
			name:       "ErrNoGrant — grant deleted or never existed → revoked",
			err:        jit.ErrNoGrant,
			wantReason: "grant_revoked",
			wantPerm:   true,
		},
		{
			name:       "wrapped ErrNoGrant survives — fmt.Errorf chain",
			err:        fmt.Errorf("lookup: %w", jit.ErrNoGrant),
			wantReason: "grant_revoked",
			wantPerm:   true,
		},
		{
			name:       "grant exists but is for different target → target mismatch",
			err:        errors.New("jit: grant \"g-1\" is not for target \"node-app-01\""),
			wantReason: "grant_target_mismatch",
			wantPerm:   true,
		},
		{
			name:       "grant expired between sessions → expired",
			err:        errors.New("jit: grant \"g-1\" expired"),
			wantReason: "grant_expired",
			wantPerm:   true,
		},
		{
			name:       "transient pg error → tolerate",
			err:        errors.New("jit: query grant: pq: connection refused"),
			wantReason: "",
			wantPerm:   false,
		},
		{
			name:       "transient timeout → tolerate",
			err:        errors.New("jit: query grant: context deadline exceeded"),
			wantReason: "",
			wantPerm:   false,
		},
		{
			name:       "unknown error string → tolerate (fail-OPEN on classifier; transient counter handles persistent case)",
			err:        errors.New("something completely unexpected"),
			wantReason: "",
			wantPerm:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, perm := classifyGrantError(c.err)
			if reason != c.wantReason {
				t.Errorf("reason = %q, want %q", reason, c.wantReason)
			}
			if perm != c.wantPerm {
				t.Errorf("permanent = %v, want %v", perm, c.wantPerm)
			}
		})
	}
}
