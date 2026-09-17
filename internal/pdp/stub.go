// SPDX-License-Identifier: AGPL-3.0-or-later

package pdp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// StubAuthorizer is a placeholder PDP for Phase 5a: it ALLOWS every request
// and stamps a decision ID. The real FalconIDPDP (Falcon-ID identity + role/
// group + region + JIT-grant policy) replaces it in 5b/5d. The JIT gate in the
// controller/worker is enforced independently of this stub, so "allow-all"
// here does NOT mean "access without a grant".
type StubAuthorizer struct{}

func decisionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "dec-" + hex.EncodeToString(b)
}

// Authorize allows the request (stub).
func (StubAuthorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	return Decision{
		Allow:      true,
		Reason:     "stub: allow-all (ADR 0030 Phase 5a; real PDP in 5b)",
		DecisionID: decisionID(),
		TTL:        15 * time.Minute,
	}, nil
}
