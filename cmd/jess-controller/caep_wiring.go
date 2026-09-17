// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5h-6 — CAEP-subscriber audit adapter. Bridges
// caep.AuditEmitter into the existing audit.Sink the controller
// already writes session-grant + revocation events through. Same
// JSONL stream → same SOC2 evidence ingest → single source of truth
// across all jess-side audit paths.

import (
	"context"
	"fmt"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
)

type caepAuditAdapter struct {
	sink audit.Sink
}

func (a caepAuditAdapter) EmitCAEPRevoke(ctx context.Context, eventType, subject string, revokedCount int) {
	if a.sink == nil {
		return
	}
	// Action name "revoke.caep" distinguishes CAEP-triggered revocations
	// from operator-initiated /admin/revoke and from the 10s
	// continuous-grant-watch ("revoke.watch"). The audit trail names
	// the propagation channel that found the revocation, which matters
	// for incident timelines (CAEP = <1s; watch = up to 10s).
	_ = a.sink.Emit(ctx, audit.Event{
		Time:    time.Now(),
		Action:  "revoke.caep",
		Subject: "system:caep-subscriber",
		Err: fmt.Sprintf("caep_event=%s target_subject=%s grants_revoked=%d",
			eventType, subject, revokedCount),
	})
}
