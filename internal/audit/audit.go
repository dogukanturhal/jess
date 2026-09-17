// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit emits structured session events to the shared funnel
// (Loki/Tempo) — the same audit surface Talon uses (ADR 0030).
//
// The tamper-evident hash chain primitive lives in
// github.com/dogukanturhal/hexx-pep-core/pkg/chain (ADR 0031); this
// package keeps the Jess-specific Event shape and the Sink interface
// callers already wire against, so spine/controller.go and spine/worker.go
// don't change.
package audit

import (
	"context"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/chain"
)

// Event is one auditable moment in a brokered session. The embedded
// chain.Stamp carries the seq + prev_hash hash-chain fields the Sink
// populates on every Emit — callers MUST NOT set them directly.
type Event struct {
	chain.Stamp
	Time       time.Time `json:"time"`
	Subject    string    `json:"subject,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Action     string    `json:"action"` // authorize | open | close | deny | query
	DecisionID string    `json:"decision_id,omitempty"`
	Region     string    `json:"region,omitempty"`
	Bytes      int64     `json:"bytes,omitempty"`
	Query      string    `json:"query,omitempty"` // SQL for db-broker query audit (truncated)
	Err        string    `json:"err,omitempty"`
}

// StampTime implements chain.TimeStamper: the shared Sink stamps Time only
// when it's zero, so callers retain the option to set Time explicitly for
// replay/backfill scenarios.
func (e *Event) StampTime(t time.Time) {
	if e.Time.IsZero() {
		e.Time = t
	}
}

// Sink receives events. The public API the rest of Jess wires against
// (spine.Controller, spine.WorkerRuntime). Implementations: JSONSink below
// for stdout/file; future OTLP / Loki push live here too.
type Sink interface {
	Emit(ctx context.Context, ev Event) error
}
