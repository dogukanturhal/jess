// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"io"

	"github.com/dogukanturhal/hexx-pep-core/pkg/chain"
)

// JSONSink writes each Event as a tamper-evident JSON line to w (e.g. stdout,
// then shipped to Loki/Tempo/SIEM). The hash-chain bookkeeping lives in
// the shared hexx-pep-core/pkg/chain primitive (ADR 0031); JSONSink is a
// thin Jess-shaped wrapper that keeps the audit.Sink interface stable for
// the rest of the broker (spine.Controller, spine.WorkerRuntime,
// dbproxy.Run).
//
// Concurrency-safe (delegates to chain.JSONLChain's internal mutex).
type JSONSink struct {
	c *chain.JSONLChain
}

// NewJSONSink writes newline-delimited JSON events to w.
func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{c: chain.NewJSONLChain(w)} }

// Emit writes one event, stamping seq + prev_hash and advancing the chain.
// audit.Event implements chain.Stamper (via the embedded chain.Stamp) and
// chain.TimeStamper (via Event.StampTime), so all the hash-chain bookkeeping
// happens inside chain.JSONLChain.Emit.
func (s *JSONSink) Emit(ctx context.Context, ev Event) error {
	return s.c.Emit(ctx, &ev)
}
