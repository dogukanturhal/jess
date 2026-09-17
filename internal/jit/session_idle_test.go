// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"testing"
	"time"
)

// Gap audit #6 — AAL3 inactivity-timeout primitives at the in-
// memory store layer. The watcher in spine.Controller depends on
// (a) Touch updating last_activity_at and (b) SessionIdleFor
// reporting the elapsed delta with a found flag.
func TestMemoryBrokerSessionActivity(t *testing.T) {
	t.Parallel()
	m := NewMemoryBroker()
	ctx := context.Background()

	sess, err := m.OpenSession(ctx, "user-1", "node-app-01", "g-1", "ssh", "ctrl-pod-0")
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// Before the worker touches the session, SessionIdleFor should
	// report found=false so the watcher knows to SKIP the idle
	// check rather than treating it as infinite idle.
	if _, found, err := m.SessionIdleFor(ctx, sess.ID); err != nil || found {
		t.Fatalf("expected (0, false, nil) before first touch, got (_, %v, %v)", found, err)
	}

	// Touch — worker emits one keepalive on first byte transfer.
	if err := m.TouchSessionActivity(ctx, sess.ID); err != nil {
		t.Fatalf("TouchSessionActivity: %v", err)
	}

	// Now SessionIdleFor should report a small delta, found=true.
	time.Sleep(10 * time.Millisecond)
	idle, found, err := m.SessionIdleFor(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SessionIdleFor: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true after TouchSessionActivity")
	}
	if idle < 5*time.Millisecond || idle > 5*time.Second {
		t.Fatalf("expected ~10ms idle, got %v", idle)
	}

	// Touch again — idle resets.
	if err := m.TouchSessionActivity(ctx, sess.ID); err != nil {
		t.Fatalf("TouchSessionActivity (2nd): %v", err)
	}
	idle2, _, _ := m.SessionIdleFor(ctx, sess.ID)
	if idle2 > idle {
		t.Fatalf("expected idle to reset after 2nd touch — was %v, now %v", idle, idle2)
	}

	// Unknown id is no-op + no-error on both methods.
	if err := m.TouchSessionActivity(ctx, "unknown-sess"); err != nil {
		t.Fatalf("Touch on unknown id should be no-op, got %v", err)
	}
	if _, found, err := m.SessionIdleFor(ctx, "unknown-sess"); err != nil || found {
		t.Fatalf("SessionIdleFor on unknown id should return (0,false,nil), got (_, %v, %v)", found, err)
	}
}
