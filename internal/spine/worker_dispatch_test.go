// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/dbproxy"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/mysqlproxy"
	"github.com/dogukanturhal/jess/internal/tunnel"
)

// These tests pin the ADR 0049 Phase 2/4 worker DISPATCH wiring: that the
// ProtoPostgres and ProtoMySQL arms now run THROUGH the broker.Broker
// (Mint→Dial→Wait→Close, like SSH) rather than the direct dbproxy/mysqlproxy
// path. They prove it WITHOUT a live database by asserting the broker's
// fail-closed semantics surface through the worker: a Recorded=true DB target
// with no recorder configured is DENIED at the broker's Dial — a deny that only
// exists on the broker path (the old direct path had no per-statement WORM
// recorder, so it could never fail closed). The full wire round-trip lives in
// the broker package's docker-gated tests.

// captureSink records every emitted audit event for assertions.
type captureSink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (c *captureSink) Emit(_ context.Context, ev audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, ev)
	return nil
}

func (c *captureSink) actions() (out []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.evs {
		out = append(out, e.Action)
	}
	return out
}

func (c *captureSink) lastDeny() (audit.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.evs) - 1; i >= 0; i-- {
		if c.evs[i].Action == "deny" {
			return c.evs[i], true
		}
	}
	return audit.Event{}, false
}

// fakeStream is a minimal tunnel.SessionStream carrying a fixed header. Its
// net.Conn behaviour is unused: the dispatch tests stop at Mint/Dial, before any
// bytes flow.
type fakeStream struct {
	net.Conn
	hdr tunnel.SessionHeader
}

func (s *fakeStream) Header() tunnel.SessionHeader { return s.hdr }
func (s *fakeStream) Read([]byte) (int, error)     { return 0, io.EOF }
func (s *fakeStream) Write(p []byte) (int, error)  { return len(p), nil }
func (s *fakeStream) Close() error                 { return nil }

// dispatchFixture wires a worker with an active grant for one target and returns
// the worker, the capture sink, and the matching session stream.
func dispatchFixture(t *testing.T, target *catalog.Target, wr *WorkerRuntime) (*WorkerRuntime, *captureSink, *fakeStream) {
	t.Helper()
	jb := jit.NewMemoryBroker()
	g := jb.Issue("op@hexxlock", target.ID, time.Minute)
	sink := &captureSink{}
	wr.ID = "worker-1"
	wr.Cat = catalog.NewMemoryCatalog(target)
	wr.JIT = jb
	wr.Audit = sink
	stream := &fakeStream{hdr: tunnel.SessionHeader{
		TargetID: target.ID, Protocol: string(target.Protocol),
		GrantID: g.ID, Subject: "op@hexxlock",
	}}
	return wr, sink, stream
}

// TestPostgresArmDeniesWhenUnconfigured proves the ProtoPostgres arm still denies
// when no DB proxy is wired (unchanged behaviour).
func TestPostgresArmDeniesWhenUnconfigured(t *testing.T) {
	target := &catalog.Target{ID: "pg", Protocol: catalog.ProtoPostgres, Address: "10.0.0.5:5432", Database: "app"}
	wr, sink, stream := dispatchFixture(t, target, &WorkerRuntime{})
	wr.handle(stream)
	dev, ok := sink.lastDeny()
	if !ok {
		t.Fatalf("expected a deny, got actions %v", sink.actions())
	}
	if dev.Protocol != string(catalog.ProtoPostgres) {
		t.Errorf("deny protocol = %q, want postgres", dev.Protocol)
	}
}

// TestPostgresArmRoutesThroughBrokerFailClosed proves the ProtoPostgres arm goes
// THROUGH the broker: a Recorded=true target with a configured proxy but NO
// recorder is denied at the broker's Dial (fail-closed), and no "open"/"close"
// is emitted. This deny is uniquely a broker-path behaviour.
func TestPostgresArmRoutesThroughBrokerFailClosed(t *testing.T) {
	target := &catalog.Target{ID: "pg", Protocol: catalog.ProtoPostgres, Address: "10.0.0.5:5432", Database: "app", Recorded: true}
	wr, sink, stream := dispatchFixture(t, target, &WorkerRuntime{
		// proxy-creds mode: a CredsFor present, no standalone CredBroker, no Recorder.
		DB: &dbproxy.Config{CredsFor: func(context.Context, *catalog.Target) (string, error) {
			return "postgres://u:p@10.0.0.5:5432/app", nil
		}},
	})
	wr.handle(stream)

	for _, a := range sink.actions() {
		if a == "open" || a == "close" {
			t.Fatalf("Recorded target with no recorder must be denied before open; got actions %v", sink.actions())
		}
	}
	dev, ok := sink.lastDeny()
	if !ok {
		t.Fatalf("expected a fail-closed deny, got actions %v", sink.actions())
	}
	if dev.Protocol != string(catalog.ProtoPostgres) {
		t.Errorf("deny protocol = %q, want postgres", dev.Protocol)
	}
}

// TestMySQLArmRoutesThroughBrokerFailClosed is the MySQL twin of the Postgres
// dispatch test.
func TestMySQLArmRoutesThroughBrokerFailClosed(t *testing.T) {
	target := &catalog.Target{ID: "my", Protocol: catalog.ProtoMySQL, Address: "10.0.0.7:3306", Database: "app", Recorded: true}
	wr, sink, stream := dispatchFixture(t, target, &WorkerRuntime{
		MySQL: &mysqlproxy.Config{CredsFor: func(context.Context, *catalog.Target) (mysqlproxy.TargetCreds, error) {
			return mysqlproxy.TargetCreds{Address: "10.0.0.7:3306", User: "u", Password: "p", Database: "app"}, nil
		}},
	})
	wr.handle(stream)

	for _, a := range sink.actions() {
		if a == "open" || a == "close" {
			t.Fatalf("Recorded target with no recorder must be denied before open; got actions %v", sink.actions())
		}
	}
	dev, ok := sink.lastDeny()
	if !ok {
		t.Fatalf("expected a fail-closed deny, got actions %v", sink.actions())
	}
	if dev.Protocol != string(catalog.ProtoMySQL) {
		t.Errorf("deny protocol = %q, want mysql", dev.Protocol)
	}
}

// TestMySQLArmDeniesWhenUnconfigured proves the ProtoMySQL arm denies when no
// MySQL proxy is wired.
func TestMySQLArmDeniesWhenUnconfigured(t *testing.T) {
	target := &catalog.Target{ID: "my", Protocol: catalog.ProtoMySQL, Address: "10.0.0.7:3306", Database: "app"}
	wr, sink, stream := dispatchFixture(t, target, &WorkerRuntime{})
	wr.handle(stream)
	if _, ok := sink.lastDeny(); !ok {
		t.Fatalf("expected a deny, got actions %v", sink.actions())
	}
}
