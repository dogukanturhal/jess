// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/dbproxy"
	"github.com/dogukanturhal/jess/internal/recording"
)

// These tests exercise the ADR 0049 Phase 2 Postgres Broker at the seam: the
// per-statement policy (statement extraction + allow/deny) and the
// recorded-statement wiring (every brokered statement teed into the WORM query
// log with the right decision), plus the Mint/Dial validation + fail-closed
// paths — all WITHOUT a live Postgres (the dbproxy package has the docker-gated
// full wire round-trip; here we prove the broker's own logic deterministically).

// --- credential broker + recorder fakes -------------------------------------

// fakeDBCreds is a stand-in CredentialBroker that records which Vault role was
// asked for and returns fixed ephemeral creds. SignSSH is unused for DB.
type fakeDBCreds struct {
	role string
	err  error
}

func (f *fakeDBCreds) SignSSH(context.Context, []byte, []string, time.Duration) ([]byte, error) {
	return nil, nil
}
func (f *fakeDBCreds) IssueDBCreds(_ context.Context, role string) (string, string, error) {
	f.role = role
	if f.err != nil {
		return "", "", f.err
	}
	return "ephemeral_user", "ephemeral_pass", nil
}

// fakePGConn is a minimal net.Conn for Mint/Dial-path tests that never reach a
// real wire handshake (the validation + fail-closed branches return first).
type fakePGConn struct{ net.Conn }

func (c *fakePGConn) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *fakePGConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakePGConn) Close() error                { return nil }

func TestPostgresBrokerProtocol(t *testing.T) {
	b := NewPostgresBroker(&dbproxy.Config{}, &fakeDBCreds{}, nil)
	if got := b.Protocol(); got != string(catalog.ProtoPostgres) {
		t.Fatalf("Protocol() = %q, want %q", got, catalog.ProtoPostgres)
	}
}

// TestPostgresBrokerMint proves Mint mints the ephemeral DB role scoped to the
// target (role = target ID) and assembles an injected DSN the operator never
// sees, and validates the grant fail-closed.
func TestPostgresBrokerMint(t *testing.T) {
	creds := &fakeDBCreds{}
	b := NewPostgresBroker(&dbproxy.Config{}, creds, nil)
	target := &catalog.Target{ID: "falcon-id-db", Protocol: catalog.ProtoPostgres, Address: "10.0.0.5:5432", Database: "falconid"}

	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, GrantID: "g1", Subject: "op@test", Client: &fakePGConn{}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if creds.role != "falcon-id-db" {
		t.Errorf("minted Vault role = %q, want target ID %q", creds.role, "falcon-id-db")
	}
	pc, ok := cred.(pgCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want pgCredential", cred)
	}
	if cred.Protocol() != string(catalog.ProtoPostgres) {
		t.Errorf("credential Protocol() = %q, want postgres", cred.Protocol())
	}
	for _, want := range []string{"ephemeral_user", "ephemeral_pass", "10.0.0.5:5432", "falconid"} {
		if !strings.Contains(pc.connString, want) {
			t.Errorf("connString %q missing %q", pc.connString, want)
		}
	}
}

// TestPostgresBrokerProxyCredsMode proves the proxy-creds fallback (ADR 0049
// worker wiring): with no standalone CredentialBroker but a proxy that already
// has a CredsFor (the worker's dbConfigFromVault), Mint succeeds and defers the
// DSN mint to the proxy's CredsFor at Wait time — so the existing prod DSN is
// reused verbatim rather than re-derived by the broker. With NEITHER a creds
// broker NOR a proxy CredsFor, Mint fails closed.
func TestPostgresBrokerProxyCredsMode(t *testing.T) {
	const wantDSN = "postgres://eph:eph@10.0.0.5:5432/falconid?sslmode=require"
	called := false
	proxy := &dbproxy.Config{CredsFor: func(context.Context, *catalog.Target) (string, error) {
		called = true
		return wantDSN, nil
	}}
	b := NewPostgresBroker(proxy, nil, nil) // no standalone creds broker
	target := &catalog.Target{ID: "falcon-id-db", Protocol: catalog.ProtoPostgres, Address: "10.0.0.5:5432", Database: "falconid"}

	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, GrantID: "g1", Subject: "op@test", Client: &fakePGConn{}})
	if err != nil {
		t.Fatalf("Mint (proxy-creds mode): %v", err)
	}
	pc, ok := cred.(pgCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want pgCredential", cred)
	}
	if pc.connString != "" {
		t.Errorf("proxy-creds mode must leave connString empty (defer to proxy), got %q", pc.connString)
	}
	if pc.credsFor == nil {
		t.Fatal("proxy-creds mode must stash the proxy CredsFor")
	}
	// The deferred CredsFor is what Wait would inject — exercise it directly.
	rc := &pgRecordedConn{cred: pc, target: target}
	cfg := rc.waitConfig()
	got, err := cfg.CredsFor(context.Background(), target)
	if err != nil {
		t.Fatalf("deferred CredsFor: %v", err)
	}
	if !called || got != wantDSN {
		t.Errorf("Wait must use the proxy CredsFor; got %q (called=%v), want %q", got, called, wantDSN)
	}

	// No creds broker AND no proxy CredsFor → fail closed.
	if _, err := NewPostgresBroker(&dbproxy.Config{}, nil, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must fail closed with neither a creds broker nor a proxy CredsFor")
	}
}

func TestPostgresBrokerMintValidation(t *testing.T) {
	b := NewPostgresBroker(&dbproxy.Config{}, &fakeDBCreds{}, nil)
	if _, err := b.Mint(context.Background(), AccessGrant{Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must reject a grant with no target")
	}
	if _, err := b.Mint(context.Background(), AccessGrant{Target: &catalog.Target{ID: "t"}}); err == nil {
		t.Error("Mint must reject a grant with no client connection")
	}
	if _, err := NewPostgresBroker(nil, &fakeDBCreds{}, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must reject a broker with no proxy configured")
	}
	if _, err := NewPostgresBroker(&dbproxy.Config{}, nil, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must reject a broker with no credential broker (cannot mint ephemeral role)")
	}
}

func TestPostgresBrokerDialRejectsForeignCredential(t *testing.T) {
	b := NewPostgresBroker(&dbproxy.Config{}, &fakeDBCreds{}, nil)
	if _, err := b.Dial(context.Background(), &catalog.Target{ID: "t"}, sshLikeCred{}); err == nil {
		t.Fatal("Dial must reject a credential minted by a different broker")
	}
}

// sshLikeCred is a foreign credential (not pgCredential) for the Dial-rejection
// test.
type sshLikeCred struct{}

func (sshLikeCred) Protocol() string { return "ssh" }

// TestPostgresBrokerDialFailClosed proves a Recorded=true target is DENIED at
// Dial when the recorder errors (no un-recorded brokered DB session), and that
// a Recorded target with NO recorder configured is denied too.
func TestPostgresBrokerDialFailClosed(t *testing.T) {
	target := &catalog.Target{ID: "t", Protocol: catalog.ProtoPostgres, Address: "127.0.0.1:1", Recorded: true}
	grant := AccessGrant{Target: target, GrantID: "g", Subject: "op", Client: &fakePGConn{}}

	// recorder errors → denied.
	b := NewPostgresBroker(&dbproxy.Config{}, &fakeDBCreds{}, errRecorder{})
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(context.Background(), target, cred); err == nil {
		t.Error("Recorded=true target must be DENIED when the recorder errors (fail-closed)")
	}

	// no recorder configured → denied.
	b2 := NewPostgresBroker(&dbproxy.Config{}, &fakeDBCreds{}, nil)
	cred2, err := b2.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b2.Dial(context.Background(), target, cred2); err == nil {
		t.Error("Recorded=true target with no recorder must be denied (fail-closed)")
	}

	// non-recorded target with a recorder error → proceeds (no recording).
	target.Recorded = false
	rc, err := b.Dial(context.Background(), target, cred)
	if err != nil {
		t.Fatalf("non-recorded target must proceed despite recorder error: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (no recorder attached): %v", err)
	}
}

// --- statement extraction (policy) ------------------------------------------

func TestDefaultStatementPolicyPassThrough(t *testing.T) {
	// The zero value is the Phase 2 pass-through seam: every statement allowed.
	p := DefaultStatementPolicy{}
	for _, sql := range []string{"SELECT 1", "INSERT INTO t VALUES (1)", "DROP TABLE x", ""} {
		if err := p.Allow(sql); err != nil {
			t.Errorf("pass-through must allow %q, got %v", sql, err)
		}
	}
}

func TestDefaultStatementPolicyReadOnly(t *testing.T) {
	p := DefaultStatementPolicy{ReadOnly: true}
	allowed := []string{"SELECT * FROM t", "  select 1", "WITH x AS (SELECT 1) SELECT * FROM x", "EXPLAIN SELECT 1", "SHOW search_path"}
	denied := []string{"INSERT INTO t VALUES (1)", "UPDATE t SET a=1", "DELETE FROM t", "DROP TABLE t", "TRUNCATE t", "GRANT ALL ON t TO x", "CALL p()"}
	for _, sql := range allowed {
		if err := p.Allow(sql); err != nil {
			t.Errorf("read-only must ALLOW %q, got %v", sql, err)
		}
	}
	for _, sql := range denied {
		if err := p.Allow(sql); err == nil {
			t.Errorf("read-only must DENY %q", sql)
		}
	}
}

func TestDefaultStatementPolicyTableAllowList(t *testing.T) {
	p := DefaultStatementPolicy{AllowedTables: []string{"accounts", "Ledger"}}
	if err := p.Allow("SELECT * FROM accounts"); err != nil {
		t.Errorf("must allow a statement referencing an allowed table: %v", err)
	}
	if err := p.Allow("SELECT * FROM ledger"); err != nil { // case-insensitive
		t.Errorf("table allow-list must be case-insensitive: %v", err)
	}
	if err := p.Allow("SELECT * FROM secrets"); err == nil {
		t.Error("must deny a statement referencing no allowed table")
	}
}

// --- recorded-statement wiring ----------------------------------------------

// captureWriter is a fake bundle WriteCloser that captures the NDJSON the
// QueryLogWriter emits, so the test can assert each brokered statement was
// recorded with the right decision. Close marks the bundle sealed.
type captureWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *captureWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *captureWriter) lines() []recording.QueryEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var evs []recording.QueryEvent
	for _, ln := range strings.Split(strings.TrimSpace(c.buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var ev recording.QueryEvent
		if err := json.Unmarshal([]byte(ln), &ev); err == nil {
			evs = append(evs, ev)
		}
	}
	return evs
}

// TestPostgresEnforceRecordsEveryStatement proves the relay's per-statement hook
// (enforce) tees EVERY brokered statement into the WORM query log with the
// policy decision, for both allowed and denied statements — and returns the
// policy error so the relay can reject the denied one. This is the headline ADR
// 0030 + 0049-Phase-2 property: the query log is the tamper-evident record of
// both what ran and what policy blocked.
func TestPostgresEnforceRecordsEveryStatement(t *testing.T) {
	cap := &captureWriter{}
	conn := &pgRecordedConn{
		target: &catalog.Target{ID: "t", Recorded: true},
		policy: DefaultStatementPolicy{ReadOnly: true},
		qlog:   recording.NewQueryLogWriter(cap),
	}

	// Allowed read: recorded as allowed, returns nil (forwarded to target).
	if err := conn.enforce("SELECT 1"); err != nil {
		t.Fatalf("enforce(SELECT) must allow, got %v", err)
	}
	// Denied write: recorded as denied, returns the policy error (rejected).
	if err := conn.enforce("DELETE FROM users"); err == nil {
		t.Fatal("enforce(DELETE) must be denied by the read-only policy")
	}

	evs := cap.lines()
	if len(evs) != 2 {
		t.Fatalf("want 2 recorded statements, got %d: %+v", len(evs), evs)
	}
	if evs[0].SQL != "SELECT 1" || evs[0].Decision != recording.QueryAllowed {
		t.Errorf("statement[0] = %+v, want SELECT 1 / allowed", evs[0])
	}
	if evs[1].SQL != "DELETE FROM users" || evs[1].Decision != recording.QueryDenied {
		t.Errorf("statement[1] = %+v, want DELETE / denied", evs[1])
	}
	if evs[1].DenyReason == "" {
		t.Error("denied statement must record a deny_reason")
	}
	if evs[0].Seq != 1 || evs[1].Seq != 2 {
		t.Errorf("statements must carry monotonic 1-based seq, got %d,%d", evs[0].Seq, evs[1].Seq)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close (seal bundle): %v", err)
	}
	if !cap.closed {
		t.Error("Close must seal the underlying bundle")
	}
}

// TestPostgresEnforcePassThroughRecording proves that with the default
// pass-through policy every statement is recorded as allowed and forwarded
// (enforce returns nil), so non-policy targets still get a full query log.
func TestPostgresEnforcePassThroughRecording(t *testing.T) {
	cap := &captureWriter{}
	conn := &pgRecordedConn{
		target: &catalog.Target{ID: "t"},
		policy: policyFor(&catalog.Target{ID: "t"}), // the wired default
		qlog:   recording.NewQueryLogWriter(cap),
	}
	for _, sql := range []string{"SELECT 1", "UPDATE t SET a=1", "DROP TABLE x"} {
		if err := conn.enforce(sql); err != nil {
			t.Fatalf("pass-through enforce(%q) must allow, got %v", sql, err)
		}
	}
	evs := cap.lines()
	if len(evs) != 3 {
		t.Fatalf("want 3 recorded statements, got %d", len(evs))
	}
	for _, ev := range evs {
		if ev.Decision != recording.QueryAllowed {
			t.Errorf("pass-through statement %q recorded as %q, want allowed", ev.SQL, ev.Decision)
		}
	}
}

// TestPostgresEnforceNoRecorderStillEnforces proves that when recording is off
// (qlog nil — a non-Recorded target), the policy is still enforced at the relay
// (statement extraction → deny) without panicking on the nil recorder.
func TestPostgresEnforceNoRecorderStillEnforces(t *testing.T) {
	conn := &pgRecordedConn{
		target: &catalog.Target{ID: "t"},
		policy: DefaultStatementPolicy{ReadOnly: true},
		qlog:   nil,
	}
	if err := conn.enforce("SELECT 1"); err != nil {
		t.Errorf("enforce(SELECT) with no recorder must allow, got %v", err)
	}
	if err := conn.enforce("INSERT INTO t VALUES (1)"); err == nil {
		t.Error("enforce(INSERT) with no recorder must still be denied by policy")
	}
	if err := conn.Close(); err != nil {
		t.Errorf("Close with no recorder must be a no-op, got %v", err)
	}
}
