// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	mclient "github.com/go-mysql-org/go-mysql/client"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/mysqlproxy"
	"github.com/dogukanturhal/jess/internal/recording"
)

// These tests exercise the ADR 0049 Phase 4 MySQL Broker at the seam: the
// per-statement policy (statement extraction + allow/deny), the
// recorded-statement wiring (every brokered statement teed into the WORM query
// log with the right decision), and the Mint/Dial validation + fail-closed paths
// — all WITHOUT a live MySQL (the mysqlproxy package has the docker-gated full
// wire round-trip; here we prove the broker's own logic deterministically,
// mirroring postgres_test.go).

func TestMySQLBrokerProtocol(t *testing.T) {
	b := NewMySQLBroker(&mysqlproxy.Config{}, &fakeDBCreds{}, nil)
	if got := b.Protocol(); got != string(catalog.ProtoMySQL) {
		t.Fatalf("Protocol() = %q, want %q", got, catalog.ProtoMySQL)
	}
}

// TestMySQLBrokerMint proves Mint mints the ephemeral DB role scoped to the
// target (role = target ID) and stashes the injected creds the operator never
// sees, defaulting the MySQL port when the catalog address omits it.
func TestMySQLBrokerMint(t *testing.T) {
	creds := &fakeDBCreds{}
	b := NewMySQLBroker(&mysqlproxy.Config{}, creds, nil)
	target := &catalog.Target{ID: "billing-db", Protocol: catalog.ProtoMySQL, Address: "10.0.0.7", Database: "billing"}

	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, GrantID: "g1", Subject: "op@test", Client: &fakePGConn{}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if creds.role != "billing-db" {
		t.Errorf("minted Vault role = %q, want target ID %q", creds.role, "billing-db")
	}
	mc, ok := cred.(mysqlCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want mysqlCredential", cred)
	}
	if cred.Protocol() != string(catalog.ProtoMySQL) {
		t.Errorf("credential Protocol() = %q, want mysql", cred.Protocol())
	}
	if mc.creds.User != "ephemeral_user" || mc.creds.Password != "ephemeral_pass" {
		t.Errorf("credential creds = %q/%q, want ephemeral_user/ephemeral_pass", mc.creds.User, mc.creds.Password)
	}
	if mc.creds.Address != "10.0.0.7:3306" { // port defaulted
		t.Errorf("addr = %q, want 10.0.0.7:3306 (default MySQL port)", mc.creds.Address)
	}
	if mc.creds.Database != "billing" {
		t.Errorf("database = %q, want billing", mc.creds.Database)
	}
}

func TestMySQLAddrKeepsExplicitPort(t *testing.T) {
	if got := mysqlAddr(&catalog.Target{Address: "db.internal:13306"}); got != "db.internal:13306" {
		t.Errorf("mysqlAddr = %q, want db.internal:13306", got)
	}
}

// TestMySQLBrokerProxyCredsMode is the MySQL twin of
// TestPostgresBrokerProxyCredsMode: with no standalone CredentialBroker but a
// proxy that already has a CredsFor (mysqlConfigFromVault), Mint defers the creds
// mint to the proxy's CredsFor at Wait time; with neither, Mint fails closed.
func TestMySQLBrokerProxyCredsMode(t *testing.T) {
	wantCreds := mysqlproxy.TargetCreds{Address: "10.0.0.9:3306", User: "eph", Password: "eph", Database: "appdb"}
	called := false
	proxy := &mysqlproxy.Config{CredsFor: func(context.Context, *catalog.Target) (mysqlproxy.TargetCreds, error) {
		called = true
		return wantCreds, nil
	}}
	b := NewMySQLBroker(proxy, nil, nil) // no standalone creds broker
	target := &catalog.Target{ID: "billing-db", Protocol: catalog.ProtoMySQL, Address: "10.0.0.9:3306", Database: "appdb"}

	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, GrantID: "g1", Subject: "op@test", Client: &fakePGConn{}})
	if err != nil {
		t.Fatalf("Mint (proxy-creds mode): %v", err)
	}
	mc, ok := cred.(mysqlCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want mysqlCredential", cred)
	}
	if mc.credsFor == nil {
		t.Fatal("proxy-creds mode must stash the proxy CredsFor")
	}
	rc := &mysqlRecordedConn{cred: mc, target: target}
	got, err := rc.waitConfig().CredsFor(context.Background(), target)
	if err != nil {
		t.Fatalf("deferred CredsFor: %v", err)
	}
	if !called || got != wantCreds {
		t.Errorf("Wait must use the proxy CredsFor; got %+v (called=%v), want %+v", got, called, wantCreds)
	}

	// No creds broker AND no proxy CredsFor → fail closed.
	if _, err := NewMySQLBroker(&mysqlproxy.Config{}, nil, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must fail closed with neither a creds broker nor a proxy CredsFor")
	}
}

func TestMySQLBrokerMintValidation(t *testing.T) {
	b := NewMySQLBroker(&mysqlproxy.Config{}, &fakeDBCreds{}, nil)
	if _, err := b.Mint(context.Background(), AccessGrant{Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must reject a grant with no target")
	}
	if _, err := b.Mint(context.Background(), AccessGrant{Target: &catalog.Target{ID: "t"}}); err == nil {
		t.Error("Mint must reject a grant with no client connection")
	}
	if _, err := NewMySQLBroker(nil, &fakeDBCreds{}, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must reject a broker with no proxy configured")
	}
	if _, err := NewMySQLBroker(&mysqlproxy.Config{}, nil, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must reject a broker with no credential broker (cannot mint ephemeral role)")
	}
	// A failing credential mint propagates fail-closed.
	if _, err := NewMySQLBroker(&mysqlproxy.Config{}, &fakeDBCreds{err: errors.New("vault down")}, nil).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakePGConn{}}); err == nil {
		t.Error("Mint must fail closed when the credential broker errors")
	}
}

func TestMySQLBrokerDialRejectsForeignCredential(t *testing.T) {
	b := NewMySQLBroker(&mysqlproxy.Config{}, &fakeDBCreds{}, nil)
	if _, err := b.Dial(context.Background(), &catalog.Target{ID: "t"}, sshLikeCred{}); err == nil {
		t.Fatal("Dial must reject a credential minted by a different broker")
	}
	// A pgCredential (sibling DB broker) must also be rejected — protocol-matched
	// credentials only.
	if _, err := b.Dial(context.Background(), &catalog.Target{ID: "t"}, pgCredential{}); err == nil {
		t.Fatal("Dial must reject a Postgres credential")
	}
}

// TestMySQLBrokerDialFailClosed proves a Recorded=true target is DENIED at Dial
// when the recorder errors (no un-recorded brokered DB session), and when no
// recorder is configured at all — and that a non-recorded target proceeds.
func TestMySQLBrokerDialFailClosed(t *testing.T) {
	target := &catalog.Target{ID: "t", Protocol: catalog.ProtoMySQL, Address: "127.0.0.1:1", Recorded: true}
	grant := AccessGrant{Target: target, GrantID: "g", Subject: "op", Client: &fakePGConn{}}

	// recorder errors → denied.
	b := NewMySQLBroker(&mysqlproxy.Config{}, &fakeDBCreds{}, errRecorder{})
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(context.Background(), target, cred); err == nil {
		t.Error("Recorded=true target must be DENIED when the recorder errors (fail-closed)")
	}

	// no recorder configured → denied.
	b2 := NewMySQLBroker(&mysqlproxy.Config{}, &fakeDBCreds{}, nil)
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

// --- statement extraction + recorded-statement wiring -----------------------

// TestMySQLEnforceRecordsEveryStatement proves the relay's per-statement hook
// (enforce, the MySQL twin of pgRecordedConn.enforce) tees EVERY brokered
// statement into the WORM query log with the policy decision, for both allowed
// and denied statements, and returns the policy error so the relay rejects the
// denied one.
func TestMySQLEnforceRecordsEveryStatement(t *testing.T) {
	cap := &captureWriter{}
	conn := &mysqlRecordedConn{
		target: &catalog.Target{ID: "t", Recorded: true},
		policy: DefaultStatementPolicy{ReadOnly: true},
		qlog:   recording.NewQueryLogWriter(cap),
	}

	if err := conn.enforce("SELECT 1"); err != nil {
		t.Fatalf("enforce(SELECT) must allow, got %v", err)
	}
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

// TestMySQLEnforcePassThroughRecording proves that with the default pass-through
// policy every statement is recorded as allowed and forwarded (enforce returns
// nil), so non-policy targets still get a full query log.
func TestMySQLEnforcePassThroughRecording(t *testing.T) {
	cap := &captureWriter{}
	conn := &mysqlRecordedConn{
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

// TestMySQLEnforceNoRecorderStillEnforces proves that with recording off (qlog
// nil — a non-Recorded target) the policy is still enforced without panicking.
func TestMySQLEnforceNoRecorderStillEnforces(t *testing.T) {
	conn := &mysqlRecordedConn{
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

// TestMySQLWaitInjectsEphemeralCredsAndPolicy proves Wait builds a per-session
// mysqlproxy config that (a) returns the injected ephemeral creds via CredsFor
// (the operator never sees them) and (b) wires enforce as the relay Policy — the
// seam through which every statement is recorded + decided. We assert the wiring
// without a live MySQL by inspecting the config Wait would hand to mysqlproxy.
func TestMySQLWaitInjectsEphemeralCredsAndPolicy(t *testing.T) {
	conn := &mysqlRecordedConn{
		target: &catalog.Target{ID: "t"},
		cred: mysqlCredential{creds: mysqlproxy.TargetCreds{
			Address: "10.0.0.9:3306", User: "ephemeral_user", Password: "ephemeral_pass", Database: "appdb",
		}},
		policy: DefaultStatementPolicy{ReadOnly: true},
	}
	cfg := conn.waitConfig()
	got, err := cfg.CredsFor(context.Background(), conn.target)
	if err != nil {
		t.Fatalf("CredsFor: %v", err)
	}
	if got.User != "ephemeral_user" || got.Password != "ephemeral_pass" || got.Address != "10.0.0.9:3306" {
		t.Errorf("CredsFor returned %+v, want injected ephemeral creds", got)
	}
	if cfg.Policy == nil {
		t.Fatal("Wait must wire the per-statement Policy (enforce) into mysqlproxy")
	}
	if err := cfg.Policy("DROP TABLE x"); err == nil {
		t.Error("wired Policy must deny a write under the read-only policy")
	} else if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("policy deny reason = %v, want a read-only denial", err)
	}
}

// --- docker-gated full round-trip (operator -> broker -> real MySQL) ---------

// startMySQL spins a throwaway MySQL in docker; SKIPS if docker/image is
// unavailable so the test stays green without docker. Mirrors mysqlproxy's
// startMySQL helper (kept local so the broker test is self-contained).
func startMySQL(t *testing.T) (addr, user, password string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "jess-broker-mysql-" + hex.EncodeToString(b)
	run := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "MYSQL_ROOT_PASSWORD=test", "-e", "MYSQL_DATABASE=jess",
		"-p", "127.0.0.1::3306", "mysql:8")
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("docker run failed (skipping): %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	var hostPort string
	for i := 0; i < 30; i++ {
		out, err := exec.Command("docker", "port", name, "3306/tcp").Output()
		if err == nil && len(out) > 0 {
			line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
			if idx := strings.LastIndex(line, ":"); idx >= 0 {
				hostPort = line[idx+1:]
				break
			}
		}
		time.Sleep(time.Second)
	}
	if hostPort == "" {
		t.Skip("could not determine mysql host port")
	}
	addr = "127.0.0.1:" + hostPort
	for i := 0; i < 60; i++ {
		if c, err := mclient.Connect(addr, "root", "test", "jess"); err == nil {
			_ = c.Close()
			return addr, "root", "test"
		}
		time.Sleep(time.Second)
	}
	t.Skip("mysql did not become ready in 60s")
	return "", "", ""
}

// stubCreds is a CredentialBroker that hands back the docker MySQL's real creds
// as the "ephemeral" role (the operator never sees them — that's the point of the
// broker), so the full mint->dial->relay path runs against a live target.
type stubCreds struct{ user, pass string }

func (s stubCreds) SignSSH(context.Context, []byte, []string, time.Duration) ([]byte, error) {
	return nil, nil
}
func (s stubCreds) IssueDBCreds(context.Context, string) (string, string, error) {
	return s.user, s.pass, nil
}

// TestMySQLBrokerRoundTrip is the docker-gated end-to-end proof: an operator
// connects to the broker (no password — jess authorized), an allowed SELECT
// round-trips to the real target and is recorded as allowed in the WORM query
// log, and a denied write (read-only policy) is rejected at the relay, never
// reaches the target, and is recorded as denied. This exercises the real relay
// + recording seam the unit tests stub out.
func TestMySQLBrokerRoundTrip(t *testing.T) {
	addr, user, pass := startMySQL(t)
	ctx := context.Background()

	rec := &captureWriter{}
	// Read-only policy so the denied-write path is exercised live.
	policyTarget := &catalog.Target{ID: "mysql-ro", Protocol: catalog.ProtoMySQL, Address: addr, Database: "jess", Recorded: true}
	b := newRoundTripBroker(stubCreds{user: user, pass: pass}, fixedRecorder{w: rec}, DefaultStatementPolicy{ReadOnly: true})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		grant := AccessGrant{Target: policyTarget, GrantID: "g", Subject: "op@test", Client: conn}
		cred, err := b.Mint(ctx, grant)
		if err != nil {
			return
		}
		rc, err := b.Dial(ctx, policyTarget, cred)
		if err != nil {
			return
		}
		defer rc.Close()
		_ = rc.Wait()
	}()

	op, err := mclient.Connect(ln.Addr().String(), "operator", "", "jess")
	if err != nil {
		t.Fatalf("operator connect (no password): %v", err)
	}
	defer op.Close()

	// Allowed read round-trips.
	r, err := op.Execute("SELECT 1 AS n")
	if err != nil {
		t.Fatalf("SELECT via broker: %v", err)
	}
	if v, _ := r.GetInt(0, 0); v != 1 {
		t.Fatalf("SELECT 1 -> %d, want 1", v)
	}

	// Denied write is rejected at the relay (read-only policy) — surfaced as a
	// MySQL error, never executed on the target.
	if _, err := op.Execute("CREATE TABLE should_not_exist (id INT)"); err == nil {
		t.Fatal("read-only policy must DENY the CREATE at the relay")
	}
	// Prove the target was never touched: the table must not exist.
	if _, err := op.Execute("SELECT 1 FROM should_not_exist"); err == nil {
		t.Fatal("denied DDL must not have reached the target (table should not exist)")
	}

	op.Close()
	// Give the broker goroutine a moment to seal the bundle on disconnect.
	time.Sleep(200 * time.Millisecond)

	evs := rec.lines()
	var sawAllowedSelect, sawDeniedCreate bool
	for _, ev := range evs {
		if strings.Contains(ev.SQL, "SELECT 1 AS n") && ev.Decision == recording.QueryAllowed {
			sawAllowedSelect = true
		}
		if strings.Contains(ev.SQL, "CREATE TABLE should_not_exist") && ev.Decision == recording.QueryDenied {
			sawDeniedCreate = true
		}
	}
	if !sawAllowedSelect {
		t.Errorf("WORM query log missing the allowed SELECT; got %+v", evs)
	}
	if !sawDeniedCreate {
		t.Errorf("WORM query log missing the denied CREATE; got %+v", evs)
	}
}

// newRoundTripBroker builds a MySQL broker whose per-statement policy is fixed to
// p (the catalog has no per-target policy columns yet — policyFor returns
// pass-through — so the round-trip test injects the read-only policy directly).
func newRoundTripBroker(creds CredentialBroker, rec recording.Recorder, p StatementPolicy) Broker {
	return &roundTripMySQLBroker{Broker: NewMySQLBroker(&mysqlproxy.Config{}, creds, rec), policy: p}
}

// roundTripMySQLBroker wraps the real broker, swapping in a fixed policy at Dial
// for the docker round-trip test. Delegates Mint/Protocol unchanged.
type roundTripMySQLBroker struct {
	Broker
	policy StatementPolicy
}

func (b *roundTripMySQLBroker) Dial(ctx context.Context, target *catalog.Target, cred Credential) (RecordedConn, error) {
	rc, err := b.Broker.Dial(ctx, target, cred)
	if err != nil {
		return nil, err
	}
	if mc, ok := rc.(*mysqlRecordedConn); ok {
		mc.policy = b.policy
	}
	return rc, nil
}

var _ io.Writer = (*captureWriter)(nil)
