// SPDX-License-Identifier: AGPL-3.0-or-later

package mysqlproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	mclient "github.com/go-mysql-org/go-mysql/client"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// TestHandleRejectsNilCredsFor pins the safety contract: if the broker is
// instantiated without a CredsFor function, Handle MUST fail loud (close
// the operator conn + return) rather than silently leak the operator into
// an un-brokered state.
func TestHandleRejectsNilCredsFor(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	c := &Config{} // CredsFor nil
	done := make(chan struct{})
	go func() {
		err := c.Handle(context.Background(), srv, &catalog.Target{ID: "t", Protocol: "mysql"}, nil)
		if err == nil || !strings.Contains(err.Error(), "CredsFor nil") {
			t.Errorf("nil-CredsFor must error; got %v", err)
		}
		close(done)
	}()
	_ = cli.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	if n, err := cli.Read(buf); err == nil {
		t.Errorf("operator conn should be closed; got %d bytes, expected error", n)
	}
	<-done
}

// TestHandleTargetUnavailable pins the target-down behaviour: when the
// broker cannot dial the target, the operator gets an error and Handle
// returns wrapped ErrTargetUnavailable so callers can distinguish "broker
// rejected" from "target down".
func TestHandleTargetUnavailable(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	c := &Config{
		CredsFor: func(_ context.Context, _ *catalog.Target) (TargetCreds, error) {
			return TargetCreds{
				Address: "127.0.0.1:1", // nothing listens here
				User:    "x",
			}, nil
		},
	}
	done := make(chan struct{})
	go func() {
		err := c.Handle(context.Background(), srv, &catalog.Target{ID: "t", Protocol: "mysql"}, nil)
		if !errors.Is(err, ErrTargetUnavailable) {
			t.Errorf("expected ErrTargetUnavailable, got %v", err)
		}
		close(done)
	}()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	if n, err := cli.Read(buf); err == nil {
		t.Errorf("operator conn should be closed; got %d bytes, expected error", n)
	}
	<-done
}

// startMySQL spins a throwaway MySQL in docker; SKIPS if docker/image is
// unavailable so the test stays green without docker. Mirrors the dbproxy
// startPostgres pattern.
func startMySQL(t *testing.T) (addr, user, password string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "jess-mysqlproxy-" + hex.EncodeToString(b)
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
	// Wait for mysqld to be ready — `mysql:8` takes a while.
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

// TestMySQLBroker exercises the full operator → broker → target round-trip:
//   - operator connects with EMPTY password (broker pre-authorized)
//   - SELECT 1 round-trips and returns the right row
//   - the SQL is captured by the audit hook
//   - PREPARE / EXECUTE round-trips and captures the prepare SQL only
//     (binary params aren't audited at execute time).
func TestMySQLBroker(t *testing.T) {
	targetAddr, targetUser, targetPass := startMySQL(t)
	ctx := context.Background()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var audited []string
	cfg := &Config{
		CredsFor: func(_ context.Context, _ *catalog.Target) (TargetCreds, error) {
			return TargetCreds{
				Address: targetAddr, User: targetUser, Password: targetPass, Database: "jess",
			}, nil // operator never sees these
		},
	}
	target := &catalog.Target{ID: "mysql", Protocol: "mysql"}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_ = cfg.Handle(ctx, conn, target, func(sql string) {
					mu.Lock()
					audited = append(audited, sql)
					mu.Unlock()
				})
			}(conn)
		}
	}()

	// Operator connects to the BROKER with empty password — Jess authorized.
	op, err := mclient.Connect(ln.Addr().String(), "operator", "", "")
	if err != nil {
		t.Fatalf("operator connect (empty password): %v", err)
	}
	defer op.Close()

	// 1. Plain query.
	r, err := op.Execute("SELECT 1 AS n")
	if err != nil {
		t.Fatalf("SELECT via broker: %v", err)
	}
	if r.RowNumber() != 1 {
		t.Fatalf("expected 1 row, got %d", r.RowNumber())
	}
	if v, _ := r.GetInt(0, 0); v != 1 {
		t.Fatalf("expected SELECT 1 → 1, got %d", v)
	}

	// 2. Prepared statement.
	stmt, err := op.Prepare("SELECT ? + ?")
	if err != nil {
		t.Fatalf("PREPARE via broker: %v", err)
	}
	pr, err := stmt.Execute(2, 3)
	if err != nil {
		t.Fatalf("EXECUTE via broker: %v", err)
	}
	if v, _ := pr.GetInt(0, 0); v != 5 {
		t.Fatalf("expected 2 + 3 → 5, got %d", v)
	}
	_ = stmt.Close()

	mu.Lock()
	got := strings.Join(audited, " | ")
	mu.Unlock()
	if !strings.Contains(got, "SELECT 1 AS n") {
		t.Errorf("plain query not audited; captured: %q", got)
	}
	if !strings.Contains(got, "SELECT ? + ?") {
		t.Errorf("PREPARE text not audited; captured: %q", got)
	}
}

// TestAuditTruncation pins the 8KB SQL ceiling — large statements get
// clipped so an `INSERT INTO huge VALUES(...)` 50MB payload can't blow
// the audit log out.
func TestAuditTruncation(t *testing.T) {
	h := &proxyHandler{audit: func(_ string) {}}
	huge := strings.Repeat("a", auditTruncate*2)
	var captured string
	h.audit = func(s string) { captured = s }
	h.emitAudit(huge)
	if len(captured) != auditTruncate {
		t.Errorf("audit not truncated: got %d bytes, want %d", len(captured), auditTruncate)
	}
}
