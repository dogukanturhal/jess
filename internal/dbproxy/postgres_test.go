// SPDX-License-Identifier: AGPL-3.0-or-later

package dbproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// startPostgres spins a throwaway Postgres in docker; SKIPS if docker/image is
// unavailable so the test stays green without docker.
func startPostgres(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "jess-dbproxy-pg-" + hex.EncodeToString(b)
	run := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=jess",
		"-p", "127.0.0.1::5432", "postgres:16-alpine")
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("docker run failed (skipping): %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	var hostPort string
	for i := 0; i < 30; i++ {
		out, err := exec.Command("docker", "port", name, "5432/tcp").Output()
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
		t.Skip("could not determine postgres host port")
	}
	dsn := fmt.Sprintf("postgres://postgres:test@127.0.0.1:%s/jess?sslmode=disable", hostPort)
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		if c, err := pgconn.Connect(ctx, dsn); err == nil {
			_ = c.Close(ctx)
			return dsn
		}
		time.Sleep(time.Second)
	}
	t.Skip("postgres did not become ready")
	return ""
}

func TestPostgresBroker(t *testing.T) {
	targetDSN := startPostgres(t)
	ctx := context.Background()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var audited []string
	cfg := &Config{
		CredsFor: func(ctx context.Context, target *catalog.Target) (string, error) {
			return targetDSN, nil // injected creds — operator never sees these
		},
	}
	target := &catalog.Target{ID: "pg", Protocol: catalog.ProtoPostgres}
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

	// Operator connects to the BROKER with NO password (Jess authorized it).
	opDSN := fmt.Sprintf("postgres://op@%s/jess?sslmode=disable", ln.Addr().String())
	op, err := pgconn.Connect(ctx, opDSN)
	if err != nil {
		t.Fatalf("operator connect (no password): %v", err)
	}
	defer op.Close(ctx)

	results, err := op.Exec(ctx, "SELECT 1").ReadAll()
	if err != nil {
		t.Fatalf("exec via broker: %v", err)
	}
	if len(results) != 1 || len(results[0].Rows) != 1 || string(results[0].Rows[0][0]) != "1" {
		t.Fatalf("unexpected result: %+v", results)
	}

	mu.Lock()
	got := strings.Join(audited, " | ")
	mu.Unlock()
	if !strings.Contains(got, "SELECT 1") {
		t.Fatalf("query not audited; captured: %q", got)
	}
}
