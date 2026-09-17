// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// startPostgres spins a throwaway Postgres in docker and returns its DSN. The
// test SKIPS (not fails) if docker is unavailable or the image can't be pulled,
// so it stays green in environments without docker while running for real in CI.
func startPostgres(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "jess-jit-pg-" + hex.EncodeToString(b)

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
		if ps, err := NewPostgresStore(ctx, dsn); err == nil {
			ps.Close()
			return dsn
		}
		time.Sleep(time.Second)
	}
	t.Skip("postgres did not become ready in time")
	return ""
}

func TestPostgresStore(t *testing.T) {
	dsn := startPostgres(t)
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	g, err := s.Issue(ctx, "op@hexxlock", "tgt", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.AssertActiveID(ctx, g.ID, "tgt")
	if err != nil || got.Subject != "op@hexxlock" {
		t.Fatalf("active grant: err=%v grant=%+v", err, got)
	}
	if _, err := s.AssertActiveID(ctx, g.ID, "other"); err == nil {
		t.Fatal("grant for the wrong target must be rejected")
	}
	if _, err := s.AssertActiveID(ctx, "grant-bogus", "tgt"); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("unknown grant: want ErrNoGrant, got %v", err)
	}

	exp, err := s.Issue(ctx, "op@hexxlock", "tgt", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := s.AssertActiveID(ctx, exp.ID, "tgt"); err == nil {
		t.Fatal("expired grant must be rejected")
	}
}
