// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/transport"
	"github.com/dogukanturhal/jess/internal/tunnel"
	"github.com/dogukanturhal/jess/internal/wire"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const (
	testIssuer   = "https://id.hexxlock.test"
	testClientID = "svc-jess"
)

func mintToken(t *testing.T, key *rsa.PrivateKey, sub string, roles []string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   testIssuer,
		"sub":   sub,
		"aud":   testClientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"roles": roles,
	})
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSpineEndToEnd proves the Phase 5a/5b spine end-to-end, in-process:
// worker dials the controller (outbound mTLS) → operator presents a VERIFIED
// Falcon-ID token → controller authorizes (RBAC + JIT grant) → opens a session
// into the worker → worker brokers raw TCP to a target → bytes round-trip.
// Also proves the auth gates: bad token, wrong role, and missing grant are denied.
func TestSpineEndToEnd(t *testing.T) {
	// --- echo "target" ---
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(c)
		}
	}()

	// --- token signing key + offline verifier ---
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := pdp.NewVerifierFromKeySet(testIssuer, testClientID, []crypto.PublicKey{&signKey.PublicKey})

	// --- dev mTLS for the worker link ---
	ca, err := transport.NewDevCA()
	if err != nil {
		t.Fatal(err)
	}
	srvCfg, err := ca.ServerConfig("controller")
	if err != nil {
		t.Fatal(err)
	}
	cliCfg, err := ca.ClientConfig("worker-1", "controller")
	if err != nil {
		t.Fatal(err)
	}

	workerL, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer workerL.Close()
	opL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer opL.Close()

	cat := catalog.NewMemoryCatalog(&catalog.Target{
		ID: "echo", Name: "echo", Protocol: catalog.ProtoTCP,
		Address: echo.Addr().String(), Region: "eu-tr",
		RequiredRoles: []string{"platform_admin"},
	})
	jb := jit.NewMemoryBroker()
	var auditBuf safeBuffer
	sink := audit.NewJSONSink(&auditBuf)

	ctrl := &Controller{
		Pool: tunnel.NewYamuxPool(), Cat: cat, JIT: jb,
		PDP: pdp.RoleAuthorizer{}, Verifier: verifier, Audit: sink,
	}
	idFn := func(c net.Conn) (string, error) {
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			return "", err
		}
		return transport.PeerCommonName(tc)
	}
	go func() { _ = ctrl.ServeWorkers(workerL, idFn) }()
	go func() { _ = ctrl.ServeOperators(opL) }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wr := &WorkerRuntime{ID: "worker-1", Cat: cat, JIT: jb, Audit: sink}
	go func() { _ = wr.Run(ctx, []string{workerL.Addr().String()}, cliCfg) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(ctrl.Pool.Workers()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("worker did not register in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	g := jb.Issue("op@hexxlock", "echo", time.Minute)

	send := func(c net.Conn, req wire.OperatorRequest) {
		b, _ := json.Marshal(req)
		_, _ = c.Write(b)
		_, _ = c.Write([]byte("hello"))
	}

	t.Run("valid token + role + grant proxies bytes", func(t *testing.T) {
		token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})
		c, err := net.Dial("tcp", opL.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		send(c, wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: g.ID})
		buf := make([]byte, 5)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("reading echo: %v", err)
		}
		if string(buf) != "hello" {
			t.Fatalf("echo mismatch: got %q", buf)
		}
	})

	expectDenied := func(t *testing.T, req wire.OperatorRequest) {
		t.Helper()
		c, err := net.Dial("tcp", opL.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		send(c, req)
		buf := make([]byte, 5)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := io.ReadFull(c, buf)
		if err == nil && n == 5 && string(buf) == "hello" {
			t.Fatal("expected denial, but got an echo")
		}
	}

	t.Run("invalid token is denied", func(t *testing.T) {
		expectDenied(t, wire.OperatorRequest{Token: "not-a-real-token", TargetID: "echo", GrantID: g.ID})
	})

	t.Run("wrong role is denied", func(t *testing.T) {
		token := mintToken(t, signKey, "op@hexxlock", []string{"viewer"})
		expectDenied(t, wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: g.ID})
	})

	t.Run("no grant is denied", func(t *testing.T) {
		token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})
		expectDenied(t, wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: "grant-bogus"})
	})

	t.Run("session is killed when the grant expires", func(t *testing.T) {
		short := jb.Issue("op@hexxlock", "echo", 800*time.Millisecond)
		token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})
		c, err := net.Dial("tcp", opL.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// Send the request but NO payload, so the bridge stays idle and only the
		// grant-expiry teardown can end the read.
		b, _ := json.Marshal(wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: short.ID})
		_, _ = c.Write(b)

		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err == nil {
			t.Fatal("expected the session to be torn down at grant expiry")
		}
		if elapsed := time.Since(start); elapsed > 4*time.Second {
			t.Fatalf("teardown too slow (%v) — grant-expiry kill not working", elapsed)
		}
	})

	if !strings.Contains(auditBuf.String(), `"action":"open"`) {
		t.Errorf("expected an audit 'open' event; audit log:\n%s", auditBuf.String())
	}
}

// TestMultiControllerHA proves that TWO stateless controllers (sharing one grant
// store + catalog + verifier) can EACH serve a session to a single worker that
// dials both — the session path survives behind a load balancer.
func TestMultiControllerHA(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(c)
		}
	}()

	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := pdp.NewVerifierFromKeySet(testIssuer, testClientID, []crypto.PublicKey{&signKey.PublicKey})

	ca, err := transport.NewDevCA()
	if err != nil {
		t.Fatal(err)
	}
	srvCfg, _ := ca.ServerConfig("controller")
	cliCfg, _ := ca.ClientConfig("worker-1", "controller")
	idFn := func(c net.Conn) (string, error) {
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			return "", err
		}
		return transport.PeerCommonName(tc)
	}

	// SHARED state across both controllers.
	jb := jit.NewMemoryBroker()
	cat := catalog.NewMemoryCatalog(&catalog.Target{
		ID: "echo", Protocol: catalog.ProtoTCP, Address: echo.Addr().String(),
		Region: "eu-tr", RequiredRoles: []string{"platform_admin"},
	})
	sink := audit.NewJSONSink(io.Discard)

	mkController := func() (*Controller, net.Listener, net.Listener) {
		wl, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
		if err != nil {
			t.Fatal(err)
		}
		ol, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c := &Controller{Pool: tunnel.NewYamuxPool(), Cat: cat, JIT: jb, PDP: pdp.RoleAuthorizer{}, Verifier: verifier, Audit: sink}
		go func() { _ = c.ServeWorkers(wl, idFn) }()
		go func() { _ = c.ServeOperators(ol) }()
		return c, wl, ol
	}
	c1, wl1, ol1 := mkController()
	defer wl1.Close()
	defer ol1.Close()
	c2, wl2, ol2 := mkController()
	defer wl2.Close()
	defer ol2.Close()

	// ONE worker dialing BOTH controllers.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wr := &WorkerRuntime{ID: "worker-1", Cat: cat, JIT: jb, Audit: sink}
	go func() { _ = wr.Run(ctx, []string{wl1.Addr().String(), wl2.Addr().String()}, cliCfg) }()

	deadline := time.Now().Add(5 * time.Second)
	for (len(c1.Pool.Workers()) == 0 || len(c2.Pool.Workers()) == 0) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(c1.Pool.Workers()) == 0 || len(c2.Pool.Workers()) == 0 {
		t.Fatalf("worker did not register with both controllers (c1=%d c2=%d)", len(c1.Pool.Workers()), len(c2.Pool.Workers()))
	}

	g := jb.Issue("op@hexxlock", "echo", time.Minute)
	token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})

	// Hit controller #2 specifically — it must be able to serve.
	c, err := net.Dial("tcp", ol2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b, _ := json.Marshal(wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: g.ID})
	_, _ = c.Write(b)
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 5)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("controller #2 failed to serve the session: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo mismatch via controller #2: got %q", buf)
	}
}
