// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/client"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/transport"
	"github.com/dogukanturhal/jess/internal/tunnel"
	"github.com/dogukanturhal/jess/internal/wire"
)

// TestClientLocalProxy proves the operator client end-to-end: jessctl's
// LocalProxy opens a loopback port, and a normal client pointed at it reaches
// the echo target through the controller + worker (with token auth + grant).
func TestClientLocalProxy(t *testing.T) {
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
		ID: "echo", Protocol: catalog.ProtoTCP, Address: echo.Addr().String(),
		Region: "eu-tr", RequiredRoles: []string{"platform_admin"},
	})
	jb := jit.NewMemoryBroker()
	sink := audit.NewJSONSink(io.Discard)
	ctrl := &Controller{Pool: tunnel.NewYamuxPool(), Cat: cat, JIT: jb, PDP: pdp.RoleAuthorizer{}, Verifier: verifier, Audit: sink}
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
			t.Fatal("worker did not register")
		}
		time.Sleep(20 * time.Millisecond)
	}

	g := jb.Issue("op@hexxlock", "echo", time.Minute)
	token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})

	local, err := client.LocalProxy(ctx, "127.0.0.1:0", opL.Addr().String(), nil,
		wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: g.ID})
	if err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "hello"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read via local proxy: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("local-proxy echo mismatch: got %q", buf)
	}
}

// TestOperatorTLS proves the operator port works when wrapped in TLS (the
// production posture — the Falcon-ID bearer token must not transit in clear).
// The listener requires + verifies an operator client cert (mTLS); the client
// dials with a matching TLS config and the token-bearing request still brokers
// a session to the echo target.
func TestOperatorTLS(t *testing.T) {
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
	// Operator-facing TLS: same dev CA, mTLS (RequireAndVerifyClientCert).
	opSrvCfg, _ := ca.ServerConfig("controller")
	opCliCfg, _ := ca.ClientConfig("operator", "controller")

	workerL, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer workerL.Close()
	rawOpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opL := tls.NewListener(rawOpL, opSrvCfg)
	defer opL.Close()

	cat := catalog.NewMemoryCatalog(&catalog.Target{
		ID: "echo", Protocol: catalog.ProtoTCP, Address: echo.Addr().String(),
		Region: "eu-tr", RequiredRoles: []string{"platform_admin"},
	})
	jb := jit.NewMemoryBroker()
	sink := audit.NewJSONSink(io.Discard)
	ctrl := &Controller{Pool: tunnel.NewYamuxPool(), Cat: cat, JIT: jb, PDP: pdp.RoleAuthorizer{}, Verifier: verifier, Audit: sink}
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
			t.Fatal("worker did not register")
		}
		time.Sleep(20 * time.Millisecond)
	}

	g := jb.Issue("op@hexxlock", "echo", time.Minute)
	token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})

	conn, err := client.Dial(ctx, opL.Addr().String(), opCliCfg,
		wire.OperatorRequest{Token: token, TargetID: "echo", GrantID: g.ID})
	if err != nil {
		t.Fatalf("dial operator (TLS): %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read over TLS operator link: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("TLS operator echo mismatch: got %q", buf)
	}
}
