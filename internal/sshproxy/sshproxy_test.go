// SPDX-License-Identifier: AGPL-3.0-or-later

package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func genSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// userCert mints an SSH user cert for opSigner's public key, signed by ca, with
// the given principals — the Vault-SSH-CA pattern (ADR 0030 Phase 2/5b).
func userCert(t *testing.T, ca ssh.Signer, opSigner ssh.Signer, principals ...string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             opSigner.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "op@test",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(cert, opSigner)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

type fakeMeta struct{ user string }

func (f fakeMeta) User() string          { return f.user }
func (f fakeMeta) SessionID() []byte     { return nil }
func (f fakeMeta) ClientVersion() []byte { return nil }
func (f fakeMeta) ServerVersion() []byte { return nil }
func (f fakeMeta) RemoteAddr() net.Addr  { return nil }
func (f fakeMeta) LocalAddr() net.Addr   { return nil }

// TestCheckOperatorCert isolates the cert-authority check from the SSH handshake.
func TestCheckOperatorCert(t *testing.T) {
	ca := genSigner(t)
	cfg := &Config{OperatorCA: ca.PublicKey()}
	op := genSigner(t)

	good := userCert(t, ca, op, "hexxlock")
	if _, err := cfg.checkOperatorCert(fakeMeta{"hexxlock"}, good.PublicKey()); err != nil {
		t.Fatalf("good cert should be accepted: %v", err)
	}

	badCA := genSigner(t)
	bad := userCert(t, badCA, op, "hexxlock")
	if _, err := cfg.checkOperatorCert(fakeMeta{"hexxlock"}, bad.PublicKey()); err == nil {
		t.Fatal("cert signed by an untrusted CA must be rejected")
	}

	wrongPrincipal := userCert(t, ca, op, "someone-else")
	if _, err := cfg.checkOperatorCert(fakeMeta{"hexxlock"}, wrongPrincipal.PublicKey()); err == nil {
		t.Fatal("cert without the requested principal must be rejected")
	}

	// A plain (non-certificate) public key must never be accepted — locks the
	// CVE-2025-49825 class so no future refactor can reintroduce an authority bypass.
	plain := genSigner(t)
	if _, err := cfg.checkOperatorCert(fakeMeta{"hexxlock"}, plain.PublicKey()); err == nil {
		t.Fatal("a non-certificate public key must be rejected")
	}
}

// startTarget runs a minimal gliderlabs sshd that greets and exits, returning
// its address and its host public key (authorized_keys line) for pinning.
func startTarget(t *testing.T) (addr, hostKey string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	hk := genSigner(t)
	srv := &gssh.Server{
		Handler:          func(s gssh.Session) { _, _ = io.WriteString(s, "hello-from-target\n") },
		PublicKeyHandler: func(ctx gssh.Context, key gssh.PublicKey) bool { return true },
	}
	srv.AddHostKey(hk)
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), string(ssh.MarshalAuthorizedKey(hk.PublicKey()))
}

func TestPinnedHostKeyCallback(t *testing.T) {
	hk := genSigner(t)
	cb, err := PinnedHostKeyCallback(string(ssh.MarshalAuthorizedKey(hk.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("host:22", nil, hk.PublicKey()); err != nil {
		t.Fatalf("matching host key rejected: %v", err)
	}
	if err := cb("host:22", nil, genSigner(t).PublicKey()); err == nil {
		t.Fatal("a mismatched target host key must be rejected (MITM guard)")
	}
}

// TestPinnedHostKeyReturnsAlgorithm guards the 2026-05-29 bug: when the target
// SSH server has multiple host keys (e.g. ssh-rsa + ecdsa-sha2-nistp256 +
// ssh-ed25519, OpenSSH default) and the worker's ssh.ClientConfig does NOT
// set HostKeyAlgorithms, the server is free to present whichever host key its
// own algorithm preference picks first — typically ECDSA on OpenSSH 9.x. The
// pinned-bytes comparison against an ed25519 pin then spuriously fails and
// the legitimate target hop is rejected as "possible MITM".
//
// Fix: PinnedHostKey returns the pinned key's algorithm name so the caller
// pins HostKeyAlgorithms = []string{algo} and SSH negotiation demands THIS
// host-key type.
func TestPinnedHostKeyReturnsAlgorithm(t *testing.T) {
	hk := genSigner(t)
	algo, cb, err := PinnedHostKey(string(ssh.MarshalAuthorizedKey(hk.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	if algo != hk.PublicKey().Type() {
		t.Errorf("PinnedHostKey algo = %q, want %q", algo, hk.PublicKey().Type())
	}
	if algo == "" {
		t.Fatal("PinnedHostKey returned empty algorithm — HostKeyAlgorithms pin would be empty, defeating the guard")
	}
	if err := cb("host:22", nil, hk.PublicKey()); err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
}

// startProxy runs the SSH record-proxy on a loopback TCP listener (a realistic
// reliable stream — like the real yamux session stream — not a synchronous
// net.Pipe). Returns the operator-facing address.
func startProxy(t *testing.T, cfg *Config, target *catalog.Target, rec io.Writer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = cfg.Handle(context.Background(), c, target, rec) }(c)
		}
	}()
	return ln.Addr().String()
}

func TestSSHRecordProxy(t *testing.T) {
	ca := genSigner(t)
	hostKey := genSigner(t)
	workerKey := genSigner(t)
	targetAddr, targetHostKey := startTarget(t)
	hostCB, err := PinnedHostKeyCallback(targetHostKey) // pin the target host key (no InsecureIgnoreHostKey)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		OperatorCA: ca.PublicKey(),
		HostKey:    hostKey,
		DialTarget: func(ctx context.Context, target *catalog.Target) (*ssh.Client, error) {
			return ssh.Dial("tcp", target.Address, &ssh.ClientConfig{
				User:            "worker",
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(workerKey)},
				HostKeyCallback: hostCB,
				Timeout:         5 * time.Second,
			})
		},
	}
	target := &catalog.Target{ID: "sshhost", Protocol: catalog.ProtoSSH, Address: targetAddr, Region: "eu-tr"}

	t.Run("valid cert: output round-trips and is recorded", func(t *testing.T) {
		var recBuf safeBuf
		rec := recording.NewAsciicastWriter(&recBuf, 80, 24)
		addr := startProxy(t, cfg, target, rec)

		opSigner := genSigner(t)
		opCert := userCert(t, ca, opSigner, "hexxlock")
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            "hexxlock",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(opCert)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		if err != nil {
			t.Fatalf("operator dial (should succeed): %v", err)
		}
		defer client.Close()
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("new session: %v", err)
		}
		out, err := sess.Output("hello")
		if err != nil {
			t.Fatalf("session output: %v", err)
		}
		if !strings.Contains(string(out), "hello-from-target") {
			t.Fatalf("operator output = %q, want the target greeting", out)
		}

		// The recorder is teed inside the proxy; allow a brief moment for the
		// final chunk to flush.
		deadline := time.Now().Add(2 * time.Second)
		for !strings.Contains(recBuf.String(), "hello-from-target") && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		recorded := recBuf.String()
		if !strings.Contains(recorded, `"version":2`) {
			t.Errorf("recording is not asciicast v2:\n%s", recorded)
		}
		if !strings.Contains(recorded, "hello-from-target") {
			t.Errorf("recording missing session output:\n%s", recorded)
		}
	})

	t.Run("cert from unknown CA is rejected", func(t *testing.T) {
		addr := startProxy(t, cfg, target, nil)
		badCA := genSigner(t)
		opSigner := genSigner(t)
		badCert := userCert(t, badCA, opSigner, "hexxlock") // signed by a CA the proxy doesn't trust

		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            "hexxlock",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(badCert)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		if err == nil {
			_ = client.Close()
			t.Fatal("expected dial to fail for a cert from an untrusted CA")
		}
	})
}
