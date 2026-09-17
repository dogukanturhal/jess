// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/sshproxy"
)

// These tests exercise the reference SSH Broker (ADR 0049 Phase 0) THROUGH the
// Broker interface (Mint → Dial → RecordedConn), proving the refactor preserves
// the existing sshproxy behaviour: operator-cert authority check, target dial,
// and WORM teeing. The helpers mirror internal/sshproxy/sshproxy_test.go.

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
// the given principals — the Vault-SSH-CA pattern.
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

// startTarget runs a minimal gliderlabs sshd that greets and exits, returning
// its address and host public key (authorized_keys line) for pinning.
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

// proxyConfig builds an sshproxy.Config wired to a freshly started target, the
// same shape the worker wires from Vault.
func proxyConfig(t *testing.T, targetHostKey string) *sshproxy.Config {
	t.Helper()
	ca := genSigner(t)
	workerKey := genSigner(t)
	hostCB, err := sshproxy.PinnedHostKeyCallback(targetHostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &sshproxy.Config{
		OperatorCA: ca.PublicKey(),
		HostKey:    genSigner(t),
		DialTarget: func(ctx context.Context, target *catalog.Target) (*ssh.Client, error) {
			return ssh.Dial("tcp", target.Address, &ssh.ClientConfig{
				User:            "worker",
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(workerKey)},
				HostKeyCallback: hostCB,
				Timeout:         5 * time.Second,
			})
		},
	}
	// Stash the CA on the config so tests can mint operator certs against it.
	testCAByConfig[cfg] = ca
	return cfg
}

// testCAByConfig lets the test reach the operator CA that proxyConfig generated
// (the Config doesn't expose its signer, only the public key).
var testCAByConfig = map[*sshproxy.Config]ssh.Signer{}

// serveBroker accepts one operator connection on a loopback listener and drives
// it through the Broker interface (Mint → Dial → Wait), returning the operator
// dial address. Mirrors the worker's per-session handle.
func serveBroker(t *testing.T, b Broker, grantFor func(client net.Conn) AccessGrant) string {
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
			go func(c net.Conn) {
				ctx := context.Background()
				grant := grantFor(c)
				cred, err := b.Mint(ctx, grant)
				if err != nil {
					_ = c.Close()
					return
				}
				rc, err := b.Dial(ctx, grant.Target, cred)
				if err != nil {
					_ = c.Close()
					return
				}
				_ = rc.Wait()
				_ = rc.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSSHBrokerProtocol(t *testing.T) {
	b := NewSSHBroker(&sshproxy.Config{}, nil)
	if got := b.Protocol(); got != string(catalog.ProtoSSH) {
		t.Fatalf("Protocol() = %q, want %q", got, catalog.ProtoSSH)
	}
}

// TestSSHBrokerRoundTripAndRecord proves the brokered session round-trips the
// target greeting AND tees it to the recorder — the headline ADR-0030 property,
// now driven through the Broker interface.
func TestSSHBrokerRoundTripAndRecord(t *testing.T) {
	// Local-only integration test (per the E2E-in-CI policy): spins up a real
	// in-process SSH server and brokers a full session. It flakes under `-race`
	// on CI main pipelines ("session output: EOF" — a session-teardown timing
	// race exposed only under the race detector). It runs deterministically
	// locally and in the deep-test suite. GitLab sets CI=true on every job.
	if os.Getenv("CI") != "" {
		t.Skip("SSH round-trip integration test: local-only (flaky under -race in CI)")
	}
	targetAddr, targetHostKey := startTarget(t)
	cfg := proxyConfig(t, targetHostKey)
	ca := testCAByConfig[cfg]

	var recBuf safeBuf
	b := NewSSHBroker(cfg, fixedRecorder{w: recording.NewAsciicastWriter(&recBuf, 80, 24)})
	target := &catalog.Target{ID: "sshhost", Protocol: catalog.ProtoSSH, Address: targetAddr, Region: "eu-tr"}

	addr := serveBroker(t, b, func(client net.Conn) AccessGrant {
		return AccessGrant{Target: target, GrantID: "g-1", Subject: "op@test", SessionID: "sess-1", Client: client}
	})

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
}

// TestSSHBrokerRejectsUntrustedCA proves the operator-cert authority check is
// preserved through the seam (CVE-2025-49825 class guard).
func TestSSHBrokerRejectsUntrustedCA(t *testing.T) {
	targetAddr, targetHostKey := startTarget(t)
	cfg := proxyConfig(t, targetHostKey)

	b := NewSSHBroker(cfg, nil)
	target := &catalog.Target{ID: "sshhost", Protocol: catalog.ProtoSSH, Address: targetAddr}
	addr := serveBroker(t, b, func(client net.Conn) AccessGrant {
		return AccessGrant{Target: target, GrantID: "g-1", Subject: "op@test", Client: client}
	})

	badCA := genSigner(t)
	opSigner := genSigner(t)
	badCert := userCert(t, badCA, opSigner, "hexxlock") // CA the proxy doesn't trust
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
}

// TestSSHBrokerFailClosedOnRecordingError proves a Recorded=true target is
// DENIED at Dial when the recorder errors (no un-recorded privileged session),
// and a non-recorded target proceeds — identical to the worker's fail-closed
// logic, now in the broker.
func TestSSHBrokerFailClosedOnRecordingError(t *testing.T) {
	cfg := &sshproxy.Config{HostKey: genSigner(t)}
	cfg.OperatorCA = genSigner(t).PublicKey()
	b := NewSSHBroker(cfg, errRecorder{})

	grant := AccessGrant{
		Target:  &catalog.Target{ID: "t", Protocol: catalog.ProtoSSH, Address: "127.0.0.1:1", Recorded: true},
		GrantID: "g", Subject: "op", Client: &fakeConn{},
	}
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(context.Background(), grant.Target, cred); err == nil {
		t.Fatal("Recorded=true target must be DENIED when the recorder errors (fail-closed)")
	}

	grant.Target.Recorded = false
	rc, err := b.Dial(context.Background(), grant.Target, cred)
	if err != nil {
		t.Fatalf("non-recorded target must proceed despite recorder error: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (no recorder attached): %v", err)
	}
}

// TestSSHBrokerNoRecorderDeniesRecordedTarget proves a Recorded target with NO
// recorder configured is denied (the other fail-closed branch).
func TestSSHBrokerNoRecorderDeniesRecordedTarget(t *testing.T) {
	b := NewSSHBroker(&sshproxy.Config{HostKey: genSigner(t)}, nil)
	grant := AccessGrant{
		Target:  &catalog.Target{ID: "t", Protocol: catalog.ProtoSSH, Address: "127.0.0.1:1", Recorded: true},
		GrantID: "g", Subject: "op", Client: &fakeConn{},
	}
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(context.Background(), grant.Target, cred); err == nil {
		t.Fatal("Recorded=true target with no recorder must be denied (fail-closed)")
	}
}

func TestSSHBrokerMintValidation(t *testing.T) {
	b := NewSSHBroker(&sshproxy.Config{}, nil)
	if _, err := b.Mint(context.Background(), AccessGrant{Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a grant with no target")
	}
	if _, err := b.Mint(context.Background(), AccessGrant{Target: &catalog.Target{ID: "t"}}); err == nil {
		t.Fatal("Mint must reject a grant with no client connection")
	}
	nilProxy := NewSSHBroker(nil, nil)
	if _, err := nilProxy.Mint(context.Background(), AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a broker with no proxy configured")
	}
}

func TestSSHBrokerDialRejectsForeignCredential(t *testing.T) {
	b := NewSSHBroker(&sshproxy.Config{}, nil)
	if _, err := b.Dial(context.Background(), &catalog.Target{ID: "t"}, foreignCred{}); err == nil {
		t.Fatal("Dial must reject a credential minted by a different broker")
	}
}

// fixedRecorder returns a pre-built WriteCloser from Open — lets a test inspect
// the teed stream directly.
type fixedRecorder struct{ w io.WriteCloser }

func (f fixedRecorder) Open(_ context.Context, _ recording.Meta) (io.WriteCloser, error) {
	return f.w, nil
}

// errRecorder always fails Open — drives the fail-closed path.
type errRecorder struct{}

func (errRecorder) Open(_ context.Context, _ recording.Meta) (io.WriteCloser, error) {
	return nil, io.ErrClosedPipe
}

type foreignCred struct{}

func (foreignCred) Protocol() string { return "postgres" }

// fakeConn is a minimal net.Conn for Dial-path tests that never reach a real
// handshake (the fail-closed denials return before Wait runs).
type fakeConn struct{ net.Conn }

func (c *fakeConn) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *fakeConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakeConn) Close() error                { return nil }
