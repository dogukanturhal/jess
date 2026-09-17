// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/client"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/sshproxy"
	"github.com/dogukanturhal/jess/internal/transport"
	"github.com/dogukanturhal/jess/internal/tunnel"
	"github.com/dogukanturhal/jess/internal/wire"
)

func sshSigner(t *testing.T) ssh.Signer {
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

func sshUserCert(t *testing.T, ca, user ssh.Signer, principals ...string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key: user.PublicKey(), Serial: 1, CertType: ssh.UserCert, KeyId: "op@test",
		ValidPrincipals: principals, ValidAfter: 0, ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(cert, user)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func startSSHTarget(t *testing.T) (addr, hostKey string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	hk := sshSigner(t)
	srv := &gssh.Server{
		Handler:          func(s gssh.Session) { _, _ = io.WriteString(s, "hello-from-target\n") },
		PublicKeyHandler: func(ctx gssh.Context, key gssh.PublicKey) bool { return true },
	}
	srv.AddHostKey(hk)
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), string(ssh.MarshalAuthorizedKey(hk.PublicKey()))
}

// TestWorkerSSHRecording drives a full operator→broker→SSH-target session and
// asserts the worker produced a tamper-evident signed recording bundle that
// Verify accepts and that contains the session output.
func TestWorkerSSHRecording(t *testing.T) {
	caSigner := sshSigner(t)
	targetAddr, targetHostKey := startSSHTarget(t)
	hostCB, err := sshproxy.PinnedHostKeyCallback(targetHostKey)
	if err != nil {
		t.Fatal(err)
	}
	workerKey := sshSigner(t)

	// Token verification (RSA, like spine_test).
	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := pdp.NewVerifierFromKeySet(testIssuer, testClientID, []crypto.PublicKey{&signKey.PublicKey})

	// Recorder → tamper-evident signed bundles in a temp FS store.
	recDir := t.TempDir()
	store := recording.NewFSStore(recDir)
	recSigner, err := recording.NewEd25519Signer("jess-rec-test")
	if err != nil {
		t.Fatal(err)
	}

	ca, _ := transport.NewDevCA()
	srvCfg, _ := ca.ServerConfig("controller")
	cliCfg, _ := ca.ClientConfig("worker-1", "controller")
	workerL, _ := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	defer workerL.Close()
	opL, _ := net.Listen("tcp", "127.0.0.1:0")
	defer opL.Close()

	cat := catalog.NewMemoryCatalog(&catalog.Target{
		ID: "sshhost", Protocol: catalog.ProtoSSH, Address: targetAddr,
		Region: "eu-tr", RequiredRoles: []string{"platform_admin"}, Recorded: true,
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
	wr := &WorkerRuntime{
		ID: "worker-1", Cat: cat, JIT: jb, Audit: sink,
		SSH: &sshproxy.Config{
			OperatorCA: caSigner.PublicKey(), HostKey: sshSigner(t),
			DialTarget: func(ctx context.Context, target *catalog.Target) (*ssh.Client, error) {
				return ssh.Dial("tcp", target.Address, &ssh.ClientConfig{
					User: "worker", Auth: []ssh.AuthMethod{ssh.PublicKeys(workerKey)},
					HostKeyCallback: hostCB, Timeout: 5 * time.Second,
				})
			},
		},
		Recorder: recording.NewBundleRecorder(store, recSigner),
	}
	go func() { _ = wr.Run(ctx, []string{workerL.Addr().String()}, cliCfg) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(ctrl.Pool.Workers()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("worker did not register")
		}
		time.Sleep(20 * time.Millisecond)
	}

	g := jb.Issue("op@hexxlock", "sshhost", time.Minute)
	token := mintToken(t, signKey, "op@hexxlock", []string{"platform_admin"})

	// Operator: open the brokered session, then run SSH over it with a CA cert.
	conn, err := client.Dial(ctx, opL.Addr().String(), nil,
		wire.OperatorRequest{Token: token, TargetID: "sshhost", GrantID: g.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	opCert := sshUserCert(t, caSigner, sshSigner(t), "hexxlock")
	cc, chans, reqs, err := ssh.NewClientConn(conn, "jess", &ssh.ClientConfig{
		User: "hexxlock", Auth: []ssh.AuthMethod{ssh.PublicKeys(opCert)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("operator SSH handshake through broker: %v", err)
	}
	sshClient := ssh.NewClient(cc, chans, reqs)
	sess, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("new ssh session: %v", err)
	}
	out, err := sess.Output("hi")
	if err != nil {
		t.Fatalf("ssh output: %v", err)
	}
	if !strings.Contains(string(out), "hello-from-target") {
		t.Fatalf("operator output = %q", out)
	}
	_ = sshClient.Close()

	// The worker seals the bundle on session close; wait for the manifest.
	var sessID string
	verifyDeadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(verifyDeadline) {
		_ = filepath.WalkDir(recDir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d != nil && d.Name() == "manifest.json" {
				sessID = filepath.Base(filepath.Dir(p))
			}
			return nil
		})
		if sessID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sessID == "" {
		t.Fatal("no recording bundle was sealed")
	}

	if err := recording.Verify(ctx, store, sessID, recSigner.Public()); err != nil {
		t.Fatalf("recording bundle failed verification: %v", err)
	}
}
