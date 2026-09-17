// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// These tests exercise the Kubernetes Broker (ADR 0049 Phase 1) THROUGH the
// Broker interface (Mint → Dial → RecordedConn). They prove the two
// protocol-specific pieces:
//   - Mint binds the apiserver credential to the operator's Falcon-ID identity
//     via impersonation (so the cluster's OWN RBAC authorizes) and never mutates
//     the worker's base credential.
//   - Dial tees the apiserver stream into the WORM recorder exactly like SSH,
//     with the same fail-closed semantics for Recorded targets.
//
// The apiserver is faked via the execOpener seam (no live cluster needed).

// fakeExecutor is a remotecommand.Executor that replays a fixed transcript to
// the session's Stdout/Stderr — standing in for a pod's exec stream. It records
// the impersonating config it was opened with so a test can assert the operator
// identity reached the apiserver layer.
type fakeExecutor struct {
	output string
}

func (f fakeExecutor) Stream(remotecommand.StreamOptions) error { return nil }

func (f fakeExecutor) StreamWithContext(_ context.Context, opts remotecommand.StreamOptions) error {
	if opts.Stdout != nil {
		if _, err := io.WriteString(opts.Stdout, f.output); err != nil {
			return err
		}
	}
	return nil
}

// k8sTestTarget is a well-formed k8s catalog target (apiserver address +
// namespace + pod) used across the Dial tests.
func k8sTestTarget(recorded bool) *catalog.Target {
	return &catalog.Target{
		ID:       "node-app-01",
		Name:     "shell-pod", // Phase 1: Target.Name = pod
		Protocol: catalog.ProtoK8s,
		Address:  "https://10.0.0.1:6443",
		Database: "default", // Phase 1: Target.Database = namespace
		Recorded: recorded,
	}
}

// newTestK8sBroker builds a k8s broker over a non-nil base config with the
// apiserver opener swapped for a fake that replays output.
func newTestK8sBroker(t *testing.T, rec recording.Recorder, output string) *k8sBroker {
	t.Helper()
	return &k8sBroker{
		base: &rest.Config{Host: "https://10.0.0.1:6443"},
		rec:  rec,
		open: func(_ *rest.Config, _ K8sTarget) (remotecommand.Executor, error) {
			return fakeExecutor{output: output}, nil
		},
	}
}

func TestK8sBrokerProtocol(t *testing.T) {
	b := NewK8sBroker(&rest.Config{}, nil)
	if got := b.Protocol(); got != string(catalog.ProtoK8s) {
		t.Fatalf("Protocol() = %q, want %q", got, catalog.ProtoK8s)
	}
}

// TestK8sBrokerMintImpersonatesOperator proves Mint binds the apiserver
// credential to the operator's Falcon-ID identity + RBAC groups (the ADR-0049
// "no parallel authz" property) and clones the base config rather than mutating
// it.
func TestK8sBrokerMintImpersonatesOperator(t *testing.T) {
	base := &rest.Config{Host: "https://10.0.0.1:6443"}
	b := &k8sBroker{base: base, open: newSPDYExecutor}

	target := k8sTestTarget(false)
	target.RequiredRoles = []string{"platform-admins", "sre"}
	grant := AccessGrant{Target: target, GrantID: "g-1", Subject: "alice@hexxlock", Client: &fakeConn{}}

	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	kc, ok := cred.(k8sCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want k8sCredential", cred)
	}
	if kc.cfg.Impersonate.UserName != "alice@hexxlock" {
		t.Errorf("impersonated user = %q, want the operator subject", kc.cfg.Impersonate.UserName)
	}
	if got := strings.Join(kc.cfg.Impersonate.Groups, ","); got != "platform-admins,sre" {
		t.Errorf("impersonated groups = %q, want the target RequiredRoles", got)
	}
	// The base config must NOT have been mutated — concurrent sessions must not
	// share an impersonation block.
	if base.Impersonate.UserName != "" {
		t.Errorf("base config impersonation was mutated: %q", base.Impersonate.UserName)
	}
	if kc.k8s.Namespace != "default" || kc.k8s.Pod != "shell-pod" {
		t.Errorf("resolved k8s target = %+v, want ns=default pod=shell-pod", kc.k8s)
	}
}

func TestK8sBrokerMintValidation(t *testing.T) {
	b := &k8sBroker{base: &rest.Config{}, open: newSPDYExecutor}
	ctx := context.Background()

	// nil base = not configured.
	if _, err := (&k8sBroker{}).Mint(ctx, AccessGrant{Target: k8sTestTarget(false), Subject: "a", Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a broker with no apiserver credential")
	}
	if _, err := b.Mint(ctx, AccessGrant{Subject: "a", Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a grant with no target")
	}
	if _, err := b.Mint(ctx, AccessGrant{Target: k8sTestTarget(false), Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a grant with no subject to impersonate")
	}
	if _, err := b.Mint(ctx, AccessGrant{Target: k8sTestTarget(false), Subject: "a"}); err == nil {
		t.Fatal("Mint must reject a grant with no client connection")
	}
	// Missing namespace.
	noNS := k8sTestTarget(false)
	noNS.Database = ""
	if _, err := b.Mint(ctx, AccessGrant{Target: noNS, Subject: "a", Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a target with no namespace")
	}
	// Missing pod.
	noPod := k8sTestTarget(false)
	noPod.Name = ""
	if _, err := b.Mint(ctx, AccessGrant{Target: noPod, Subject: "a", Client: &fakeConn{}}); err == nil {
		t.Fatal("Mint must reject a target with no pod")
	}
}

// TestK8sBrokerRoundTripAndRecord is the headline test: the brokered exec
// session round-trips the pod's output to the operator AND tees it to the WORM
// recorder (asciicast v2), driven through the Broker interface.
func TestK8sBrokerRoundTripAndRecord(t *testing.T) {
	var recBuf safeBuf
	b := newTestK8sBroker(t, fixedRecorder{w: recording.NewAsciicastWriter(&recBuf, 80, 24)}, "hello-from-pod\n")

	target := k8sTestTarget(true) // Recorded
	var opOut safeBuf
	client := &rwcConn{r: strings.NewReader(""), w: &opOut}
	grant := AccessGrant{Target: target, GrantID: "g-1", Subject: "alice@hexxlock", SessionID: "sess-1", Client: client}

	ctx := context.Background()
	cred, err := b.Mint(ctx, grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rc, err := b.Dial(ctx, target, cred)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := rc.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (seal): %v", err)
	}

	// Operator saw the pod output.
	if !strings.Contains(opOut.String(), "hello-from-pod") {
		t.Errorf("operator output = %q, want the pod greeting", opOut.String())
	}
	// The recorder captured it as asciicast v2.
	recorded := recBuf.String()
	if !strings.Contains(recorded, `"version":2`) {
		t.Errorf("recording is not asciicast v2:\n%s", recorded)
	}
	if !strings.Contains(recorded, "hello-from-pod") {
		t.Errorf("recording missing session output:\n%s", recorded)
	}
}

// TestK8sBrokerFailClosedOnRecordingError proves a Recorded=true target is
// DENIED at Dial when the recorder errors, and a non-recorded target proceeds —
// identical fail-closed semantics to the SSH broker.
func TestK8sBrokerFailClosedOnRecordingError(t *testing.T) {
	b := newTestK8sBroker(t, errRecorder{}, "x")
	ctx := context.Background()

	recorded := k8sTestTarget(true)
	grant := AccessGrant{Target: recorded, GrantID: "g", Subject: "a", Client: &fakeConn{}}
	cred, err := b.Mint(ctx, grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(ctx, recorded, cred); err == nil {
		t.Fatal("Recorded=true target must be DENIED when the recorder errors (fail-closed)")
	}

	// Non-recorded target proceeds despite the recorder error.
	open := k8sTestTarget(false)
	cred2, err := b.Mint(ctx, AccessGrant{Target: open, GrantID: "g", Subject: "a", Client: &fakeConn{}})
	if err != nil {
		t.Fatalf("mint (non-recorded): %v", err)
	}
	rc, err := b.Dial(ctx, open, cred2)
	if err != nil {
		t.Fatalf("non-recorded target must proceed despite recorder error: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (no recorder attached): %v", err)
	}
}

// TestK8sBrokerNoRecorderDeniesRecordedTarget proves a Recorded target with NO
// recorder configured is denied (the other fail-closed branch).
func TestK8sBrokerNoRecorderDeniesRecordedTarget(t *testing.T) {
	b := &k8sBroker{base: &rest.Config{}, open: newSPDYExecutor}
	ctx := context.Background()
	target := k8sTestTarget(true)
	cred, err := b.Mint(ctx, AccessGrant{Target: target, GrantID: "g", Subject: "a", Client: &fakeConn{}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(ctx, target, cred); err == nil {
		t.Fatal("Recorded=true target with no recorder must be denied (fail-closed)")
	}
}

func TestK8sBrokerDialRejectsForeignCredential(t *testing.T) {
	b := NewK8sBroker(&rest.Config{}, nil)
	if _, err := b.Dial(context.Background(), k8sTestTarget(false), foreignCred{}); err == nil {
		t.Fatal("Dial must reject a credential minted by a different broker")
	}
}

// TestK8sBrokerDialRejectsUnbrokeredVerb proves a verb jess does not yet broker
// is denied at Dial — no silent fall-through to an un-recorded path.
func TestK8sBrokerDialRejectsUnbrokeredVerb(t *testing.T) {
	b := newTestK8sBroker(t, nil, "x")
	target := k8sTestTarget(false)
	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, Subject: "a", Client: &fakeConn{}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	kc := cred.(k8sCredential)
	kc.k8s.Verb = K8sVerbLogs // not brokered (logs is still un-wired as of Phase 4)
	if _, err := b.Dial(context.Background(), target, kc); err == nil {
		t.Fatal("Dial must reject an unbrokered verb (no silent fall-through)")
	}
}

// rwcConn is a minimal io.ReadWriteCloser backing the operator side of a k8s
// session (the apiserver relay only needs ReadWriteCloser, unlike SSH's
// net.Conn). r feeds operator stdin; w captures what the pod sent back.
type rwcConn struct {
	r io.Reader
	w io.Writer
}

func (c *rwcConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *rwcConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *rwcConn) Close() error                { return nil }

// ---------------------------------------------------------------------------
// Port-forward (ADR 0049 Phase 4) tests — exercised THROUGH the Broker
// interface (Mint → Dial → RecordedConn). They prove the port-forward verb:
//   - Dial brokers port-forward (no longer denied) via the pfOpener seam.
//   - Wait relays the raw byte tunnel bidirectionally between operator and pod
//     port AND tees BOTH directions into the WORM raw-stream recorder.
//   - The same fail-closed recording semantics as exec/the SSH broker apply.
//
// The apiserver port-forward stream is faked via the pfOpener seam (no live
// cluster needed).

// fakePFStream is a fake apiserver port-forward data stream: it serves a fixed
// transcript to the operator (read side) and captures whatever the operator
// sends toward the pod (write side). errMsg, when non-empty, is served on the
// error stream to drive the forward-failure path.
type fakePFStream struct {
	fromPod *strings.Reader // bytes the pod sends back to the operator
	toPod   safeBuf         // captures bytes the operator sent toward the pod
	closed  bool
}

func (s *fakePFStream) Read(p []byte) (int, error)  { return s.fromPod.Read(p) }
func (s *fakePFStream) Write(p []byte) (int, error) { return s.toPod.Write(p) }
func (s *fakePFStream) Close() error                { s.closed = true; return nil }

// newPFK8sBroker builds a k8s broker whose port-forward opener returns a fake
// stream replaying fromPod and capturing operator→pod bytes. errMsg drives the
// error-stream failure path when non-empty. The returned *fakePFStream lets the
// test assert what the operator sent.
func newPFK8sBroker(t *testing.T, rec recording.Recorder, fromPod, errMsg string) (*k8sBroker, *fakePFStream) {
	t.Helper()
	stream := &fakePFStream{fromPod: strings.NewReader(fromPod)}
	var errR io.Reader
	if errMsg != "" {
		errR = strings.NewReader(errMsg)
	} else {
		errR = strings.NewReader("")
	}
	b := &k8sBroker{
		base: &rest.Config{Host: "https://10.0.0.1:6443"},
		rec:  rec,
		open: func(_ *rest.Config, _ K8sTarget) (remotecommand.Executor, error) {
			return fakeExecutor{}, nil
		},
		openPF: func(_ *rest.Config, _ K8sTarget) (portForwardStream, error) {
			return portForwardStream{Data: stream, Err: errR, Close: stream.Close}, nil
		},
	}
	return b, stream
}

// pfCred mints a port-forward credential against a target, forcing the verb +
// remote port on the resolved K8sTarget (the catalog→K8sTarget port-forward
// resolution is a documented scaffold gap; see k8sTargetFor).
func pfCred(t *testing.T, b *k8sBroker, target *catalog.Target, client io.ReadWriteCloser) Credential {
	t.Helper()
	grant := AccessGrant{Target: target, GrantID: "g-pf", Subject: "alice@hexxlock", SessionID: "sess-pf", Client: client}
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	kc := cred.(k8sCredential)
	kc.k8s.Verb = K8sVerbPortForward
	kc.k8s.Port = 5432
	return kc
}

// TestK8sBrokerPortForwardRoundTripAndRecord is the headline port-forward test:
// the brokered tunnel round-trips the pod's bytes to the operator, forwards the
// operator's bytes to the pod, AND tees BOTH directions into the WORM raw-stream
// recorder (base64 NDJSON), driven through the Broker interface.
func TestK8sBrokerPortForwardRoundTripAndRecord(t *testing.T) {
	cap := &captureWriter{}
	b, stream := newPFK8sBroker(t, fixedRecorder{w: cap}, "PONG-FROM-POD", "")

	target := k8sTestTarget(true) // Recorded
	var opOut safeBuf
	client := &rwcConn{r: strings.NewReader("PING-FROM-OPERATOR"), w: &opOut}
	cred := pfCred(t, b, target, client)

	ctx := context.Background()
	rc, err := b.Dial(ctx, target, cred)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := rc.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (seal): %v", err)
	}

	// Operator received the pod's bytes.
	if !strings.Contains(opOut.String(), "PONG-FROM-POD") {
		t.Errorf("operator output = %q, want the pod bytes", opOut.String())
	}
	// Pod received the operator's bytes.
	if !strings.Contains(stream.toPod.String(), "PING-FROM-OPERATOR") {
		t.Errorf("pod received = %q, want the operator bytes", stream.toPod.String())
	}

	// The recording is raw-stream NDJSON: a meta header line + chunk lines for
	// BOTH directions carrying the base64 bytes.
	recorded := cap.buf.String()
	if !strings.Contains(recorded, `"kind":"meta"`) || !strings.Contains(recorded, `"verb":"port-forward"`) {
		t.Errorf("recording missing raw-stream meta header:\n%s", recorded)
	}
	if !strings.Contains(recorded, `"dir":"`+recording.RawDirClientToTarget+`"`) {
		t.Errorf("recording missing operator→pod chunk:\n%s", recorded)
	}
	if !strings.Contains(recorded, `"dir":"`+recording.RawDirTargetToClient+`"`) {
		t.Errorf("recording missing pod→operator chunk:\n%s", recorded)
	}
	// The base64 of the operator's PING must be present in a recorded chunk.
	wantB64 := base64.StdEncoding.EncodeToString([]byte("PING-FROM-OPERATOR"))
	if !strings.Contains(recorded, wantB64) {
		t.Errorf("recording missing base64 of operator bytes (%s):\n%s", wantB64, recorded)
	}
	if !cap.closed {
		t.Error("bundle was not sealed (Close not propagated to the WORM writer)")
	}
}

// TestK8sBrokerPortForwardFailClosedOnRecordingError proves a Recorded=true
// port-forward target is DENIED at Dial when the recorder errors, and a
// non-recorded target proceeds — same fail-closed semantics as exec.
func TestK8sBrokerPortForwardFailClosedOnRecordingError(t *testing.T) {
	b, _ := newPFK8sBroker(t, errRecorder{}, "x", "")
	ctx := context.Background()

	recorded := k8sTestTarget(true)
	cred := pfCred(t, b, recorded, &fakeConn{})
	if _, err := b.Dial(ctx, recorded, cred); err == nil {
		t.Fatal("Recorded=true port-forward must be DENIED when the recorder errors (fail-closed)")
	}

	// Non-recorded target proceeds despite the recorder error.
	open := k8sTestTarget(false)
	cred2 := pfCred(t, b, open, &fakeConn{})
	rc, err := b.Dial(ctx, open, cred2)
	if err != nil {
		t.Fatalf("non-recorded port-forward must proceed despite recorder error: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (no recorder attached): %v", err)
	}
}

// TestK8sBrokerPortForwardNoRecorderDeniesRecordedTarget proves a Recorded
// port-forward target with NO recorder configured is denied (fail-closed).
func TestK8sBrokerPortForwardNoRecorderDeniesRecordedTarget(t *testing.T) {
	b, _ := newPFK8sBroker(t, nil, "x", "")
	target := k8sTestTarget(true)
	cred := pfCred(t, b, target, &fakeConn{})
	if _, err := b.Dial(context.Background(), target, cred); err == nil {
		t.Fatal("Recorded=true port-forward with no recorder must be denied (fail-closed)")
	}
}

// TestK8sBrokerPortForwardRejectsMissingPort proves a port-forward with no
// resolved remote port is denied (no silent broad-scope tunnel).
func TestK8sBrokerPortForwardRejectsMissingPort(t *testing.T) {
	b, _ := newPFK8sBroker(t, nil, "x", "")
	target := k8sTestTarget(false)
	grant := AccessGrant{Target: target, GrantID: "g", Subject: "a", Client: &fakeConn{}}
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	kc := cred.(k8sCredential)
	kc.k8s.Verb = K8sVerbPortForward // Port left 0
	if _, err := b.Dial(context.Background(), target, kc); err == nil {
		t.Fatal("port-forward with no remote port must be denied")
	}
}

// TestK8sBrokerPortForwardSurfacesErrorStream proves a non-empty apiserver
// error stream (e.g. the remote port is closed) is surfaced as a Wait error.
func TestK8sBrokerPortForwardSurfacesErrorStream(t *testing.T) {
	b, _ := newPFK8sBroker(t, nil, "", "connection refused")
	target := k8sTestTarget(false)
	var opOut safeBuf
	client := &rwcConn{r: strings.NewReader(""), w: &opOut}
	cred := pfCred(t, b, target, client)

	rc, err := b.Dial(context.Background(), target, cred)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := rc.Wait(); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Wait must surface the error stream, got: %v", err)
	}
}
