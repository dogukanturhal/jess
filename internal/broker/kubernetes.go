// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// k8sBroker is the Kubernetes Broker (ADR 0049 Phase 1). It fronts the apiserver
// for the streaming verbs (exec / attach / logs / port-forward) the same way the
// SSH broker fronts sshd: a per-session short-lived credential is minted, the
// backend stream is opened, and every byte is teed into the ADR-0030 WORM
// recorder. Crucially it mints an IMPERSONATION credential bound to the
// operator's Falcon-ID identity (grant.Subject) rather than a standing service
// account, so the cluster's OWN RBAC authorizes (or denies) the request — there
// is no parallel authz in jess. The broker's base credential needs only the
// `impersonate` verb; what the operator can actually do is whatever their
// Falcon-ID user/groups are granted by the cluster's RoleBindings.
//
// Phase 1 implements the `exec` verb end-to-end (the highest value-to-effort
// path, identical recording shape to SSH). `attach`/`logs`/`port-forward` reuse
// the same mint + the same recorded relay; exec is the reference verb here and
// the others are wired the same way as they land (see Verb).
type k8sBroker struct {
	// base is the worker's own apiserver credential (in production built via
	// rest.InClusterConfig — the jess-worker ServiceAccount, which is granted
	// ONLY the `impersonate` verb). Mint clones it and layers the operator's
	// identity on as an ImpersonationConfig; the operator's key/token never
	// reaches the apiserver. nil base = the broker is not configured (Mint
	// denies), mirroring the SSH broker's nil-proxy guard.
	base *rest.Config
	// rec captures the session to a tamper-evident signed WORM bundle, or nil
	// for no recording (a Recorded=true target is then denied, fail-closed) —
	// identical semantics to the SSH broker.
	rec recording.Recorder
	// open dials the apiserver streaming verb for an impersonating config and
	// returns an Executor. Defaults to newSPDYExecutor (the real apiserver SPDY
	// transport); tests inject a fake so the recorded-stream wiring is provable
	// without a live apiserver. Injected, not global, so parallel tests don't
	// race (cf. nowFunc which is read-only after pinning).
	open execOpener
	// openPF dials the apiserver port-forward SPDY stream for an impersonating
	// config and returns a portForwardStream (the raw data stream + the error
	// stream). Defaults to newSPDYPortForward (the real apiserver SPDY
	// transport); tests inject a fake so the recorded raw-stream relay is
	// provable without a live apiserver. Separate from `open` because
	// port-forward uses the apiserver portforward subresource + a distinct stream
	// protocol (not the remotecommand Executor), and is recorded as a raw stream
	// rather than an asciicast.
	openPF pfOpener
}

// execOpener opens an apiserver exec/attach stream for cfg against the resolved
// session coordinates. It is the single seam tests fake. The returned
// Executor's StreamWithContext runs the session (teed into the recorder by the
// relay).
type execOpener func(cfg *rest.Config, kt K8sTarget) (remotecommand.Executor, error)

// pfOpener opens an apiserver port-forward stream for cfg against the resolved
// session coordinates (pod + remote port). It is the single seam the
// port-forward tests fake. The returned portForwardStream is the raw byte tunnel
// the relay copies bidirectionally (and tees into the raw-stream recorder).
type pfOpener func(cfg *rest.Config, kt K8sTarget) (portForwardStream, error)

// portForwardStream is one opened apiserver port-forward tunnel. Data is the raw
// bidirectional byte stream to the pod port (read = bytes from the pod, write =
// bytes to the pod). Err is the apiserver's per-connection error stream: the
// SPDY port-forward protocol multiplexes a separate error channel alongside the
// data channel, and a non-empty read from it means the forward failed (e.g. the
// remote port is closed). The relay reports it; Close tears the tunnel down.
type portForwardStream struct {
	Data io.ReadWriteCloser
	Err  io.Reader
	// Close tears down the underlying SPDY connection + streams. May be nil if
	// closing Data is sufficient (fakes); the relay calls it iff set.
	Close func() error
}

// K8sVerb is the apiserver streaming verb a k8s session brokers. Phase 1 ships
// exec; the others share the mint + recorded relay and are listed so the worker
// can route them as they land.
type K8sVerb string

const (
	// K8sVerbExec is `kubectl exec` — a command/shell in a pod container,
	// recorded as a terminal (asciicast) stream like SSH.
	K8sVerbExec K8sVerb = "exec"
	// K8sVerbAttach is `kubectl attach` — attach to a running container's
	// process; recorded identically to exec.
	K8sVerbAttach K8sVerb = "attach"
	// K8sVerbLogs is `kubectl logs -f` — a streamed read of container logs.
	K8sVerbLogs K8sVerb = "logs"
	// K8sVerbPortForward is `kubectl port-forward` — a tunnelled byte stream;
	// recorded as a raw-stream track (ADR 0049 Phase 4).
	K8sVerbPortForward K8sVerb = "port-forward"
)

// K8sTarget is the apiserver-side coordinates a k8s session brokers. It is
// resolved from the catalog Target (Address = apiserver "host:port" the worker
// reaches; Database = namespace; the pod/container/command come from the target
// metadata or the session request). Kept as a struct so the executor seam and
// the impersonation scope are explicit and testable.
type K8sTarget struct {
	Verb      K8sVerb  // exec | attach | logs | port-forward
	Namespace string   // pod namespace
	Pod       string   // pod name
	Container string   // container name ("" = default container)
	Command   []string // exec/attach command (e.g. ["/bin/sh"])
	TTY       bool     // allocate a TTY (interactive shell)
	Port      int      // remote pod port (port-forward only; from Target.Address port)
}

// NewK8sBroker returns the Kubernetes Broker over the worker's base apiserver
// credential (the impersonate-only ServiceAccount) and recorder. rec may be nil
// — recording is then unavailable and Recorded targets are denied fail-closed,
// exactly as the SSH broker does.
func NewK8sBroker(base *rest.Config, rec recording.Recorder) Broker {
	return &k8sBroker{base: base, rec: rec, open: newSPDYExecutor, openPF: newSPDYPortForward}
}

// Protocol implements Broker.
func (b *k8sBroker) Protocol() string { return string(catalog.ProtoK8s) }

// k8sCredential is the k8s broker's per-session credential: a short-lived
// apiserver config that impersonates the operator's Falcon-ID identity. It is
// NOT a long-lived token — it derives from the worker's base credential plus an
// ImpersonationConfig scoped to this grant, so every apiserver request is
// authorized by the cluster's RBAC as the operator (ADR 0049: "No standing
// credentials"; "Integrates with the cluster's existing RBAC, no parallel
// authz"). Dial of the same broker consumes it.
type k8sCredential struct {
	cfg    *rest.Config // impersonating apiserver config (operator-bound)
	grant  AccessGrant  // carries recording metadata for Dial
	k8s    K8sTarget    // resolved verb + pod coordinates
	asUser string       // the impersonated identity (for audit)
}

func (k8sCredential) Protocol() string { return string(catalog.ProtoK8s) }

// Mint implements Broker. It resolves the k8s session coordinates from the
// grant's target and mints a short-lived impersonating apiserver config bound
// to the operator's Falcon-ID identity (grant.Subject) plus, when the target
// declares them, the operator's RBAC groups (target.RequiredRoles) — so the
// cluster authorizes the session as the operator, not as jess. The base
// credential is cloned (never mutated) so concurrent sessions don't share an
// impersonation. The cluster RBAC, not jess, decides what the operator may do.
func (b *k8sBroker) Mint(_ context.Context, grant AccessGrant) (Credential, error) {
	if b.base == nil {
		return nil, fmt.Errorf("k8s broker: apiserver credential not configured")
	}
	if grant.Target == nil {
		return nil, fmt.Errorf("k8s broker: grant has no target")
	}
	if grant.Subject == "" {
		// Impersonation REQUIRES a concrete operator identity. Refusing here is
		// the fail-closed guard against impersonating an empty (== anonymous /
		// jess-self) user, which would silently bypass the operator's RBAC.
		return nil, fmt.Errorf("k8s broker: grant has no subject to impersonate")
	}
	if grant.Client == nil {
		return nil, fmt.Errorf("k8s broker: grant has no client connection")
	}

	kt, err := k8sTargetFor(grant.Target)
	if err != nil {
		return nil, fmt.Errorf("k8s broker: %w", err)
	}

	// Clone the base config and layer the operator's identity on as
	// impersonation. CopyConfig deep-copies so the worker's base credential is
	// never mutated and parallel sessions never share an Impersonate block.
	cfg := rest.CopyConfig(b.base)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: grant.Subject,
		Groups:   grant.Target.RequiredRoles,
	}

	return k8sCredential{cfg: cfg, grant: grant, k8s: kt, asUser: grant.Subject}, nil
}

// Dial implements Broker. It sets up the WORM recorder (identical fail-closed
// semantics to the SSH broker) and returns a RecordedConn whose Wait opens the
// apiserver stream for the impersonating config and tees the session to the
// bundle, and whose Close seals it.
func (b *k8sBroker) Dial(ctx context.Context, target *catalog.Target, cred Credential) (RecordedConn, error) {
	kc, ok := cred.(k8sCredential)
	if !ok {
		return nil, fmt.Errorf("k8s broker: credential is not a k8s credential (%T)", cred)
	}
	if target == nil {
		return nil, fmt.Errorf("k8s broker: nil target")
	}
	// Phase 4 brokers exec/attach through the remotecommand SPDY relay
	// (asciicast) and port-forward through its own SPDY relay (raw stream). Each
	// uses a DIFFERENT apiserver subresource + recording format, so dispatch by
	// verb. logs is still un-brokered and is denied here so an un-recorded path
	// can never open by falling through (no silent bypass).
	switch kc.k8s.Verb {
	case K8sVerbPortForward:
		return b.dialPortForward(ctx, target, kc)
	case K8sVerbExec, K8sVerbAttach:
		// handled below (the exec/attach asciicast relay)
	default:
		return nil, fmt.Errorf("k8s broker: verb %q not yet brokered (Phase 4 = exec/attach/port-forward)", kc.k8s.Verb)
	}
	if b.open == nil {
		return nil, fmt.Errorf("k8s broker: executor opener not configured")
	}

	conn := &k8sRecordedConn{ctx: ctx, open: b.open, cfg: kc.cfg, target: target, client: kc.grant.Client, k8s: kc.k8s}

	if b.rec != nil {
		meta := recordingMetaFor(kc.grant, string(catalog.ProtoK8s), recording.FormatAsciicastV2)
		rc, rerr := recording.RecordSession(ctx, b.rec, meta, 80, 24)
		if rerr != nil {
			if target.Recorded {
				// Fail closed: a must-record target is denied if recording fails.
				return nil, fmt.Errorf("k8s broker: recording required but unavailable (fail-closed): %w", rerr)
			}
			// Non-recorded target: proceed without a recorder, as SSH does.
		} else {
			conn.rec = rc // Close seals the signed bundle to WORM
		}
	} else if target.Recorded {
		return nil, fmt.Errorf("k8s broker: recording required but no recorder configured (fail-closed)")
	}

	return conn, nil
}

// dialPortForward sets up a port-forward session: it opens the WORM raw-stream
// recorder (same fail-closed semantics as exec/the SSH broker — a Recorded=true
// target is DENIED if recording is unavailable) and returns a RecordedConn whose
// Wait opens the apiserver port-forward SPDY stream for the impersonating config
// and relays the raw byte tunnel, teeing both directions into the bundle, and
// whose Close seals it. Port-forward is recorded as a RAW STREAM (base64 NDJSON)
// not an asciicast — the tunnel is opaque bytes, not a terminal (see
// recording.FormatRawStream / rawstream.go for the format rationale).
func (b *k8sBroker) dialPortForward(ctx context.Context, target *catalog.Target, kc k8sCredential) (RecordedConn, error) {
	if b.openPF == nil {
		return nil, fmt.Errorf("k8s broker: port-forward opener not configured")
	}
	if kc.k8s.Port <= 0 {
		// No silent broad-scope tunnel: a port-forward with no resolved remote
		// port is rejected (the port comes from the target Address; see
		// k8sTargetFor).
		return nil, fmt.Errorf("k8s broker: port-forward has no remote port")
	}

	conn := &k8sPortForwardConn{ctx: ctx, openPF: b.openPF, cfg: kc.cfg, target: target, client: kc.grant.Client, k8s: kc.k8s}

	if b.rec != nil {
		// Open the bundle directly (not recording.RecordSession, which wraps an
		// asciicast writer) and layer the raw-stream NDJSON writer on top, exactly
		// as the Postgres broker layers the query-log writer.
		meta := recordingMetaFor(kc.grant, string(catalog.ProtoK8s), recording.FormatRawStream)
		w, rerr := b.rec.Open(ctx, meta)
		if rerr != nil {
			if target.Recorded {
				return nil, fmt.Errorf("k8s broker: recording required but unavailable (fail-closed): %w", rerr)
			}
			// Non-recorded target: proceed without a recorder, as exec/SSH does.
		} else {
			conn.raw = recording.NewRawStreamWriter(w, recording.RawStreamMeta{
				Protocol:  string(catalog.ProtoK8s),
				Verb:      string(K8sVerbPortForward),
				Namespace: kc.k8s.Namespace,
				Pod:       kc.k8s.Pod,
				Container: kc.k8s.Container,
				Port:      kc.k8s.Port,
			}) // Close seals the signed bundle to WORM
		}
	} else if target.Recorded {
		return nil, fmt.Errorf("k8s broker: recording required but no recorder configured (fail-closed)")
	}

	return conn, nil
}

// k8sPortForwardConn is an open k8s port-forward brokered session. Wait opens the
// apiserver port-forward SPDY stream and relays the raw byte tunnel between the
// operator and the pod port, teeing both directions into the raw-stream
// recorder; Close seals the recording bundle.
type k8sPortForwardConn struct {
	ctx    context.Context
	openPF pfOpener
	cfg    *rest.Config
	target *catalog.Target
	client io.ReadWriteCloser
	k8s    K8sTarget
	raw    *recording.RawStreamWriter // nil = not recording
}

// Wait opens the apiserver port-forward stream for the impersonating config and
// relays the raw byte tunnel bidirectionally between the operator and the pod
// port, recording every chunk (both directions) into the WORM raw-stream bundle.
// It returns when either side closes the tunnel (or the context is cancelled),
// or when the apiserver error stream reports a forward failure.
func (c *k8sPortForwardConn) Wait() error {
	pf, err := c.openPF(c.cfg, c.k8s)
	if err != nil {
		return fmt.Errorf("k8s broker: open apiserver port-forward stream: %w", err)
	}
	if pf.Close != nil {
		defer pf.Close()
	} else if pf.Data != nil {
		defer pf.Data.Close()
	}

	// Drain the apiserver's per-connection error stream: a non-empty read means
	// the forward failed (e.g. the remote port is closed). Captured for the
	// return value; runs concurrently with the copies.
	errCh := make(chan error, 1)
	go func() {
		if pf.Err == nil {
			errCh <- nil
			return
		}
		msg, _ := io.ReadAll(pf.Err)
		if len(msg) > 0 {
			errCh <- fmt.Errorf("k8s broker: port-forward error stream: %s", string(msg))
			return
		}
		errCh <- nil
	}()

	// Bidirectional relay. Each direction is copied through a recording tee so the
	// WORM bundle captures the full tunnel transcript with direction labels. The
	// first direction to finish ends the session (then we close the tunnel via
	// the deferred Close, which unblocks the other copy).
	var wg sync.WaitGroup
	var c2tErr, t2cErr error
	wg.Add(2)
	// operator → target (pod port)
	go func() {
		defer wg.Done()
		dst := io.Writer(pf.Data)
		if c.raw != nil {
			dst = io.MultiWriter(pf.Data, &rawDirWriter{w: c.raw, dir: recording.RawDirClientToTarget})
		}
		_, c2tErr = io.Copy(dst, c.client)
		// Half-close the tunnel write side so the pod sees EOF; closing Data here
		// also unblocks the reverse copy if the server then closes.
		if pf.Data != nil {
			_ = pf.Data.Close()
		}
	}()
	// target (pod port) → operator
	go func() {
		defer wg.Done()
		dst := io.Writer(c.client)
		if c.raw != nil {
			dst = io.MultiWriter(c.client, &rawDirWriter{w: c.raw, dir: recording.RawDirTargetToClient})
		}
		_, t2cErr = io.Copy(dst, pf.Data)
	}()
	wg.Wait()

	streamErr := <-errCh
	if streamErr != nil {
		return streamErr
	}
	if c2tErr != nil {
		return fmt.Errorf("k8s broker: port-forward relay (operator→pod): %w", c2tErr)
	}
	if t2cErr != nil {
		return fmt.Errorf("k8s broker: port-forward relay (pod→operator): %w", t2cErr)
	}
	return nil
}

// Close seals the raw-stream recording bundle (Close error fails the session
// closed, ADR 0030 Phase 5). Safe to call when not recording.
func (c *k8sPortForwardConn) Close() error {
	if c.raw == nil {
		return nil
	}
	return c.raw.Close()
}

// rawDirWriter adapts a RawStreamWriter (Record(dir, p)) to an io.Writer for one
// fixed direction, so it can sit in an io.MultiWriter tee alongside the live
// relay. Record copies p, so reuse of the relay buffer after Write is safe.
type rawDirWriter struct {
	w   *recording.RawStreamWriter
	dir string
}

func (d *rawDirWriter) Write(p []byte) (int, error) {
	if err := d.w.Record(d.dir, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// k8sRecordedConn is an open k8s brokered session. Wait opens the apiserver
// stream and runs it (returns when the operator disconnects or the command
// exits); Close seals the recording bundle.
type k8sRecordedConn struct {
	ctx    context.Context
	open   execOpener
	cfg    *rest.Config
	target *catalog.Target
	client io.ReadWriteCloser
	k8s    K8sTarget
	rec    io.WriteCloser // nil = not recording
}

// Wait opens the apiserver exec/attach stream for the impersonating config and
// proxies it to the operator connection, teeing stdout/stderr into the recorder
// (asciicast). It returns when the command exits or the operator disconnects.
func (c *k8sRecordedConn) Wait() error {
	exec, err := c.open(c.cfg, c.k8s)
	if err != nil {
		return fmt.Errorf("k8s broker: open apiserver stream: %w", err)
	}

	// Tee the backend's stdout/stderr through the recorder, exactly like the SSH
	// broker tees terminal output. Operator stdin flows straight to the pod (we
	// do not record keystrokes here — the recording is the authoritative output
	// transcript, matching the SSH asciicast track).
	var out io.Writer = c.client
	if c.rec != nil {
		out = io.MultiWriter(c.client, c.rec)
	}

	opts := remotecommand.StreamOptions{
		Stdin:  c.client,
		Stdout: out,
		Tty:    c.k8s.TTY,
	}
	// Without a TTY the apiserver multiplexes a separate stderr channel; record
	// it too. With a TTY stderr is folded into stdout (a single PTY stream).
	if !c.k8s.TTY {
		opts.Stderr = out
	}

	return exec.StreamWithContext(c.ctx, opts)
}

// Close seals the recording bundle (Close error fails the session closed, ADR
// 0030 Phase 5). It is safe to call when not recording.
func (c *k8sRecordedConn) Close() error {
	if c.rec == nil {
		return nil
	}
	return c.rec.Close()
}

// k8sTargetFor resolves the apiserver session coordinates from a catalog Target.
// The catalog model is reused unchanged (ADR 0049): Address is the apiserver
// host:port the worker reaches, Database carries the namespace, and the pod /
// container / command are encoded in the target Name (the worker-side resolved
// pod) — Phase 1 brokers an interactive shell (exec, TTY) which is the common
// "kubectl exec -it" path. Fields default safely; missing namespace/pod is an
// error (no silent broad-scope session).
//
// SCAFFOLD GAP (port-forward, Phase 4): this resolver still always returns the
// exec verb. The port-forward verb selection + the remote pod Port are not yet
// sourced from the catalog Target (there is no Target.Port field and the verb is
// not yet encoded in the model), so a port-forward session's Verb + Port must be
// set on the K8sTarget by the caller until that wiring lands. The broker's
// dialPortForward path + the recorded raw-stream relay are fully implemented and
// tested through the pfOpener seam; only this catalog→K8sTarget resolution for
// port-forward remains.
func k8sTargetFor(t *catalog.Target) (K8sTarget, error) {
	if t.Address == "" {
		return K8sTarget{}, fmt.Errorf("target %q has no apiserver address", t.ID)
	}
	ns := t.Database
	if ns == "" {
		return K8sTarget{}, fmt.Errorf("target %q has no namespace (Target.Database)", t.ID)
	}
	if t.Name == "" {
		return K8sTarget{}, fmt.Errorf("target %q has no pod (Target.Name)", t.ID)
	}
	return K8sTarget{
		Verb:      K8sVerbExec,
		Namespace: ns,
		Pod:       t.Name,
		Command:   []string{"/bin/sh"},
		TTY:       true,
	}, nil
}

// newSPDYExecutor is the production execOpener: it builds the apiserver exec URL
// for the resolved pod (POST .../pods/{pod}/exec?command=…&stdin&stdout&tty)
// over the impersonating config and returns a SPDY remotecommand.Executor. This
// is the single place that talks the real apiserver streaming transport; tests
// swap it out via k8sBroker.open. Because cfg carries the operator's
// ImpersonationConfig, the apiserver authorizes the exec as the operator —
// reusing the cluster's RBAC (ADR 0049).
func newSPDYExecutor(cfg *rest.Config, kt K8sTarget) (remotecommand.Executor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil apiserver config")
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build apiserver client: %w", err)
	}
	req := cli.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(kt.Namespace).
		Name(kt.Pod).
		SubResource(string(kt.Verb)). // "exec" | "attach"
		VersionedParams(&corev1.PodExecOptions{
			Container: kt.Container,
			Command:   kt.Command,
			Stdin:     true,
			Stdout:    true,
			Stderr:    !kt.TTY, // with a TTY stderr folds into stdout
			TTY:       kt.TTY,
		}, scheme.ParameterCodec)
	return remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
}

// newSPDYPortForward is the production pfOpener: it builds the apiserver
// port-forward URL for the resolved pod (POST .../pods/{pod}/portforward) over
// the impersonating config, dials the SPDY connection, and creates the error +
// data streams for the remote pod port — returning the raw data stream the relay
// copies bidirectionally. This is the single place that talks the real apiserver
// port-forward transport; tests swap it out via k8sBroker.openPF. Because cfg
// carries the operator's ImpersonationConfig, the apiserver authorizes the
// port-forward as the operator — reusing the cluster's RBAC (ADR 0049).
//
// The stream setup mirrors client-go's own tools/portforward.handleConnection:
// the SPDY connection multiplexes a per-request error stream (StreamTypeError,
// drained for failures) and a data stream (StreamTypeData) carrying the raw
// tunnel bytes, both tagged with the remote PortHeader + a request id.
func newSPDYPortForward(cfg *rest.Config, kt K8sTarget) (portForwardStream, error) {
	if cfg == nil {
		return portForwardStream{}, fmt.Errorf("nil apiserver config")
	}
	if kt.Port <= 0 {
		return portForwardStream{}, fmt.Errorf("port-forward has no remote port")
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return portForwardStream{}, fmt.Errorf("build apiserver client: %w", err)
	}
	req := cli.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(kt.Namespace).
		Name(kt.Pod).
		SubResource(string(K8sVerbPortForward))

	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return portForwardStream{}, fmt.Errorf("build SPDY round-tripper: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())
	streamConn, _, err := dialer.Dial(portForwardProtocolV1Name)
	if err != nil {
		return portForwardStream{}, fmt.Errorf("dial port-forward SPDY: %w", err)
	}

	port := strconv.Itoa(kt.Port)
	// Error stream first (the apiserver expects it before the data stream), then
	// the data stream — both carry the remote port + a shared request id.
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, port)
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errStream, err := streamConn.CreateStream(headers)
	if err != nil {
		streamConn.Close()
		return portForwardStream{}, fmt.Errorf("create port-forward error stream: %w", err)
	}
	// We never write to the error stream.
	_ = errStream.Close()

	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := streamConn.CreateStream(headers)
	if err != nil {
		streamConn.Close()
		return portForwardStream{}, fmt.Errorf("create port-forward data stream: %w", err)
	}

	return portForwardStream{
		Data:  dataStream,
		Err:   errStream,
		Close: func() error { return streamConn.Close() },
	}, nil
}

// portForwardProtocolV1Name is the apiserver port-forward SPDY subprotocol
// (mirrors client-go tools/portforward.PortForwardProtocolV1Name; redeclared so
// the broker does not import the high-level PortForwarder, which binds local TCP
// listeners — jess relays the raw stream over the operator connection instead).
const portForwardProtocolV1Name = "portforward.k8s.io"
