// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// These tests exercise the ADR 0049 Phase 3 RDP Broker THROUGH the Broker
// interface (Mint → Dial → RecordedConn), proving the protocol-specific pieces
// WITHOUT a live RDP wire (the real engine is stubbed/faked):
//   - Mint mints the ephemeral AD credential / gateway ticket scoped to the
//     target (role = target ID) and validates the grant fail-closed.
//   - Dial sets up the WORM metadata+screenshot recorder with the same
//     fail-closed semantics as the SSH/Postgres brokers.
//   - The recorded relay tees session_start/end + periodic screenshots + every
//     virtual-channel decision into the WORM track, and the channel gate denies
//     redirection channels fail-closed by default.

// --- fakes ------------------------------------------------------------------

// fakeRDPCreds is a stand-in RDPCredentialBroker that records the Vault role it
// was asked for and returns a fixed ephemeral AD credential.
type fakeRDPCreds struct {
	role string
	err  error
}

func (f *fakeRDPCreds) IssueRDPCredential(_ context.Context, role string) (RDPSecret, error) {
	f.role = role
	if f.err != nil {
		return RDPSecret{}, f.err
	}
	return RDPSecret{Kind: RDPSecretADCredential, Username: "svc-ephemeral", Password: "p@ss", Domain: "HEXXLOCK"}, nil
}

// fakeRDPConn is a minimal net.Conn for the Mint/Dial paths.
type fakeRDPConn struct{ net.Conn }

func (c *fakeRDPConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *fakeRDPConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakeRDPConn) Close() error                { return nil }

// fakeRDPEngine replays a scripted RDP session: it offers a set of virtual
// channels to the gate (recording the decisions), serves a fixed number of
// snapshots, and ends when Run is told to. It records the secret it was opened
// with so a test can assert the minted credential reached the engine.
type fakeRDPEngine struct {
	offerChannels []string // channels the engine tries to negotiate (gated)
	snapshot      []byte   // bytes Snapshot returns (empty = no frame)
	gotSecret     RDPSecret
}

func (e *fakeRDPEngine) Open(_ context.Context, _ *catalog.Target, sec RDPSecret, _ io.ReadWriteCloser, gate channelGate) (rdpSession, error) {
	e.gotSecret = sec
	// Drive the channel gate exactly like a real engine would during channel
	// negotiation — this is what records the per-channel decisions.
	for _, ch := range e.offerChannels {
		_ = gate.Allow(ch)
	}
	return &fakeRDPSession{snapshot: e.snapshot, done: make(chan struct{})}, nil
}

type fakeRDPSession struct {
	snapshot []byte
	done     chan struct{}
	once     sync.Once
}

func (s *fakeRDPSession) Run() error {
	<-s.done // ends when Close is called (operator disconnect)
	return nil
}
func (s *fakeRDPSession) Snapshot() ([]byte, int, int, error) {
	if len(s.snapshot) == 0 {
		return nil, 0, 0, nil
	}
	return s.snapshot, 1920, 1080, nil
}
func (s *fakeRDPSession) Close() error {
	s.end()
	return nil
}

// end makes Run return (operator disconnect), idempotently.
func (s *fakeRDPSession) end() { s.once.Do(func() { close(s.done) }) }

// endFakeRDPSession signals the live fake session to return from Run, simulating
// an operator disconnect — WITHOUT sealing the recording bundle (that is Close's
// job, called after Wait returns, matching the production lifecycle).
func endFakeRDPSession(t *testing.T, rc *rdpRecordedConn) {
	t.Helper()
	rc.mu.Lock()
	sess := rc.session
	rc.mu.Unlock()
	fs, ok := sess.(*fakeRDPSession)
	if !ok {
		t.Fatalf("live session is %T, want *fakeRDPSession", sess)
	}
	fs.end()
}

// captureRecorder hands out a single capturing WriteCloser so the test can read
// the NDJSON RDP track the relay teed.
type captureRecorder struct{ w *rdpCaptureWriter }

func (r captureRecorder) Open(context.Context, recording.Meta) (io.WriteCloser, error) {
	return r.w, nil
}

type rdpCaptureWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (c *rdpCaptureWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *rdpCaptureWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *rdpCaptureWriter) events() []recording.RDPEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var evs []recording.RDPEvent
	for _, ln := range strings.Split(strings.TrimSpace(c.buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var ev recording.RDPEvent
		if err := json.Unmarshal([]byte(ln), &ev); err == nil {
			evs = append(evs, ev)
		}
	}
	return evs
}

// --- tests ------------------------------------------------------------------

func TestRDPBrokerProtocol(t *testing.T) {
	b := NewRDPBroker(&fakeRDPCreds{}, nil, 0)
	if got := b.Protocol(); got != string(catalog.ProtoRDP) {
		t.Fatalf("Protocol() = %q, want %q", got, catalog.ProtoRDP)
	}
}

// TestRDPBrokerMint proves Mint mints the ephemeral credential scoped to the
// target (role = target ID) and that the operator's grant carries it for Dial.
func TestRDPBrokerMint(t *testing.T) {
	creds := &fakeRDPCreds{}
	b := NewRDPBroker(creds, nil, 0)
	target := &catalog.Target{ID: "win-dc-01", Protocol: catalog.ProtoRDP, Address: "10.0.0.9:3389"}

	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, GrantID: "g1", Subject: "op@test", Client: &fakeRDPConn{}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if creds.role != "win-dc-01" {
		t.Errorf("minted Vault role = %q, want target ID %q", creds.role, "win-dc-01")
	}
	rc, ok := cred.(rdpCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want rdpCredential", cred)
	}
	if cred.Protocol() != string(catalog.ProtoRDP) {
		t.Errorf("credential Protocol() = %q, want rdp", cred.Protocol())
	}
	if rc.sec.Kind != RDPSecretADCredential || rc.sec.Username != "svc-ephemeral" {
		t.Errorf("minted secret = %+v, want ephemeral AD credential", rc.sec)
	}
}

func TestRDPBrokerMintValidation(t *testing.T) {
	b := NewRDPBroker(&fakeRDPCreds{}, nil, 0)
	if _, err := b.Mint(context.Background(), AccessGrant{Client: &fakeRDPConn{}}); err == nil {
		t.Error("Mint must reject a grant with no target")
	}
	if _, err := b.Mint(context.Background(), AccessGrant{Target: &catalog.Target{ID: "t"}}); err == nil {
		t.Error("Mint must reject a grant with no client connection")
	}
	if _, err := NewRDPBroker(nil, nil, 0).Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakeRDPConn{}}); err == nil {
		t.Error("Mint must reject a broker with no credential broker (cannot mint ephemeral credential)")
	}
}

func TestRDPBrokerMintCredErrorFailsClosed(t *testing.T) {
	b := NewRDPBroker(&fakeRDPCreds{err: io.ErrUnexpectedEOF}, nil, 0)
	if _, err := b.Mint(context.Background(),
		AccessGrant{Target: &catalog.Target{ID: "t"}, Client: &fakeRDPConn{}}); err == nil {
		t.Error("Mint must surface a Vault mint error (fail-closed, no session without a credential)")
	}
}

func TestRDPBrokerDialRejectsForeignCredential(t *testing.T) {
	b := NewRDPBroker(&fakeRDPCreds{}, nil, 0)
	if _, err := b.Dial(context.Background(), &catalog.Target{ID: "t"}, foreignCred{}); err == nil {
		t.Fatal("Dial must reject a credential minted by a different broker")
	}
}

// TestRDPBrokerDialFailClosed proves a Recorded=true target is DENIED at Dial
// when the recorder errors and when no recorder is configured, and that a
// non-recorded target proceeds despite a recorder error.
func TestRDPBrokerDialFailClosed(t *testing.T) {
	target := &catalog.Target{ID: "t", Protocol: catalog.ProtoRDP, Address: "127.0.0.1:3389", Recorded: true}
	grant := AccessGrant{Target: target, GrantID: "g", Subject: "op", Client: &fakeRDPConn{}}

	// recorder errors → denied.
	b := NewRDPBroker(&fakeRDPCreds{}, errRecorder{}, 0)
	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.Dial(context.Background(), target, cred); err == nil {
		t.Error("Recorded=true target must be DENIED when the recorder errors (fail-closed)")
	}

	// no recorder configured → denied.
	b2 := NewRDPBroker(&fakeRDPCreds{}, nil, 0)
	cred2, err := b2.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b2.Dial(context.Background(), target, cred2); err == nil {
		t.Error("Recorded=true target with no recorder must be denied (fail-closed)")
	}

	// non-recorded target with a recorder error → proceeds (no recording).
	target.Recorded = false
	rc, err := b.Dial(context.Background(), target, cred)
	if err != nil {
		t.Fatalf("non-recorded target must proceed despite recorder error: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close (no recorder attached): %v", err)
	}
}

// TestStubEngineFailsClosed proves the default (un-wired) RDP engine refuses to
// open a session — a registered RDP broker fails LOUD, never silently bypasses.
func TestStubEngineFailsClosed(t *testing.T) {
	target := &catalog.Target{ID: "t", Protocol: catalog.ProtoRDP, Address: "127.0.0.1:3389"}
	b := NewRDPBroker(&fakeRDPCreds{}, nil, 0)
	cred, err := b.Mint(context.Background(), AccessGrant{Target: target, Client: &fakeRDPConn{}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	conn, err := b.Dial(context.Background(), target, cred)
	if err != nil {
		t.Fatalf("dial (non-recorded): %v", err)
	}
	if err := conn.Wait(); err == nil {
		t.Error("stub RDP engine must fail closed on Wait (engine not implemented)")
	}
	_ = conn.Close()
}

// TestRDPRecordedRelay is the headline test: with a fake engine, Wait records
// session_start, the periodic screenshots, every channel decision, and
// session_end into the WORM track — and the minted credential reaches the engine
// (NLA/CredSSP terminated at the broker). The channel gate denies a non-allowed
// redirection channel fail-closed and allows an explicitly allow-listed one.
func TestRDPRecordedRelay(t *testing.T) {
	cap := &rdpCaptureWriter{}
	engine := &fakeRDPEngine{
		offerChannels: []string{RDPChannelClipboard, RDPChannelSound}, // clipboard denied, sound allowed
		snapshot:      []byte("PNGDATA"),
	}
	// Allow only the sound channel; clipboard/drive/printer stay denied (default).
	b := NewRDPBroker(&fakeRDPCreds{}, captureRecorder{w: cap}, 5*time.Millisecond).(*rdpBroker)
	b.withRDPEngine(engine)

	target := &catalog.Target{ID: "win-dc-01", Protocol: catalog.ProtoRDP, Address: "10.0.0.9:3389", Recorded: true}
	grant := AccessGrant{Target: target, GrantID: "g1", Subject: "op@test", Client: &fakeRDPConn{}}

	cred, err := b.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	conn, err := b.Dial(context.Background(), target, cred)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	rc := conn.(*rdpRecordedConn)
	// Override the deny-all default gate so we can prove BOTH an allow and a deny
	// are recorded (channelGateFor has no per-target column yet).
	rc.gate = ChannelPolicy{AllowedChannels: []string{RDPChannelSound}}

	// Run the relay in the background; let the screenshot pump tick a few times,
	// then end the session as an OPERATOR DISCONNECT would: the wire's Run returns
	// (here driven by ending the fake session), Wait records session_end and
	// returns, THEN Close seals the bundle. This is the production lifecycle order
	// (Close-seals-last) — using Close to end Run would seal before session_end.
	waitErr := make(chan error, 1)
	go func() { waitErr <- conn.Wait() }()
	time.Sleep(30 * time.Millisecond) // allow several 5ms screenshot ticks
	endFakeRDPSession(t, rc)          // operator disconnect → Run returns
	if err := <-waitErr; err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close (seal bundle): %v", err)
	}

	// The minted ephemeral credential reached the engine (broker re-auth to target).
	if engine.gotSecret.Username != "svc-ephemeral" {
		t.Errorf("engine got secret %+v, want the minted ephemeral credential", engine.gotSecret)
	}
	if !cap.closed {
		t.Error("Close must seal the underlying bundle")
	}

	evs := cap.events()
	var (
		sawStart, sawEnd bool
		shots            int
		clipDenied       bool
		soundAllowed     bool
	)
	for _, ev := range evs {
		switch ev.Event {
		case recording.RDPEventSessionStart:
			sawStart = true
		case recording.RDPEventSessionEnd:
			sawEnd = true
		case recording.RDPEventScreenshot:
			shots++
			if ev.ScreenshotSHA256 == "" {
				t.Error("screenshot event must carry a screenshot_sha256 reference")
			}
			if ev.Width != 1920 || ev.Height != 1080 {
				t.Errorf("screenshot dims = %dx%d, want 1920x1080", ev.Width, ev.Height)
			}
		case recording.RDPEventChannel:
			switch ev.Channel {
			case RDPChannelClipboard:
				if ev.Decision == recording.RDPDenied && ev.DenyReason != "" {
					clipDenied = true
				}
			case RDPChannelSound:
				if ev.Decision == recording.RDPAllowed {
					soundAllowed = true
				}
			}
		}
	}
	if !sawStart || !sawEnd {
		t.Errorf("track must record session_start AND session_end (start=%v end=%v)", sawStart, sawEnd)
	}
	if shots == 0 {
		t.Error("periodic-screenshot pump must record at least one screenshot reference")
	}
	if !clipDenied {
		t.Error("clipboard channel must be recorded as DENIED with a reason (fail-closed gate)")
	}
	if !soundAllowed {
		t.Error("allow-listed sound channel must be recorded as ALLOWED")
	}
	// session_start must precede the first screenshot and session_end be last.
	if len(evs) < 3 || evs[0].Event != recording.RDPEventSessionStart {
		t.Errorf("first event must be session_start, got %+v", evs)
	}
	if evs[len(evs)-1].Event != recording.RDPEventSessionEnd {
		t.Errorf("last event must be session_end, got %q", evs[len(evs)-1].Event)
	}
}

// TestChannelPolicyDenyByDefault proves the zero-value ChannelPolicy is
// fail-closed (every redirection channel denied) and an allow-list permits only
// listed channels.
func TestChannelPolicyDenyByDefault(t *testing.T) {
	deny := ChannelPolicy{}
	for _, ch := range []string{RDPChannelClipboard, RDPChannelDrive, RDPChannelPrinter, RDPChannelSound} {
		if err := deny.Allow(ch); err == nil {
			t.Errorf("zero-value ChannelPolicy must DENY %q (fail-closed)", ch)
		}
	}
	allow := ChannelPolicy{AllowedChannels: []string{RDPChannelSound}}
	if err := allow.Allow(RDPChannelSound); err != nil {
		t.Errorf("allow-list must permit listed channel: %v", err)
	}
	if err := allow.Allow(RDPChannelClipboard); err == nil {
		t.Error("allow-list must deny an unlisted channel")
	}
}

// TestChannelGateForDefaultsDenyAll proves the wired per-target gate defaults to
// deny-all (no catalog channel column yet).
func TestChannelGateForDefaultsDenyAll(t *testing.T) {
	g := channelGateFor(&catalog.Target{ID: "t"})
	if err := g.Allow(RDPChannelClipboard); err == nil {
		t.Error("channelGateFor default must deny clipboard (data-exfil off by default)")
	}
}
