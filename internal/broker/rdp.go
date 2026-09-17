// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// rdpBroker is the ADR 0049 Phase 3 RDP Broker. It applies the SAME jess spine
// to RDP as the SSH/Postgres/k8s brokers — identity/posture → policy/JIT → mint
// → relay → WORM recording — with two protocol-specific pieces:
//
//   - Mint issues a SHORT-LIVED backend credential (an ephemeral AD credential
//     OR a gateway ticket) from Vault, scoped to the target + grant. NLA/CredSSP
//     is terminated AT THE BROKER: the broker authenticates the operator-side
//     connection (jess device-cert + posture, already done before the grant) and
//     then re-authenticates to the target with the freshly minted credential, so
//     no standing AD credential ever reaches the operator (ADR 0049 "No standing
//     credentials").
//   - Dial opens the RDP wire to the target via an injectable RDP engine seam
//     (rdpEngine — the IronRDP integration, STUBBED in Phase 3) and relays bytes
//     between the operator and target, teeing a LIGHTER metadata + periodic-
//     screenshot track into the ADR-0030 WORM chain (recording.RDPLogWriter).
//     Virtual channels (clipboard / drive / printer) are policy-gated at the
//     relay before they are negotiated.
//
// It mirrors the k8s broker (kubernetes.go) most closely: the heavy, hard-to-
// test wire engine sits behind an injectable interface (cf. execOpener) so the
// Broker + relay + recording seam is unit-tested with a fake, and the real RDP
// protocol engine is swapped in without touching this file's wiring.
type rdpBroker struct {
	// creds mints the per-session ephemeral AD credential / gateway ticket from
	// Vault. Required: an RDP broker with no credential source can never connect
	// to a target (Mint fails closed). It reuses the shared CredentialBroker seam
	// via RDPCredentialBroker (see rdpMintFunc) so the Vault plumbing matches the
	// other brokers.
	mint rdpMintFunc
	// engine opens the RDP wire to the target with the minted credential and
	// terminates NLA/CredSSP at the broker. Defaults to the STUB engine
	// (newStubRDPEngine), which is wired but not a real RDP implementation —
	// tests inject a fake; the real IronRDP engine slots in here (ADR 0033).
	engine rdpEngine
	// rec captures the metadata + periodic-screenshot track to a tamper-evident
	// signed WORM bundle, or nil for no recording (a Recorded=true target is then
	// denied, fail-closed — identical to the SSH/Postgres brokers).
	rec recording.Recorder
	// screenshotEvery is the periodic full-frame screenshot cadence for the
	// recording track. Zero = the default (defaultScreenshotInterval). The pixel
	// bytes are captured from the engine and stored as bundle artifacts named by
	// their SHA-256; this NDJSON track records only the reference + dimensions.
	screenshotEvery time.Duration
}

// defaultScreenshotInterval is the periodic-screenshot cadence for the RDP
// recording track when a target does not override it. 10s balances audit
// fidelity against bundle size (cf. the recording-fidelity knob, ADR 0049
// Consequences).
const defaultScreenshotInterval = 10 * time.Second

// RDPCredentialBroker mints the short-lived backend credential for an RDP
// session: an ephemeral AD credential OR a gateway ticket. It is the RDP analog
// of CredentialBroker.IssueDBCreds (Postgres) — a Vault-backed per-session mint,
// scoped to the target, with a short TTL so the credential only outlives the
// brokered session. STUBBED in Phase 3: no Vault AD secrets-engine / RDG ticket
// issuer is wired yet (see RemainingStub). Implementations live alongside the
// other Vault credential mints.
type RDPCredentialBroker interface {
	// IssueRDPCredential returns a short-lived AD credential (username/password)
	// OR an opaque gateway ticket for the target's Vault role, plus its kind. The
	// operator never sees it; Dial's engine consumes it to re-authenticate to the
	// target (NLA/CredSSP terminated at the broker).
	IssueRDPCredential(ctx context.Context, role string) (RDPSecret, error)
}

// RDPSecretKind distinguishes the two mint shapes ADR 0049 allows.
type RDPSecretKind string

const (
	// RDPSecretADCredential is an ephemeral AD username/password (Vault AD
	// secrets engine, short TTL).
	RDPSecretADCredential RDPSecretKind = "ad-credential"
	// RDPSecretGatewayTicket is an opaque RD-Gateway / broker ticket the engine
	// presents to the target gateway.
	RDPSecretGatewayTicket RDPSecretKind = "gateway-ticket"
)

// RDPSecret is the minted backend credential the engine uses to re-authenticate
// to the target. Exactly one shape is populated per Kind. It never leaves the
// worker.
type RDPSecret struct {
	Kind     RDPSecretKind
	Username string // RDPSecretADCredential
	Password string // RDPSecretADCredential
	Domain   string // RDPSecretADCredential (AD domain)
	Ticket   string // RDPSecretGatewayTicket (opaque)
}

// rdpMintFunc is the credential-mint seam used by Mint. It is a function rather
// than the interface directly so tests can inject a mint without a full Vault
// fake, mirroring how the k8s broker injects its executor opener. NewRDPBroker
// adapts an RDPCredentialBroker into one.
type rdpMintFunc func(ctx context.Context, target *catalog.Target) (RDPSecret, error)

// rdpEngine is the injectable RDP protocol engine — the single seam the real
// IronRDP integration (ADR 0033, Rust crates/ironrdp-bridge) plugs into, and the
// one thing tests fake. It owns the RDP wire: terminating NLA/CredSSP at the
// broker, connecting to the target with the minted secret, relaying the RDP
// stream between the operator and target, gating virtual channels, and producing
// periodic screenshots for the recording track.
//
// Phase 3 ships ONLY a stub implementation (newStubRDPEngine) — it does NOT
// speak RDP. The real engine is the deep, weeks-of-work part (see RemainingStub).
type rdpEngine interface {
	// Open connects to the target with sec (NLA/CredSSP terminated here) and
	// returns a live rdpSession bound to the operator-side connection. The
	// channelGate is consulted before any virtual channel is negotiated.
	Open(ctx context.Context, target *catalog.Target, sec RDPSecret, client io.ReadWriteCloser, gate channelGate) (rdpSession, error)
}

// rdpSession is one open RDP wire session produced by an rdpEngine. Run relays
// the RDP stream until the operator disconnects (or a fatal wire error). Snapshot
// captures the current framebuffer as encoded pixel bytes (PNG-ish) for the
// periodic-screenshot recording track. Close tears the wire down.
type rdpSession interface {
	// Run relays the RDP stream between operator and target, returning when the
	// session ends.
	Run() error
	// Snapshot returns the current framebuffer as encoded image bytes plus its
	// pixel dimensions, for the periodic-screenshot track. A nil/empty return
	// means "no frame available yet" (the pump skips that tick).
	Snapshot() (img []byte, width, height int, err error)
	// Close tears the RDP wire down.
	Close() error
}

// channelGate is the per-virtual-channel policy hook the relay enforces BEFORE a
// clipboard / drive / printer channel is negotiated (ADR 0049: "Clipboard /
// drive redirection / printer channels are policy-gated at the relay"). Allow
// returns nil to permit the channel; a non-nil error denies it (the engine must
// refuse to negotiate that channel and the denial is recorded). It is the RDP
// analog of the Postgres StatementPolicy.
type channelGate interface {
	// Allow reports whether the named virtual channel (e.g. "cliprdr",
	// "rdpdr", "rdpsnd") may be negotiated; a non-nil error is the deny reason.
	Allow(channel string) error
}

// Well-known RDP virtual channel names the gate reasons about.
const (
	RDPChannelClipboard = "cliprdr" // clipboard redirection
	RDPChannelDrive     = "rdpdr"   // drive/device redirection (incl. printers)
	RDPChannelPrinter   = "rdpdr-printer"
	RDPChannelSound     = "rdpsnd" // audio redirection
)

// ChannelPolicy is the Phase 3 reference channelGate: an allow-list of virtual
// channels. The zero value (AllowedChannels nil) is FAIL-CLOSED — it denies
// every redirection channel, which is the safe default for a privileged session
// (clipboard/drive/printer off unless a target explicitly opts in). This is the
// inverse default from the Postgres pass-through policy ON PURPOSE: data
// exfiltration channels default off.
type ChannelPolicy struct {
	// AllowedChannels is the set of virtual channels permitted for this session
	// (matched exactly, case-sensitive on the RDP channel name). Empty = deny all
	// redirection channels.
	AllowedChannels []string
}

// Allow implements channelGate.
func (p ChannelPolicy) Allow(channel string) error {
	for _, c := range p.AllowedChannels {
		if c == channel {
			return nil
		}
	}
	return fmt.Errorf("rdp channel %q denied by policy (not in allow-list)", channel)
}

// NewRDPBroker returns the RDP Broker over the Vault credential broker (for the
// ephemeral AD credential / gateway-ticket mint), the recorder, and the periodic-
// screenshot cadence (every<=0 uses the default). rec may be nil — recording is
// then unavailable and Recorded targets are denied fail-closed, exactly as the
// other brokers do. The RDP engine defaults to the STUB (newStubRDPEngine); use
// withRDPEngine (tests) or wire the real IronRDP engine to replace it.
func NewRDPBroker(creds RDPCredentialBroker, rec recording.Recorder, every time.Duration) Broker {
	b := &rdpBroker{
		engine:          newStubRDPEngine(),
		rec:             rec,
		screenshotEvery: every,
	}
	if creds != nil {
		b.mint = func(ctx context.Context, t *catalog.Target) (RDPSecret, error) {
			return creds.IssueRDPCredential(ctx, vaultRDPRole(t))
		}
	}
	return b
}

// withRDPEngine swaps the injectable engine (tests). Kept unexported: the only
// production engine is the one NewRDPBroker installs.
func (b *rdpBroker) withRDPEngine(e rdpEngine) *rdpBroker { b.engine = e; return b }

// Protocol implements Broker.
func (b *rdpBroker) Protocol() string { return string(catalog.ProtoRDP) }

// rdpCredential is the RDP broker's per-session credential: the freshly minted
// short-lived AD credential / gateway ticket plus the recording metadata Dial
// needs. It never leaves the worker — the operator authenticates to jess, and
// the broker terminates NLA/CredSSP and re-authenticates to the target with this.
type rdpCredential struct {
	sec   RDPSecret
	grant AccessGrant
}

func (rdpCredential) Protocol() string { return string(catalog.ProtoRDP) }

// Mint implements Broker. It mints the short-lived AD credential / gateway
// ticket from Vault scoped to the target + grant. The operator never sees it;
// Dial's engine consumes it to re-authenticate to the target (NLA/CredSSP
// terminated at the broker). Fails closed if the credential mint is unconfigured.
func (b *rdpBroker) Mint(ctx context.Context, grant AccessGrant) (Credential, error) {
	if grant.Target == nil {
		return nil, fmt.Errorf("rdp broker: grant has no target")
	}
	if grant.Client == nil {
		return nil, fmt.Errorf("rdp broker: grant has no client connection")
	}
	if b.mint == nil {
		return nil, fmt.Errorf("rdp broker: no credential broker configured (cannot mint ephemeral AD credential / gateway ticket)")
	}
	sec, err := b.mint(ctx, grant.Target)
	if err != nil {
		return nil, fmt.Errorf("rdp broker: mint ephemeral credential (role %q): %w", vaultRDPRole(grant.Target), err)
	}
	return rdpCredential{sec: sec, grant: grant}, nil
}

// Dial implements Broker. It sets up the WORM metadata+screenshot recorder
// (identical fail-closed semantics to the other brokers) and returns a
// RecordedConn whose Wait opens the RDP wire via the engine, relays it, runs the
// periodic-screenshot pump, and gates virtual channels — and whose Close seals
// the bundle.
func (b *rdpBroker) Dial(ctx context.Context, target *catalog.Target, cred Credential) (RecordedConn, error) {
	rc, ok := cred.(rdpCredential)
	if !ok {
		return nil, fmt.Errorf("rdp broker: credential is not an RDP credential (%T)", cred)
	}
	if target == nil {
		return nil, fmt.Errorf("rdp broker: nil target")
	}
	if b.engine == nil {
		return nil, fmt.Errorf("rdp broker: engine not configured")
	}

	conn := &rdpRecordedConn{
		ctx:             ctx,
		engine:          b.engine,
		target:          target,
		client:          rc.grant.Client,
		sec:             rc.sec,
		gate:            channelGateFor(target),
		screenshotEvery: b.effectiveInterval(),
	}

	if b.rec != nil {
		meta := recordingMetaFor(rc.grant, string(catalog.ProtoRDP), recording.FormatDrawing)
		w, rerr := b.rec.Open(ctx, meta)
		if rerr != nil {
			if target.Recorded {
				// Fail closed: a must-record target is denied if recording fails.
				return nil, fmt.Errorf("rdp broker: recording required but unavailable (fail-closed): %w", rerr)
			}
			// Non-recorded target: proceed without a recorder, as the other brokers do.
		} else {
			conn.rlog = recording.NewRDPLogWriter(w) // Close seals the signed bundle to WORM
		}
	} else if target.Recorded {
		return nil, fmt.Errorf("rdp broker: recording required but no recorder configured (fail-closed)")
	}

	return conn, nil
}

func (b *rdpBroker) effectiveInterval() time.Duration {
	if b.screenshotEvery > 0 {
		return b.screenshotEvery
	}
	return defaultScreenshotInterval
}

// rdpRecordedConn is an open RDP brokered session. Wait opens the RDP wire,
// relays it, records the metadata + periodic-screenshot track, and gates virtual
// channels; Close seals the recording bundle.
type rdpRecordedConn struct {
	ctx             context.Context
	engine          rdpEngine
	target          *catalog.Target
	client          io.ReadWriteCloser
	sec             RDPSecret
	gate            channelGate
	screenshotEvery time.Duration
	rlog            *recording.RDPLogWriter // nil = not recording

	mu      sync.Mutex
	session rdpSession
}

// Wait opens the RDP wire to the target via the engine (NLA/CredSSP terminated
// at the broker), records session_start, starts the periodic-screenshot pump,
// runs the relay until the operator disconnects, then records session_end. The
// channel gate is handed to the engine so a denied clipboard/drive/printer
// channel is refused before negotiation; the gate is wrapped so every channel
// decision is also recorded into the WORM track.
func (c *rdpRecordedConn) Wait() error {
	gate := c.gate
	if c.rlog != nil {
		gate = &recordingChannelGate{inner: c.gate, rlog: c.rlog}
	} else if gate == nil {
		gate = ChannelPolicy{} // fail-closed default even with no recorder
	}

	// Record session_start BEFORE opening the wire: the engine's Open negotiates
	// (and gates) virtual channels, which logically happens after the session has
	// begun, so session_start must be the first event in the track.
	c.recordEvent(recording.RDPEvent{
		Event:  recording.RDPEventSessionStart,
		Detail: "NLA/CredSSP terminated at broker; ephemeral credential used to re-authenticate to target",
	})

	sess, err := c.engine.Open(c.ctx, c.target, c.sec, c.client, gate)
	if err != nil {
		// session_start is already recorded; record the end so the track is a
		// complete, sealed start→end pair even when the wire fails to open.
		c.recordEvent(recording.RDPEvent{Event: recording.RDPEventSessionEnd, DenyReason: err.Error()})
		return fmt.Errorf("rdp broker: open RDP wire: %w", err)
	}
	c.mu.Lock()
	c.session = sess
	c.mu.Unlock()
	defer func() { _ = sess.Close() }()

	// Periodic-screenshot pump (the lighter recording track). It runs only while
	// recording; the relay (sess.Run) is the session lifecycle, so the pump stops
	// when Run returns. A nil snapshot is skipped (no frame yet).
	stop := make(chan struct{})
	var pumpWG sync.WaitGroup
	if c.rlog != nil {
		pumpWG.Add(1)
		go func() {
			defer pumpWG.Done()
			c.screenshotPump(sess, stop)
		}()
	}

	runErr := sess.Run()

	close(stop)
	pumpWG.Wait()

	c.recordEvent(recording.RDPEvent{Event: recording.RDPEventSessionEnd})
	return runErr
}

// screenshotPump periodically snapshots the framebuffer and records a screenshot
// reference into the WORM track until stop is closed. The encoded pixel bytes are
// hashed (SHA-256) and that hash names the bundle artifact the bytes are stored
// under; this NDJSON track carries only the reference + dimensions, keeping the
// per-event records small.
//
// NOTE: persisting the pixel bytes themselves as a bundle artifact is part of
// the recorder/Bundle work that is STUBBED in Phase 3 (see RemainingStub) — here
// we hash + reference them so the seam and the metadata track are complete and
// tested; wiring the bytes through to a Bundle artifact is the remaining step.
func (c *rdpRecordedConn) screenshotPump(sess rdpSession, stop <-chan struct{}) {
	interval := c.screenshotEvery
	if interval <= 0 {
		interval = defaultScreenshotInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-c.ctx.Done():
			return
		case <-t.C:
			img, w, h, err := sess.Snapshot()
			if err != nil || len(img) == 0 {
				continue // no frame this tick; skip
			}
			sum := sha256.Sum256(img)
			c.recordEvent(recording.RDPEvent{
				Event:            recording.RDPEventScreenshot,
				ScreenshotSHA256: hex.EncodeToString(sum[:]),
				Width:            w,
				Height:           h,
			})
		}
	}
}

// recordEvent writes one event to the WORM track if recording is on. A recording
// failure on a Recorded target is logged into the returned terminal error path
// by Close (which seals/fails closed); per-event we best-effort record so a
// transient encode error does not silently drop the rest of the track.
func (c *rdpRecordedConn) recordEvent(ev recording.RDPEvent) {
	if c.rlog == nil {
		return
	}
	_ = c.rlog.Record(ev) // Close seals + surfaces a fatal bundle error
}

// Close tears the RDP wire down and seals the recording bundle (Close error
// fails the session closed, ADR 0030 Phase 5). Safe to call when not recording.
func (c *rdpRecordedConn) Close() error {
	c.mu.Lock()
	sess := c.session
	c.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
	if c.rlog == nil {
		return nil
	}
	return c.rlog.Close()
}

// recordingChannelGate wraps a channelGate so every virtual-channel decision
// (allowed or denied) is teed into the WORM track before the engine acts on it —
// the recording is the tamper-evident record of which redirection channels were
// requested and which the relay blocked (cf. the Postgres enforce hook recording
// allowed AND denied statements).
type recordingChannelGate struct {
	inner channelGate
	rlog  *recording.RDPLogWriter
}

func (g *recordingChannelGate) Allow(channel string) error {
	var perr error
	if g.inner != nil {
		perr = g.inner.Allow(channel)
	}
	ev := recording.RDPEvent{
		Event:    recording.RDPEventChannel,
		Channel:  channel,
		Decision: recording.RDPAllowed,
	}
	if perr != nil {
		ev.Decision = recording.RDPDenied
		ev.DenyReason = perr.Error()
	}
	_ = g.rlog.Record(ev)
	return perr
}

// channelGateFor derives the per-session channel policy from the target. Phase 3
// has no per-target channel allow-list column in the catalog yet, so this returns
// the FAIL-CLOSED default (deny all redirection channels) — the seam is wired and
// enforced; opening clipboard/drive/printer for a target is a catalog change, not
// a relay change. Returning a concrete gate (not nil) keeps enforcement live.
func channelGateFor(_ *catalog.Target) channelGate {
	return ChannelPolicy{} // deny-all by default (data-exfil channels off)
}

// vaultRDPRole is the Vault role the broker mints the ephemeral AD credential /
// gateway ticket from for a target — the conventional 1:1 role-per-target
// mapping (cf. vaultDBRole). A target with no ID falls back to a generic role so
// the mint still has a name (and fails loudly at Vault if it doesn't exist).
func vaultRDPRole(t *catalog.Target) string {
	if t.ID != "" {
		return t.ID
	}
	return "rdp"
}

// --- STUB RDP engine --------------------------------------------------------

// stubRDPEngine is the Phase 3 placeholder rdpEngine. It does NOT speak the RDP
// wire protocol — it exists so the Broker + relay + recording + channel-gate seam
// is wired end-to-end and unit-testable, and so the worker can register an RDP
// broker that fails LOUD (not silently bypasses) until the real IronRDP engine
// (ADR 0033) is plugged in via withRDPEngine. See RemainingStub.
type stubRDPEngine struct{}

func newStubRDPEngine() rdpEngine { return stubRDPEngine{} }

// Open refuses to broker an RDP session: the real wire engine is not implemented.
// Failing closed here (rather than silently relaying raw bytes) preserves the ADR
// 0049 invariant that access is ONLY via a real, recording broker — a registered
// stub never opens an un-engineered (and effectively un-recorded-graphics) path.
func (stubRDPEngine) Open(context.Context, *catalog.Target, RDPSecret, io.ReadWriteCloser, channelGate) (rdpSession, error) {
	return nil, fmt.Errorf("rdp broker: RDP protocol engine not implemented (Phase 3 stub) — wire the IronRDP engine (ADR 0033) before brokering RDP")
}

// compile-time guards.
var (
	_ Broker      = (*rdpBroker)(nil)
	_ Credential  = rdpCredential{}
	_ channelGate = ChannelPolicy{}
	_ channelGate = (*recordingChannelGate)(nil)
	_ rdpEngine   = stubRDPEngine{}
	_ io.Closer   = (*rdpRecordedConn)(nil)
)
