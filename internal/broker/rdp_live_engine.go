// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

// liveRDPEngine — ADR 0051 P2c "Go↔Rust bridge". The real rdpEngine that
// replaces the Phase-3 fail-closed stub: it spawns the Rust `session_live`
// binary (services/ironrdp-broker, built with the `ironrdp_live` feature) as a
// SUBPROCESS and bridges the finalized P2b streaming TLV wire protocol between
// the operator-side connection and the subprocess.
//
//   operator client  <─[u32 len][type][payload] TLV both ways]─>  liveRDPEngine
//   liveRDPEngine    <─ subprocess stdin  ([u32 len][type][payload] TLV in)
//   liveRDPEngine    <─ subprocess stdout ([u32 len][type][payload] TLV out)
//   session_live     <─ RDP wire ─>  target Windows DC (NLA/CredSSP at the bin)
//
// The Go bridge is wire-transparent: the `client` io.ReadWriteCloser already
// carries the EXACT framed TLV stream the subprocess speaks (the jess-web WS
// layer is the thing that strips/prepends the u32 length so a browser sees one
// WS binary frame per message). So Run() is two io.Copy legs, with the
// server→client (stdout) leg passing through a tee that parses the framing far
// enough to (a) extract DESKTOP_SIZE and (b) snapshot the most-recent FRAME PNG
// into the ADR-0030 WORM screenshot track — keeping the existing
// rdpRecordedConn + periodic-screenshot seam intact.
//
// CREDENTIALS are passed to the subprocess via the ENVIRONMENT ONLY
// (RDP_USER/RDP_PASS/RDP_DOMAIN), NEVER via argv (argv is world-readable in
// /proc on a shared host). The password is never logged.
//
// !!! SECURITY / PRODUCTION BOUNDARY (operator: strict) !!!
//   - This milestone sources the NLA credential from the minted RDPSecret and
//     hands it to the subprocess via env. PRODUCTION must source the NLA
//     credential from VAULT (the RDPCredentialBroker mint already does this for
//     the broker path) and the smartcard end-state per ADR 0051. An
//     operator-TYPED-password path must be ENV-GATED dev-only and is NOT wired
//     here.
//   - The catalog `ProtoRDP` target + its Vault cred role wiring (vaultRDPRole)
//     is a runtime/deploy step — see NewRDPBroker / the worker registration TODO.
//
// FAIL-CLOSED: Open() fails if JESS_RDP_SESSION_BIN is unset or the file is
// missing/not executable (a registered RDP broker never silently bypasses the
// real engine). Run() returns the subprocess's nonzero exit as a session error
// so the operator sees a failed — not a silently-empty — session.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/rdphosttrust"
	"github.com/dogukanturhal/jess/internal/recording"
)

// Wire-protocol message-type bytes (server→client), mirrored from the Rust
// crate's stream.rs so the Go tee can recognise DESKTOP_SIZE / FRAME without a
// full codec. Kept in lock-step with services/ironrdp-broker/.../stream.rs.
const (
	msgDesktopSize uint8 = 1 // [u16 w][u16 h]
	msgFrame       uint8 = 2 // [u16 x][u16 y][u16 w][u16 h][PNG bytes] — lossless
	msgClose       uint8 = 3 // empty
	msgFrameWebp   uint8 = 4 // [u16 x][u16 y][u16 w][u16 h][WebP bytes] — lossy (Tier-1 live)
	// msgH264 (ADR 0053/0058) — the MS-RDPEGFX/AVC420 H.264 access-unit path.
	// [u8 flags][u16 x][u16 y][u16 w][u16 h][AVC NAL bytes (Annex-B)]. The browser
	// feeds the NAL to a WebCodecs VideoDecoder; the WORM recorder records the AU
	// (NAL + keyframe flag + geometry) so an EGFX-driven session is replayable.
	msgH264 uint8 = 5
)

// msgH264 flag bits (the first payload byte after the type byte). Mirrors the
// Rust crate's H264_FLAG_* (services/ironrdp-broker/.../stream.rs) and the SPA
// (web/src/api/rdp.ts).
const (
	h264FlagKeyframe uint8 = 0b0000_0001 // access unit is an IDR/keyframe (SPS+PPS)
	h264FlagAVC444   uint8 = 0b0000_0010 // main view of an AVC444 4:4:4 pair (aux follows)
	h264FlagAux      uint8 = 0b0000_0100 // AVC444 auxiliary (chroma) view — recombined client-side, NOT recorded (ADR 0059)
)

// Wire-protocol message-type bytes (client→server), mirrored from the SPA
// encoder (web/src/api/rdp.ts) so the input tee can record operator events into
// the v2 stream. Kept in lock-step with the browser + the Rust crate.
const (
	clientMsgMouse uint8 = 1 // [u16 x][u16 y][u8 button_mask][i8 wheel]
	clientMsgKey   uint8 = 2 // [u8 is_down][u32 scancode]
)

// maxServerPayload caps a single server→client TLV payload the tee will buffer.
// A full-desktop FRAME PNG is well under this; the cap defends the tee parser
// against a corrupt length prefix from a misbehaving subprocess.
const maxServerPayload = 16 * 1024 * 1024 // 16 MiB

// envSessionBin is the env var holding the absolute path to the `session_live`
// binary (the cargo build output). Unset → the engine fails closed.
const envSessionBin = "JESS_RDP_SESSION_BIN"

// liveRDPEngine spawns the Rust session_live subprocess per Open().
type liveRDPEngine struct {
	// binPath is the session_live executable. Resolved from JESS_RDP_SESSION_BIN
	// at Open() time so a wiring change doesn't require a restart of the seam.
	binPath string
	// hostTrust is the P2.4 AD-CS RDP host-trust validator (ADR 0047 → 0062).
	// When non-nil, Open() PRE-FLIGHTS the target's TLS host certificate against
	// the configured AD-CS anchors before spawning session_live and FAILS CLOSED
	// on a validation failure — retiring the accept-any/TOFU host trust. nil (or
	// an inert validator with no anchors) preserves legacy behaviour for targets
	// that neither opt in (Target.RDPTLSCASigned) nor fall under global enforce.
	hostTrust *rdphosttrust.HostTrust
}

// newLiveRDPEngine returns the real subprocess-spawning engine. binPath may be
// empty — Open then resolves JESS_RDP_SESSION_BIN at call time (and fails closed
// if still empty), so the broker can be constructed before the env is set.
func newLiveRDPEngine(binPath string) *liveRDPEngine {
	return &liveRDPEngine{binPath: binPath}
}

// newLiveRDPEngineWithTrust is newLiveRDPEngine plus the P2.4 AD-CS host-trust
// validator wired in. ht may be nil (no host-trust) or inert (no anchors).
func newLiveRDPEngineWithTrust(binPath string, ht *rdphosttrust.HostTrust) *liveRDPEngine {
	return &liveRDPEngine{binPath: binPath, hostTrust: ht}
}

// NewLiveRDPBroker is the production constructor: an RDP broker whose engine is
// the real session_live subprocess bridge. binPath empty → resolved from
// JESS_RDP_SESSION_BIN at Open() time. It is otherwise identical to
// NewRDPBroker (same Vault credential mint + WORM recorder + screenshot cadence
// + fail-closed semantics).
func NewLiveRDPBroker(creds RDPCredentialBroker, rec recording.Recorder, every time.Duration, binPath string) Broker {
	b, _ := NewRDPBroker(creds, rec, every).(*rdpBroker)
	b.withRDPEngine(newLiveRDPEngine(binPath))
	return b
}

// NewLiveRDPBrokerWithTrust is NewLiveRDPBroker with the P2.4 AD-CS host-trust
// validator wired into the engine, so the broker Dial path pre-flights the
// target's TLS host certificate against the AD-CS anchors before spawning
// session_live (fail-closed). ht may be nil / inert (legacy behaviour).
func NewLiveRDPBrokerWithTrust(creds RDPCredentialBroker, rec recording.Recorder, every time.Duration, binPath string, ht *rdphosttrust.HostTrust) Broker {
	b, _ := NewRDPBroker(creds, rec, every).(*rdpBroker)
	b.withRDPEngine(newLiveRDPEngineWithTrust(binPath, ht))
	return b
}

// --- exported web adapter -------------------------------------------------

// RDPLiveSession is the exported handle a non-broker caller (jess-web) drives:
// Run relays the live TLV stream until the session ends; Snapshot returns the
// latest FRAME PNG for the screenshot track; Close tears the subprocess down.
// It mirrors the unexported rdpSession so the in-process WS bridge can use the
// engine directly without the full Mint→Dial spine.
type RDPLiveSession interface {
	Run() error
	Snapshot() (img []byte, width, height int, err error)
	Close() error
}

// WebRDPEngine is the exported engine seam for the in-process jess-web bridge.
// OpenSession spawns session_live for the target with the given (already-minted
// or dev-env) secret, bound to the operator-side client stream. The channel
// gate is fixed to the fail-closed deny-all default (session_live negotiates no
// redirection channels in this milestone).
//
// ADR 0051 P4: the optional `rec` is a per-session jess-rdp-recording-v2 writer
// the engine tees the FULL decoded stream into (every DESKTOP_SIZE, FRAME, and
// input event). When rec is non-nil the engine records; when nil it does not.
// The CALLER (jess-web bridge) owns the fail-closed decision — it opens the
// recorder bundle (binding the real operator identity) and only opens a recorded
// target's session once that bundle opened, mirroring the broker Dial path.
type WebRDPEngine interface {
	OpenSession(ctx context.Context, target *catalog.Target, sec RDPSecret, client io.ReadWriteCloser, rec *recording.RDPStreamWriter, desktop RDPDesktopSize) (RDPLiveSession, error)
}

// RDPDesktopSize is the resolution the browser asks the session to request
// from the server (ADR 0051 — quality item #3, resolution match). A zero
// Width/Height means "unset" — the Rust session_live then falls back to its
// default (1280×1024). The Rust side clamps any out-of-range value, so the Go
// side only needs to pass the operator's request through verbatim.
type RDPDesktopSize struct {
	Width  int
	Height int
}

// webEngineAdapter exposes liveRDPEngine through the exported WebRDPEngine seam.
type webEngineAdapter struct{ e *liveRDPEngine }

// NewLiveRDPEngineForWeb returns the exported live engine for the jess-web WS
// bridge. binPath empty → resolved from JESS_RDP_SESSION_BIN at OpenSession
// time. Credentials are sourced by the CALLER (dev env today, Vault mint in
// production) and passed in per session — this seam never reads creds itself.
func NewLiveRDPEngineForWeb(binPath string) WebRDPEngine {
	return &webEngineAdapter{e: newLiveRDPEngine(binPath)}
}

// NewLiveRDPEngineForWebWithTrust is NewLiveRDPEngineForWeb with the P2.4 AD-CS
// host-trust validator wired in: OpenSession pre-flights the target's TLS host
// certificate against the AD-CS anchors before spawning session_live and fails
// closed on a validation failure. ht may be nil / inert (legacy behaviour).
func NewLiveRDPEngineForWebWithTrust(binPath string, ht *rdphosttrust.HostTrust) WebRDPEngine {
	return &webEngineAdapter{e: newLiveRDPEngineWithTrust(binPath, ht)}
}

// OpenSession implements WebRDPEngine. rec (may be nil) is the v2 recording the
// engine tees the full decoded stream into. desktop is the browser-requested
// resolution (zero ⇒ session_live's default).
func (a *webEngineAdapter) OpenSession(ctx context.Context, target *catalog.Target, sec RDPSecret, client io.ReadWriteCloser, rec *recording.RDPStreamWriter, desktop RDPDesktopSize) (RDPLiveSession, error) {
	// Deny-all channel gate: session_live negotiates no redirection channels.
	sess, err := a.e.open(ctx, target, sec, client, ChannelPolicy{}, rec, desktop)
	if err != nil {
		return nil, err
	}
	return sess.(RDPLiveSession), nil
}

// resolveBin returns the session_live path, preferring the configured binPath
// and falling back to JESS_RDP_SESSION_BIN. Fails closed if neither is set or
// the file is missing / not a regular executable.
func (e *liveRDPEngine) resolveBin() (string, error) {
	p := e.binPath
	if p == "" {
		p = os.Getenv(envSessionBin)
	}
	if p == "" {
		return "", fmt.Errorf("rdp live engine: %s unset and no bin path configured (fail-closed)", envSessionBin)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("rdp live engine: session_live binary %q not found (fail-closed): %w", p, err)
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return "", fmt.Errorf("rdp live engine: session_live %q is not an executable file (fail-closed)", p)
	}
	return p, nil
}

// Open spawns session_live for the target with the minted secret (env, not
// argv) and returns a live rdpSession bound to the operator-side `client`
// stream. The channelGate is consulted up-front for the redirection channels
// the broker may negotiate; session_live does NOT negotiate clipboard/drive/
// printer in this milestone (graphics + input only), so a denied channel is a
// no-op pass-through here — the seam stays wired for when the Rust side grows
// virtual channels. Fails closed if the binary is unavailable or the secret is
// not an AD credential.
func (e *liveRDPEngine) Open(ctx context.Context, target *catalog.Target, sec RDPSecret, client io.ReadWriteCloser, gate channelGate) (rdpSession, error) {
	// The broker Dial path uses the periodic-screenshot recorder (rdpRecordedConn)
	// rather than the full-stream v2 tee, so no v2 recorder is wired here. It also
	// doesn't carry a browser-requested resolution, so session_live uses its
	// default desktop size.
	return e.open(ctx, target, sec, client, gate, nil, RDPDesktopSize{})
}

// open is the recorder-aware implementation. rec (may be nil) is a
// jess-rdp-recording-v2 writer the resulting session tees the full decoded
// stream (DESKTOP_SIZE / FRAME / input) into. desktop (zero ⇒ default) is the
// browser-requested resolution to ask the server for.
func (e *liveRDPEngine) open(ctx context.Context, target *catalog.Target, sec RDPSecret, client io.ReadWriteCloser, gate channelGate, rec *recording.RDPStreamWriter, desktop RDPDesktopSize) (rdpSession, error) {
	if target == nil {
		return nil, fmt.Errorf("rdp live engine: nil target")
	}
	if client == nil {
		return nil, fmt.Errorf("rdp live engine: nil operator client connection")
	}
	if sec.Kind != RDPSecretADCredential {
		// Gateway-ticket mint isn't a session_live shape (it expects user/pass
		// NLA). Fail closed rather than spawn a bin that can't authenticate.
		return nil, fmt.Errorf("rdp live engine: secret kind %q unsupported (session_live needs an AD credential)", sec.Kind)
	}
	if sec.Username == "" || sec.Password == "" {
		return nil, fmt.Errorf("rdp live engine: minted AD credential missing username/password (fail-closed)")
	}
	bin, err := e.resolveBin()
	if err != nil {
		return nil, err
	}

	// P2.4 — AD-CS host-trust pre-flight (ADR 0047 → 0062). Validate the RDS
	// host's TLS certificate against the configured AD-CS anchors BEFORE
	// spawning session_live; fail closed on a validation failure so a wrong-CA /
	// self-signed / revoked / expired host cert never gets a brokered session.
	// nil / inert validator or a non-required target ⇒ Preflight is a no-op
	// (legacy TOFU preserved for un-enrolled targets during migration).
	if err := e.hostTrust.Preflight(ctx, target); err != nil {
		return nil, fmt.Errorf("rdp live engine: host-trust pre-flight (fail-closed): %w", err)
	}

	// The gate is consulted so the WORM track records the (default deny-all)
	// decisions even though session_live doesn't negotiate these channels yet.
	for _, ch := range []string{RDPChannelClipboard, RDPChannelDrive, RDPChannelPrinter, RDPChannelSound} {
		_ = gate.Allow(ch)
	}

	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, bin)
	// CREDENTIALS via ENV ONLY — never argv. Start from a CLEAN env (don't leak
	// the broker's own secrets to the subprocess), then add exactly what
	// session_live reads.
	cmd.Env = sessionEnv(target.Address, sec, desktop)
	// P2.4 — forward the AD-CS anchor PEM path to the subprocess so the Rust
	// session_live side can (when it grows chain validation) enforce the SAME
	// host-cert trust the Go pre-flight just validated, closing the pre-flight
	// TOCTOU window as defense in depth. Harmless when the Rust side does not
	// yet read it; the Go pre-flight above is the enforced gate today.
	if p := e.hostTrust.AnchorPath(); p != "" {
		cmd.Env = append(cmd.Env, rdphosttrust.EnvCAPEM+"="+p)
	}
	// recording (rec != nil) ⇒ how we capture the WORM feed depends on the codec:
	//
	//   - BITMAP path (default, JESS_RDP_H264 off): tell session_live to ALSO emit a
	//     lossless PNG FRAME per region (alongside the live WebP). The stdout tee
	//     records the PNG and forwards only the WebP, so the WORM bundle stays
	//     lossless + format-unchanged while the live wire gets the smaller WebP.
	//     This is the unchanged legacy behaviour.
	//
	//   - H.264 path (ADR 0058, JESS_RDP_H264 on): the EGFX/AVC420 access units ARE
	//     the recorded stream — the tee records each msgH264 AU into the v2 bundle.
	//     We therefore do NOT request the lossless-PNG twin (there is no bitmap
	//     stream to record), which is what previously forced EGFX off for recorded
	//     sessions. record_lossless was also the Rust side's "is recording" gate
	//     that disabled H.264; leaving it unset lets enable_h264 = h264_requested().
	//
	// JESS_RDP_H264 (EGFX host-AVC) and JESS_RDP_H264_SW (ADR 0061 software encode)
	// BOTH make the session emit MSG_H264 instead of WebP — so neither needs the
	// lossless-PNG twin, and both are recorded via the existing MSG_H264 tee
	// (ADR 0058). Process-env (forwarded by sessionEnv), so the Go side reads the
	// SAME values the subprocess sees — keeping the lossless gate in lock-step.
	h264 := envBool("JESS_RDP_H264") || envBool("JESS_RDP_H264_SW")
	if rec != nil && !h264 {
		cmd.Env = append(cmd.Env, "JESS_RDP_RECORD_LOSSLESS=1")
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("rdp live engine: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("rdp live engine: stdout pipe: %w", err)
	}
	// session_live logs human-readable progress to stderr; surface it under a
	// prefix so a failed handshake is diagnosable (the password is redacted by
	// the bin itself — it only prints "<redacted, N chars>").
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("rdp live engine: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("rdp live engine: start session_live %q (fail-closed): %w", bin, err)
	}

	s := &liveRDPSession{
		cmd:    cmd,
		cancel: cancel,
		stdin:  stdin,
		stdout: stdout,
		client: client,
		rec:    rec,
		// Tier-1: WebP is the live default unless the operator forces lossless
		// via JESS_RDP_LOSSLESS (forwarded to session_live below). Kept in
		// lock-step so the stdout tee forwards/records the right message type.
		webpLive: !envBool("JESS_RDP_LOSSLESS"),
	}
	go s.drainStderr(stderr)
	return s, nil
}

// sessionEnv builds the minimal subprocess environment: the target + the AD
// credential. Credentials are passed HERE (env) and NOWHERE else — not argv,
// not a temp file, not a log line.
//
// desktop (quality item #3) is forwarded as RDP_DESKTOP_W / RDP_DESKTOP_H so
// session_live requests a resolution matching the browser. Only positive dims
// are set — a zero (unset) axis is omitted so the Rust side keeps its default,
// preserving the legacy behaviour for callers that don't request a size.
//
// The Tier-1 recording flag (JESS_RDP_RECORD_LOSSLESS) is appended by the
// caller (open) when rec != nil, not here, so this stays the pure target +
// credential + resolution env.
func sessionEnv(addr string, sec RDPSecret, desktop RDPDesktopSize) []string {
	env := []string{
		"RDP_TARGET=" + addr,
		"RDP_USER=" + sec.Username,
		"RDP_PASS=" + sec.Password,
	}
	if sec.Domain != "" {
		env = append(env, "RDP_DOMAIN="+sec.Domain)
	}
	if desktop.Width > 0 {
		env = append(env, "RDP_DESKTOP_W="+strconv.Itoa(desktop.Width))
	}
	if desktop.Height > 0 {
		env = append(env, "RDP_DESKTOP_H="+strconv.Itoa(desktop.Height))
	}
	// Pass through RUST_LOG / PATH if set so the operator can tune subprocess
	// verbosity without us hard-coding it; PATH lets the bin find shared libs.
	// JESS_RDP_BUDGET_SECS is the canonical wall-clock session-budget knob
	// (unset/0 → session_live's large 4h default); RDP_BUDGET_SECS is the
	// legacy alias still honoured by the bin. JESS_RDP_CLIPBOARD (ADR 0054)
	// enables the CLIPRDR clipboard virtual channel — DEFAULT OFF: unset keeps
	// the legacy graphics+input-only session, so clipboard is opt-in by
	// deployment/policy (no per-target wiring needed for this milestone).
	for _, k := range []string{
		"RUST_LOG", "PATH", "JESS_RDP_BUDGET_SECS", "RDP_BUDGET_SECS", "RDP_IDLE_SECS",
		// Tier-1 live encoding knobs: JESS_RDP_LOSSLESS=1 forces lossless PNG
		// live frames; JESS_RDP_WEBP_QUALITY tunes the lossy WebP quality (0-100).
		"JESS_RDP_LOSSLESS", "JESS_RDP_WEBP_QUALITY",
		// Tier-3 clipboard virtual channel (CLIPRDR).
		"JESS_RDP_CLIPBOARD",
		// Tier-2 MS-RDPEGFX/AVC420 H.264 path (ADR 0053). DEFAULT OFF. session_live
		// hard-gates it off for recorded sessions (the WORM PNG track needs the
		// bitmap path) and, when on, auto-falls-back to the bitmap path on a host
		// that can't encode H.264 — so it is safe to enable by deployment/policy.
		"JESS_RDP_H264",
		// JESS_RDP_AVC444 (also gated by JESS_RDP_H264) additionally advertises
		// AVC444 so a GPU-capable host may send the higher-quality dual-stream
		// codec; we display its 4:2:0 main view. DEFAULT OFF.
		"JESS_RDP_AVC444",
		// ADR 0061: SOFTWARE H.264. session_live CPU-encodes the decoded
		// framebuffer as H.264 → MSG_H264 (native-feel smoothness, NO GPU, any
		// host). Wins over EGFX. DEFAULT OFF; tunables for bitrate/fps.
		"JESS_RDP_H264_SW", "JESS_RDP_H264_SW_BITRATE", "JESS_RDP_H264_SW_FPS",
	} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// envBool reports whether the env var is set to a truthy value (1/true/yes,
// case-insensitive). Mirrors session_live's env_flag so the Go tee's
// forward/record decision tracks the subprocess's live-encoding mode.
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// liveRDPSession is one open subprocess-backed RDP session.
type liveRDPSession struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout io.ReadCloser
	client io.ReadWriteCloser

	// snapshot state — the latest FRAME PNG + desktop dims the stdout tee
	// observed, for the ADR-0030 periodic-screenshot WORM track.
	snapMu    sync.Mutex
	lastFrame []byte
	deskW     int
	deskH     int

	// webpLive reflects the Tier-1 live encoding session_live is using: true ⇒
	// the browser frame is the lossy WebP (msgFrameWebp) and any msgFrame (PNG)
	// is the recorder-only lossless feed (recorded, NOT forwarded to the
	// browser); false ⇒ lossless mode, where msgFrame IS the browser frame
	// (forwarded AND recorded). Kept in lock-step with the JESS_RDP_LOSSLESS env
	// the engine forwards to the subprocess.
	webpLive bool

	// rec is the ADR 0051 P4 full-stream recorder (jess-rdp-recording-v2). When
	// non-nil, the server→client tee records every DESKTOP_SIZE + FRAME and the
	// client→stdin leg records every input event; Close seals the bundle. nil =
	// not recording (the caller's fail-closed gate decided a recorder isn't
	// required for this session). Best-effort per-event (a transient encode error
	// doesn't drop the rest of the stream); a SEAL failure is surfaced by Close.
	rec *recording.RDPStreamWriter

	closeOnce sync.Once
}

// Run relays the TLV stream both ways until the operator disconnects, the
// subprocess emits CLOSE / exits, or a fatal wire error occurs. It returns the
// subprocess's nonzero exit as an error (fail-closed: the operator sees a
// failed session, not a silently-empty canvas).
//
// Lifecycle: the stdout leg ending (subprocess emitted CLOSE / exited) is the
// authoritative "session over" signal. An operator disconnect (client read EOF)
// instead closes the subprocess stdin so it sees EOF and exits NATURALLY — we
// do NOT immediately SIGKILL, so the subprocess can flush its CLOSE and exit 0.
// A guard timer SIGKILLs only if the subprocess hangs after disconnect.
func (s *liveRDPSession) Run() error {
	const exitGrace = 5 * time.Second

	// client → stdin: operator input (MOUSE/KEY TLVs, already framed) → bin.
	// On operator disconnect, close stdin so the bin sees EOF. When recording,
	// the leg passes through a tee that parses each input TLV into the v2 stream
	// (the forward to stdin stays byte-for-byte verbatim).
	go func() {
		if s.rec != nil {
			_ = s.teeClientStream(s.client, s.stdin)
		} else {
			_, _ = io.Copy(s.stdin, s.client)
		}
		_ = s.stdin.Close()
	}()

	// stdout → client (through the snapshot tee). This goroutine returning is
	// the session-end signal: the subprocess closed stdout (CLOSE / exit).
	stdoutDone := make(chan error, 1)
	go func() {
		stdoutDone <- s.teeServerStream(s.stdout, s.client)
	}()

	// Wait for the subprocess to exit. If stdout has already ended, Wait
	// resolves immediately; otherwise (e.g. operator-disconnect → stdin EOF)
	// the bin should exit within the grace window — failing that we cancel
	// (SIGKILL via CommandContext) so a hung subprocess can't leak.
	<-stdoutDone
	waitErr := s.waitWithGrace(exitGrace)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code := -1
			if exitErr.ProcessState != nil {
				code = exitErr.ProcessState.ExitCode()
			}
			if code == -1 {
				// Killed by our guard SIGKILL (signal) — operator-driven end.
				return nil
			}
			return fmt.Errorf("rdp live engine: session_live exited %d (fail-closed): %w", code, waitErr)
		}
		return fmt.Errorf("rdp live engine: session_live wait: %w", waitErr)
	}
	return nil
}

// waitWithGrace waits for the subprocess to exit, SIGKILLing it (via cancel) if
// it hasn't exited within grace — so an operator disconnect can't leave a hung
// session_live behind. Returns the subprocess wait error.
func (s *liveRDPSession) waitWithGrace(grace time.Duration) error {
	waitCh := make(chan error, 1)
	go func() { waitCh <- s.cmd.Wait() }()
	select {
	case err := <-waitCh:
		return err
	case <-time.After(grace):
		s.cancel() // SIGKILL the hung subprocess
		return <-waitCh
	}
}

// teeServerStream copies the framed server→client TLV stream from src to dst,
// while parsing each frame to capture the latest FRAME PNG + DESKTOP_SIZE for
// Snapshot() and to feed the WORM recorder.
//
// Tier-1 forwarding is type-aware (no longer byte-for-byte) ONLY for the
// lossless recorder-feed PNG: when this session is recording with WebP live
// frames (s.rec != nil && s.webpLive), session_live emits BOTH a lossy
// msgFrameWebp (the browser frame) AND a lossless msgFrame PNG per region (the
// recorder feed). The PNG is recorded but NOT forwarded to the browser (it'd be
// a redundant lossless repaint over the WebP); everything else is forwarded
// verbatim. In all other modes every frame is forwarded as before.
func (s *liveRDPSession) teeServerStream(src io.Reader, dst io.Writer) error {
	br := bufio.NewReaderSize(src, 64*1024)
	var lenBuf [4]byte
	for {
		// Length prefix.
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // bin closed stdout — clean end
			}
			return err
		}
		totalLen := binary.BigEndian.Uint32(lenBuf[:])
		if totalLen == 0 || int(totalLen) > maxServerPayload {
			return fmt.Errorf("rdp live engine: server frame bad length %d", totalLen)
		}
		body := make([]byte, totalLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return err
		}
		// Read-only parse for the screenshot track + the WORM recorder.
		s.observeFrame(body)
		// Decide whether to forward this frame to the browser. The recorder-only
		// lossless PNG (msgFrame, while recording with WebP live frames) is NOT
		// forwarded — the browser renders the lossy WebP. All other frames are.
		if s.recorderOnly(body) {
			continue
		}
		if _, err := dst.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := dst.Write(body); err != nil {
			return err
		}
	}
}

// recorderOnly reports whether a server→client frame is the lossless PNG feed
// that exists solely for the WORM recorder and must NOT be forwarded to the
// browser. That is exactly a msgFrame (PNG) when this session records AND uses
// lossy WebP live frames — the browser gets the sibling msgFrameWebp instead.
func (s *liveRDPSession) recorderOnly(body []byte) bool {
	return len(body) >= 1 && body[0] == msgFrame && s.rec != nil && s.webpLive
}

// observeFrame inspects one [u8 type][payload] body for the snapshot track AND
// (ADR 0051 P4) tees DESKTOP_SIZE / FRAME / CLOSE into the full-stream v2
// recorder when one is wired. This is a read-only side-channel; the caller does
// the forward.
//
// Tier-1 split:
//   - The Snapshot() track (broker Dial periodic-screenshot, ADR-0030) is fed
//     from EITHER frame type — its bytes are only SHA-256-hashed + referenced,
//     so the lossy WebP is fine when that's all session_live emits. This keeps
//     the non-recording Dial path producing screenshots even though live frames
//     are WebP.
//   - The v2 recorder (jess-rdp-recording-v2) is fed from the lossless PNG
//     msgFrame (bitmap path) OR, on an EGFX/AVC420 session, from the msgH264
//     access units (ADR 0058) — never both in one recording. So the WORM bundle
//     stays lossless (PNG) or fully replayable (H.264). WebP frames are never
//     written to it.
func (s *liveRDPSession) observeFrame(body []byte) {
	if len(body) < 1 {
		return
	}
	switch body[0] {
	case msgDesktopSize:
		if len(body) >= 5 {
			w := int(binary.BigEndian.Uint16(body[1:3]))
			h := int(binary.BigEndian.Uint16(body[3:5]))
			s.snapMu.Lock()
			s.deskW = w
			s.deskH = h
			s.snapMu.Unlock()
			if s.rec != nil {
				_ = s.rec.Resize(w, h)
			}
		}
	case msgFrame:
		// [type][x:2][y:2][w:2][h:2][PNG] — lossless. Feeds both the snapshot
		// track and the v2 WORM recorder (the latter must stay lossless).
		if len(body) >= 9 {
			png := body[9:]
			if len(png) > 0 {
				cp := make([]byte, len(png))
				copy(cp, png)
				s.snapMu.Lock()
				s.lastFrame = cp
				s.snapMu.Unlock()
				if s.rec != nil {
					x := int(binary.BigEndian.Uint16(body[1:3]))
					y := int(binary.BigEndian.Uint16(body[3:5]))
					w := int(binary.BigEndian.Uint16(body[5:7]))
					h := int(binary.BigEndian.Uint16(body[7:9]))
					_ = s.rec.Frame(x, y, w, h, cp)
				}
			}
		}
	case msgFrameWebp:
		// [type][x:2][y:2][w:2][h:2][WebP] — lossy live frame. Feeds the
		// snapshot track ONLY (hash + dims reference); NEVER the v2 recorder
		// (which stays lossless PNG via the sibling msgFrame when recording).
		if len(body) >= 9 {
			webp := body[9:]
			if len(webp) > 0 {
				cp := make([]byte, len(webp))
				copy(cp, webp)
				s.snapMu.Lock()
				s.lastFrame = cp
				s.snapMu.Unlock()
			}
		}
	case msgH264:
		// [type][flags:1][x:2][y:2][w:2][h:2][AVC NAL (Annex-B)] — the
		// MS-RDPEGFX/AVC420 H.264 access unit (ADR 0058). Tees the AU (NAL +
		// keyframe flag + AVC444 flag + surface rect) into the v2 recorder so an
		// EGFX-driven session is replayable. The AU is ALSO forwarded to the
		// browser (it IS the live frame — recorderOnly returns false for it).
		//
		// The snapshot track (ADR-0030 periodic-screenshot) is NOT fed from an
		// H.264 AU: raw NAL bytes are not a decodable screenshot image, and the
		// snapshot track is only used on the rec==nil broker Dial path (which never
		// runs H.264). Leaving lastFrame untouched avoids serving a corrupt PNG.
		//
		// AVC444 auxiliary (chroma) frames (h264FlagAux, ADR 0059) are SKIPPED for
		// the recorder: the browser recombines them with the main view into 4:4:4
		// live, but a recording stays the AVC420 main view (4:2:0) — so the aux
		// frames never enter the v2 stream and the ADR 0058 format is unchanged.
		// They are still forwarded to the browser (forwarding is independent of
		// this recorder tee — recorderOnly returns false for every msgH264).
		if len(body) >= 10 && s.rec != nil && body[1]&h264FlagAux == 0 {
			flags := body[1]
			x := int(binary.BigEndian.Uint16(body[2:4]))
			y := int(binary.BigEndian.Uint16(body[4:6]))
			w := int(binary.BigEndian.Uint16(body[6:8]))
			h := int(binary.BigEndian.Uint16(body[8:10]))
			nal := body[10:]
			if len(nal) > 0 {
				cp := make([]byte, len(nal))
				copy(cp, nal)
				keyframe := flags&h264FlagKeyframe != 0
				avc444 := flags&h264FlagAVC444 != 0
				_ = s.rec.H264Frame(x, y, w, h, keyframe, avc444, cp)
			}
		}
	case msgClose:
		if s.rec != nil {
			_ = s.rec.CloseEvent()
		}
	}
}

// teeClientStream copies the framed client→stdin TLV stream byte-for-byte while
// parsing each input TLV ([u32 len][u8 type][payload]) into the v2 recorder. The
// forward to stdin is verbatim (the subprocess gets the exact bytes); the parse
// is a read-only side-channel. Used only when recording is on.
func (s *liveRDPSession) teeClientStream(src io.Reader, dst io.Writer) error {
	br := bufio.NewReaderSize(src, 64*1024)
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return err // EOF = operator disconnect
		}
		totalLen := binary.BigEndian.Uint32(lenBuf[:])
		if totalLen == 0 || int(totalLen) > maxServerPayload {
			return fmt.Errorf("rdp live engine: client frame bad length %d", totalLen)
		}
		body := make([]byte, totalLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return err
		}
		// Forward verbatim to the subprocess stdin.
		if _, err := dst.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := dst.Write(body); err != nil {
			return err
		}
		s.observeInput(body)
	}
}

// observeInput parses one client [u8 type][payload] body and records it as an
// input event in the v2 stream. Mirrors the SPA's encodeMouseTLV / encodeKeyTLV
// (see web/src/api/rdp.ts): MOUSE = [u16 x][u16 y][u8 mask][i8 wheel],
// KEY = [u8 is_down][u32 scancode].
func (s *liveRDPSession) observeInput(body []byte) {
	if s.rec == nil || len(body) < 1 {
		return
	}
	switch body[0] {
	case clientMsgMouse:
		if len(body) >= 7 {
			x := int(binary.BigEndian.Uint16(body[1:3]))
			y := int(binary.BigEndian.Uint16(body[3:5]))
			mask := int(body[5])
			wheel := int(int8(body[6]))
			_ = s.rec.Mouse(x, y, mask, wheel)
		}
	case clientMsgKey:
		if len(body) >= 6 {
			down := body[1] != 0
			sc := binary.BigEndian.Uint32(body[2:6])
			_ = s.rec.Key(down, sc)
		}
	}
}

// Snapshot returns the most-recent FRAME PNG + the desktop dimensions for the
// periodic-screenshot WORM track. A nil/empty return ("no frame yet") makes the
// pump skip that tick — identical contract to the stub/fake.
func (s *liveRDPSession) Snapshot() (img []byte, width, height int, err error) {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if len(s.lastFrame) == 0 {
		return nil, 0, 0, nil
	}
	w, h := s.deskW, s.deskH
	cp := make([]byte, len(s.lastFrame))
	copy(cp, s.lastFrame)
	return cp, w, h, nil
}

// Close tears the subprocess down (cancel → SIGKILL via CommandContext), closes
// the operator-side pipes, and SEALS the v2 recording bundle if one is wired. A
// seal error is RETURNED (not swallowed): a recorded session whose bundle didn't
// commit to WORM is an audit gap, and the caller (jess-web bridge) must surface
// it fail-closed. Idempotent: the subprocess teardown runs once; the seal is safe
// to call more than once (RDPStreamWriter.Close is idempotent).
func (s *liveRDPSession) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.stdin.Close()
		_ = s.stdout.Close()
	})
	if s.rec != nil {
		if err := s.rec.Close(); err != nil {
			return fmt.Errorf("rdp live engine: seal recording bundle (fail-closed): %w", err)
		}
	}
	return nil
}

// drainStderr surfaces session_live's human-readable progress under a prefix so
// a failed handshake is diagnosable. session_live redacts the password itself.
func (s *liveRDPSession) drainStderr(r io.ReadCloser) {
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		log.Printf("rdp session_live: %s", line)
	}
}

// compile-time guard.
var (
	_ rdpEngine      = (*liveRDPEngine)(nil)
	_ rdpSession     = (*liveRDPSession)(nil)
	_ RDPLiveSession = (*liveRDPSession)(nil) // exported web seam
	_ WebRDPEngine   = (*webEngineAdapter)(nil)
)
