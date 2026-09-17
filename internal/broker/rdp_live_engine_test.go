// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

// Unit tests for the live (subprocess-spawning) RDP engine — ADR 0051 P2c.
//
// These prove the Go↔Rust bridge layer WITHOUT a real Windows DC by compiling a
// tiny FAKE `session_live` Go helper that speaks the exact P2b TLV wire protocol
// (DESKTOP_SIZE + a couple of FRAME messages on stdout, echoing input it reads
// on stdin into a deterministic FRAME). We then drive the engine through the
// Broker Mint→Dial→RecordedConn path and assert:
//   - the engine spawns the bin, relays the server→client FRAME stream verbatim,
//     and forwards operator input into the subprocess;
//   - DESKTOP_SIZE + FRAME bytes reach the operator client unchanged;
//   - the WORM screenshot track captures a real FRAME PNG via Snapshot();
//   - fail-closed when the bin is missing / not executable.
//
// The helper is compiled once per test run (a few hundred ms) and is fully
// deterministic — no network, no timing flake.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// fakeSessionLiveSrc is a self-contained Go program that emulates the Rust
// session_live binary's wire behaviour:
//
//	stdout: DESKTOP_SIZE(1280x1024), FRAME(0,0,2,2, 1-byte fake "png"),
//	        then for each client MOUSE/KEY it reads on stdin, one echo FRAME
//	        whose "png" byte encodes the input msg_type; CLOSE on stdin EOF.
//
// All framing is the [u32 total_len][u8 type][payload] big-endian TLV.
const fakeSessionLiveSrc = `package main

import (
	"encoding/binary"
	"io"
	"os"
)

func writeMsg(w io.Writer, body []byte) error {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(body)))
	if _, err := w.Write(lp[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func frame(msgType byte, x, y, ww, hh uint16, img []byte) []byte {
	b := make([]byte, 0, 9+len(img))
	b = append(b, msgType) // 2 = MSG_FRAME (PNG), 4 = MSG_FRAME_WEBP (lossy live)
	var t [2]byte
	binary.BigEndian.PutUint16(t[:], x); b = append(b, t[:]...)
	binary.BigEndian.PutUint16(t[:], y); b = append(b, t[:]...)
	binary.BigEndian.PutUint16(t[:], ww); b = append(b, t[:]...)
	binary.BigEndian.PutUint16(t[:], hh); b = append(b, t[:]...)
	b = append(b, img...)
	return b
}

func main() {
	// FATAL like the real bin if the target/creds are absent — proves env wiring.
	if os.Getenv("RDP_TARGET") == "" || os.Getenv("RDP_USER") == "" || os.Getenv("RDP_PASS") == "" {
		os.Stderr.WriteString("FATAL: missing RDP_TARGET/RDP_USER/RDP_PASS\n")
		os.Exit(2)
	}
	out := os.Stdout
	// When the bridge records a session it sets JESS_RDP_RECORD_LOSSLESS=1; the
	// real session_live then emits, per region, BOTH a lossy WebP live frame
	// (forwarded to the browser) AND a lossless PNG (recorder-only). Mirror that
	// dual-emit so the engine's recorderOnly guard has the WebP twin to forward;
	// without the twin it would (correctly) swallow the PNG and the browser would
	// receive nothing. In the non-recording case, emit a single PNG as before.
	recordLossless := os.Getenv("JESS_RDP_RECORD_LOSSLESS") == "1"
	emit := func(x, y, ww, hh uint16, marker byte) error {
		if recordLossless {
			if err := writeMsg(out, frame(4, x, y, ww, hh, []byte{marker})); err != nil {
				return err
			}
			return writeMsg(out, frame(2, x, y, ww, hh, []byte{marker}))
		}
		return writeMsg(out, frame(2, x, y, ww, hh, []byte{marker}))
	}
	// DESKTOP_SIZE 1280x1024.
	ds := []byte{1, 0x05, 0x00, 0x04, 0x00}
	if writeMsg(out, ds) != nil { os.Exit(1) }
	// One initial FRAME with a recognisable marker byte 0xAB.
	if emit(0, 0, 2, 2, 0xAB) != nil { os.Exit(1) }

	// Echo loop: for every client TLV on stdin, emit a FRAME whose marker byte is
	// the input msg_type, so the test can assert input round-tripped through.
	in := os.Stdin
	var lp [4]byte
	for {
		if _, err := io.ReadFull(in, lp[:]); err != nil {
			break // EOF = operator disconnect
		}
		n := binary.BigEndian.Uint32(lp[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(in, body); err != nil {
			break
		}
		mt := byte(0)
		if len(body) > 0 { mt = body[0] }
		_ = emit(1, 1, 1, 1, mt)
	}
	// CLOSE.
	_ = writeMsg(out, []byte{3})
}
`

// buildFakeSessionLive compiles the fake helper into a temp executable and
// returns its path. Skips the test (not fails) if there's no Go toolchain.
func buildFakeSessionLive(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable — cannot build fake session_live")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(fakeSessionLiveSrc), 0o600); err != nil {
		t.Fatalf("write fake src: %v", err)
	}
	bin := filepath.Join(dir, "fake_session_live")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake session_live: %v\n%s", err, out)
	}
	return bin
}

// pipeClient is a bidirectional in-memory operator-side connection: the bridge
// reads operator INPUT from `in` and writes server FRAMES to `out`. The test
// drives `in` (writing client TLVs) and reads `out` (server TLVs).
type pipeClient struct {
	in  *io.PipeReader // bridge reads operator input here
	out *io.PipeWriter // bridge writes server frames here
}

func (c *pipeClient) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *pipeClient) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *pipeClient) Close() error {
	_ = c.in.Close()
	return c.out.Close()
}

// newOperatorBridge wires a client whose input the test writes via inW and
// whose server output the test reads via outR.
func newOperatorBridge() (client io.ReadWriteCloser, inW *io.PipeWriter, outR *io.PipeReader) {
	inR, inW := io.Pipe()   // test → bridge stdin
	outR, outW := io.Pipe() // bridge stdout → test
	return &pipeClient{in: inR, out: outW}, inW, outR
}

// readOneServerMsg reads one [u32 len][u8 type][payload] TLV from r.
func readOneServerMsg(t *testing.T, r io.Reader) (msgType byte, payload []byte) {
	t.Helper()
	var lp [4]byte
	if _, err := io.ReadFull(r, lp[:]); err != nil {
		t.Fatalf("read len prefix: %v", err)
	}
	n := binary.BigEndian.Uint32(lp[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body[0], body[1:]
}

// encodeClientTLV frames a [u8 type][payload] body as [u32 len][body].
func encodeClientTLV(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

// TestLiveEngineRelaysFramesAndForwardsInput is the headline bridge test: the
// engine spawns the fake session_live, relays its DESKTOP_SIZE + FRAME stream
// verbatim to the operator client, and forwards operator MOUSE/KEY input into
// the subprocess (proven by the echo FRAME carrying the input msg_type).
func TestLiveEngineRelaysFramesAndForwardsInput(t *testing.T) {
	bin := buildFakeSessionLive(t)
	eng := newLiveRDPEngine(bin)

	client, inW, outR := newOperatorBridge()
	target := &catalog.Target{ID: "win-dc-01", Protocol: catalog.ProtoRDP, Address: "10.0.0.9:3389"}
	sec := RDPSecret{Kind: RDPSecretADCredential, Username: "svc", Password: "p@ss", Domain: "HEXXLOCK"}

	sess, err := eng.Open(context.Background(), target, sec, client, ChannelPolicy{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run() }()

	// 1) DESKTOP_SIZE 1280x1024 reaches the client verbatim.
	mt, payload := readOneServerMsg(t, outR)
	if mt != msgDesktopSize {
		t.Fatalf("first msg type = %d, want DESKTOP_SIZE(%d)", mt, msgDesktopSize)
	}
	if len(payload) != 4 || binary.BigEndian.Uint16(payload[0:2]) != 1280 || binary.BigEndian.Uint16(payload[2:4]) != 1024 {
		t.Fatalf("DESKTOP_SIZE payload = %v, want 1280x1024", payload)
	}

	// 2) Initial FRAME with png byte 0xAB.
	mt, payload = readOneServerMsg(t, outR)
	if mt != msgFrame {
		t.Fatalf("second msg type = %d, want FRAME(%d)", mt, msgFrame)
	}
	if len(payload) < 9 || payload[8] != 0xAB {
		t.Fatalf("initial FRAME png = %v, want trailing 0xAB", payload)
	}

	// 3) Forward operator input: a MOUSE TLV. The fake echoes a FRAME whose png
	// byte == the input msg_type (1 = MOUSE).
	mouse := []byte{1, 0x01, 0x2C, 0x01, 0x90, 0x01, 0x00} // type=1,x=300,y=400,mask=L,wheel=0
	if _, err := inW.Write(encodeClientTLV(mouse)); err != nil {
		t.Fatalf("write client MOUSE: %v", err)
	}
	mt, payload = readOneServerMsg(t, outR)
	if mt != msgFrame || len(payload) < 9 || payload[8] != 1 {
		t.Fatalf("echo FRAME after MOUSE = type %d png %v, want FRAME with png byte 1 (MOUSE)", mt, payload)
	}

	// 4) A KEY TLV → echo FRAME png byte 2 (KEY).
	key := []byte{2, 0x01, 0x00, 0x00, 0x00, 0x1E} // type=2,is_down=1,scancode=0x1E ('A')
	if _, err := inW.Write(encodeClientTLV(key)); err != nil {
		t.Fatalf("write client KEY: %v", err)
	}
	mt, payload = readOneServerMsg(t, outR)
	if mt != msgFrame || len(payload) < 9 || payload[8] != 2 {
		t.Fatalf("echo FRAME after KEY = type %d png %v, want FRAME with png byte 2 (KEY)", mt, payload)
	}

	// 5) The snapshot track captured a real FRAME PNG + the desktop dims.
	img, w, h, serr := sess.Snapshot()
	if serr != nil {
		t.Fatalf("Snapshot: %v", serr)
	}
	if len(img) == 0 {
		t.Fatal("Snapshot returned no frame — the screenshot WORM track would be empty")
	}
	if w != 1280 || h != 1024 {
		t.Errorf("Snapshot dims = %dx%d, want 1280x1024 (from DESKTOP_SIZE)", w, h)
	}

	// 6) Operator disconnect → close client → bin sees stdin EOF → CLOSE → exit 0.
	_ = client.Close()
	drainUntilClose(t, outR)
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error on clean disconnect: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after operator disconnect")
	}
}

// drainUntilClose reads server frames until CLOSE (or EOF), so the bin's stdout
// pump finishes and the process exits cleanly.
func drainUntilClose(t *testing.T, r io.Reader) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var lp [4]byte
		if _, err := io.ReadFull(r, lp[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lp[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		if len(body) > 0 && body[0] == msgClose {
			return
		}
	}
}

// TestLiveEngineFailsClosedMissingBin proves Open fails closed when the bin path
// is unset / missing — a registered RDP broker never silently bypasses the real
// engine.
func TestLiveEngineFailsClosedMissingBin(t *testing.T) {
	t.Setenv(envSessionBin, "") // ensure no env fallback
	client, _, _ := newOperatorBridge()
	defer client.Close()
	target := &catalog.Target{ID: "t", Address: "10.0.0.9:3389"}
	sec := RDPSecret{Kind: RDPSecretADCredential, Username: "u", Password: "p"}

	// Empty configured path + empty env → fail closed.
	if _, err := newLiveRDPEngine("").Open(context.Background(), target, sec, client, ChannelPolicy{}); err == nil {
		t.Error("Open must fail closed when no session_live bin is configured")
	}
	// Nonexistent path → fail closed.
	if _, err := newLiveRDPEngine("/nonexistent/session_live").Open(context.Background(), target, sec, client, ChannelPolicy{}); err == nil {
		t.Error("Open must fail closed when the session_live bin does not exist")
	}
	// Non-executable file → fail closed.
	f := filepath.Join(t.TempDir(), "notexec")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newLiveRDPEngine(f).Open(context.Background(), target, sec, client, ChannelPolicy{}); err == nil {
		t.Error("Open must fail closed when the session_live bin is not executable")
	}
}

// TestLiveEngineRejectsNonADSecret proves a gateway-ticket secret is refused
// (session_live needs an NLA user/pass).
func TestLiveEngineRejectsNonADSecret(t *testing.T) {
	bin := buildFakeSessionLive(t)
	client, _, _ := newOperatorBridge()
	defer client.Close()
	target := &catalog.Target{ID: "t", Address: "10.0.0.9:3389"}
	sec := RDPSecret{Kind: RDPSecretGatewayTicket, Ticket: "opaque"}
	if _, err := newLiveRDPEngine(bin).Open(context.Background(), target, sec, client, ChannelPolicy{}); err == nil {
		t.Error("Open must reject a gateway-ticket secret (session_live needs an AD credential)")
	}
}

// TestLiveEngineNonzeroExitFailsClosed proves a subprocess that exits nonzero
// (here: missing creds in env) surfaces as a Run error — the operator sees a
// failed session, not a silently-empty canvas.
func TestLiveEngineNonzeroExitFailsClosed(t *testing.T) {
	bin := buildFakeSessionLive(t)
	eng := newLiveRDPEngine(bin)
	client, _, outR := newOperatorBridge()
	defer client.Close()
	// Empty username → the fake bin os.Exit(2) before any frame.
	target := &catalog.Target{ID: "t", Address: "10.0.0.9:3389"}
	sec := RDPSecret{Kind: RDPSecretADCredential, Username: "", Password: "p"}
	// Open validates username up-front, so to exercise the *subprocess* exit path
	// we pass a valid secret but clear RDP_USER would be hard; instead validate
	// the up-front guard rejects empty creds (still fail-closed).
	if _, err := eng.Open(context.Background(), target, sec, client, ChannelPolicy{}); err == nil {
		t.Error("Open must reject an empty-password/username AD credential")
	}
	_ = outR

	// Now exercise the genuine subprocess nonzero-exit path with a bin that
	// always exits 1 regardless of env.
	failBin := buildAlwaysFailBin(t)
	eng2 := newLiveRDPEngine(failBin)
	client2, _, outR2 := newOperatorBridge()
	defer client2.Close()
	good := RDPSecret{Kind: RDPSecretADCredential, Username: "u", Password: "p"}
	sess, err := eng2.Open(context.Background(), target, good, client2, ChannelPolicy{})
	if err != nil {
		t.Fatalf("Open (fail bin) should start the process: %v", err)
	}
	// Drain whatever the bin wrote (nothing) so Run's stdout leg sees EOF.
	go io.Copy(io.Discard, outR2)
	runErr := make(chan error, 1)
	go func() { runErr <- sess.Run() }()
	select {
	case err := <-runErr:
		if err == nil {
			t.Error("Run must surface a nonzero subprocess exit as a session error (fail-closed)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return for an always-failing subprocess")
	}
}

// buildAlwaysFailBin compiles a trivial program that exits 1 immediately.
func buildAlwaysFailBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "fail.go")
	if err := os.WriteFile(src, []byte("package main\nimport \"os\"\nfunc main(){ os.Exit(1) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "fail")
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("build fail bin: %v\n%s", err, out)
	}
	return bin
}

// guard against an unused import if the suite is trimmed.
var _ = sync.Once{}

// --- ADR 0051 P4: full-stream recording in the live engine -----------------

// TestLiveEngineRecordsFullStream proves the engine's recorder-aware open() tees
// the ENTIRE decoded stream — DESKTOP_SIZE, every FRAME, and operator input — into
// a jess-rdp-recording-v2 bundle, sealed via Close, with the real operator
// subject bound into the signed manifest.
func TestLiveEngineRecordsFullStream(t *testing.T) {
	bin := buildFakeSessionLive(t)
	eng := newLiveRDPEngine(bin)

	// A real signed bundle over a filesystem store.
	dir := t.TempDir()
	store := recording.NewFSStore(dir)
	signer, err := recording.NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	rec := recording.NewBundleRecorder(store, signer)

	const sid = "rdp-sess-1"
	bw, err := rec.Open(context.Background(), recording.Meta{
		SessionID: sid,
		Subject:   "u-operator-42", // the REAL operator sub
		TargetID:  "win-dc-01",
		Protocol:  "rdp",
		Format:    recording.FormatRDPStreamV2,
	})
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	sw := recording.NewRDPStreamWriter(bw, recording.RDPStreamMeta{
		Subject: "u-operator-42", Target: "win-dc-01", SessionID: sid,
	})

	client, inW, outR := newOperatorBridge()
	target := &catalog.Target{ID: "win-dc-01", Protocol: catalog.ProtoRDP, Address: "10.0.0.9:3389", Recorded: true}
	sec := RDPSecret{Kind: RDPSecretADCredential, Username: "svc", Password: "p@ss", Domain: "HEXXLOCK"}

	sess, err := eng.open(context.Background(), target, sec, client, ChannelPolicy{}, sw, RDPDesktopSize{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run() }()

	// Read the server stream so the subprocess keeps emitting.
	readOneServerMsg(t, outR) // DESKTOP_SIZE
	readOneServerMsg(t, outR) // initial FRAME

	// Send a MOUSE + a KEY (recorded as input events).
	if _, err := inW.Write(encodeClientTLV([]byte{1, 0x01, 0x2C, 0x01, 0x90, 0x01, 0x00})); err != nil {
		t.Fatalf("write mouse: %v", err)
	}
	readOneServerMsg(t, outR) // echo
	if _, err := inW.Write(encodeClientTLV([]byte{2, 0x01, 0x00, 0x00, 0x00, 0x1E})); err != nil {
		t.Fatalf("write key: %v", err)
	}
	readOneServerMsg(t, outR) // echo

	// Operator disconnect → bin sees stdin EOF → CLOSE → exit.
	_ = client.Close()
	drainUntilClose(t, outR)
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}

	// Close SEALS the bundle (and must surface a seal error if any).
	if err := sess.Close(); err != nil {
		t.Fatalf("Close (seal) failed: %v", err)
	}

	// Verify the sealed bundle + assert the v2 stream content.
	res, err := recording.VerifyDetail(context.Background(), store, sid, signer.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.SignatureValid || !res.HashMatch {
		t.Fatalf("sealed bundle should verify: %+v", res)
	}
	if res.Manifest.Subject != "u-operator-42" {
		t.Errorf("manifest subject = %q, want the operator sub (NOT the broker)", res.Manifest.Subject)
	}
	if res.Manifest.Format != recording.FormatRDPStreamV2 {
		t.Errorf("manifest format = %q, want rdp-stream-v2", res.Manifest.Format)
	}

	content, err := store.Get(context.Background(), res.Manifest.ContentKey)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var resize, frames, inputs int
	for i, ln := range lines {
		var ev struct {
			Kind, Input, Subject string
			Version              int
		}
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("parse line %d %q: %v", i, ln, err)
		}
		switch {
		case i == 0:
			if ev.Kind != "meta" || ev.Version != 2 || ev.Subject != "u-operator-42" {
				t.Errorf("meta header wrong: %+v", ev)
			}
		case ev.Kind == "resize":
			resize++
		case ev.Kind == "frame":
			frames++
		case ev.Kind == "input":
			inputs++
		}
	}
	if resize < 1 {
		t.Errorf("recorded resize events = %d, want ≥1 (DESKTOP_SIZE)", resize)
	}
	if frames < 1 {
		t.Errorf("recorded frame events = %d, want ≥1 (decoded FRAME stream)", frames)
	}
	if inputs != 2 {
		t.Errorf("recorded input events = %d, want 2 (MOUSE + KEY)", inputs)
	}
	t.Logf("recorded v2 stream: resize=%d frames=%d inputs=%d total_lines=%d", resize, frames, inputs, len(lines))
}

// sessionEnv must forward a browser-requested desktop size as
// RDP_DESKTOP_W/RDP_DESKTOP_H (quality item #3), and must OMIT a zero axis so
// session_live keeps its default (preserving legacy behaviour). It must never
// leak credentials anywhere but the dedicated RDP_USER/RDP_PASS vars.
func TestSessionEnvDesktopSize(t *testing.T) {
	sec := RDPSecret{Kind: RDPSecretADCredential, Username: "svc", Password: "p@ss", Domain: "HEXXLOCK"}

	has := func(env []string, kv string) bool {
		for _, e := range env {
			if e == kv {
				return true
			}
		}
		return false
	}
	hasKey := func(env []string, key string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, key+"=") {
				return true
			}
		}
		return false
	}

	// Both axes requested → both forwarded verbatim.
	env := sessionEnv("10.0.0.9:3389", sec, RDPDesktopSize{Width: 1920, Height: 1080})
	if !has(env, "RDP_DESKTOP_W=1920") {
		t.Errorf("env missing RDP_DESKTOP_W=1920: %v", env)
	}
	if !has(env, "RDP_DESKTOP_H=1080") {
		t.Errorf("env missing RDP_DESKTOP_H=1080: %v", env)
	}
	if !has(env, "RDP_TARGET=10.0.0.9:3389") || !has(env, "RDP_USER=svc") {
		t.Errorf("env missing target/user: %v", env)
	}

	// Zero size → neither var is set (legacy default preserved).
	env = sessionEnv("10.0.0.9:3389", sec, RDPDesktopSize{})
	if hasKey(env, "RDP_DESKTOP_W") || hasKey(env, "RDP_DESKTOP_H") {
		t.Errorf("zero desktop size must omit RDP_DESKTOP_W/H, got: %v", env)
	}
}
