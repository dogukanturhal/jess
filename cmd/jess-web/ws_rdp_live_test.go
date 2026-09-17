// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Headless WS-client tests for the /ws/rdp-live in-process Go↔Rust bridge.
//
// These prove the WS framing translation + bidirectional relay deterministically
// by injecting a FAKE engine in place of the real session_live spawner:
//   - server→browser: the engine writes full [u32 len][type][payload] TLVs to
//     its client pipe; the bridge must STRIP the u32 len and deliver one WS
//     BINARY frame per TLV ([type][payload]);
//   - browser→engine: the browser sends a WS BINARY [type][payload]; the bridge
//     must PREPEND the u32 len and the engine must read the full framed TLV.
//
// Auth + catalog resolution go through the real handler (cookie session + a
// httptest controller catalog), so the operator-auth + target-resolve legs are
// exercised too.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/dogukanturhal/jess/internal/broker"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// fakeLiveEngine is a deterministic stand-in for the session_live spawner: on
// OpenSession it returns a session that, on Run, emits DESKTOP_SIZE + a FRAME on
// the client pipe, then echoes each operator input TLV it reads back as a FRAME
// carrying the input's msg_type (so the test can assert input round-tripped).
type fakeLiveEngine struct {
	gotSecret  broker.RDPSecret
	gotAddr    string
	gotRec     *recording.RDPStreamWriter
	gotDesktop broker.RDPDesktopSize
}

func (e *fakeLiveEngine) OpenSession(_ context.Context, target *catalog.Target, sec broker.RDPSecret, client io.ReadWriteCloser, rec *recording.RDPStreamWriter, desktop broker.RDPDesktopSize) (broker.RDPLiveSession, error) {
	e.gotSecret = sec
	e.gotAddr = target.Address
	e.gotRec = rec
	e.gotDesktop = desktop
	return &fakeLiveSession{client: client, rec: rec, done: make(chan struct{})}, nil
}

type fakeLiveSession struct {
	client io.ReadWriteCloser
	rec    *recording.RDPStreamWriter
	done   chan struct{}
	once   sync.Once
}

func (s *fakeLiveSession) Run() error {
	// Emit DESKTOP_SIZE 1280x1024 then an initial FRAME (png byte 0xAB). When a
	// recorder is wired, tee the same events into the v2 stream (so the test can
	// assert the WORM recording captured the real decoded stream + input).
	writeFramedTLV(s.client, []byte{1, 0x05, 0x00, 0x04, 0x00})
	if s.rec != nil {
		_ = s.rec.Resize(1280, 1024)
	}
	writeFramedTLV(s.client, frameTLV(0xAB))
	if s.rec != nil {
		_ = s.rec.Frame(0, 0, 1, 1, []byte{0xAB})
	}

	// Echo loop: read operator TLVs off the client pipe, emit a FRAME whose png
	// byte == the input msg_type.
	var lp [4]byte
	for {
		if _, err := io.ReadFull(s.client, lp[:]); err != nil {
			break
		}
		n := binary.BigEndian.Uint32(lp[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(s.client, body); err != nil {
			break
		}
		mt := byte(0)
		if len(body) > 0 {
			mt = body[0]
		}
		if s.rec != nil && len(body) > 0 {
			switch body[0] {
			case 1: // MOUSE
				_ = s.rec.Mouse(int(body[1])<<8|int(body[2]), 0, int(body[5]), 0)
			case 2: // KEY
				_ = s.rec.Key(body[1] != 0, 0)
			}
		}
		writeFramedTLV(s.client, frameTLV(mt))
	}
	// stdin EOF (operator disconnect) ends the session — close the client so the
	// bridge's engine→browser leg unblocks (mirrors the real subprocess exit).
	_ = s.client.Close()
	return nil
}
func (s *fakeLiveSession) Snapshot() ([]byte, int, int, error) { return nil, 0, 0, nil }
func (s *fakeLiveSession) Close() error {
	s.once.Do(func() { close(s.done) })
	if s.rec != nil {
		_ = s.rec.CloseEvent()
		_ = s.rec.Close() // seal the bundle (idempotent)
	}
	return s.client.Close()
}

// frameTLV builds a [type=FRAME][x:2][y:2][w:2][h:2][png byte] body.
func frameTLV(png byte) []byte {
	return []byte{2, 0, 0, 0, 0, 0, 1, 0, 1, png}
}

// writeFramedTLV prepends the u32 len and writes [u32 len][body].
func writeFramedTLV(w io.Writer, body []byte) {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(body)))
	_, _ = w.Write(lp[:])
	_, _ = w.Write(body)
}

// newTestRDPLiveServer wires the real handler over a test session + a httptest
// controller catalog, with the fake engine injected.
func newTestRDPLiveServer(t *testing.T, eng rdpLiveEngine) (srv *httptest.Server, cookie *http.Cookie) {
	t.Helper()

	// Controller catalog stub: one RDP target.
	catalogSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"id": "win-dc-01", "address": "10.0.20.10:3389", "protocol": "rdp"},
		})
	}))
	t.Cleanup(catalogSrv.Close)

	sessions := newSessionStore()
	grants := newGrantsClient(catalogSrv.URL, nil, sessions)

	cfg := &rdpLiveConfig{
		sessions:   sessions,
		grants:     grants,
		engine:     eng,
		devEnabled: true,
		devCreds: broker.RDPSecret{
			Kind: broker.RDPSecretADCredential, Username: "svc", Password: "p@ss", Domain: "HEXXLOCK",
		},
	}

	// A signed-in operator session.
	sid, _ := newSessionID()
	sessions.put(sid, &Operator{Token: "tok", Subject: "op@test", Expires: time.Now().Add(time.Hour)})

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/rdp-live", cfg.handleRDPLiveSession)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &http.Cookie{Name: sessionCookie, Value: sid}
}

func dialLiveWS(t *testing.T, srv *httptest.Server, cookie *http.Cookie, query string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/rdp-live" + query
	hdr := http.Header{}
	hdr.Set("Cookie", cookie.String())
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	return ws
}

// readWSBinary reads one WS binary frame and returns its [type][payload].
func readWSBinary(t *testing.T, ws *websocket.Conn) (msgType byte, payload []byte) {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("ws frame type = %d, want binary", mt)
	}
	if len(data) == 0 {
		t.Fatal("empty ws binary frame")
	}
	return data[0], data[1:]
}

// TestRDPLiveBridgeRelaysFramesAndInput is the headline WS test: DESKTOP_SIZE +
// FRAME arrive as one WS binary frame each (u32 len stripped), and operator
// input sent as a WS binary frame round-trips through the engine.
func TestRDPLiveBridgeRelaysFramesAndInput(t *testing.T) {
	eng := &fakeLiveEngine{}
	srv, cookie := newTestRDPLiveServer(t, eng)
	// A grant is now HARD-required on every live open (V8 parity with SSH/DB);
	// the test controller stub answers /grants/assert 200 → active.
	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01&grant=g-1")
	defer ws.Close()

	// 1) DESKTOP_SIZE as one WS binary frame, len stripped → [type=1][w:2][h:2].
	mt, payload := readWSBinary(t, ws)
	if mt != 1 {
		t.Fatalf("first WS frame type = %d, want DESKTOP_SIZE(1)", mt)
	}
	if len(payload) != 4 || binary.BigEndian.Uint16(payload[0:2]) != 1280 || binary.BigEndian.Uint16(payload[2:4]) != 1024 {
		t.Fatalf("DESKTOP_SIZE payload = %v, want 1280x1024", payload)
	}

	// 2) Initial FRAME (png byte 0xAB).
	mt, payload = readWSBinary(t, ws)
	if mt != 2 || payload[len(payload)-1] != 0xAB {
		t.Fatalf("FRAME = type %d png %v, want FRAME with trailing 0xAB", mt, payload)
	}

	// 3) Send a MOUSE input as one WS binary frame [type=1][payload] — the bridge
	// prepends the u32 len; the fake echoes a FRAME with png byte = 1 (MOUSE).
	mouse := []byte{1, 0x01, 0x2C, 0x01, 0x90, 0x01, 0x00}
	if err := ws.WriteMessage(websocket.BinaryMessage, mouse); err != nil {
		t.Fatalf("write mouse: %v", err)
	}
	mt, payload = readWSBinary(t, ws)
	if mt != 2 || payload[len(payload)-1] != 1 {
		t.Fatalf("echo after MOUSE = type %d png %v, want FRAME png byte 1", mt, payload)
	}

	// 4) A KEY input → echo FRAME png byte 2 (KEY).
	key := []byte{2, 0x01, 0x00, 0x00, 0x00, 0x1E}
	if err := ws.WriteMessage(websocket.BinaryMessage, key); err != nil {
		t.Fatalf("write key: %v", err)
	}
	mt, payload = readWSBinary(t, ws)
	if mt != 2 || payload[len(payload)-1] != 2 {
		t.Fatalf("echo after KEY = type %d png %v, want FRAME png byte 2", mt, payload)
	}

	// The engine received the dev credential + resolved target address.
	if eng.gotSecret.Username != "svc" {
		t.Errorf("engine got secret %+v, want dev credential", eng.gotSecret)
	}
	if eng.gotAddr != "10.0.20.10:3389" {
		t.Errorf("engine got addr %q, want the catalog-resolved address", eng.gotAddr)
	}
}

// TestRDPLiveBridgeFailClosedNoDevCreds proves the handler fails closed (TLV
// error type 0xFF + close) when dev creds are disabled.
func TestRDPLiveBridgeFailClosedNoDevCreds(t *testing.T) {
	sessions := newSessionStore()
	grants := newGrantsClient("http://unused", nil, sessions)
	cfg := &rdpLiveConfig{sessions: sessions, grants: grants, engine: &fakeLiveEngine{}, devEnabled: false}
	sid, _ := newSessionID()
	sessions.put(sid, &Operator{Token: "tok", Subject: "op", Expires: time.Now().Add(time.Hour)})

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/rdp-live", cfg.handleRDPLiveSession)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ws := dialLiveWS(t, srv, &http.Cookie{Name: sessionCookie, Value: sid}, "?target=win-dc-01")
	defer ws.Close()
	mt, payload := readWSBinary(t, ws)
	if mt != liveMsgError {
		t.Fatalf("first frame type = %d, want error(0xFF)", mt)
	}
	// V16 error hygiene: the browser gets the stable "not configured" message,
	// not the env-var-naming detail (which stays in the server log).
	if !strings.Contains(string(payload), "not configured") {
		t.Errorf("error payload = %q, want the stable not-configured message", payload)
	}
}

// fakeSessionCreds is a deterministic stand-in for the Vault per-session
// credential mint (broker.RDPSessionCredBroker). It records the target + sub it
// was minted for so tests can assert the operator-sub binding.
type fakeSessionCreds struct {
	gotTarget string
	gotSub    string
	calls     int
	sec       broker.RDPSecret
	ttl       time.Duration
	err       error
}

func (f *fakeSessionCreds) IssueForOperator(_ context.Context, targetID, operatorSub string) (broker.RDPSecret, time.Duration, error) {
	f.calls++
	f.gotTarget = targetID
	f.gotSub = operatorSub
	if f.err != nil {
		return broker.RDPSecret{}, 0, f.err
	}
	return f.sec, f.ttl, nil
}

// newTestRDPLiveServerVault wires the handler with the Vault per-session cred
// minter as the credential source (NO dev creds) — the production path.
func newTestRDPLiveServerVault(t *testing.T, eng rdpLiveEngine, creds rdpSessionCredMinter) (*httptest.Server, *http.Cookie) {
	t.Helper()
	catalogSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"id": "win-dc-01", "address": "10.0.20.10:3389", "protocol": "rdp"},
		})
	}))
	t.Cleanup(catalogSrv.Close)

	sessions := newSessionStore()
	grants := newGrantsClient(catalogSrv.URL, nil, sessions)
	cfg := &rdpLiveConfig{sessions: sessions, grants: grants, engine: eng, vaultCreds: creds}

	sid, _ := newSessionID()
	sessions.put(sid, &Operator{Token: "tok", Subject: "op@test", Expires: time.Now().Add(time.Hour)})

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/rdp-live", cfg.handleRDPLiveSession)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &http.Cookie{Name: sessionCookie, Value: sid}
}

// TestRDPLiveVaultIsDefaultAndSubBound proves that when the Vault cred minter is
// wired, it is the DEFAULT credential source, it mints bound to the real
// operator sub + target, and the minted secret reaches the engine.
func TestRDPLiveVaultIsDefaultAndSubBound(t *testing.T) {
	creds := &fakeSessionCreds{
		sec: broker.RDPSecret{Kind: broker.RDPSecretADCredential, Username: "v-ldap-eph", Password: "x", Domain: "HEXXLOCK"},
		ttl: 15 * time.Minute,
	}
	eng := &fakeLiveEngine{}
	srv, cookie := newTestRDPLiveServerVault(t, eng, creds)

	// grant required in the Vault path → pass it.
	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01&grant=g-123")
	defer ws.Close()

	// First frame is DESKTOP_SIZE — confirms the session opened with the minted cred.
	mt, _ := readWSBinary(t, ws)
	if mt != 1 {
		t.Fatalf("first WS frame type = %d, want DESKTOP_SIZE(1)", mt)
	}
	if creds.calls != 1 {
		t.Fatalf("Vault mint called %d times, want 1", creds.calls)
	}
	if creds.gotSub != "op@test" {
		t.Errorf("mint bound to sub %q, want the real operator sub op@test", creds.gotSub)
	}
	if creds.gotTarget != "win-dc-01" {
		t.Errorf("mint target = %q, want win-dc-01", creds.gotTarget)
	}
	if eng.gotSecret.Username != "v-ldap-eph" {
		t.Errorf("engine got %+v, want the Vault-minted credential", eng.gotSecret.Username)
	}
}

// TestRDPLiveVaultRequiresGrant proves the Vault path rejects a session with no
// grant (grant assertion) BEFORE minting any credential.
func TestRDPLiveVaultRequiresGrant(t *testing.T) {
	creds := &fakeSessionCreds{sec: broker.RDPSecret{Kind: broker.RDPSecretADCredential, Username: "u", Password: "p"}, ttl: time.Minute}
	srv, cookie := newTestRDPLiveServerVault(t, &fakeLiveEngine{}, creds)

	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01") // no grant
	defer ws.Close()
	mt, payload := readWSBinary(t, ws)
	if mt != liveMsgError {
		t.Fatalf("first frame type = %d, want error(0xFF) for missing grant", mt)
	}
	// V16 hygiene: the gate returns the stable, opaque not-authorized message
	// (it never reveals whether the grant is missing vs inactive vs foreign).
	// The security-relevant proof is creds.calls==0 below: no mint before authz.
	if !strings.Contains(string(payload), "not authorized") {
		t.Errorf("error payload = %q, want the stable not-authorized message", payload)
	}
	if creds.calls != 0 {
		t.Errorf("credential minted despite missing grant (calls=%d) — must assert grant first", creds.calls)
	}
}

// TestRDPLiveVaultMintErrorFailsClosed proves a Vault mint failure fails the
// session closed (TLV error) and never opens the engine.
func TestRDPLiveVaultMintErrorFailsClosed(t *testing.T) {
	creds := &fakeSessionCreds{err: errStr("permission denied")}
	eng := &fakeLiveEngine{}
	srv, cookie := newTestRDPLiveServerVault(t, eng, creds)

	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01&grant=g-1")
	defer ws.Close()
	mt, payload := readWSBinary(t, ws)
	if mt != liveMsgError {
		t.Fatalf("first frame type = %d, want error(0xFF) on mint failure", mt)
	}
	// V16 hygiene: the raw Vault mint error ("permission denied") stays in the
	// server log; the browser gets the stable credential-failure message.
	if !strings.Contains(string(payload), "credential") {
		t.Errorf("error payload = %q, want the stable credential-failure message", payload)
	}
	if eng.gotAddr != "" {
		t.Error("engine opened despite mint failure — must fail closed before OpenSession")
	}
}

// TestRDPLiveBridgeRejectsAnon proves an unauthenticated request is rejected
// before the WS upgrade (401 JSON, no upgrade).
func TestRDPLiveBridgeRejectsAnon(t *testing.T) {
	eng := &fakeLiveEngine{}
	srv, _ := newTestRDPLiveServer(t, eng)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/rdp-live?target=win-dc-01"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil) // no cookie
	if err == nil {
		t.Fatal("anon dial must fail (no session)")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		got := 0
		if resp != nil {
			got = resp.StatusCode
		}
		t.Errorf("anon status = %d, want 401", got)
	}
}

// --- ADR 0051 P4: full-stream WORM recording + identity binding + fail-closed --

// fsRecorder is a BundleRecorder over a filesystem store + an in-process
// ed25519 signer, for asserting the sealed v2 bundle in tests.
type fsRecorder struct {
	rec    recording.Recorder
	store  *recording.FSStore
	signer *recording.Ed25519Signer
	dir    string
}

func newFSRecorder(t *testing.T) *fsRecorder {
	t.Helper()
	dir := t.TempDir()
	store := recording.NewFSStore(dir)
	signer, err := recording.NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return &fsRecorder{rec: recording.NewBundleRecorder(store, signer), store: store, signer: signer, dir: dir}
}

// errRecorder is a recording.Recorder whose Open always fails — to prove the
// handler denies a Recorded target when the bundle can't be opened.
type errRecorder struct{}

func (errRecorder) Open(context.Context, recording.Meta) (io.WriteCloser, error) {
	return nil, errFakeRecorderBroken
}

var errFakeRecorderBroken = recordingBrokenErr("recorder backend down")

type recordingBrokenErr string

func (e recordingBrokenErr) Error() string { return string(e) }

// newTestRDPLiveServerCfg wires the real handler with a fully custom config (so a
// test can inject a recorder + control target.Recorded).
func newTestRDPLiveServerCfg(t *testing.T, eng rdpLiveEngine, rec recording.Recorder, recorded bool) (srv *httptest.Server, cookie *http.Cookie) {
	t.Helper()
	catalogSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "win-dc-01", "address": "10.0.20.10:3389", "protocol": "rdp", "recorded": recorded},
		})
	}))
	t.Cleanup(catalogSrv.Close)

	sessions := newSessionStore()
	grants := newGrantsClient(catalogSrv.URL, nil, sessions)
	cfg := &rdpLiveConfig{
		sessions:   sessions,
		grants:     grants,
		engine:     eng,
		devEnabled: true,
		devCreds:   broker.RDPSecret{Kind: broker.RDPSecretADCredential, Username: "svc", Password: "p@ss", Domain: "HEXXLOCK"},
		recorder:   rec,
	}
	sid, _ := newSessionID()
	sessions.put(sid, &Operator{Token: "tok", Subject: "op@test", Expires: time.Now().Add(time.Hour)})

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/rdp-live", cfg.handleRDPLiveSession)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &http.Cookie{Name: sessionCookie, Value: sid}
}

// TestRDPLiveBridgeRecordsFullStream proves the live bridge tees the FULL decoded
// stream into a signed WORM bundle (jess-rdp-recording-v2) bound to the REAL
// operator subject — resize, frame, and operator input all land, and the sealed
// bundle verifies.
func TestRDPLiveBridgeRecordsFullStream(t *testing.T) {
	fr := newFSRecorder(t)
	eng := &fakeLiveEngine{}
	srv, cookie := newTestRDPLiveServerCfg(t, eng, fr.rec, true /* recorded */)

	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01&grant=g-1")

	// Drive the session: read DESKTOP_SIZE + initial FRAME, send a MOUSE + a KEY.
	mt, _ := readWSBinary(t, ws)
	if mt != 1 {
		t.Fatalf("first frame = %d, want DESKTOP_SIZE", mt)
	}
	mt, _ = readWSBinary(t, ws)
	if mt != 2 {
		t.Fatalf("second frame = %d, want FRAME", mt)
	}
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte{1, 0x02, 0x80, 0x01, 0x90, 0x01, 0x00}); err != nil {
		t.Fatalf("write mouse: %v", err)
	}
	readWSBinary(t, ws) // echo
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte{2, 0x01, 0x00, 0x00, 0x00, 0x1E}); err != nil {
		t.Fatalf("write key: %v", err)
	}
	readWSBinary(t, ws) // echo

	// Close the WS → handler tears down → sess.Close seals the bundle.
	_ = ws.Close()

	// The engine was handed a non-nil recorder (the Recorded-target binding).
	deadline := time.Now().Add(3 * time.Second)
	for eng.gotRec == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if eng.gotRec == nil {
		t.Fatal("engine got nil recorder for a Recorded target — recording would be absent")
	}

	// The handler tears down + seals asynchronously after the WS closes — wait
	// for the sealed bundle (manifest.json) to land in the store.
	sid := waitForSealedSession(t, fr.dir)
	res, err := recording.VerifyDetail(t.Context(), fr.store, sid, fr.signer.Public())
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if !res.SignatureValid || !res.HashMatch {
		t.Fatalf("sealed bundle should verify: %+v", res)
	}
	if res.Manifest.Format != recording.FormatRDPStreamV2 {
		t.Errorf("manifest format = %q, want rdp-stream-v2", res.Manifest.Format)
	}
	// IDENTITY BINDING: the manifest carries the REAL operator sub, not the broker.
	if res.Manifest.Subject != "op@test" {
		t.Errorf("manifest subject = %q, want the real operator sub op@test", res.Manifest.Subject)
	}
	if res.Manifest.TargetID != "win-dc-01" {
		t.Errorf("manifest target = %q, want win-dc-01", res.Manifest.TargetID)
	}

	// The content stream is v2 NDJSON: meta (subject) + resize + frame + ≥1 input.
	content, err := fr.store.Get(t.Context(), res.Manifest.ContentKey)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	assertV2Stream(t, content)
}

// TestRDPLiveBridgeDeniesRecordedTargetNoRecorder proves a Recorded target with
// NO recorder configured is DENIED (fail-closed) — an audit gap is never opened.
func TestRDPLiveBridgeDeniesRecordedTargetNoRecorder(t *testing.T) {
	eng := &fakeLiveEngine{}
	srv, cookie := newTestRDPLiveServerCfg(t, eng, nil /* no recorder */, true /* recorded */)
	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01&grant=g-1")
	defer ws.Close()
	mt, payload := readWSBinary(t, ws)
	if mt != liveMsgError {
		t.Fatalf("first frame = %d, want error(0xFF) — Recorded target must be denied", mt)
	}
	if !strings.Contains(string(payload), "recording required") {
		t.Errorf("deny payload = %q, want a recording-required message", payload)
	}
	if eng.gotRec != nil {
		t.Error("engine must NOT be opened when a Recorded target is denied")
	}
}

// TestRDPLiveBridgeDeniesRecordedTargetBrokenRecorder proves a Recorded target is
// DENIED when the recorder is configured but its bundle Open fails (fail-closed).
func TestRDPLiveBridgeDeniesRecordedTargetBrokenRecorder(t *testing.T) {
	eng := &fakeLiveEngine{}
	srv, cookie := newTestRDPLiveServerCfg(t, eng, errRecorder{}, true /* recorded */)
	ws := dialLiveWS(t, srv, cookie, "?target=win-dc-01&grant=g-1")
	defer ws.Close()
	mt, payload := readWSBinary(t, ws)
	if mt != liveMsgError {
		t.Fatalf("first frame = %d, want error(0xFF) — broken recorder must deny", mt)
	}
	if !strings.Contains(string(payload), "recording required") {
		t.Errorf("deny payload = %q, want a recording-required message", payload)
	}
	if eng.gotRec != nil {
		t.Error("engine must NOT be opened when the recorder can't open the bundle")
	}
}

// waitForSealedSession polls the FS store root until exactly one session dir
// holds a manifest.json (the bundle sealed) and returns its id. The handler
// tears down + seals the bundle asynchronously after the WS closes.
func waitForSealedSession(t *testing.T, root string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(root)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if _, serr := os.Stat(filepath.Join(root, e.Name(), "manifest.json")); serr == nil {
					return e.Name()
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no SEALED session bundle (manifest.json) appeared in store")
	return ""
}

// assertV2Stream parses the sealed content stream and asserts it is
// jess-rdp-recording-v2 NDJSON with a meta header binding the real operator
// subject, plus resize/frame/input events.
func assertV2Stream(t *testing.T, content []byte) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 4 {
		t.Fatalf("v2 stream too short (%d lines): %s", len(lines), content)
	}
	var meta struct {
		Kind, Protocol, Subject string
		Version                 int
	}
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		t.Fatalf("parse meta line: %v", err)
	}
	if meta.Kind != "meta" || meta.Version != 2 || meta.Protocol != "rdp" {
		t.Errorf("meta header wrong: %+v", meta)
	}
	if meta.Subject != "op@test" {
		t.Errorf("meta subject = %q, want the real operator sub op@test", meta.Subject)
	}
	var sawResize, sawFrame, sawInput bool
	for _, ln := range lines[1:] {
		var ev struct{ Kind, Input string }
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("parse event %q: %v", ln, err)
		}
		switch ev.Kind {
		case "resize":
			sawResize = true
		case "frame":
			sawFrame = true
		case "input":
			sawInput = true
		}
	}
	if !sawResize || !sawFrame || !sawInput {
		t.Errorf("v2 stream missing events: resize=%v frame=%v input=%v", sawResize, sawFrame, sawInput)
	}
}
