// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// WebSocket session bridge — operator's browser xterm.js <→ jess-web
// Go goroutine <→ controller operator port <→ brokered worker <→ target.
//
// Wire shape per leg:
//
//   browser <-(text/binary WebSocket frames)-> jess-web
//   jess-web <-(TLS to operator port, wire.OperatorRequest header,
//               then raw SSH bytes)->                controller
//
// WebSocket frame split (Phase 5e-8):
//
//   server → client BINARY  → terminal output (xterm.js renders)
//   server → client TEXT    → JSON envelope (session_meta etc.) — SPA
//                             parses, never writes to xterm
//   client → server TEXT    → operator keystrokes (xterm.onData)
//   client → server BINARY  → resize / future control frames
//
// The TEXT-as-JSON channel lets jess-web push session metadata to the
// browser without polluting the terminal byte stream. Today the only
// metadata frame is `session_meta` with the controller-allocated
// jit_sessions row id + the WORM bundle path.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/dogukanturhal/jess/internal/client"
	"github.com/dogukanturhal/jess/internal/wire"
)

// connectConfig holds the per-process controller-dial config.
type connectConfig struct {
	controllerAddr string         // host:port (operator port; default :7101)
	tlsCfg         *tls.Config    // optional; nil = plaintext (dev only)
	sessions       *sessionStore  // cookie session store
	grants         *grantsClient  // admin proxy — used to fetch session_meta after WS upgrade
	sshCert        *sshCertConfig // Vault SSH-CA minter; nil = legacy raw byte bridge (dev/pre-Vault)
}

// upgrader configures the WS handshake. Origin check is permissive
// for dev (same-origin pages always allowed); production behind a
// known LB hostname should narrow this.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(_ *http.Request) bool { return true },
}

// handleSession upgrades the WS, dials the controller, and bridges.
// Auth: cookie session. Target is required; grant is optional —
// when omitted, the controller's admin-direct-connect path
// (spine.AdminAutoGrantRole + AdminAutoGrantRequireAMR — Phase 5j)
// auto-mints a self-approved grant inline for callers carrying the
// admin role + a satisfying MFA amr. If the operator lacks either,
// the controller denies with reason "step_up_required" or "authz"
// and the SPA's terminal renders the close-frame natively.
func (c *connectConfig) handleSession(w http.ResponseWriter, r *http.Request) {
	op, err := c.sessions.operatorFromRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"not signed in"}`))
		return
	}
	target := r.URL.Query().Get("target")
	grant := r.URL.Query().Get("grant") // empty = admin-direct-connect path
	if target == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"target query param required"}`))
		return
	}
	// Initial terminal size from the SPA (xterm fit addon). The browser
	// re-asserts size with a resize control frame right after open too, so a
	// missing/garbage value here is harmless — defaults applied downstream.
	cols := atoiDefault(r.URL.Query().Get("cols"), 80)
	rows := atoiDefault(r.URL.Query().Get("rows"), 24)

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	up, err := client.Dial(ctx, c.controllerAddr, c.tlsCfg, wire.OperatorRequest{
		Token: op.Token, TargetID: target, GrantID: grant,
	})
	if err != nil {
		_ = ws.WriteMessage(websocket.TextMessage,
			[]byte("\x1b[31mjess-web: controller dial failed: "+err.Error()+"\x1b[0m\r\n"))
		_ = ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "controller dial: "+err.Error()),
			time.Now().Add(2*time.Second))
		return
	}
	defer up.Close()

	log.Printf("jess-web: session open op=%s target=%s grant=%s ssh_client=%v", op.Subject, target, grant, c.sshCert != nil)
	bridge(ctx, ws, up, op, target, grant, c.grants, c.sshCert, cols, rows)
	log.Printf("jess-web: session closed op=%s target=%s grant=%s", op.Subject, target, grant)
}

// atoiDefault parses s as a positive int, returning def on any failure. Used
// for the optional cols/rows query params.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// SessionMeta is the JSON envelope jess-web sends to the browser as the
// first metadata text frame, once the controller has persisted the
// jit_sessions row. The SPA stores it + renders in the Session.tsx
// footer (session id chip with copy + recording_path link).
//
// Fields that may be empty:
//
//   - SessionID — controller hasn't written the row yet OR the grant
//     store isn't a SessionStore (dev mode). SPA hides the chip.
//   - RecordingPath — only set when target.Recorded=true AND the
//     protocol is recorded (SSH today). SPA shows "not recorded"
//     state otherwise.
type SessionMeta struct {
	Type          string `json:"type"` // always "session_meta"
	SessionID     string `json:"session_id,omitempty"`
	TargetID      string `json:"target_id"`
	GrantID       string `json:"grant_id"`
	OperatorEmail string `json:"operator_email,omitempty"`
	StartedAt     string `json:"started_at"` // RFC3339; jess-web's wall clock
	RecordingPath string `json:"recording_path,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	ControllerID  string `json:"controller_id,omitempty"`
}

// bridge pumps bytes both ways + emits the session_meta frame.
//
// Phase 5e-8: a goroutine queries the controller admin for the operator's
// just-created jit_sessions row (matching target+grant), then sends a
// TEXT frame with the metadata. Bridge byte-copies are BINARY only so
// the SPA can distinguish meta (TEXT) from terminal output (BINARY)
// without escaping or framing inside the byte stream.
func bridge(ctx context.Context, ws *websocket.Conn, up net.Conn, op *Operator, target, grant string, grants *grantsClient, sshCert *sshCertConfig, cols, rows int) {
	var writeMu sync.Mutex
	writeFrame := func(typ int, b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return ws.WriteMessage(typ, b)
	}

	// Async metadata emitter — runs alongside the bridge. Worst case
	// fetches fail and the SPA just shows "session id unknown"; the
	// bridge stays bytes-only with no surprise framing.
	if grants != nil {
		go emitSessionMeta(ctx, writeFrame, grants, op, target, grant)
	}

	// Clientless SSH path: jess-web is the SSH client (mints an operator SSH
	// cert + completes the handshake against the worker's sshproxy, then opens
	// a PTY shell and relays it to the browser xterm). This is the fix for the
	// raw-banner / "operator handshake: i/o deadline reached" bug — the browser
	// never spoke SSH, so the worker's SSH server timed out. When sshCert is
	// nil (dev / no Vault SSH-CA env) we fall back to the legacy raw byte
	// bridge below so the build + non-SSH dev flows are unaffected.
	if sshCert != nil {
		if err := runBrowserSSH(ctx, ws, up, sshCert, writeFrame, cols, rows); err != nil {
			log.Printf("jess-web ssh: op=%s target=%s err=%v", op.Subject, target, err)
			_ = writeFrame(websocket.TextMessage,
				[]byte(`{"type":"error","stage":"ssh","msg":`+jsonString(err.Error())+`}`))
			_ = ws.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "ssh: "+err.Error()),
				time.Now().Add(2*time.Second))
		} else {
			_ = ws.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"),
				time.Now().Add(2*time.Second))
		}
		return
	}

	upToWs := func() error {
		buf := make([]byte, 4096)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				if werr := writeFrame(websocket.BinaryMessage, buf[:n]); werr != nil {
					return werr
				}
			}
			if err != nil {
				return err
			}
		}
	}

	wsToUp := func() error {
		for {
			_ = ws.SetReadDeadline(time.Now().Add(60 * time.Minute))
			_, data, err := ws.ReadMessage()
			if err != nil {
				return err
			}
			if _, err := up.Write(data); err != nil {
				return err
			}
		}
	}

	pingTick := time.NewTicker(30 * time.Second)
	defer pingTick.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-pingTick.C:
				_ = writeFrame(websocket.PingMessage, nil)
			}
		}
	}()

	done := make(chan error, 2)
	go func() { done <- upToWs() }()
	go func() { done <- wsToUp() }()
	err := <-done
	if err != nil && err != io.EOF {
		log.Printf("jess-web bridge: op=%s target=%s err=%v", op.Subject, target, err)
	}
	_ = up.Close()
	_ = ws.Close()
	<-done
}

// emitSessionMeta is the Phase 5e-8 metadata sender. Retries once after
// 500ms if the first fetch misses the freshly-created row (race window
// where controller's INSERT hasn't landed yet — typically <100ms but
// the retry covers cold Postgres / DB latency spikes).
//
// Fails open: any error → send a degraded meta frame with just the
// operator-side fields (target, grant, started_at). The SPA then
// shows "session id: pending" until the next refresh.
func emitSessionMeta(ctx context.Context, writeFrame func(int, []byte) error, grants *grantsClient, op *Operator, target, grant string) {
	startedAt := time.Now().UTC().Format(time.RFC3339)

	// Two attempts: ~50ms (fast path, INSERT usually landed before WS
	// upgrade RTT) and ~500ms (cold path). Total budget ~700ms before
	// giving up.
	var matched *SessionView
	for i, wait := range []time.Duration{50 * time.Millisecond, 500 * time.Millisecond} {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if m := fetchOpenSessionForOperator(ctx, grants, op.Token, target, grant); m != nil {
			matched = m
			break
		}
		if i == 1 {
			log.Printf("jess-web: session_meta fetch missed twice op=%s target=%s grant=%s (degraded frame)", op.Subject, target, grant)
		}
	}

	meta := SessionMeta{
		Type:          "session_meta",
		TargetID:      target,
		GrantID:       grant,
		OperatorEmail: op.Email,
		StartedAt:     startedAt,
	}
	if matched != nil {
		meta.SessionID = matched.ID
		meta.RecordingPath = matched.RecordingPath
		meta.Protocol = matched.Protocol
		meta.ControllerID = matched.ControllerID
	}
	payload, _ := json.Marshal(meta)
	if err := writeFrame(websocket.TextMessage, payload); err != nil {
		log.Printf("jess-web: session_meta write failed: %v", err)
	}
}

// SessionView is the local mirror of admin.SessionView (just the fields
// jess-web cares about for surface). Duplicated here to avoid pulling
// the admin package into jess-web — tightens the dependency arrow.
type SessionView struct {
	ID            string `json:"id"`
	Subject       string `json:"subject"`
	TargetID      string `json:"target_id"`
	GrantID       string `json:"grant_id"`
	Protocol      string `json:"protocol"`
	StartedAt     string `json:"started_at"`
	EndedAt       string `json:"ended_at,omitempty"`
	RecordingPath string `json:"recording_path"`
	ControllerID  string `json:"controller_id"`
	Active        bool   `json:"active"`
}

// fetchOpenSessionForOperator queries the controller admin's /sessions
// endpoint with ?mine=true, filters in-memory to the row matching
// (target, grant) and active=true, returns the newest match.
//
// Why filter client-side: the controller doesn't have a (target, grant)
// query parameter today and adding one for a single use case isn't worth
// the API surface bloat. The mine=true filter already bounds the result
// to the caller's own sessions; iterating 10-50 rows in jess-web is
// cheap.
func fetchOpenSessionForOperator(ctx context.Context, grants *grantsClient, bearer, target, grant string) *SessionView {
	if grants == nil {
		return nil
	}
	body, status, err := grants.adminGet(ctx, bearer, "/sessions?mine=true&limit=20")
	if err != nil || status != http.StatusOK || len(body) == 0 {
		return nil
	}
	var rows []SessionView
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	var newest *SessionView
	for i := range rows {
		r := &rows[i]
		if r.TargetID != target || r.GrantID != grant {
			continue
		}
		if !r.Active {
			// Look for a still-active row only — there could be older
			// closed rows for the same (target,grant) pair if the
			// operator opened/closed repeatedly.
			continue
		}
		if newest == nil || r.StartedAt > newest.StartedAt {
			newest = r
		}
	}
	return newest
}

// jsonString returns a JSON-encoded string literal (including the surrounding
// quotes) for s, so it can be interpolated into a hand-built JSON error frame
// without breaking on quotes/newlines in the error text.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// helpfulWebSocketError surfaces a more descriptive message in the
// terminal for common failure modes.
func helpfulWebSocketError(closeCode int) string {
	switch closeCode {
	case websocket.CloseNormalClosure:
		return "session ended normally"
	case websocket.CloseAbnormalClosure:
		return "controller dropped the brokered session (grant expired? target offline?)"
	case websocket.CloseInternalServerErr:
		return "jess-web internal error — see controller logs"
	default:
		// Trim any leading whitespace / prefixes a future websocket
		// library version might prepend so the unit-test assertion on
		// "code <n>" stays stable.
		return strings.TrimSpace(fmt.Sprintf("session closed with code %d", closeCode))
	}
}
