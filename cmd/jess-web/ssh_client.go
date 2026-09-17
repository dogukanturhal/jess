// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Clientless browser SSH (mirrors the RDP clientless model in ws_rdp.go).
//
// THE BUG this fixes: the worker's SSH record-proxy (internal/sshproxy) is an
// SSH *server* — it authenticates the operator by completing an SSH handshake
// against an SSH certificate signed by the Vault operator SSH CA, then opens a
// session channel + PTY + shell. In the CLI path that handshake is performed by
// the operator's local `ssh` binary (jessctl just exposes a loopback proxy and
// the operator points ssh at it). The browser xterm.js has NO SSH client — the
// old ws.go bridge byte-copied raw frames between the xterm and the controller
// tunnel, so the worker's SSH server saw the xterm's raw bytes (not an SSH
// handshake), hit its 15s handshake deadline, and logged
// "sshproxy: operator handshake: i/o deadline reached" while the browser saw
// only the worker's "SSH-2.0-Go" banner then a 1006 close.
//
// THE FIX: jess-web becomes the SSH *client* on behalf of the browser (exactly
// as it is the RDP client in ws_rdp.go and the DB client in db-console.go):
//
//   1. mint a short-lived operator SSH cert (Vault SSH CA, same mount/role an
//      operator's `jessctl`/Vault flow uses) over a per-session ephemeral key;
//   2. complete the SSH handshake as the client over the controller tunnel;
//   3. open a session channel, request a PTY (term/size from the browser), and
//      start a shell;
//   4. relay PTY stdout/stderr → WS (binary) → xterm, xterm keystrokes (WS) →
//      SSH stdin, and browser resize → SSH window-change.
//
// The worker still runs its MitM and tees terminal output to the WORM bundle —
// this change only supplies the missing SSH-client peer; the recording, grant,
// and authz paths are untouched.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// sshCertConfig holds the per-process Vault SSH-CA config jess-web uses to mint
// an operator SSH cert for each browser session. nil = not configured: the WS
// handler then falls back to the legacy raw byte bridge (dev / pre-Vault), so a
// deploy without the SSH-CA env keeps building and serving.
type sshCertConfig struct {
	vc        *vaultx.Client
	mount     string        // Vault SSH CA mount, e.g. "ssh-client-signer"
	role      string        // sign role, e.g. "ssh-admin"
	principal string        // operator cert principal / SSH login user, e.g. "hexxlock"
	ttl       time.Duration // operator cert TTL (kept short; the worker also bounds it)
}

// newSSHCertConfig builds the SSH-CA mint config from env, or nil if the mount
// is unset. The mount/role MUST be the operator-cert SSH CA whose public key
// the worker carries as JESS_SSH_OPERATOR_CA — otherwise the worker rejects the
// handshake with "operator cert rejected: ... not signed by authority".
//
//	JESS_WEB_SSH_CA_VAULT_MOUNT   Vault SSH CA mount          default "ssh-client-signer"
//	JESS_WEB_SSH_CA_VAULT_ROLE    sign role                   default "ssh-admin"
//	JESS_WEB_SSH_OPERATOR_USER    cert principal / SSH user   default "hexxlock"
//	JESS_WEB_SSH_CERT_TTL         operator cert TTL           default "5m"
//
// Gated on JESS_VAULT_ADDR (same gate as the svc-cert flow) so a Vault-less dev
// build never tries to mint.
func newSSHCertConfig(vc *vaultx.Client) *sshCertConfig {
	if vc == nil {
		return nil
	}
	mount := env("JESS_WEB_SSH_CA_VAULT_MOUNT", "")
	if mount == "" {
		// Default to the operator SSH CA mount only when Vault itself is
		// configured; leaving it unset keeps the legacy bridge for dev.
		if env("JESS_VAULT_ADDR", "") == "" {
			return nil
		}
		mount = "ssh-client-signer"
	}
	return &sshCertConfig{
		vc:        vc,
		mount:     mount,
		role:      env("JESS_WEB_SSH_CA_VAULT_ROLE", "ssh-admin"),
		principal: env("JESS_WEB_SSH_OPERATOR_USER", "hexxlock"),
		ttl:       durationEnv("JESS_WEB_SSH_CERT_TTL", 5*time.Minute),
	}
}

// mintOperatorSSH generates a per-session ephemeral ed25519 key, has Vault sign
// its public half as an operator SSH cert (principal = c.principal), and returns
// a cert-signer ready for ssh.PublicKeys auth. The private key never leaves this
// process and dies with the session — the SSH CA model identical to jessctl.
func (c *sshCertConfig) mintOperatorSSH(ctx context.Context) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh keygen: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ssh signer: %w", err)
	}
	authPub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	certStr, err := c.vc.SignSSHCert(ctx, c.mount, c.role, authPub, []string{c.principal}, c.ttl)
	if err != nil {
		return nil, fmt.Errorf("vault sign operator ssh cert (mount=%s role=%s): %w", c.mount, c.role, err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		return nil, fmt.Errorf("parse vault-signed operator cert: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("vault ssh/sign did not return a certificate")
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("operator cert signer: %w", err)
	}
	return certSigner, nil
}

// resizeMsg is the browser→server control frame (sent as a WebSocket BINARY
// frame; the documented client→server BINARY channel is "resize / future
// control frames"). A magic-prefixed 9-byte frame so it can never collide with
// terminal keystrokes (which arrive as TEXT frames):
//
//	byte 0    : 0x01  (resize opcode)
//	bytes 1-4 : cols  (uint32 big-endian)
//	bytes 5-8 : rows  (uint32 big-endian)
const resizeOpcode = 0x01

// runBrowserSSH performs the full clientless SSH ceremony over `up` (the already-
// dialed controller tunnel, post-OperatorRequest header) and bridges it to the
// browser WebSocket. It returns when either side closes.
//
// `writeFrame` is the same locked WS writer the metadata emitter uses, so the
// PTY byte stream and the session_meta TEXT frame never interleave a partial
// frame. termCols/termRows are the initial terminal size (defaults applied by
// the caller).
func runBrowserSSH(
	ctx context.Context,
	ws *websocket.Conn,
	up net.Conn,
	cert *sshCertConfig,
	writeFrame func(int, []byte) error,
	initialCols, initialRows int,
) error {
	mintCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	signer, err := cert.mintOperatorSSH(mintCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("mint operator ssh cert: %w", err)
	}

	// SSH handshake as the CLIENT against the worker's sshproxy SSH server.
	// HostKeyCallback is permissive here: the worker host key is the broker's
	// own key (the *target* host key is validated by the worker's DialTarget,
	// not by us), the link to the worker is already an mTLS-authenticated
	// controller tunnel, and the operator's identity is bound by the token +
	// grant + the cert principal — not by pinning the broker's ephemeral host
	// key. This matches the CLI e2e doc (operators dial with
	// StrictHostKeyChecking=no through the local proxy).
	clientCfg := &ssh.ClientConfig{
		User:            cert.principal,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // broker host key; identity bound by token+grant+cert over the mTLS controller tunnel
		Timeout:         15 * time.Second,
	}
	_ = up.SetDeadline(time.Now().Add(20 * time.Second)) // bound the handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(up, "jess-worker", clientCfg)
	if err != nil {
		return fmt.Errorf("ssh client handshake: %w", err)
	}
	_ = up.SetDeadline(time.Time{}) // clear; the session itself has no deadline
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session: %w", err)
	}
	defer sess.Close()

	// PTY. xterm.js is a real ANSI terminal — request one so the remote shell
	// emits cursor moves / colours / line editing. modes mirror a sane default
	// interactive PTY.
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if initialCols <= 0 {
		initialCols = 80
	}
	if initialRows <= 0 {
		initialRows = 24
	}
	if err := sess.RequestPty("xterm-256color", initialRows, initialCols, modes); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := sess.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	// PTY output (stdout + stderr) → WS BINARY → xterm. Both streams go to the
	// same terminal, as in a real PTY.
	done := make(chan error, 2)
	pumpOut := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				if werr := writeFrame(websocket.BinaryMessage, buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if rerr != nil {
				done <- rerr
				return
			}
		}
	}
	go pumpOut(stdout)
	go pumpOut(stderr)

	// Browser → SSH. TEXT frames are keystrokes (xterm.onData); BINARY frames
	// are control frames (resize). Closing stdin on read error / WS close ends
	// the remote shell cleanly.
	go func() {
		defer func() { _ = stdin.Close() }()
		for {
			_ = ws.SetReadDeadline(time.Now().Add(60 * time.Minute))
			mt, data, rerr := ws.ReadMessage()
			if rerr != nil {
				done <- rerr
				return
			}
			switch mt {
			case websocket.BinaryMessage:
				if cols, rows, ok := parseResize(data); ok {
					if werr := sess.WindowChange(rows, cols); werr != nil {
						log.Printf("jess-web ssh: window-change failed: %v", werr)
					}
					continue
				}
				// Unknown binary control frame — ignore (forward-compat).
			default: // TextMessage
				if _, werr := stdin.Write(data); werr != nil {
					done <- werr
					return
				}
			}
		}
	}()

	// Wait for the session to finish (shell exit) or the first transport error.
	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()

	var first error
	select {
	case <-ctx.Done():
		first = ctx.Err()
	case first = <-done:
	case first = <-waitErr:
	}
	// Tear everything down so the remaining goroutines unblock.
	_ = sess.Close()
	_ = client.Close()
	_ = up.Close()
	if first == io.EOF || first == nil {
		return nil
	}
	return first
}

// parseResize decodes a browser resize control frame. Returns (cols, rows,
// true) on a well-formed frame, else ok=false (caller ignores).
func parseResize(b []byte) (cols, rows int, ok bool) {
	if len(b) != 9 || b[0] != resizeOpcode {
		return 0, 0, false
	}
	c := binary.BigEndian.Uint32(b[1:5])
	r := binary.BigEndian.Uint32(b[5:9])
	// Sanity-bound: a terminal larger than this is almost certainly a bad
	// frame; clamp rather than honour an absurd window-change.
	if c == 0 || r == 0 || c > 1000 || r > 1000 {
		return 0, 0, false
	}
	return int(c), int(r), true
}

// ensure json import is retained for any future control-frame additions and to
// keep the file's import set stable across edits.
var _ = json.Marshal
