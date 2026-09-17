// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// ws_rdp_live — ADR 0051 P2c. The in-process Go↔Rust bridge WS endpoint that
// drives the real broker.liveRDPEngine (session_live subprocess) and relays the
// finalized P2b streaming TLV protocol to the browser canvas.
//
// This is the "first pixels in the browser" path. It differs from the existing
// /ws/rdp proxy (ws_rdp.go), which forwards to a SEPARATE jess-ironrdp-broker
// service speaking the older 5f-8a JSON-handshake protocol. /ws/rdp-live instead
// spawns session_live LOCALLY via the broker engine seam and speaks the TLV wire
// format end-to-end:
//
//   browser  <─ WS BINARY  [u8 msg_type][payload] (ONE WS frame per TLV) ─>  jess-web
//   jess-web <─ (add/strip the u32 len) ─>  engine client pipe  <─>  session_live
//
// Auth: the SAME real Falcon-ID operator token + grant check as the SSH/DB
// console (operatorFromRequest). target is required; grant is optional and is
// passed through for the controller-side grant assertion when wired.
//
// !!! CREDENTIALS / PRODUCTION BOUNDARY (operator: strict) !!!
//   - PRODUCTION (DEFAULT): the NLA credential is minted PER-SESSION from VAULT
//     (broker.RDPSessionCredBroker over the LDAP secrets engine), audit-bound to
//     the real operator sub + target. No standing credential ever exists; the
//     lease auto-revokes the ephemeral directory account after the session. This
//     is the path taken whenever JESS_RDP_VAULT_MOUNT is configured.
//   - DEV FALLBACK (strictly secondary): if Vault is NOT configured, the env
//     credential path (JESS_RDP_DEV_CREDS=1 + RDP_USER/RDP_PASS/RDP_DOMAIN) is
//     used. It is clearly dev-only and never the default when Vault is present.
//   - The minted RDPSecret is handed to the engine, which passes it to the
//     subprocess via ENV (never argv) and never logs the password.
//
// GRANT ASSERTION: the `grant` query param is threaded into the mint + session
// open (operator sub + target + grant) so the controller can authorize the
// access. The controller-side verify endpoint remainder is noted inline.
//
// FAIL-CLOSED: if NEITHER Vault nor dev creds are configured, or session_live is
// missing (JESS_RDP_SESSION_BIN unset / not executable), the handler synthesises
// a TLV error and closes — it never opens an un-engineered or un-credentialed path.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/dogukanturhal/jess/internal/broker"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/rdphosttrust"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// rdpLiveConfig holds the per-process live-bridge config: the operator cookie
// session store, the engine (session_live spawner), the catalog resolver (to
// turn a target ID into a host:port), and the dev-gated env credential.
type rdpLiveConfig struct {
	sessions *sessionStore
	grants   *grantsClient // controller catalog lookup for the target address
	engine   rdpLiveEngine

	// vaultCreds is the PRODUCTION per-session NLA credential mint (Vault LDAP
	// secrets engine, audit-bound to the operator sub). When non-nil it is the
	// DEFAULT credential path; the dev env path below is used only when this is
	// nil (Vault unconfigured).
	vaultCreds rdpSessionCredMinter

	// devCreds is the dev-only env-sourced NLA credential, or zero when the
	// dev-creds gate is off. It is STRICTLY SECONDARY — used only when vaultCreds
	// is nil. With neither configured the handler fails closed.
	devCreds   broker.RDPSecret
	devEnabled bool

	// recorder is the signed WORM recorder for the full decoded RDP stream (ADR
	// 0051 P4, jess-rdp-recording-v2). nil when JESS_REC_S3_ENDPOINT is unset:
	// the handler then records nothing AND denies any Recorded target
	// (fail-closed — a must-record session with no recorder is an audit gap).
	recorder recording.Recorder

	// credReady (optional) waits for a freshly-minted Vault ephemeral AD account
	// to propagate before it's used for the RDP logon (AD eventual consistency —
	// see rdp_cred_readiness.go). nil = gate disabled (no behaviour change).
	credReady *credReadiness

	// offlineReg (optional, DDIL P3.8) opts a resolved target into pre-positioned
	// offline credentials when it is eligible (opted-in + non-Tier-0). nil when
	// JESS_OFFLINE_CREDS_ENABLED is off. Registration is what lets the background
	// refresh loop cache a credential usable if Vault later goes unreachable.
	offlineReg targetRegistrar
}

// targetRegistrar opts a resolved target into offline-credential pre-positioning.
// Satisfied by *broker.OfflineRDPCredBroker (which enforces the Tier-0 hard-
// exclusion un-overridably).
type targetRegistrar interface {
	RegisterTarget(*catalog.Target)
}

// rdpSessionCredMinter is the subset of broker.RDPSessionCredBroker the handler
// needs — the per-session, operator-sub-bound Vault mint. A package-local alias
// keeps the seam injectable in tests.
type rdpSessionCredMinter interface {
	IssueForOperator(ctx context.Context, targetID, operatorSub string) (broker.RDPSecret, time.Duration, error)
}

// rdpLiveEngine is the subset of broker.rdpEngine the handler needs. It is
// satisfied by broker's live engine via the exported adapter
// broker.NewLiveRDPEngineForWeb. The optional rec (may be nil) is the
// per-session v2 recorder the engine tees the full decoded stream into.
type rdpLiveEngine interface {
	OpenSession(ctx context.Context, target *catalog.Target, sec broker.RDPSecret, client io.ReadWriteCloser, rec *recording.RDPStreamWriter, desktop broker.RDPDesktopSize) (broker.RDPLiveSession, error)
}

// newRDPLiveConfig builds the live-bridge config from the environment. The
// credential source is selected by precedence:
//
//  1. PRODUCTION (default): if vc is non-nil AND JESS_RDP_VAULT_MOUNT is set,
//     the per-session Vault LDAP-secrets-engine mint is the credential path.
//  2. DEV FALLBACK (only when Vault is absent): JESS_RDP_DEV_CREDS=1 +
//     RDP_USER/RDP_PASS sources the credential from the env.
//  3. Neither → the handler fails closed.
//
// The recorder (may be nil) is the v2 WORM stream recorder; nil → Recorded RDP
// targets are denied fail-closed. vc may be nil (Vault not enabled); the dev
// path then governs. Wiring the Vault mint NEVER falls back to env creds
// silently — if the mount is set but the broker can't be built, that is a fatal
// startup error.
func newRDPLiveConfig(ctx context.Context, sessions *sessionStore, grants *grantsClient, recorder recording.Recorder, vc *vaultx.Client) *rdpLiveConfig {
	// P2.4 — AD-CS RDP host-trust (ADR 0047 → 0062). Load the trust anchors +
	// enforcement mode from the JESS_RDP_TLS_* env. A malformed anchor/CRL PEM is
	// a FATAL startup error (never silently accept-all). With nothing configured
	// the validator is inert: non-opt-in RDP targets keep legacy TOFU while any
	// target marked rdp_tls_ca_signed still fails closed (it needs anchors).
	hostTrust, err := rdphosttrust.LoadFromEnv()
	if err != nil {
		log.Fatalf("jess-web RDP live: host-trust config invalid: %v", err)
	}
	switch {
	case hostTrust.AllowTOFU():
		log.Printf("jess-web RDP live: AD-CS host-trust TOFU ESCAPE HATCH armed (%s) — RDP host certs NOT validated (migration only)", rdphosttrust.EnvTOFU)
	case hostTrust.Enforced():
		log.Printf("jess-web RDP live: AD-CS host-trust ENFORCED for ALL RDP targets (anchors=%s)", envOr(hostTrust.AnchorPath(), "<inline>"))
	case hostTrust.Configured():
		log.Printf("jess-web RDP live: AD-CS host-trust configured, per-target opt-in only (rdp_tls_ca_signed); global enforce OFF")
	default:
		log.Printf("jess-web RDP live: AD-CS host-trust NOT configured (set %s) — RDP host trust is legacy TOFU except targets marked rdp_tls_ca_signed (which then fail closed)", rdphosttrust.EnvCAPEM)
	}

	c := &rdpLiveConfig{
		sessions: sessions,
		grants:   grants,
		engine:   broker.NewLiveRDPEngineForWebWithTrust(os.Getenv("JESS_RDP_SESSION_BIN"), hostTrust),
		recorder: recorder,
	}
	if recorder != nil {
		log.Print("jess-web RDP live: WORM stream recorder ENABLED (jess-rdp-recording-v2)")
	} else {
		log.Print("jess-web RDP live: no WORM recorder configured — Recorded RDP targets will be DENIED (fail-closed)")
	}

	// 1. Production: Vault per-session mint (the default when configured).
	if mount := os.Getenv("JESS_RDP_VAULT_MOUNT"); mount != "" {
		if vc == nil {
			log.Fatalf("jess-web RDP live: JESS_RDP_VAULT_MOUNT=%s set but no Vault client (set JESS_VAULT_ADDR) — refusing to fall back to dev creds", mount)
		}
		vb, err := broker.NewVaultRDPCredBroker(vc, broker.VaultRDPCredsConfig{
			Mount:  mount,
			Role:   os.Getenv("JESS_RDP_VAULT_ROLE"), // "" → per-target role (target ID)
			Domain: os.Getenv("JESS_RDP_VAULT_DOMAIN"),
			TTL:    durationEnv("JESS_RDP_CRED_TTL", 0),
		})
		if err != nil {
			log.Fatalf("jess-web RDP live: build Vault RDP credential broker: %v", err)
		}
		c.vaultCreds = vb
		log.Printf("jess-web RDP live: PRODUCTION credentials = Vault LDAP secrets engine (mount=%s role=%s domain=%s) — per-session, operator-sub-bound",
			mount, envOr(os.Getenv("JESS_RDP_VAULT_ROLE"), "<per-target>"), os.Getenv("JESS_RDP_VAULT_DOMAIN"))

		// DDIL P3.8 (ADR 0062): wrap the Vault mint with pre-positioned offline
		// credentials so an opted-in, non-Tier-0 target survives a Vault outage on
		// a governed short-TTL cached credential. OFF by default; the wrapper is a
		// transparent pass-through while Vault is reachable.
		if offlineCredsEnabled() {
			wrapped, oerr := newOfflineRDPCreds(ctx, vb, vc)
			if oerr != nil {
				log.Fatalf("jess-web RDP live: build offline-credentials manager: %v", oerr)
			}
			c.vaultCreds = wrapped
			c.offlineReg = wrapped
		}

		// Optional AD-propagation wait for the ephemeral mint (only meaningful on
		// the Vault path — dev creds are static). Off unless the readiness URL is set.
		if c.credReady = newCredReadiness(); c.credReady != nil {
			log.Printf("jess-web RDP live: credential-readiness gate ENABLED (ldap=%s timeout=%s) — waits for AD propagation before the RDP logon",
				c.credReady.ldapURL, c.credReady.timeout)
		}
		return c // Vault is authoritative; do not also wire dev creds.
	}

	// 2. Dev fallback (strictly secondary — only reached when Vault is absent).
	if os.Getenv("JESS_RDP_DEV_CREDS") == "1" {
		user, pass := os.Getenv("RDP_USER"), os.Getenv("RDP_PASS")
		if user != "" && pass != "" {
			c.devEnabled = true
			c.devCreds = broker.RDPSecret{
				Kind:     broker.RDPSecretADCredential,
				Username: user,
				Password: pass,
				Domain:   os.Getenv("RDP_DOMAIN"),
			}
			log.Printf("jess-web RDP live: DEV credentials enabled from env (user=%s domain=%s) — NOT for production; set JESS_RDP_VAULT_MOUNT to use Vault", user, os.Getenv("RDP_DOMAIN"))
		} else {
			log.Printf("jess-web RDP live: JESS_RDP_DEV_CREDS=1 but RDP_USER/RDP_PASS unset — handler fails closed")
		}
	} else {
		log.Printf("jess-web RDP live: no credential source configured (set JESS_RDP_VAULT_MOUNT for prod, or JESS_RDP_DEV_CREDS=1 for dev) — handler fails closed")
	}
	return c
}

// envOr returns v, or def when v is empty — for log lines only.
func envOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// handleRDPLiveSession upgrades the WS, resolves the target, opens the engine
// session, and relays the TLV stream both ways.
func (c *rdpLiveConfig) handleRDPLiveSession(w http.ResponseWriter, r *http.Request) {
	op, err := c.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	// The session id backs the continuous grant-watch's token refresh (the
	// watch outlives this request and must present a non-expired id_token each
	// tick). operatorFromRequest already validated the cookie, so it is present.
	sid := ""
	if ck, cerr := r.Cookie(sessionCookie); cerr == nil {
		sid = ck.Value
	}
	targetID := r.URL.Query().Get("target")
	if targetID == "" {
		writeJSONErr(w, http.StatusBadRequest, "target query param required")
		return
	}
	grant := r.URL.Query().Get("grant")
	// QUALITY item #3 — resolution match. The browser may request a desktop
	// size matching its viewport via ?w=&h= so the session renders close to
	// 1:1 (no CSS upscaling blur). Parsing failures / absent params yield a
	// zero size, which the engine + Rust side treat as "use the default".
	desktop := parseRDPDesktopSize(r.URL.Query().Get("w"), r.URL.Query().Get("h"))

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("jess-web RDP live: client upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	// Fail-closed if NO credential source is configured (neither Vault nor dev).
	if c.vaultCreds == nil && !c.devEnabled {
		log.Print("jess-web RDP live: DENY — no credential source configured (set JESS_RDP_VAULT_MOUNT for prod, or JESS_RDP_DEV_CREDS=1 + RDP_USER/RDP_PASS for dev)")
		writeWSTLVError(ws, clientErrNotConfigured)
		return
	}

	// Resolve the target address from the controller catalog. Error hygiene
	// (ASVS L2 V16): the operator sees a stable message; the controller/store
	// detail stays in the server log only.
	target, err := c.resolveTarget(r.Context(), op.Token, targetID)
	if err != nil {
		log.Printf("jess-web RDP live: resolve target FAILED op=%s target=%s: %v", op.Subject, targetID, err)
		writeWSTLVError(ws, clientErrTargetResolve)
		return
	}
	if target.Protocol != catalog.ProtoRDP {
		log.Printf("jess-web RDP live: target %s is not RDP (protocol=%s) op=%s", targetID, target.Protocol, op.Subject)
		writeWSTLVError(ws, clientErrNotRDP)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// ASVS L2 V8 — HARD grant gate (parity with the SSH/DB data-plane worker's
	// AssertActiveID). Re-check the authorizing grant against the controller's
	// store-backed /grants/assert BEFORE opening a WORM bundle or minting a
	// credential; deny (close the WS) on any non-active/absent grant. Fail-
	// closed: a transient controller/store error also denies the open.
	if gerr := c.assertGrantActive(ctx, op.Token, grant, target.ID); gerr != nil {
		log.Printf("jess-web RDP live: grant gate DENIED op=%s target=%s grant=%q: %v", op.Subject, targetID, grant, gerr)
		writeWSTLVError(ws, clientErrNotAuthorized)
		return
	}

	// ADR 0051 P4: open the full-stream WORM recorder FIRST, bound to the REAL
	// operator identity (op.Subject — never the broker/service identity).
	// Fail-closed: a Recorded target whose recorder can't open is DENIED here
	// (mirrors the broker Dial path, rdp.go) — before we mint a credential we'd
	// never use. A non-recorded target proceeds without a recorder.
	sessionID := newRDPLiveSessionID(op.Subject, targetID)
	rec, rerr := c.openRecorder(ctx, op.Subject, grant, target, sessionID)
	if rerr != nil {
		log.Printf("jess-web RDP live: recorder open DENIED op=%s target=%s: %v", op.Subject, targetID, rerr)
		writeWSTLVError(ws, clientErrRecording)
		return
	}

	// Select the credential source. PRODUCTION (default): mint per-session from
	// Vault, audit-bound to the real operator sub + target. DEV fallback: the
	// env credential (only when Vault is unconfigured). The grant is already
	// hard-asserted above, so the mint is only reached for an authorized open.
	sec, credSource, err := c.credentialFor(ctx, target, op.Subject)
	if err != nil {
		// Seal the just-opened bundle so the recorded attempt isn't left unsealed.
		if rec != nil {
			_ = rec.CloseEvent()
			_ = rec.Close()
		}
		// Error hygiene (V16): the Vault/mint detail stays server-side only.
		log.Printf("jess-web RDP live: credential mint failed op=%s target=%s grant=%s: %v", op.Subject, targetID, grant, err)
		writeWSTLVError(ws, clientErrCredential)
		return
	}

	log.Printf("jess-web RDP live: session open op=%s target=%s addr=%s grant=%s cred=%s recorded=%v", op.Subject, targetID, target.Address, grant, credSource, target.Recorded)

	// The engine's client side is a pipe carrying the FULL framed TLV stream.
	// The WS bridge adds/strips the u32 length so the browser sees one WS binary
	// frame per message.
	clientConn, browserIn, engineOut := newEnginePipe()

	sess, err := c.engine.OpenSession(ctx, target, sec, clientConn, rec, desktop)
	if err != nil {
		// The engine never started, so its Close (which seals the bundle) won't
		// run — seal here so we don't leak an unsealed half-open bundle, and so a
		// Recorded target's session_start→failure is still committed to WORM.
		if rec != nil {
			_ = rec.CloseEvent()
			_ = rec.Close()
		}
		log.Printf("jess-web RDP live: engine open FAILED op=%s target=%s: %v", op.Subject, targetID, err)
		writeWSTLVError(ws, clientErrSessionOpen)
		return
	}
	// sess.Close SEALS the v2 bundle (and tears the subprocess down). A seal
	// failure is an audit gap — surface it (the session is already over by then,
	// so we log loudly rather than denying a finished session).
	defer func() {
		if cerr := sess.Close(); cerr != nil {
			log.Printf("jess-web RDP live: WORM SEAL FAILURE op=%s target=%s session=%s: %v", op.Subject, targetID, sessionID, cerr)
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run() }()

	// ASVS L2 V8 — continuous grant re-check (parity with the controller's
	// tunnel-session grant-watch): a grant revoked mid-session tears this live
	// RDP session down within one interval, not just future opens. revoke()
	// SIGKILLs the subprocess (cancel), unblocks the engine→browser bridge pump
	// (closing engineOut — a blocked io.Pipe read returns on Close), then closes
	// the WS to unblock the browser→engine pump. Teardown is abrupt (no graceful
	// reason frame — the bridge owns the WS write mutex), matching how the
	// controller drops a revoked tunnel session.
	revoke := func(reason string) {
		log.Printf("jess-web RDP live: tearing down session op=%s target=%s grant=%s reason=%s", op.Subject, targetID, grant, reason)
		cancel()
		_ = engineOut.Close()
		_ = ws.Close()
	}
	go c.watchGrantLive(ctx, sid, op.Subject, target.ID, grant, revoke)

	bridgeWSToEngine(ctx, cancel, ws, browserIn, engineOut)

	// Surface a session-level error (nonzero subprocess exit) to the browser.
	select {
	case err := <-runDone:
		if err != nil {
			log.Printf("jess-web RDP live: session ended with error op=%s target=%s: %v", op.Subject, targetID, err)
		}
	default:
	}
	log.Printf("jess-web RDP live: session closed op=%s target=%s session=%s", op.Subject, targetID, sessionID)
}

// openRecorder opens a per-session jess-rdp-recording-v2 bundle bound to the real
// operator identity. Returns:
//
//   - (nil, nil)    when the target is NOT recorded (effective recording off) —
//     proceed un-recorded, regardless of whether a recorder is configured;
//   - (writer, nil) when the target IS recorded and the bundle opened;
//   - (nil, err)    fail-closed: the target requires recording but the recorder
//     is unconfigured or the bundle failed to open. The caller DENIES.
func (c *rdpLiveConfig) openRecorder(ctx context.Context, subject, grantID string, target *catalog.Target, sessionID string) (*recording.RDPStreamWriter, error) {
	// Honour the EFFECTIVE per-target recording decision (admin override or
	// catalog default), already resolved into target.Recorded by resolveTarget.
	// A target that is NOT recorded is NEVER recorded — even when a WORM recorder
	// IS configured. Previously this gate only existed in the no-recorder branch,
	// so with a recorder live (prod) every RDP session recorded regardless of the
	// admin catalog toggle. This is the bug behind "toggle off but still recording".
	if !target.Recorded {
		return nil, nil
	}
	// target.Recorded == true → recording is REQUIRED. No recorder → fail-closed
	// (the caller DENIES the session rather than running a must-record session
	// with no audit trail).
	if c.recorder == nil {
		return nil, fmt.Errorf("no WORM recorder configured for a must-record target")
	}
	meta := recording.Meta{
		SessionID: sessionID,
		Subject:   subject, // REAL Falcon-ID operator sub — bound into the signed manifest
		GrantID:   grantID,
		TargetID:  target.ID,
		Protocol:  string(catalog.ProtoRDP),
		Format:    recording.FormatRDPStreamV2,
		StartedAt: time.Now(),
	}
	bw, err := c.recorder.Open(ctx, meta)
	if err != nil {
		// Only reachable for a must-record target (the !Recorded case returned
		// above) — fail-closed so the caller DENIES rather than running a
		// must-record session whose WORM bundle never opened.
		return nil, fmt.Errorf("open WORM bundle: %w", err)
	}
	return recording.NewRDPStreamWriter(bw, recording.RDPStreamMeta{
		Subject:   subject,
		Target:    target.ID,
		SessionID: sessionID,
	}), nil
}

// newRDPLiveSessionID is the WORM bundle storage key for a live RDP session. It
// matches the controller-issued jit_sessions id shape used by the other brokers
// (a stable, unique-per-session id). Until the controller grant assertion wires
// the canonical id into this handler (the production deploy step), we derive a
// unique id from the operator + target + wall clock so the bundle key is stable
// and greppable.
func newRDPLiveSessionID(subject, targetID string) string {
	return fmt.Sprintf("rdp-%s-%s-%d", sanitizeKeySeg(subject), sanitizeKeySeg(targetID), time.Now().UnixMilli())
}

// sanitizeKeySeg makes a string safe as one path segment of an object-store key
// (no slashes / spaces that would split the key or confuse the bundle layout).
func sanitizeKeySeg(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}

// credentialFor selects + produces the per-session NLA credential, returning it
// plus a short label describing the source (for the audit log line).
//
// The authorizing grant is HARD-ASSERTED by the CALLER (the WS handler's
// assertGrantActive; the WT info endpoint) BEFORE this is reached — see the V8
// grant gate — so this is only entered for an already-authorized open and no
// longer performs the (previously soft, Vault-only) grant check itself.
//
// PRODUCTION (default): when the Vault session-cred broker is wired, it mints a
// short-lived AD credential from the LDAP secrets engine, audit-bound to the
// real operator sub + target. DEV fallback: when Vault is NOT wired but dev
// creds are enabled, the env credential is used. Fails closed if neither is
// available.
func (c *rdpLiveConfig) credentialFor(ctx context.Context, target *catalog.Target, operatorSub string) (broker.RDPSecret, string, error) {
	if c.vaultCreds != nil {
		// DDIL P3.8: opt an eligible (opted-in, non-Tier-0) target into
		// pre-positioning. Idempotent + Tier-0-safe; no-op when offline creds are
		// disabled. This must happen while Vault is (normally) reachable — the
		// operator initiating a session is exactly that moment.
		if c.offlineReg != nil {
			c.offlineReg.RegisterTarget(target)
		}
		sec, ttl, err := c.vaultCreds.IssueForOperator(ctx, target.ID, operatorSub)
		if err != nil {
			return broker.RDPSecret{}, "", err
		}
		// Wait for the freshly-minted ephemeral AD account to propagate before it
		// reaches the Windows logon (AD is eventually consistent; HashiCorp's
		// remedy is to wait+retry the new password). Advisory + fail-open: a
		// timeout/unreachable LDAP never denies the already-authorised session.
		if c.credReady != nil {
			c.credReady.wait(ctx, sec)
		}
		return sec, "vault(ttl=" + ttl.String() + ")", nil
	}
	if c.devEnabled {
		return c.devCreds, "dev-env", nil
	}
	return broker.RDPSecret{}, "", errNoCredSource
}

// grantCheckResult classifies the controller's answer to an active-grant
// re-check. It drives BOTH the initial hard-gate (open only on grantActive) and
// the continuous watch (kill on grantRevoked; tolerate grantCheckUnavailable up
// to a small budget).
type grantCheckResult int

const (
	grantActive           grantCheckResult = iota // 200 — active AND belongs to caller
	grantRevoked                                  // permanent — revoked/expired/wrong-target/foreign-subject/token-invalid
	grantCheckUnavailable                         // transient — controller unreachable / grant store blip
)

// checkGrantActive re-checks (grant, target) against the controller's
// store-backed GET /grants/assert — the SAME jit.GrantStore.AssertActiveID the
// data-plane worker runs, exposed over the admin port. The controller ALSO
// binds the grant to the bearer's subject, so a 200 means "active AND owned by
// this operator". bearer must be a FRESH operator id_token (the watch refreshes
// it each tick). This is the authoritative gate — NOT the old log-only stub.
func (c *rdpLiveConfig) checkGrantActive(ctx context.Context, bearer, grant, targetID string) grantCheckResult {
	q := url.Values{}
	q.Set("grant", grant)
	q.Set("target", targetID)
	_, status, err := c.grants.adminGet(ctx, bearer, "/grants/assert?"+q.Encode())
	if err != nil {
		return grantCheckUnavailable // transport failure — controller unreachable
	}
	switch status {
	case http.StatusOK:
		return grantActive
	case http.StatusNotFound, http.StatusForbidden, http.StatusUnauthorized, http.StatusBadRequest:
		// 404 no active grant · 403 not this subject · 401 token rejected ·
		// 400 malformed — all definitive "not authorized to proceed".
		return grantRevoked
	default:
		// 503 grant-store blip / 5xx / anything else — transient. The initial
		// open fails closed on this; the watch tolerates it up to its budget.
		return grantCheckUnavailable
	}
}

// assertGrantActive is the HARD grant gate for a live RDP session open (WS
// handler + WT info endpoint). It requires a named grant and confirms — against
// the controller's store-backed re-check — that the grant is ACTIVE and belongs
// to this operator BEFORE any WORM bundle opens or credential is minted. Fail-
// closed: a transient controller/store error denies the open (the operator
// retries) rather than opening an un-reauthorized session. This is the parity
// with the SSH/DB worker's independent AssertActiveID.
func (c *rdpLiveConfig) assertGrantActive(ctx context.Context, bearer, grant, targetID string) error {
	if grant == "" {
		return errGrantRequired
	}
	switch c.checkGrantActive(ctx, bearer, grant, targetID) {
	case grantActive:
		return nil
	case grantRevoked:
		return errGrantNotActive
	default:
		return errGrantCheckUnavailable
	}
}

// rdpGrantWatchInterval is the live-RDP grant-watch tick cadence. It reuses the
// controller's JESS_GRANT_WATCH_INTERVAL_SECONDS knob (default 10s, bounded
// [1,300]) so the in-process RDP re-check and the controller's tunnel-session
// watch share one cadence.
func rdpGrantWatchInterval() time.Duration {
	const defaultSec = 10
	v := os.Getenv("JESS_GRANT_WATCH_INTERVAL_SECONDS")
	if v == "" {
		return defaultSec * time.Second
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 300 {
		return defaultSec * time.Second
	}
	return time.Duration(n) * time.Second
}

// watchGrantLive is the RDP-live equivalent of the controller's continuous
// grant-watch (internal/spine/controller.go watchGrant). It re-checks the
// authorizing grant on an interval and TEARS THE SESSION DOWN when the grant is
// revoked/expired — so a CAEP/JIT revocation kills a LIVE RDP session within
// one interval, not just future opens. Each tick it re-resolves a FRESH
// operator token from the session (id_tokens are ~1h; RDP sessions can run
// longer), and a lapsed session (refresh failed / 8h ceiling) is itself a
// teardown trigger (continuous authentication). Transient check failures are
// tolerated up to a small budget so a controller blip doesn't drop a live
// session; a definitive revocation kills immediately. revoke() performs the
// teardown (caller-supplied, since WS and WT tear down differently).
func (c *rdpLiveConfig) watchGrantLive(ctx context.Context, sid, subject, targetID, grant string, revoke func(reason string)) {
	tick := time.NewTicker(rdpGrantWatchInterval())
	defer tick.Stop()
	const maxTransient = 3
	transient := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			op, err := c.sessions.operatorByID(ctx, sid)
			if err != nil {
				// Session lapsed / refresh failed → operator no longer
				// authenticated → end the session (continuous auth).
				revoke("session expired")
				return
			}
			switch c.checkGrantActive(ctx, op.Token, grant, targetID) {
			case grantActive:
				transient = 0
			case grantRevoked:
				log.Printf("jess-web RDP live: grant-watch REVOKED op=%s target=%s grant=%s — terminating session", subject, targetID, grant)
				revoke("access revoked: grant no longer active")
				return
			default:
				transient++
				log.Printf("jess-web RDP live: grant-watch transient check failure %d/%d op=%s target=%s grant=%s", transient, maxTransient, subject, targetID, grant)
				if transient >= maxTransient {
					log.Printf("jess-web RDP live: grant-watch fail-closed after %d consecutive failures op=%s target=%s grant=%s — terminating", maxTransient, subject, targetID, grant)
					revoke("grant re-check unavailable (fail-closed)")
					return
				}
			}
		}
	}
}

// resolveTarget looks the target up in the controller catalog and returns its
// address + protocol. Uses the operator's bearer so it respects controller authz.
func (c *rdpLiveConfig) resolveTarget(ctx context.Context, bearer, targetID string) (*catalog.Target, error) {
	body, status, err := c.grants.adminGet(ctx, bearer, "/admin/catalog")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errResolveStatus(status)
	}
	// The catalog payload is an array of targets (admin/catalog). Decode just
	// the fields we need (incl. `recorded` — the GitOps catalog DEFAULT).
	type catRow struct {
		ID             string `json:"id"`
		Address        string `json:"address"`
		Protocol       string `json:"protocol"`
		Recorded       bool   `json:"recorded"`
		RDPTLSCASigned bool   `json:"rdp_tls_ca_signed"` // P2.4 per-target AD-CS host-trust opt-in
	}
	var rows []catRow
	if err := json.Unmarshal(body, &rows); err != nil {
		// Some controller versions wrap the array in {"targets":[...]}.
		var wrap struct {
			Targets []catRow `json:"targets"`
		}
		if err2 := json.Unmarshal(body, &wrap); err2 != nil {
			return nil, err
		}
		rows = wrap.Targets
	}
	for _, t := range rows {
		if t.ID == targetID {
			target := &catalog.Target{ID: t.ID, Address: t.Address, Protocol: catalog.Protocol(t.Protocol), Recorded: t.Recorded, RDPTLSCASigned: t.RDPTLSCASigned}
			// catRow.Recorded is the GitOps catalog DEFAULT. The live RDP path is
			// in-process — it does NOT go through the controller session-open, so
			// (unlike SSH/DB) it must resolve the EFFECTIVE recording decision
			// itself: the per-target admin override beats the catalog default. This
			// mirrors the controller's resolveEffectiveRecorded. Without it, the
			// admin "recording off" toggle in the catalog was silently ignored and
			// every RDP session recorded.
			c.applyEffectiveRecorded(ctx, bearer, target)
			return target, nil
		}
	}
	return nil, errTargetNotFound(targetID)
}

// applyEffectiveRecorded overrides target.Recorded in place with the EFFECTIVE
// recording decision from the controller's per-target admin override store
// (GET /admin/recording-settings returns `recorded` already merged: override if
// present, else the catalog default). Fails OPEN to the catalog default already
// on the target on any error (call failure / 503 when no override store is wired
// in dev / decode error) — matching the controller's fail-open semantics so an
// override-store blip never silently changes the broker's recording behaviour.
func (c *rdpLiveConfig) applyEffectiveRecorded(ctx context.Context, bearer string, target *catalog.Target) {
	body, status, err := c.grants.adminGet(ctx, bearer, "/admin/recording-settings")
	if err != nil || status != http.StatusOK {
		return // keep the catalog default already set on target.Recorded
	}
	var rows []struct {
		TargetID string `json:"target_id"`
		Recorded bool   `json:"recorded"` // EFFECTIVE (override-or-default)
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return
	}
	for _, row := range rows {
		if row.TargetID == target.ID {
			target.Recorded = row.Recorded
			return
		}
	}
}

// handleRDPRecorded answers GET /api/rdp/recorded?target=<id> with the EFFECTIVE
// recording decision for a target, so the live RDP console can show an HONEST
// recording indicator (recording is per-target now — the prior "always
// recording" UI affirmation was a stale substrate invariant). Same auth + target
// resolution as the session itself, so a live session and this answer agree.
func (c *rdpLiveConfig) handleRDPRecorded(w http.ResponseWriter, r *http.Request) {
	op, err := c.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	targetID := r.URL.Query().Get("target")
	if targetID == "" {
		writeJSONErr(w, http.StatusBadRequest, "target query param required")
		return
	}
	target, err := c.resolveTarget(r.Context(), op.Token, targetID)
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, "resolve target: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc, _ := json.Marshal(map[string]any{"target": target.ID, "recorded": target.Recorded})
	_, _ = w.Write(enc)
}

// --- the engine-side pipe + the WS↔engine TLV bridge ----------------------

// enginePipe is the operator-side io.ReadWriteCloser handed to the engine. The
// engine READS operator input from it (the bridge writes framed client TLVs in)
// and WRITES server frames to it (the bridge reads framed server TLVs out).
type enginePipe struct {
	in  *io.PipeReader // engine reads operator input here
	out *io.PipeWriter // engine writes server frames here
}

func (p *enginePipe) Read(b []byte) (int, error)  { return p.in.Read(b) }
func (p *enginePipe) Write(b []byte) (int, error) { return p.out.Write(b) }
func (p *enginePipe) Close() error {
	_ = p.in.Close()
	return p.out.Close()
}

// newEnginePipe returns the engine client conn, the writer the bridge uses to
// feed operator input INTO the engine (browserIn), and the reader the bridge
// uses to pull server frames OUT of the engine (engineOut).
func newEnginePipe() (client io.ReadWriteCloser, browserIn *io.PipeWriter, engineOut *io.PipeReader) {
	inR, inW := io.Pipe()   // browser → engine stdin
	outR, outW := io.Pipe() // engine stdout → browser
	return &enginePipe{in: inR, out: outW}, inW, outR
}

// bridgeWSToEngine pumps the two TLV legs between the browser WS and the engine
// pipe, translating the framing:
//
//	browser→engine: read a WS BINARY frame [u8 type][payload], PREPEND the u32
//	                total_len, write the full [u32 len][type][payload] to the
//	                engine (browserIn).
//	engine→browser: read a full [u32 len][type][payload] TLV from the engine
//	                (engineOut), STRIP the u32 len, send [type][payload] as one
//	                WS BINARY frame.
func bridgeWSToEngine(ctx context.Context, cancel context.CancelFunc, ws *websocket.Conn, browserIn *io.PipeWriter, engineOut *io.PipeReader) {
	var writeMu sync.Mutex
	writeWS := func(b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return ws.WriteMessage(websocket.BinaryMessage, b)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// engine → browser
	go func() {
		defer wg.Done()
		defer cancel()
		defer engineOut.Close()
		var lp [4]byte
		for {
			if _, err := io.ReadFull(engineOut, lp[:]); err != nil {
				return // engine closed stdout (CLOSE / exit)
			}
			n := binary.BigEndian.Uint32(lp[:])
			if n == 0 || int(n) > maxLiveTLV {
				log.Printf("jess-web RDP live: engine sent bad TLV len %d", n)
				return
			}
			body := make([]byte, n) // [u8 type][payload] — exactly the WS frame
			if _, err := io.ReadFull(engineOut, body); err != nil {
				return
			}
			if err := writeWS(body); err != nil {
				return
			}
		}
	}()

	// browser → engine
	go func() {
		defer wg.Done()
		defer cancel()
		defer browserIn.Close()
		inputN := 0
		for {
			_ = ws.SetReadDeadline(time.Now().Add(60 * time.Minute))
			mt, payload, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage || len(payload) == 0 {
				continue // ignore text / control / empty frames
			}
			if len(payload) > maxLiveTLV {
				log.Printf("jess-web RDP live: browser sent oversized input frame (%d bytes) — dropping", len(payload))
				continue
			}
			// DIAGNOSTIC: confirm operator input actually reaches the bridge.
			// type 1=MOUSE, 2=KEY. Bounded so mouse-move doesn't spam the log.
			inputN++
			if inputN <= 60 {
				log.Printf("jess-web RDP live: browser input #%d type=%d len=%d", inputN, payload[0], len(payload))
			}
			var lp [4]byte
			binary.BigEndian.PutUint32(lp[:], uint32(len(payload)))
			if _, err := browserIn.Write(lp[:]); err != nil {
				return
			}
			if _, err := browserIn.Write(payload); err != nil {
				return
			}
		}
	}()

	// Keepalive ping so an idle desktop doesn't drop the WS.
	pingTick := time.NewTicker(30 * time.Second)
	defer pingTick.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-pingTick.C:
				writeMu.Lock()
				_ = ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
				writeMu.Unlock()
			}
		}
	}()

	wg.Wait()
}

// parseRDPDesktopSize turns the optional ?w=&h= query params into an
// RDPDesktopSize (quality item #3 — resolution match). Unparseable, non-
// positive, or absent values yield a zero on that axis, which the engine omits
// from the subprocess env so session_live keeps its default resolution. The
// authoritative clamp to a sane range lives on the Rust side
// (desktop_size_from_request); this is just a permissive pass-through of the
// operator's request.
func parseRDPDesktopSize(wStr, hStr string) broker.RDPDesktopSize {
	parse := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return 0
		}
		return n
	}
	return broker.RDPDesktopSize{Width: parse(wStr), Height: parse(hStr)}
}

// maxLiveTLV caps a single TLV body (type+payload) the bridge will relay in
// either direction — a defence against a corrupt length from either side. A
// full-desktop FRAME PNG is comfortably under 16 MiB.
const maxLiveTLV = 16 * 1024 * 1024

// writeWSTLVError sends a synthetic TLV-shaped error the canvas can render, then
// closes the WS. It uses a reserved msg_type (0xFF) carrying a UTF-8 message so
// the browser can distinguish it from DESKTOP_SIZE/FRAME/CLOSE without parsing
// PNG bytes.
func writeWSTLVError(ws *websocket.Conn, msg string) {
	frame := append([]byte{liveMsgError}, []byte(msg)...)
	_ = ws.WriteMessage(websocket.BinaryMessage, frame)
	_ = ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseInternalServerErr, msg))
}

// liveMsgError is a jess-web-synthesised error message type, OUTSIDE the Rust
// protocol's 1/2/3 server types so it never collides with a real frame.
const liveMsgError uint8 = 0xFF

// Stable, non-leaking client-facing messages for the live-RDP error frame
// (ASVS L2 V16 error hygiene). The canvas renders these verbatim; the full
// internal detail (Vault mint errors, controller/store text, engine/subprocess
// failures) is logged SERVER-SIDE only and never crosses to the browser. Shared
// by the WS bridge (ws_rdp_live.go) and the WebTransport bridge (wt_rdp_live.go)
// so both carriers classify failures identically.
const (
	clientErrNotConfigured = "rdp live bridge not configured"
	clientErrTargetResolve = "cannot resolve target"
	clientErrNotRDP        = "target is not an RDP target"
	clientErrNotAuthorized = "access not authorized for this target"
	clientErrRecording     = "session recording required but unavailable"
	clientErrCredential    = "could not establish session credential"
	clientErrSessionOpen   = "could not start remote session"
)

// credential-source + grant errors. These are server-side sentinels (they gate
// the flow + are logged); the operator only ever sees the stable clientErr*
// message the handler maps them to.
var (
	errNoCredSource          = errStr("no RDP credential source configured (fail-closed)")
	errGrantRequired         = errStr("a grant id is required for a production RDP session (pass ?grant=<id>)")
	errGrantNotActive        = errStr("no active grant authorizes this target for the operator")
	errGrantCheckUnavailable = errStr("grant re-check unavailable (fail-closed)")
)

type errStr string

func (e errStr) Error() string { return string(e) }

// small typed errors for resolveTarget.
type resolveStatusErr int

func (e resolveStatusErr) Error() string {
	return "controller catalog returned status " + http.StatusText(int(e))
}
func errResolveStatus(s int) error { return resolveStatusErr(s) }

type targetNotFoundErr string

func (e targetNotFoundErr) Error() string { return "target not found in catalog: " + string(e) }
func errTargetNotFound(id string) error   { return targetNotFoundErr(id) }
