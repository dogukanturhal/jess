// SPDX-License-Identifier: AGPL-3.0-or-later

// Command jess-web is the browser-side access to Jess-brokered sessions
// (ADR 0030 Phase 5e — "build our own Guacamole"). A Go HTTP server
// serving an hxm-designed React SPA, Falcon-ID OIDC sign-in, the
// WebSocket bridge that turns a browser xterm.js into a brokered
// SSH session through the controller, and a thin admin-proxy that
// lets the browser submit JIT grant requests.
//
// Stack
//
//   - Backend: Go, single static binary. Hosts /auth/*, /api/*, /ws/*
//     and the SPA shell at /.
//   - Frontend: React + TypeScript + Vite, bundled to web/dist and
//     embedded via go:embed (Teleport pattern — tier-1 industry
//     standard for browser PAM/session brokers).
//   - Terminal: @xterm/xterm + @xterm/addon-fit, npm-pinned (no CDN).
//
// Phase 5e-3 (this MR) — bundle of three sub-features
//
//   - mTLS service-cert auto-mint from jess-ca Vault PKI mount, presented
//     on every controller-operator-port dial (svc_cert.go). Closes the
//     bearer-only TLS gap left in 5e-2.
//   - Browser grant-request flow: POST /api/requests + GET /api/requests/{id}
//     proxied to controller admin port (grants.go). Operators can ask
//     for JIT access without leaving the browser.
//   - Recording-status indicator surfaced in the session footer (UI in
//     web/src/pages/Session.tsx). Live pulse while the WS is open;
//     "stopped" pill on close.
//
// Phase 5e-2 carried forward
//
//   - Falcon-ID OIDC authorization-code + PKCE sign-in (auth.go).
//   - WebSocket /ws/session bridging xterm.js to the controller's
//     operator port (ws.go).
//   - /api/me operator-identity endpoint.
//
// Scope kept out (Phase 5e-4+)
//
//   - Per-request GET on controller admin port (today /api/requests/{id}
//     returns 501; SPA degrades to "submitted — approver paged").
//   - Recording-path/manifest surfacing through the WS first frame.
//   - Rust IronRDP worker for web-RDP (Phase 5f).
//
// Config via env
//
//	JESS_WEB_ADDR                  HTTP listen addr               default :7102
//	JESS_WEB_TLS_CERT/KEY          optional TLS server cert
//	JESS_WEB_DIAG_ADDR             diagnostics listener           default :7111
//	JESS_OIDC_ISSUER               Falcon-ID issuer URL           default https://id.hexxlock.com
//	JESS_OIDC_CLIENT_ID            OAuth client (svc-jess-web)    required
//	JESS_OIDC_CLIENT_SECRET        Confidential-client secret     optional (public = "")
//	JESS_OIDC_REDIRECT_URL         /auth/callback absolute URL    required (must match registered)
//	JESS_CONTROLLER_OPERATOR_ADDR  Controller operator port       default jess-controller.jess.svc:7101
//	JESS_CONTROLLER_OPERATOR_TLS_CA   Optional CA PEM path for TLS-verify
//	JESS_CONTROLLER_ADMIN_ADDR     Controller admin URL           default https://jess-controller.jess.svc:7103
//	JESS_VAULT_ADDR                Vault address                  optional (gates svc-cert flow)
//	JESS_VAULT_K8S_MOUNT           default "kubernetes"
//	JESS_VAULT_K8S_ROLE            Vault role (e.g. "jess-web")
//	JESS_WEB_SVC_CERT_VAULT_MOUNT  PKI mount                      default "jess-ca"
//	JESS_WEB_SVC_CERT_VAULT_ROLE   PKI sign role                  default "jess-web-svc"
//	JESS_WEB_SVC_CERT_CN           CN for the svc cert            default "jess-web"
//
// Clientless browser SSH — operator SSH cert mint (ssh_client.go). jess-web is
// the SSH client for the browser xterm; it mints a per-session operator SSH
// cert from the operator SSH CA whose public key the worker carries as
// JESS_SSH_OPERATOR_CA. Gated on JESS_VAULT_ADDR (else legacy raw bridge).
//
//	JESS_WEB_SSH_CA_VAULT_MOUNT    Vault SSH CA mount             default "ssh-client-signer"
//	JESS_WEB_SSH_CA_VAULT_ROLE     sign role                     default "ssh-admin"
//	JESS_WEB_SSH_OPERATOR_USER     cert principal / SSH user     default "hexxlock"
//	JESS_WEB_SSH_CERT_TTL          operator cert TTL             default "5m"
//
// RDP live console — credential source (ws_rdp_live.go)
//
//	JESS_RDP_SESSION_BIN           session_live path     default /usr/local/bin/session_live (in-image)
//	JESS_RDP_VAULT_MOUNT           Vault LDAP secrets-engine mount (e.g. "ldap") — enables the
//	                               PRODUCTION per-session credential mint (the DEFAULT when set)
//	JESS_RDP_VAULT_ROLE            shared dynamic role, or unset → per-target role (target ID)
//	JESS_RDP_VAULT_DOMAIN          AD domain stamped onto the NLA credential (RDP_DOMAIN)
//	JESS_RDP_CRED_TTL              session-bind TTL hint (Vault role TTL is authoritative)
//	JESS_RDP_DEV_CREDS=1           DEV-ONLY env credential path (strictly secondary; ignored
//	                               when JESS_RDP_VAULT_MOUNT is set). Needs RDP_USER/RDP_PASS[/RDP_DOMAIN]
package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/dogukanturhal/jess/internal/diag"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/transport"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// staticFS contains the Vite-built SPA bundle. The `all:` prefix is
// required so dot-prefixed files (e.g. .gitkeep) are included — embed
// silently drops them otherwise.
//
//go:embed all:web/dist
var staticFS embed.FS

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("JESS_WEB_ADDR", ":7102")
	diagAddr := env("JESS_WEB_DIAG_ADDR", ":7111")

	dist, err := fs.Sub(staticFS, "web/dist")
	if err != nil {
		log.Fatalf("jess-web: embed: %v", err)
	}

	// --- OIDC + sessions -------------------------------------------------
	sessions := newSessionStore()
	issuer := env("JESS_OIDC_ISSUER", "https://id.hexxlock.com")
	clientID := os.Getenv("JESS_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("JESS_OIDC_CLIENT_SECRET") // may be empty (public client)
	redirectURL := os.Getenv("JESS_OIDC_REDIRECT_URL")
	var auth *authConfig
	if clientID == "" || redirectURL == "" {
		log.Print("WARNING: JESS_OIDC_CLIENT_ID or JESS_OIDC_REDIRECT_URL unset — sign-in disabled (dev only)")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		auth, err = newAuthConfig(ctx, issuer, clientID, clientSecret, redirectURL, sessions)
		cancel()
		if err != nil {
			log.Fatalf("jess-web: oidc init: %v", err)
		}
		log.Printf("jess-web: OIDC issuer=%s client_id=%s redirect=%s", issuer, clientID, redirectURL)
	}

	// --- Controller dial cfg (for the WS bridge) ------------------------
	controllerAddr := env("JESS_CONTROLLER_OPERATOR_ADDR", "jess-controller.jess.svc.cluster.local:7101")
	var ctrlTLS *tls.Config
	if caPath := os.Getenv("JESS_CONTROLLER_OPERATOR_TLS_CA"); caPath != "" {
		serverName := env("JESS_CONTROLLER_OPERATOR_SERVER_NAME", "")
		ctrlTLS, err = transport.LoadClientTLS(caPath, serverName, "", "")
		if err != nil {
			log.Fatalf("jess-web: controller-TLS load: %v", err)
		}
		log.Printf("jess-web: controller dial=%s TLS verify CA=%s server=%s", controllerAddr, caPath, serverName)
	} else {
		log.Printf("jess-web: controller dial=%s PLAINTEXT (set JESS_CONTROLLER_OPERATOR_TLS_CA for TLS)", controllerAddr)
	}

	// --- Vault PKI svc-cert (Phase 5e-3) --------------------------------
	// Optional: only activates when JESS_VAULT_ADDR is set. Until the iac
	// MR lands the jess-web Vault role + jess-ca svc-cert role, this stays
	// dormant — the bearer-only TLS path from 5e-2 is the fallback.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var webRecorder recording.Recorder
	var webRecSpool *recording.SpoolStore // DDIL P3.6 WORM store-and-forward handle (nil when disabled); its reconciler runs under ctx
	var vc *vaultx.Client                 // shared across svc-cert, recorder, and the RDP-live Vault cred mint
	var webSSHCert *sshCertConfig         // operator-SSH-cert minter for the clientless browser SSH bridge (ws.go → ssh_client.go); nil = legacy raw bridge
	if os.Getenv("JESS_VAULT_ADDR") != "" {
		var vErr error
		vc, vErr = newWebVaultClient()
		if vErr != nil {
			log.Fatalf("jess-web: vault client: %v", vErr)
		}
		mintCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		mgr, mErr := newSvcCertManager(
			ctx, vc,
			env("JESS_WEB_SVC_CERT_VAULT_MOUNT", "jess-ca"),
			env("JESS_WEB_SVC_CERT_VAULT_ROLE", "jess-web-svc"),
			env("JESS_WEB_SVC_CERT_CN", "jess-web"),
		)
		cancel()
		_ = mintCtx
		if mErr != nil {
			log.Fatalf("jess-web: svc-cert mint: %v", mErr)
		}
		// Phase 5h-3b: HTTP-proxy recorder. Same Vault client + Transit
		// key as the worker — single signing identity across the audit
		// chain. Returns nil if JESS_REC_S3_ENDPOINT is unset; the
		// /proxy handler 503s in that case rather than recording-less.
		recCtx, recCancel := context.WithTimeout(ctx, 30*time.Second)
		webRecorder, webRecSpool, mErr = recorderFromVault(recCtx, vc)
		recCancel()
		if mErr != nil {
			log.Fatalf("jess-web: WORM recorder init: %v", mErr)
		}
		if webRecorder != nil {
			log.Print("jess-web: WORM recorder ENABLED (MinIO Object-Lock + Vault Transit)")
		}
		if webRecSpool != nil {
			// DDIL P3.6: drain buffered recordings to WORM in the background, bound
			// to the process lifetime. A must-record RDP/browser session whose seal
			// can't reach MinIO is now buffered durably and reconciled on reconnect
			// instead of being lost.
			go webRecSpool.Run(ctx)
			log.Print("jess-web: WORM store-and-forward spool ENABLED (DDIL P3.6 — buffers recordings on MinIO outage, reconciles on reconnect)")
		}
		// Attach to the controller-dial TLS config. If ctrlTLS was nil
		// (no CA path set) we promote to mTLS-with-server-verify-off —
		// not a great posture; loud-warn the operator. Production
		// MUST set JESS_CONTROLLER_OPERATOR_TLS_CA.
		if ctrlTLS == nil {
			log.Print("WARNING: svc-cert configured but JESS_CONTROLLER_OPERATOR_TLS_CA unset — mTLS dial without server-side verification (dev only)")
			ctrlTLS = &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} // #nosec G402 — gated on dev-only env
		}
		ctrlTLS.GetClientCertificate = mgr.certForClient
		log.Print("jess-web: controller dial = mTLS (svc cert presenting on every handshake)")

		// Clientless browser SSH: jess-web mints a short-lived operator SSH
		// cert (Vault SSH CA) per session and acts as the SSH client for the
		// browser xterm (ws.go → ssh_client.go). Without this the browser sends
		// raw bytes to the worker's SSH *server*, which times out the operator
		// handshake — the bug this fixes. Uses the operator SSH CA mount whose
		// public key the worker carries as JESS_SSH_OPERATOR_CA.
		webSSHCert = newSSHCertConfig(vc)
		if webSSHCert != nil {
			log.Printf("jess-web: clientless browser SSH ENABLED (Vault SSH-CA mount=%s role=%s principal=%s ttl=%s)",
				webSSHCert.mount, webSSHCert.role, webSSHCert.principal, webSSHCert.ttl)
		} else {
			log.Print("jess-web: clientless browser SSH NOT configured — falling back to legacy raw byte bridge (set JESS_WEB_SSH_CA_VAULT_MOUNT)")
		}
	}

	// --- Controller admin proxy (grant requests + session_meta) ---------
	// Default to in-cluster headless Service over HTTPS (controller admin
	// port is :7103 per the GitOps repository jess/controller.yaml). For dev
	// without TLS, set JESS_CONTROLLER_ADMIN_ADDR=http://localhost:7103.
	adminURL := env("JESS_CONTROLLER_ADMIN_ADDR", "https://jess-controller.jess.svc.cluster.local:7103")
	grants := newGrantsClient(adminURL, ctrlTLS, sessions)
	log.Printf("jess-web: grants proxy → %s", adminURL)

	// Phase 5e-8: the WS bridge uses the same grants client to fetch the
	// just-created jit_sessions row for the session_meta browser frame.
	connect := &connectConfig{controllerAddr: controllerAddr, tlsCfg: ctrlTLS, sessions: sessions, grants: grants, sshCert: webSSHCert}

	// Browser SQL console (ADR 0049 Phase 2/4): same controller operator-port
	// dial + svc-cert mTLS as the SSH WS bridge, but the relay carries the
	// Postgres/MySQL wire protocol — jess-web is the DB client, the browser only
	// POSTs {sql} and renders {columns, rows}. Server-side policy + WORM query
	// log stay enforced at the worker relay (db-console.go header).
	dbConsole := &dbConsoleConfig{controllerAddr: controllerAddr, tlsCfg: ctrlTLS, sessions: sessions}

	// --- HTTP mux -------------------------------------------------------
	mux := http.NewServeMux()
	if auth != nil {
		mux.HandleFunc("/auth/login", auth.loginHandler)
		mux.HandleFunc("/auth/callback", auth.callbackHandler)
		mux.HandleFunc("/auth/logout", auth.logoutHandler)
		mux.HandleFunc("/api/me", auth.meHandler)
	} else {
		mux.HandleFunc("/auth/login", oidcDisabled)
		mux.HandleFunc("/api/me", oidcDisabled)
	}
	mux.HandleFunc("/api/requests", grants.handleSubmitRequest)
	mux.HandleFunc("/api/requests/", grants.handleGetRequest)
	mux.HandleFunc("/api/my/requests", grants.handleMyRequests)
	mux.HandleFunc("/api/my/sessions", grants.handleMySessions)
	// /api/my/sessions/{id}/recording streams the asciicast bundle for
	// the SPA player. Same auth + owner-gate as the controller admin
	// endpoint underneath.
	mux.HandleFunc("/api/my/sessions/", grants.handleMyRecording)
	// Admin-panel proxies — server-side role gate inside each handler.
	mux.HandleFunc("/api/admin/requests", grants.handleAdminListRequests)
	mux.HandleFunc("/api/admin/requests/", grants.handleAdminRequestAction)
	mux.HandleFunc("/api/admin/sessions", grants.handleAdminListSessions)
	mux.HandleFunc("/api/admin/grants", grants.handleAdminGrants)
	mux.HandleFunc("/api/admin/grants/", grants.handleAdminGrants)
	mux.HandleFunc("/api/admin/audit/export", grants.handleAdminAuditExport)
	mux.HandleFunc("/api/admin/audit/chain/verify", grants.handleAdminAuditChainVerify)
	mux.HandleFunc("/api/admin/rdp-probe", grants.handleAdminRDPProbe)
	mux.HandleFunc("/api/admin/rdp-probe/sweep", grants.handleAdminRDPProbeSweep)
	mux.HandleFunc("/api/admin/catalog", grants.handleAdminCatalog)                       // Phase 7h — unified catalog with source attribution
	mux.HandleFunc("/api/admin/recording-settings", grants.handleAdminRecordingSettings)  // per-target recording override (list)
	mux.HandleFunc("/api/admin/recording-settings/", grants.handleAdminRecordingSettings) // per-target recording override (set/clear)
	mux.HandleFunc("/api/admin/pending", grants.handleAdminPending)                       // ADR 0052 discovery review queue (list)
	mux.HandleFunc("/api/admin/pending/", grants.handleAdminPending)                      // ADR 0052 discovery review queue (approve/reject)
	// Corporate device pre-registration (allowlist) CRUD. The exact import
	// pattern out-specifics the trailing-slash delete subtree, and the bare
	// list pattern out-specifics both — ServeMux longest-match wins.
	mux.HandleFunc("/api/admin/devices/pre-registrations", grants.handleAdminPreRegistrations)
	mux.HandleFunc("/api/admin/devices/pre-registrations/import", grants.handleAdminPreRegistrationsImport)
	mux.HandleFunc("/api/admin/devices/pre-registrations/", grants.handleAdminPreRegistrationDelete)
	// TOFU device auto-enroll review queue.
	mux.HandleFunc("/api/admin/devices/pending", grants.handleAdminPendingDevices)
	mux.HandleFunc("/api/admin/devices/pending/", grants.handleAdminPendingDeviceAction)
	// Enroll-first, approve-later onboarding queue (registry-backed).
	mux.HandleFunc("/api/admin/devices/onboarding", grants.handleAdminOnboardingDevices)
	mux.HandleFunc("/api/admin/devices/onboarding/", grants.handleAdminOnboardingApprove)
	mux.HandleFunc("/api/config", configHandler(loadWebConfig()))
	// Browser SQL console query API — runs one statement through the brokered
	// Postgres/MySQL relay (server-side; the browser never speaks raw wire).
	mux.HandleFunc("/api/db/query", dbConsole.handleQuery)
	mux.HandleFunc("/ws/session", connect.handleSession)
	// Phase 5f-7: WS proxy from SPA to jess-ironrdp-broker for /rdp/:targetId.
	rdpProxy := newRDPProxyConfig(sessions)
	mux.HandleFunc("/ws/rdp", rdpProxy.handleRDPSession)
	// ADR 0051 P2c: in-process Go↔Rust bridge — spawns session_live locally and
	// streams the P2b TLV protocol to the browser canvas (first pixels).
	// PRODUCTION mints the per-session NLA credential from Vault (LDAP secrets
	// engine, audit-bound to the operator sub) when JESS_RDP_VAULT_MOUNT is set;
	// the env path (JESS_RDP_DEV_CREDS) is the strictly-secondary dev fallback.
	// ADR 0051 P4: the SAME signed WORM recorder (MinIO Object-Lock + Vault
	// Transit) records the full decoded RDP stream (jess-rdp-recording-v2) into
	// the audit-archive bucket; nil → Recorded RDP targets are denied fail-closed.
	rdpLive := newRDPLiveConfig(ctx, sessions, grants, webRecorder, vc)
	mux.HandleFunc("/ws/rdp-live", rdpLive.handleRDPLiveSession)
	// EXPERIMENTAL WebTransport (HTTP/3) carrier for the same RDP TLV stream
	// (ADR 0055). OFF unless JESS_RDP_WEBTRANSPORT_ADDR is set (e.g. ":8444").
	// The info endpoint is Talon-fronted (issues a one-time ticket); the QUIC
	// listener is a direct browser→jess-web path. WS stays the default.
	if wtAddr := os.Getenv("JESS_RDP_WEBTRANSPORT_ADDR"); wtAddr != "" {
		wtPublic := envOr(os.Getenv("JESS_RDP_WEBTRANSPORT_PUBLIC"), wtAddr)
		if wt, werr := newWTServer(rdpLive, wtAddr, wtPublic); werr != nil {
			log.Printf("jess-web RDP live: WebTransport disabled (setup failed): %v", werr)
		} else {
			mux.HandleFunc("/api/rdp/webtransport-info", wt.handleInfo)
			go wt.listen()
		}
	}
	// Effective per-target recording decision for the live RDP console's HONEST
	// recording indicator (recording is per-target — admin override beats the
	// catalog default; the prior "always recording" UI affirmation was stale).
	mux.HandleFunc("/api/rdp/recorded", rdpLive.handleRDPRecorded)
	// ADR 0051 P4 replay: owner-scoped list/verify/download of the operator's own
	// jess-rdp-recording-v2 bundles (served directly from the recorder store —
	// live RDP sessions aren't controller jit_sessions rows). 503s when no recorder.
	rdpRecordings := newRDPRecordingsConfig(sessions, webRecorder)
	mux.HandleFunc("/api/rdp/recordings", rdpRecordings.handleRecordings)
	mux.HandleFunc("/api/rdp/recordings/", rdpRecordings.handleRecordings)
	// Phase 5h-3b: HTTP proxy for browser-recorded admin access to
	// in-cluster services (Grafana first; ArgoCD/AlertManager after
	// 5h-3c subpath rewriting lands). 503s when webRecorder is nil
	// (recording is mandatory — see http_proxy.go header).
	httpProxy := newHTTPProxyConfig(webRecorder)
	mux.HandleFunc("/proxy/", httpProxy.handleProxy(sessions))
	// ZTNA device-enrollment bootstrap. Proxied to the controller admin port
	// (self-authenticating via Bearer + witness JWS; no jess-web session).
	// Registered before the SPA catch-all so the not-yet-enrolled device gets
	// the controller's JSON response instead of index.html. Matches the Talon
	// publicPath carve-out on the jess-ops route.
	mux.HandleFunc("/device-cert/attest", grants.handleDeviceCertAttest)
	mux.Handle("/", spaHandler(dist))

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	// Diagnostics on a separate listener so the operator-facing port can
	// be exposed publicly while /metrics + /healthz stay in-cluster only.
	go func() {
		log.Printf("jess-web: diagnostics on %s (/healthz /readyz)", diagAddr)
		if derr := diag.Serve(context.Background(), diagAddr, diag.Handler(nil, readyCheck)); derr != nil {
			log.Printf("diagnostics server: %v", derr)
		}
	}()

	// Periodic session GC — 5min cadence, light.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sessions.gc()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		log.Print("jess-web: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if certPath, keyPath := os.Getenv("JESS_WEB_TLS_CERT"), os.Getenv("JESS_WEB_TLS_KEY"); certPath != "" && keyPath != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		log.Printf("jess-web: HTTPS on %s", addr)
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("jess-web: %v", err)
		}
	} else {
		log.Printf("WARNING: jess-web on %s in PLAINTEXT — set JESS_WEB_TLS_CERT/KEY (dev only)", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("jess-web: %v", err)
		}
	}
}

// spaHandler serves the React SPA with the standard SPA caching split, which
// is what stops operators from seeing a stale bundle after a deploy:
//
//   - /assets/* — Vite emits content-hashed filenames here, so the bytes at a
//     given URL never change. Served `public, max-age=1y, immutable` so the
//     browser keeps them forever without revalidating.
//   - index.html AND the SPA fallback — served `no-cache, no-store,
//     must-revalidate` (see serveSPAShell) so the browser ALWAYS revalidates
//     the shell and immediately picks up the new hashed-asset references after
//     a deploy. No hard refresh required.
//   - Other real top-level static files (favicon.ico / favicon.svg / the PNG
//     icon set / site.webmanifest / robots.txt) — these have STABLE, un-hashed
//     names, so they're served `no-cache` too: the browser revalidates and a
//     re-branded favicon/icon shows up on the next load instead of being
//     pinned to a cached copy.
//
// Any path that doesn't resolve to a real embedded file falls back to the SPA
// shell so client-side routing (e.g. /admin/sessions) survives a hard refresh.
// Security headers apply to BOTH the shell and assets.
func spaHandler(dist fs.FS) http.Handler {
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		clean := path.Clean(r.URL.Path)
		// Content-hashed Vite output → cache forever, never revalidate.
		if strings.HasPrefix(clean, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			files.ServeHTTP(w, r)
			return
		}
		// Any other path that maps to a real embedded file (favicons, icon
		// PNGs, the webmanifest, robots.txt, …) is served directly with a
		// revalidating cache so re-branding lands without a hard refresh.
		// Everything else (app routes) falls through to the SPA shell.
		if clean != "/" && existsInFS(dist, clean) {
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
			return
		}
		serveSPAShell(w, dist)
	})
}

// existsInFS reports whether the cleaned URL path maps to a real (non-dir)
// file in the embedded SPA bundle. Used to distinguish static assets (serve
// the file) from SPA routes (serve index.html).
func existsInFS(dist fs.FS, clean string) bool {
	name := strings.TrimPrefix(clean, "/")
	if name == "" {
		return false
	}
	info, err := fs.Stat(dist, name)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func serveSPAShell(w http.ResponseWriter, dist fs.FS) {
	f, err := dist.Open("index.html")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w,
			`{"error":"jess-web SPA bundle missing — run 'pnpm --dir cmd/jess-web/web install && pnpm --dir cmd/jess-web/web build'"}`)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = io.Copy(w, f)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self'; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src 'self' https://fonts.gstatic.com data:; "+
			"img-src 'self' data:; "+
			"connect-src 'self' ws: wss:; "+
			"frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func oidcDisabled(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"OIDC not configured — set JESS_OIDC_CLIENT_ID + JESS_OIDC_REDIRECT_URL"}`))
}

// readyCheck — true once the listener is up. Phase 5e-4 widens this to
// "controller dial reachable" (skip the dial under cold-start jitter).
func readyCheck(_ context.Context) error { return nil }
