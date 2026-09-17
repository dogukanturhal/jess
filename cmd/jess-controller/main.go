// SPDX-License-Identifier: AGPL-3.0-or-later

// Command jess-controller is the Jess control plane (ADR 0030 Phase 5a): it
// accepts outbound-dialed workers (mTLS), authorizes operator requests against
// the PDP + JIT gate, and bridges operators to brokered worker sessions.
//
// Config via env:
//
//	JESS_WORKER_ADDR    listen addr for workers (mTLS)        default :7100
//	JESS_OPERATOR_ADDR  listen addr for operators             default :7101
//	JESS_TLS_CERT/KEY/CA  PEM paths for the worker-facing mTLS (file-PEM path)
//	JESS_TARGETS        path to a JSON array of targets       (optional)
//
// Worker-facing mTLS has two paths, selected by the JESS_SPIRE_SVID dual-auth
// flag (default OFF = legacy file-PEM mTLS above):
//
//	JESS_SPIRE_SVID       "1"/"true" to prefer SPIRE X.509-SVID mTLS  default off
//	JESS_SPIRE_SOCKET     SPIRE Agent Workload API address   default unix:///spiffe-workload-api/spire-agent.sock
//	JESS_SPIRE_TRUST_DOMAIN  SPIFFE trust domain             default prod.hexxlock
//	JESS_SPIRE_WORKER_ID  worker SPIFFE ID the controller pins (AuthorizeID)
//	                      default spiffe://prod.hexxlock/ns/jess/sa/jess/worker
//
// The SVID path activates ONLY when SPIRE is deployed (a Workload API socket is
// present) AND JESS_SPIRE_SVID is on. With the flag off, or when SPIRE isn't
// reachable, the controller stays on the file-PEM path — it never hard-fails
// because SPIRE is down. Retires ADR-0038's deferred plan (2026-07-19 SPIFFE/
// SPIRE identity foundation design).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dogukanturhal/jess/internal/admin"
	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/caep"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/devicecrl"
	"github.com/dogukanturhal/jess/internal/devicepolicy"
	"github.com/dogukanturhal/jess/internal/diag"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/lifecycle/pending"
	"github.com/dogukanturhal/jess/internal/metrics"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/spine"
	"github.com/dogukanturhal/jess/internal/stepup"
	"github.com/dogukanturhal/jess/internal/transport"
	"github.com/dogukanturhal/jess/internal/tunnel"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean env var (strconv.ParseBool: 1/t/true/0/f/false, ...),
// returning def when unset or unparseable. Used for the JESS_SPIRE_SVID gate.
func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// splitAndTrim splits a comma-separated list, trimming whitespace and dropping
// empty entries. Used for multi-value env vars (e.g. accepted token audiences).
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// peerSPIFFEIDFn / peerCNFn derive the worker identity from the verified peer
// cert after the mTLS handshake (SPIFFE ID for the SPIFFE path; CommonName for
// the file-cert dev path).
func peerSPIFFEIDFn(c net.Conn) (string, error) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("worker conn is not TLS")
	}
	if err := tc.Handshake(); err != nil {
		return "", err
	}
	return transport.PeerSPIFFEID(tc)
}

func peerCNFn(c net.Conn) (string, error) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("worker conn is not TLS")
	}
	if err := tc.Handshake(); err != nil {
		return "", err
	}
	return transport.PeerCommonName(tc)
}

func main() {
	workerAddr := env("JESS_WORKER_ADDR", ":7100")
	operatorAddr := env("JESS_OPERATOR_ADDR", ":7101")
	// Worker-facing mTLS is dual-auth: SPIRE X.509-SVID when JESS_SPIRE_SVID is
	// on AND a SPIRE Workload API socket is present, else the legacy file-PEM
	// path (the default; also the graceful fallback when SPIRE isn't reachable).
	// idFn derives the worker identity from the verified peer certificate — its
	// SPIFFE ID (URI SAN) on the SVID path, its CommonName on the file path.
	var (
		srvCfg *tls.Config
		idFn   func(net.Conn) (string, error)
		err    error
	)
	if envBool("JESS_SPIRE_SVID", false) {
		trustDomain := env("JESS_SPIRE_TRUST_DOMAIN", transport.DefaultSpireTrustDomain)
		workerID := env("JESS_SPIRE_WORKER_ID", transport.DefaultWorkerSPIFFEID)
		// Pin the peer to the worker's exact SPIFFE ID (AuthorizeID). A bad ID
		// here is a config typo (surfaced now), not a SPIRE outage.
		authz, aerr := transport.AuthorizeSPIFFEID(workerID)
		if aerr != nil {
			log.Fatalf("jess-controller: JESS_SPIRE_WORKER_ID=%q invalid: %v", workerID, aerr)
		}
		socket := env("JESS_SPIRE_SOCKET", transport.DefaultSpireSocket)
		src, active, serr := transport.AcquireSVIDSource(context.Background(), true, socket, transport.DefaultSVIDDialTimeout)
		if serr != nil {
			log.Fatalf("jess-controller: SPIRE SVID source: %v", serr)
		}
		if active {
			defer src.Close()
			srvCfg = transport.SVIDServerConfig(src, authz)
			idFn = peerSPIFFEIDFn
			log.Printf("jess-controller: worker-facing mTLS = SPIRE X.509-SVID (trust-domain=%s, authorized worker=%s, socket=%s)", trustDomain, workerID, socket)
		}
		// active == false: AcquireSVIDSource already logged the fallback reason
		// (SPIRE not deployed / not ready). Fall through to the file-PEM path.
	}
	if srvCfg == nil {
		certFile, keyFile, caFile := os.Getenv("JESS_TLS_CERT"), os.Getenv("JESS_TLS_KEY"), os.Getenv("JESS_TLS_CA")
		if certFile == "" || keyFile == "" || caFile == "" {
			log.Fatal("set JESS_SPIRE_SVID=1 (with SPIRE deployed), or JESS_TLS_CERT/KEY/CA (worker-facing mTLS)")
		}
		if srvCfg, err = transport.LoadServerConfig(certFile, keyFile, caFile); err != nil {
			log.Fatalf("server mTLS: %v", err)
		}
		idFn = peerCNFn
	}

	var targets []*catalog.Target
	if p := os.Getenv("JESS_TARGETS"); p != "" {
		if targets, err = catalog.LoadFile(p); err != nil {
			log.Fatalf("targets: %v", err)
		}
	} else {
		log.Print("warning: JESS_TARGETS unset — empty catalog")
	}

	// Operator-token verification against Falcon-ID (OIDC). Identity (subject +
	// roles) is derived ONLY from the verified token.
	issuer := env("JESS_OIDC_ISSUER", "https://id.hexxlock.com")
	clientID := os.Getenv("JESS_OIDC_CLIENT_ID")
	if clientID == "" {
		log.Fatal("JESS_OIDC_CLIENT_ID is required (the Jess Falcon-ID OAuth client = token audience)")
	}
	// Operator tokens reach the controller from more than one first-party jess
	// OAuth client: svc-jess (jessctl CLI id/access token) and svc-jess-web
	// (the browser SPA, whose id_token carries aud=svc-jess-web). Accept any
	// audience in the allowlist (membership). JESS_OIDC_CLIENT_ID stays the
	// primary; JESS_OIDC_ACCEPTED_AUDIENCES (comma-separated) overrides the
	// full set, defaulting to "<clientID>,svc-jess-web". This is an explicit
	// allowlist of jess operator clients — deliberately NOT the broad platform-
	// API audience, because the admin chain is the critical ADR-0030 surface.
	acceptedAuds := splitAndTrim(env("JESS_OIDC_ACCEPTED_AUDIENCES", clientID+",svc-jess-web"))
	verifier, verr := pdp.NewFalconIDVerifierMulti(context.Background(), issuer, acceptedAuds)
	if verr != nil {
		log.Fatalf("oidc verifier: %v", verr)
	}
	log.Printf("jess-controller: operator token audiences accepted = %v (issuer=%s)", acceptedAuds, issuer)

	// Durable, shared grant store: Postgres in production (so >1 controller +
	// the workers see the same grants), in-memory only for dev.
	var grants jit.GrantStore
	if dsn := os.Getenv("JESS_DB_DSN"); dsn != "" {
		ps, perr := jit.NewPostgresStore(context.Background(), dsn)
		if perr != nil {
			log.Fatalf("postgres grant store: %v", perr)
		}
		if perr := ps.Migrate(context.Background()); perr != nil {
			log.Fatalf("grant store migrate: %v", perr)
		}
		grants = ps
	} else {
		log.Print("warning: JESS_DB_DSN unset — using in-memory grants (NOT for production/HA)")
		grants = jit.NewMemoryBroker()
	}

	m := metrics.New()
	// Phase 7c: build the catalog via buildCatalog so the JESS_K8S_DISCOVERY
	// opt-in path can layer the Kubernetes Node watch + Aggregator. Default
	// (env unset) falls back to the same MemoryCatalog the pre-7c controller
	// used — zero behavior change.
	auditSink := audit.NewJSONSink(os.Stdout)
	cat, adminTargetsProv, catShutdown := buildCatalog(context.Background(), targets, auditSink)
	defer catShutdown()

	// Phase E — JessPendingTarget reconciler (opt-in via JESS_PENDING_RECONCILER_ENABLED).
	// Watches PendingTarget CRs; runs the Rego policy at
	// JESS_PENDING_REGO_FILE; promotes (creates JessTarget CR + deletes
	// Pending) or rejects (writes status.policy_reason).
	pendingShutdown := startPendingReconciler(auditSink)
	defer pendingShutdown()
	ctrl := &spine.Controller{
		Pool:     tunnel.NewYamuxPool(),
		Cat:      cat,
		JIT:      grants,
		PDP:      pdp.RoleAuthorizer{},
		Verifier: verifier,
		Audit:    auditSink,
		Metrics:  m,
		// Phase 5e-6: wire the SessionStore for per-session persistence
		// when the grant store implements it (Postgres + Memory both do).
		// Type-assert on the interface so the spine doesn't depend on the
		// concrete grant-store impl. The controller's spine code is
		// nil-safe — if SessionStore is nil (a custom GrantStore that
		// doesn't implement it), the spine just skips the row write.
		ControllerID: env("HOSTNAME", ""),
	}
	if ss, ok := grants.(jit.SessionStore); ok {
		ctrl.Sessions = ss
	}
	// Per-target admin recording override (runtime-override-on-GitOps-
	// default). Wired when the grant store implements
	// jit.RecordingOverrideStore (Postgres + Memory both do); session-open
	// then resolves the effective recorded value (override beats catalog
	// default) and propagates it to the worker. Nil = catalog default
	// only (a custom GrantStore that doesn't implement the interface).
	if ro, ok := grants.(jit.RecordingOverrideStore); ok {
		ctrl.RecordingOverrides = ro
	}

	// Admin-direct-connect: when set, an OperatorRequest from a caller
	// holding this role bypasses the JIT request/grant queue — controller
	// auto-mints a self-approved grant inline.
	//
	// Step-up gate (REQUIRED for the feature to activate): caller's
	// verified token amr claim must contain at least one of the values
	// in JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR (comma-separated). Empty
	// list = feature gated open (no admin-direct-connect at all).
	// Production tier-1 default: "mfa,otp,totp,hwk,webauthn".
	ctrl.AdminAutoGrantRole = env("JESS_ADMIN_DIRECT_CONNECT_ROLE", "")
	// Gap audit #3 — phishing-resistant-only mode. NIST SP 800-63B-4
	// §3.2.5 (Final, 2025-07-31) recognises only two phishing-resistant
	// authn methods: channel binding (PIV / CAC client-auth TLS) AND
	// verifier name binding (WebAuthn / FIDO2 DNS-bound). OTP +
	// out-of-band are explicitly EXCLUDED. Setting this flag drops
	// any amr value not in {hwk, webauthn, piv, cac} from the
	// require-amr allowlist + denies tokens that carry only excluded
	// amrs even if they happen to satisfy the literal CSV list.
	// Required for AAL2/AAL3 alignment per the gap audit.
	phishingResistantOnly := env("JESS_ADMIN_DIRECT_CONNECT_PHISHING_RESISTANT", "") == "true"
	ctrl.AdminAutoGrantPhishingResistantOnly = phishingResistantOnly
	if amrCSV := env("JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR", ""); amrCSV != "" {
		for _, a := range strings.Split(amrCSV, ",") {
			v := strings.TrimSpace(a)
			if v == "" {
				continue
			}
			if phishingResistantOnly && !isPhishingResistantAMR(v) {
				log.Printf("jess-controller: dropping non-phishing-resistant amr=%q from allowlist (JESS_ADMIN_DIRECT_CONNECT_PHISHING_RESISTANT=true; NIST SP 800-63B-4 §3.2.5)", v)
				continue
			}
			ctrl.AdminAutoGrantRequireAMR = append(ctrl.AdminAutoGrantRequireAMR, v)
		}
	}
	// Direct-connect TTL env (gap audit follow-up — previously hard-
	// coded 1h via spine.adminAutoGrantTTL()). Now operator-tunable
	// per the platform's AAL bound (NIST: 12h SHALL for AAL3 reauth
	// ceiling; 30m default for jess matches conservative tier-1
	// break-glass posture).
	if v := env("JESS_ADMIN_DIRECT_CONNECT_TTL", ""); v != "" {
		if d, derr := time.ParseDuration(v); derr == nil && d > 0 {
			ctrl.AdminAutoGrantTTL = d
		} else {
			log.Printf("jess-controller: invalid JESS_ADMIN_DIRECT_CONNECT_TTL=%q (parse=%v) — defaulting to 1h", v, derr)
		}
	}
	// Gap audit #6 — AAL3 inactivity-timeout. NIST SP 800-63B-4 says
	// SHOULD ≤15 minutes; 900s is the recommended baseline. Zero
	// (default) disables the check entirely. Worker-side touch via
	// SessionActivityStore.TouchSessionActivity is independent — when
	// idle limit is set but the SessionStore doesn't implement
	// SessionActivityStore, the watcher skips the idle check.
	if v := env("JESS_SESSION_IDLE_TIMEOUT", ""); v != "" {
		if d, derr := time.ParseDuration(v); derr == nil && d > 0 {
			ctrl.SessionIdleTimeout = d
			log.Printf("jess-controller: AAL3 inactivity-timeout ENABLED (idle > %s = kill)", d)
		} else {
			log.Printf("jess-controller: invalid JESS_SESSION_IDLE_TIMEOUT=%q (parse=%v) — feature disabled", v, derr)
		}
	}
	if ctrl.AdminAutoGrantRole != "" && len(ctrl.AdminAutoGrantRequireAMR) > 0 {
		log.Printf("jess-controller: admin-direct-connect ENABLED role=%s require-amr=%v phishing-resistant-only=%v auto-grant TTL=%s",
			ctrl.AdminAutoGrantRole, ctrl.AdminAutoGrantRequireAMR, phishingResistantOnly, ctrl.AdminAutoGrantTTLOrDefault())
	} else if ctrl.AdminAutoGrantRole != "" {
		log.Printf("jess-controller: admin-direct-connect role=%s set BUT require-amr empty — feature INERT (set JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR)",
			ctrl.AdminAutoGrantRole)
	}
	// P2.5 — per-session MFA step-up floor (ADR 0037). Per-target tiers live in
	// the catalog (RequireSessionMFA); this env sets a fleet-wide MINIMUM applied
	// to any target that leaves its tier unset. A target's explicit stronger tier
	// still wins. Invalid value ⇒ fatal (a mis-set security floor must be loud).
	if v := env("JESS_STEP_UP_DEFAULT_POLICY", ""); v != "" {
		pol, perr := stepup.Parse(v)
		if perr != nil {
			log.Fatalf("jess-controller: invalid JESS_STEP_UP_DEFAULT_POLICY=%q: %v", v, perr)
		}
		ctrl.DefaultStepUpPolicy = pol
		if pol != stepup.PolicyNone {
			log.Printf("jess-controller: per-session MFA step-up floor ENABLED (default policy=%s applied to targets with no explicit tier; ADR 0037)", pol)
		}
	}
	m.RegisterWorkerGauge(func() float64 { return float64(len(ctrl.Pool.Workers())) })

	// Phase 5h-6 — CAEP subscriber. Long-lived SSE client to
	// Falcon-ID's /api/v1/cae/events stream; on session_revoked /
	// password_changed / mfa_revoked / role_revoked /
	// credential_compromised it terminates every active grant held
	// by the affected subject through GrantRevoker. Gated on the
	// endpoint + token-file env so a controller without CAEP wiring
	// (dev/test) compiles unchanged.
	if endpoint := env("JESS_CAEP_ENDPOINT_URL", ""); endpoint != "" {
		tokenFile := env("JESS_CAEP_TOKEN_FILE", "")
		if tokenFile == "" {
			log.Fatal("jess-controller: JESS_CAEP_ENDPOINT_URL set but JESS_CAEP_TOKEN_FILE empty — refusing to start unauthenticated CAEP subscriber")
		}
		revoker, ok := grants.(caep.GrantRevoker)
		if !ok {
			log.Fatalf("jess-controller: CAEP requires a GrantStore implementing RevokeBySubject (current store: %T)", grants)
		}
		// ASVS L2 V10 — SSF 1.0 §4.1.6 anti-spoofing is now FAIL-CLOSED by
		// default: a CAEP receiver that accepts SETs without validating the
		// issuer will act on a spoofed session_revoked/credential_compromised
		// event (revoking grants) OR, worse, silently ignore attacker-omitted
		// iss. So an enabled subscriber MUST declare the expected issuer.
		// Mirrors the JESS_CAEP_TOKEN_FILE fail-closed above. The explicit
		// dev/legacy escape hatch (JESS_CAEP_ALLOW_ANY_ISSUER=1) leaves the
		// check disabled — loudly — for a stream that doesn't yet stamp iss.
		expectedIssuer := env("JESS_CAEP_EXPECTED_ISSUER", "")
		if expectedIssuer == "" {
			if env("JESS_CAEP_ALLOW_ANY_ISSUER", "") != "1" {
				log.Fatal("jess-controller: JESS_CAEP_ENDPOINT_URL set but JESS_CAEP_EXPECTED_ISSUER empty — refusing to start CAEP subscriber without SET issuer validation (SSF 1.0 §4.1.6 anti-spoofing). Set JESS_CAEP_EXPECTED_ISSUER=<Falcon-ID OIDC issuer URL>, or JESS_CAEP_ALLOW_ANY_ISSUER=1 to explicitly disable the check (dev/legacy only).")
			}
			log.Print("jess-controller: WARNING — CAEP SET issuer validation DISABLED via JESS_CAEP_ALLOW_ANY_ISSUER=1 (SSF 1.0 §4.1.6 anti-spoofing OFF); every SET is accepted regardless of iss. Set JESS_CAEP_EXPECTED_ISSUER for production.")
		}
		subscriber := &caep.Subscriber{
			EndpointURL: endpoint,
			Token:       caep.FileTokenSource{Path: tokenFile},
			Revoker:     revoker,
			Metrics:     m,
			Audit:       caepAuditAdapter{sink: ctrl.Audit},
			// SSF 1.0 §4.1.6 — anti-spoofing: receiver MUST validate that the
			// SET's iss matches the Stream Configuration. Required by default
			// (fail-closed above); empty ONLY under the explicit
			// JESS_CAEP_ALLOW_ANY_ISSUER=1 dev/legacy opt-out.
			ExpectedIssuer: expectedIssuer,
		}
		go subscriber.Run(context.Background())
		log.Printf("jess-controller: CAEP subscriber STARTED endpoint=%s token-file=%s expected-iss=%q",
			endpoint, tokenFile, subscriber.ExpectedIssuer)
	}

	// Diagnostics: /metrics, /healthz, /readyz (readiness = grant store reachable).
	diagAddr := env("JESS_DIAG_ADDR", ":7109")
	ready := func(rctx context.Context) error {
		if p, ok := grants.(interface{ Ping(context.Context) error }); ok {
			return p.Ping(rctx)
		}
		return nil
	}
	go func() {
		log.Printf("jess-controller: diagnostics on %s (/metrics /healthz /readyz)", diagAddr)
		if derr := diag.Serve(context.Background(), diagAddr, diag.Handler(m.Handler(), ready)); derr != nil {
			log.Printf("diagnostics server: %v", derr)
		}
	}()

	// ADR 0048 — device-cert silent renewal. Dedicated plain-HTTP listener:
	// Envoy terminates the agent's device-cert mTLS + forwards XFCC; Linkerd
	// secures the Envoy→here hop. SEPARATE from the Talon-fronted mTLS admin
	// port (attest). Gated by JESS_DEVICE_RENEW_ENABLED (default off).
	if renewH, ok := buildDeviceRenewHandler(http.NotFoundHandler()); ok {
		renewAddr := env("JESS_DEVICE_RENEW_ADDR", ":7110")
		go func() {
			srv := &http.Server{Addr: renewAddr, Handler: renewH, ReadHeaderTimeout: 5 * time.Second}
			log.Printf("jess-controller: device-renew (Envoy XFCC) on %s", renewAddr)
			log.Fatalf("device-renew server: %v", srv.ListenAndServe())
		}()
	}

	workerL, err := tls.Listen("tcp", workerAddr, srvCfg)
	if err != nil {
		log.Fatalf("worker listener: %v", err)
	}
	operatorL, err := net.Listen("tcp", operatorAddr)
	if err != nil {
		log.Fatalf("operator listener: %v", err)
	}
	// Operator port carries the Falcon-ID bearer token. Wrap it in TLS so the
	// token never transits in cleartext. JESS_OPERATOR_TLS_CA (optional) also
	// requires + verifies operator client certs (mTLS, device binding).
	//
	// PKI Phase 3: when JESS_OPERATOR_CA_VAULT_MOUNT is also set, the Vault
	// PKI CA is appended to the trust pool so PKI-signed operator certs
	// validate alongside the file-mounted legacy CA. Both old + new operator
	// certs are accepted throughout the migration window.
	var opCfg *tls.Config
	var crlCache *admin.CRLCache // Phase 4 full — set when PKI signer is wired below
	if cert, key := os.Getenv("JESS_OPERATOR_TLS_CERT"), os.Getenv("JESS_OPERATOR_TLS_KEY"); cert != "" && key != "" {
		var oerr error
		opCfg, oerr = transport.LoadServerTLS(cert, key, os.Getenv("JESS_OPERATOR_TLS_CA"))
		if oerr != nil {
			log.Fatalf("operator TLS: %v", oerr)
		}
		if pkiMount := os.Getenv("JESS_OPERATOR_CA_VAULT_MOUNT"); pkiMount != "" {
			vc, vErr := newControllerVaultClient()
			if vErr != nil {
				log.Fatalf("PKI trust-bundle Vault client: %v", vErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			pkiCAPem, perr := vc.ReadRawPEM(ctx, "/v1/"+strings.Trim(pkiMount, "/")+"/ca/pem")
			cancel()
			if perr != nil {
				log.Fatalf("PKI trust-bundle fetch (mount=%s): %v", pkiMount, perr)
			}
			if len(pkiCAPem) == 0 {
				log.Fatalf("PKI trust-bundle fetch (mount=%s) returned empty PEM", pkiMount)
			}
			if aerr := transport.AppendClientCAs(opCfg, pkiCAPem); aerr != nil {
				log.Fatalf("PKI trust-bundle append: %v", aerr)
			}
			log.Printf("jess-controller: appended Vault PKI CA from %s/ca/pem to operator-port trust pool (%d bytes)", pkiMount, len(pkiCAPem))

			// Phase 4 full — wire CRL enforcement on the operator-port +
			// admin-port mTLS layer. Background refresher polls
			// /v1/<mount>/crl/pem every CRLRefreshInterval; TLS handshake
			// rejects any client cert whose serial appears on the cached
			// CRL. Fail-open until first successful fetch (acceptable
			// initial window) per "soft-fail" pattern (Chrome/Firefox/
			// OpenSSL all do this). Combined with the 8h cert TTL, worst-
			// case revocation latency is min(refreshInterval, cert remaining
			// TTL); typical is sub-5min.
			crlCache = admin.NewCRLCache(admin.NewVaultCRLSource(vc, pkiMount), admin.DefaultCRLRefreshInterval, 0 /* no hard-fail */, m)
			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			crlCache.Start(ctx2)
			cancel2()
			opCfg.VerifyPeerCertificate = crlCache.VerifyPeerCertificate
			log.Printf("jess-controller: CRL enforcement enabled on operator port (poll=%s, mount=%s/crl/pem)", admin.DefaultCRLRefreshInterval, pkiMount)
		}
		operatorL = tls.NewListener(operatorL, opCfg)
		log.Printf("jess-controller: operator port TLS enabled (mTLS=%v)", os.Getenv("JESS_OPERATOR_TLS_CA") != "" || os.Getenv("JESS_OPERATOR_CA_VAULT_MOUNT") != "")
	} else {
		log.Print("WARNING: operator port is PLAINTEXT — set JESS_OPERATOR_TLS_CERT/KEY so the bearer token is not sent in clear (dev only)")
	}

	// Admin port — POST/GET/DELETE /grants. Same Falcon-ID verifier as the
	// operator path; gated on platform_admin role. Empty JESS_ADMIN_ADDR
	// disables the admin server (legacy psql workflow stays usable).
	// Reuses the operator-port TLS files so operators connect with the same
	// cert/CA they already have; tells callers to set JESS_OPERATOR_TLS_*
	// before turning the admin port on. Plaintext fallback is intentional
	// for dev-only setups (the warning is loud).
	if adminAddr := env("JESS_ADMIN_ADDR", ""); adminAddr != "" {
		ps, ok := grants.(admin.Store)
		if !ok {
			log.Printf("WARNING: JESS_ADMIN_ADDR set but grant store does not implement admin.Store — admin server NOT started")
		} else {
			role := env("JESS_ADMIN_ROLE", "platform_admin")
			base := admin.New(ps, verifier, role)

			// WORM-audit base admin mutations (e.g. the corp-asset approval on
			// /devices/onboarding/{uuid}/approve) onto the same tamper-evident
			// hash-chain sink the rest of the broker emits to.
			base = base.WithAuditSink(auditSink)

			// TOFU auto-enroll review queue — ONE store shared by the device-attest
			// handler (records would-be-CORP non-corp-asset devices into it) and the
			// admin /devices/pending routes (list/approve/reject). In-memory; approving
			// a row writes durably to Falcon-ID via BulkPreRegister.
			pendingDevices := deviceattest.NewPendingDeviceStore()
			base = base.WithPendingDevices(pendingDevices)

			// Task #136 — wire the device-enrollment store so the
			// /devices list + disable endpoints work. Sourced from the
			// same Falcon-ID s2s base URL + access token that
			// FalconIDEnrollmentStore uses elsewhere. Empty
			// JESS_FALCON_ID_INTERNAL_URL disables the routes (503).
			if falconURL := env("JESS_FALCON_ID_INTERNAL_URL", ""); falconURL != "" {
				// Prefer the live token file written by the svctoken-
				// refresher sidecar (rotation propagates with no restart);
				// fall back to the legacy read-once env token. When neither
				// is set the /devices routes are left unwired (503) rather
				// than panicking on an empty token.
				var tokenSrc devicepolicy.TokenSource
				if path := env("JESS_FALCON_ID_S2S_TOKEN_FILE", ""); path != "" {
					tokenSrc = caep.FileTokenSource{Path: path}
				} else if tok := env("JESS_FALCON_ID_S2S_TOKEN", ""); tok != "" {
					tokenSrc = caep.StaticTokenSource{Tok: tok}
				}
				if tokenSrc == nil {
					log.Print("WARNING: JESS_FALCON_ID_INTERNAL_URL set but neither JESS_FALCON_ID_S2S_TOKEN_FILE nor JESS_FALCON_ID_S2S_TOKEN set — /devices routes NOT enabled")
				} else {
					deviceStore := devicepolicy.NewFalconIDEnrollmentStoreWithSource(falconURL, tokenSrc)
					base = base.WithDeviceStore(deviceStore)
					// Same Falcon-ID s2s store backs the corporate
					// pre-registration (allowlist) CRUD surface.
					base = base.WithPreRegStore(deviceStore)
					log.Printf("jess-controller: /devices endpoints enabled (falcon-id=%s)", falconURL)
				}
			} else {
				log.Print("jess-controller: /devices endpoints NOT configured (set JESS_FALCON_ID_INTERNAL_URL + JESS_FALCON_ID_S2S_TOKEN_FILE)")
			}

			// Task #130 — wire the SSH client-cert minter. Uses the
			// Vault SSH-CA mount + role; same vaultx.Client the
			// operator-cert path uses below.
			if sshMount := env("JESS_SSH_CA_VAULT_MOUNT", ""); sshMount != "" {
				vc, vErr := newControllerVaultClient()
				if vErr != nil {
					log.Fatalf("ssh-cert Vault client: %v", vErr)
				}
				sshRole := env("JESS_SSH_CA_VAULT_ROLE", "operator-client")
				maxTTLStr := env("JESS_SSH_CA_MAX_TTL", "12h")
				maxTTL, parseErr := time.ParseDuration(maxTTLStr)
				if parseErr != nil {
					log.Fatalf("JESS_SSH_CA_MAX_TTL=%q parse: %v", maxTTLStr, parseErr)
				}
				base = base.WithSSHCertSigner(admin.SSHCertConfig{
					Vault:           vc,
					Mount:           sshMount,
					Role:            sshRole,
					MaxTTL:          maxTTL,
					PrincipalPrefix: env("JESS_SSH_CA_PRINCIPAL_PREFIX", "git-"),
				})
				log.Printf("jess-controller: /ssh-cert endpoint enabled (Vault SSH mount=%s role=%s, max TTL=%s)",
					sshMount, sshRole, maxTTL)
			}

			// Task #140 — Phase 2 closure: verify the
			// X-Talon-Identity-Token JWT against Talon's auth.ops JWKS
			// instead of trusting the bare X-Talon-Device-UUID header.
			// Set JESS_TALON_IDENTITY_ISSUER to enable the verifier;
			// audience defaults to "jess" (matches the iap-identity-
			// token aud claim Talon stamps).
			if talonIss := env("JESS_TALON_IDENTITY_ISSUER", ""); talonIss != "" {
				audience := env("JESS_TALON_IDENTITY_AUDIENCE", "jess")
				tv, terr := admin.NewTalonIdentityVerifier(context.Background(), talonIss, audience)
				if terr != nil {
					log.Fatalf("talon identity verifier (issuer=%s): %v", talonIss, terr)
				}
				base = base.WithTalonIdentityVerifier(tv)
				log.Printf("jess-controller: X-Talon-Identity-Token verification enabled (issuer=%s aud=%s)", talonIss, audience)
			} else {
				log.Print("jess-controller: X-Talon-Identity-Token verification NOT configured (set JESS_TALON_IDENTITY_ISSUER) — falling back to bare X-Talon-Device-UUID header (dev-only)")
			}

			// Task #131 — wire the jess-device-ca CRL + OCSP responder.
			// Proxies Vault PKI's /crl + /ocsp endpoints through jess so
			// Talon's edge mTLS verifier (+ device-cert clients) can
			// validate revocation without holding Vault tokens.
			if deviceMount := env("JESS_DEVICE_CA_VAULT_MOUNT", ""); deviceMount != "" {
				vc, vErr := newControllerVaultClient()
				if vErr != nil {
					log.Fatalf("device-crl Vault client: %v", vErr)
				}
				responder := devicecrl.New(devicecrl.Config{
					Vault: vc,
					Mount: deviceMount,
					// CacheTTL=0 → devicecrl uses its 5min default.
				})
				base = base.WithCRLResponder(responder)
				log.Printf("jess-controller: /crl.pem + /ocsp endpoints enabled (Vault mount=%s)", deviceMount)
			}

			var handler http.Handler = base
			// Wire the Phase 5b request workflow if the store implements it
			// (PostgresStore does once MigrateRequests runs).
			if rs, rok := grants.(admin.RequestStore); rok {
				if mr, mok := grants.(interface {
					MigrateRequests(context.Context) error
				}); mok {
					if mErr := mr.MigrateRequests(context.Background()); mErr != nil {
						log.Fatalf("requests migrate: %v", mErr)
					}
				}
				requestsHandler := admin.NewRequests(base, rs)
				// Phase 5h-4a — opt-in risk-score auto-approval. nil-safe;
				// when JESS_RISK_AUTO_APPROVAL is unset, requestsHandler
				// keeps its pre-5h-4a (every-request-requires-human)
				// behaviour and these calls return nil tuple.
				if eval, lookup, audit, met, enabled := maybeWireRiskScore(ctrl.Cat, ctrl.Audit, m); enabled {
					requestsHandler = requestsHandler.WithRiskScore(eval, lookup, audit, met)
				}
				handler = requestsHandler
				// Operator-cert minting (POST /operator-cert). Two backends —
				// signer is picked at startup, both surface the same HTTP API:
				//   1. Vault PKI mount (PKI Phase 2+, preferred) when
				//      JESS_OPERATOR_CA_VAULT_MOUNT is set. Every issuance
				//      audit-logged by Vault; CA key never leaves Vault;
				//      revocable via `vault write <mount>/revoke serial=...`.
				//   2. File-mounted CA (Phase 1 / break-glass) when
				//      JESS_OPERATOR_CA_CERT + JESS_OPERATOR_CA_KEY are set
				//      and the Vault path is unset. CA key at-rest in pod.
				// Unset both => endpoint returns 503 (graceful degradation).
				var certSigner admin.Signer
				if pkiMount := os.Getenv("JESS_OPERATOR_CA_VAULT_MOUNT"); pkiMount != "" {
					vc, vErr := newControllerVaultClient()
					if vErr != nil {
						log.Fatalf("operator-cert Vault client: %v", vErr)
					}
					pkiRole := env("JESS_OPERATOR_CA_VAULT_ROLE", "operator-cert")
					vs, sErr := admin.NewVaultSigner(context.Background(), vc, pkiMount, pkiRole)
					if sErr != nil {
						log.Fatalf("operator-cert Vault signer: %v", sErr)
					}
					log.Printf("jess-controller: operator-cert endpoint enabled (Vault PKI mount=%s role=%s, max TTL=%s)", pkiMount, pkiRole, admin.MaxOperatorCertTTL)
					certSigner = vs
				} else if caCertPath, caKeyPath := os.Getenv("JESS_OPERATOR_CA_CERT"), os.Getenv("JESS_OPERATOR_CA_KEY"); caCertPath != "" && caKeyPath != "" {
					ls, scErr := admin.NewCertSigner(caCertPath, caKeyPath)
					if scErr != nil {
						log.Fatalf("operator-cert signer: %v", scErr)
					}
					log.Printf("jess-controller: operator-cert endpoint enabled (file-mount CA=%s, max TTL=%s)", caCertPath, admin.MaxOperatorCertTTL)
					certSigner = ls
				} else {
					log.Print("jess-controller: operator-cert endpoint NOT configured (set JESS_OPERATOR_CA_VAULT_MOUNT for Vault PKI, OR JESS_OPERATOR_CA_CERT + JESS_OPERATOR_CA_KEY for file mount)")
				}
				if certSigner != nil {
					certHandler := admin.NewCert(requestsHandler, certSigner)
					handler = certHandler
					// Phase 5e-6: layer /sessions on top when the grant
					// store implements SessionStore (Postgres + Memory
					// both do). nil-safe inside NewSessions — surfaces
					// 503 on /sessions if not wired.
					if ss, sok := grants.(jit.SessionStore); sok {
						sessHandler := admin.NewSessions(certHandler, ss)
						// Optional in-browser recording playback (admin
						// GET /sessions/{id}/recording). Activates only
						// when JESS_REC_S3_ENDPOINT + creds are set —
						// the controller doesn't normally need MinIO
						// read access (worker writes it), but exposing
						// read here lets the SPA player work without an
						// SSO round-trip to MinIO Console.
						if rec := recordingReaderFromEnv(); rec != nil {
							sessHandler = sessHandler.WithRecordings(rec)
							log.Printf("jess-controller: recording-stream endpoint enabled (MinIO read on %s/%s)", env("JESS_REC_S3_ENDPOINT", ""), env("JESS_REC_S3_BUCKET", "audit-archive"))
							// Phase 5e-14: tamper-evidence verifier shares the
							// same MinIO read store (no second pool). Vault
							// transit public key fetched once at startup.
							if v := recordingVerifierFromEnv(rec); v != nil {
								sessHandler = sessHandler.WithVerifier(v)
							}
						}
						// Phase 5f-2d: catalog wired into admin handler so the
						// /rdp-probe/sweep endpoint can walk every target.
						sessHandler = sessHandler.WithCatalog(catalogLister{ctrl.Cat})
						handler = sessHandler
						// Phase 5f-9: background RDP probe-sweep monitor.
						// Same cadence + goroutine pattern as the chain
						// monitor + requests expirer. No-op when the
						// catalog has zero RDP targets — the metrics
						// surface stays at 0/0 (no alert).
						go runRDPSweepMonitor(sessHandler, m, ctrl.Audit)
					}
				}
				// Background expirer — transitions pending requests past
				// expires_at into expired so the approver list stays clean.
				if ex, eok := grants.(interface {
					ExpireOld(context.Context) (int, error)
				}); eok {
					go func() {
						t := time.NewTicker(5 * time.Minute)
						defer t.Stop()
						for range t.C {
							if n, err := ex.ExpireOld(context.Background()); err != nil {
								log.Printf("requests expirer: %v", err)
							} else if n > 0 {
								log.Printf("requests expirer: %d stale requests aged out", n)
							}
						}
					}()
				}
				// Phase 5e-18: cross-session WORM chain integrity monitor.
				// Runs VerifyChain on the same 5min cadence; emits an
				// audit Event on break AND updates Prometheus so the
				// SRE alert fires within minutes of any tampering. The
				// first verify runs immediately at startup so a freshly-
				// booted controller doesn't sit at jess_chain_intact=-1
				// (unverified) for 5min before publishing reality.
				if cv, vok := grants.(jit.ChainVerifier); vok {
					go runChainMonitor(cv, m, ctrl.Audit)
				}
			}
			// Phase 7f: wrap the chain with the targets handler when
			// adminapi.Provider is wired (i.e. when JESS_K8S_DISCOVERY
			// or JESS_PROXMOX_DISCOVERY is on). Falls through cleanly
			// when adminTargetsProv is nil — the wrapping is a no-op
			// because the outer ServeHTTP just forwards to next.
			if adminTargetsProv != nil {
				handler = admin.NewTargets(handler, base, adminTargetsProv)
				log.Print("jess-controller: /admin/targets API enabled (Phase 7f)")
			}
			// Phase 7h: GET /admin/catalog — full unified catalog
			// across providers, used by the SPA admin panel.
			handler = admin.NewCatalog(handler, base, ctrl.Cat)
			log.Print("jess-controller: /admin/catalog read endpoint enabled (Phase 7h)")
			// ASVS L2 V8 — GET /grants/assert active-grant re-check. Exposes
			// the SAME store-backed AssertActiveID the data-plane worker runs
			// so the in-browser RDP-live path (jess-web) can hard-gate its
			// session open + re-check continuously, reaching SSH/DB parity.
			// Subject-scoped self-service (verified caller can only assert their
			// OWN grant) — the handler runs its own authn ahead of the base role
			// gate, so it is NOT platform_admin gated. `grants` is a
			// jit.GrantStore, which satisfies admin.GrantAsserter.
			handler = admin.NewGrantAssert(handler, base, grants)
			log.Print("jess-controller: /grants/assert active-grant re-check endpoint enabled (RDP-live parity, ASVS L2 V8)")
			// Per-target admin recording override — GET/PUT/DELETE
			// /recording-settings. Runtime-override-on-GitOps-default:
			// the catalog's `recorded` flag stays the GitOps default; an
			// override here flips a target on/off at runtime, honoured by
			// RDP/SSH/DB session-open (effective value propagated to the
			// worker). Audited (updated_by + recording.* audit rows).
			// nil-safe inside the handler — 503 when override store /
			// catalog aren't both wired.
			handler = admin.NewRecording(handler, base, ctrl.RecordingOverrides, ctrl.Cat, ctrl.Audit)
			log.Print("jess-controller: /recording-settings admin endpoint enabled (per-target recording override)")
			// ADR 0052 Phase F — discovery review queue (list/approve/reject the
			// JessPendingTarget candidates). Best-effort dynamic client; nil →
			// the routes 503. Same platform_admin gate as the rest of the chain.
			if pdyn, perr := pending.NewInCluster(); perr == nil {
				handler = admin.NewPending(handler, base, pdyn, ctrl.Audit)
				log.Print("jess-controller: /pending discovery review API enabled (GET /pending, POST /pending/{name}/approve|reject)")
			} else {
				log.Printf("jess-controller: /pending review API NOT enabled (k8s client: %v)", perr)
			}
			// Gap audit #12 — POST /admin/policy/simulate dry-run.
			// Runs the live PDP against a synthetic OperatorRequest
			// shape and returns the verdict without opening anything.
			// Useful for incident response + policy authoring tests.
			handler = admin.NewPolicySimulate(handler, base, ctrl.PDP, ctrl.Cat)
			log.Print("jess-controller: /admin/policy/simulate dry-run endpoint enabled (gap audit #12)")
			// Gap audit #9 — the catalog drift / health prober lives
			// on the WORKER side, not here. Rationale: the controller
			// pod's network namespace cannot necessarily reach every
			// brokering target (cluster pods often can't TCP-connect
			// to bare-IP node addresses without explicit routing),
			// while the worker MUST be able to reach every target by
			// design — that's the brokering invariant. Running the
			// prober where the brokering actually happens gives an
			// honest signal: "can a session-open against this target
			// succeed RIGHT NOW?". See cmd/jess-worker/main.go.
			// Phase 7g: POST /admin/attest — cloud-attestation
			// verification. Registry is built from env opt-ins
			// (JESS_AWS_ATTESTATION, JESS_AZURE_ATTESTATION); when
			// nil, the handler returns 503 — endpoint is layered in
			// either way so the audit row attributes attempts even
			// when the operator hasn't opted into any cloud yet.
			if attReg := buildAttestationRegistry(); attReg != nil {
				handler = admin.NewAttest(handler, base, attReg, ctrl.Audit)
				log.Print("jess-controller: /admin/attest endpoint enabled (Phase 7g)")
			}
			// Phase 5j-1 (ADR 0034 priority #4 + #7): admin lock primitive.
			// Composes with the JIT grant substrate so admins can kill all
			// sessions for a subject / to a target in one call. Live
			// sessions are killed by the continuous grant watcher's lock
			// re-check (spine.Controller — Phase 5g-6 grant-tick now also
			// evaluates IsLockedAny). Endpoint is layered if the grant
			// store implements jit.LockStore (PostgresStore + MemoryBroker
			// both do).
			if ls, ok := grants.(jit.LockStore); ok {
				handler = admin.NewLocks(handler, base, ls).WithMetrics(m)
				log.Print("jess-controller: /locks admin endpoint enabled (Phase 5j-1)")
				// Single 5-min ticker runs both the expirer (GC past-
				// expiry rows) AND the active-gauge refresher (snapshot
				// counts by target_type → Prometheus). Same cadence
				// because ListLocks-after-ExpireOldLocks gives a
				// consistent post-GC view; running them on separate
				// tickers would race + double the DB load for no win.
				go func() {
					t := time.NewTicker(5 * time.Minute)
					defer t.Stop()
					// Tick once at startup so the gauge isn't empty
					// for the first 5 min after a pod bounce — admins
					// looking at the dashboard right after a deploy
					// would otherwise see "0 active" regardless of
					// real state.
					refreshLockGauges(ls, m)
					for range t.C {
						if ex, ok := grants.(jit.LockExpirer); ok {
							if n, err := ex.ExpireOldLocks(context.Background()); err != nil {
								log.Printf("locks expirer: %v", err)
							} else if n > 0 {
								log.Printf("locks expirer: %d past-expiry locks dropped", n)
								m.JITLocksExpired(n)
							}
						}
						refreshLockGauges(ls, m)
					}
				}()
				ctrl.Locks = ls
			}
			// ZTNA Phase 3 — device-cert attestation handler (#117/#122).
			// Gated on JESS_DEVICE_ATTEST_ENABLED=true (default false).
			// When enabled, POST /device-cert/attest is layered on top of
			// the existing handler chain. When disabled, the path 404s —
			// no silent degradation. buildDeviceAttestHandler is a no-op
			// (returns false) when the env gate is unset so the controller
			// behavior is unchanged for all current deployments.
			// The device-enrollment access token is minted for the
			// hexxlock-access desktop app, which targets the platform API
			// resource: Falcon-ID stamps aud=[client, https://api.hexxlock.com,
			// hexxlock-services] per its multi-audience model (audience.go).
			// That is a DIFFERENT audience from the operator svc-jess token the
			// admin chain above consumes, so the attest path validates with its
			// OWN verifier against the platform-API audience (membership), not
			// svc-jess. The jess-specific, replay-protected binding for
			// enrollment is provided by the WebAuthn witness JWS — not this
			// token's audience — so accepting the platform-API audience here is
			// safe (an enrollment still requires an operator-witnessed, device-
			// bound, ~5min-fresh witness; the cert is bound to the token sub).
			attestVerifier := verifier
			if os.Getenv("JESS_DEVICE_ATTEST_ENABLED") == "true" {
				attestAud := env("JESS_DEVICE_ATTEST_AUDIENCE", "https://api.hexxlock.com")
				av, averr := pdp.NewFalconIDVerifier(context.Background(), issuer, attestAud)
				if averr != nil {
					log.Fatalf("jess-controller: device-attest token verifier (issuer=%s aud=%s): %v", issuer, attestAud, averr)
				}
				log.Printf("jess-controller: device-attest token audience = %s (issuer=%s)", attestAud, issuer)
				attestVerifier = av
			}
			if attestHandler, enabled := buildDeviceAttestHandler(handler, attestVerifier, pendingDevices); enabled {
				handler = attestHandler
			}

			srv := &http.Server{Addr: adminAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
			// Admin port reuses the operator-port TLS config (Clone so a
			// future tweak to opCfg doesn't bleed; same trust pool + the
			// Phase 4 full VerifyPeerCertificate hook). Without this clone
			// the admin port previously fell back to a default tls.Config
			// that did NOT request a client cert — the log line claiming
			// "mTLS=…" was misleading. With opCfg cloned, RequireAndVerify
			// ClientCert is enforced (set by transport.LoadServerTLS or
			// transport.AppendClientCAs when the trust pool is non-empty).
			if opCfg != nil {
				srv.TLSConfig = opCfg.Clone()
			}
			go func() {
				if cert, key := os.Getenv("JESS_OPERATOR_TLS_CERT"), os.Getenv("JESS_OPERATOR_TLS_KEY"); cert != "" && key != "" {
					mtls := os.Getenv("JESS_OPERATOR_TLS_CA") != "" || os.Getenv("JESS_OPERATOR_CA_VAULT_MOUNT") != ""
					log.Printf("jess-controller: admin server on %s (TLS, mTLS=%v, CRL=%v, role=%s)", adminAddr, mtls, crlCache != nil, role)
					// When TLSConfig carries the cert+key in its Certificates,
					// ListenAndServeTLS with empty paths uses TLSConfig.
					// When srv.TLSConfig is nil (no opCfg — env-only path),
					// fall back to passing cert+key directly.
					if srv.TLSConfig != nil {
						log.Fatalf("admin server: %v", srv.ListenAndServeTLS("", ""))
					}
					log.Fatalf("admin server: %v", srv.ListenAndServeTLS(cert, key))
				} else {
					log.Printf("WARNING: admin server on %s in PLAINTEXT — set JESS_OPERATOR_TLS_CERT/KEY (dev only)", adminAddr)
					log.Fatalf("admin server: %v", srv.ListenAndServe())
				}
			}()
		}
	}

	log.Printf("jess-controller: workers=%s operators=%s targets=%d", workerAddr, operatorAddr, len(targets))
	// Gap audit #12: SIGTERM drain handler. On TERM, flip controller
	// to drain mode (new session-opens rejected with reason=
	// "draining") and wait JESS_DRAIN_GRACE_SECONDS (default 30s)
	// before letting the process exit. In-flight sessions are
	// unaffected by the drain — they reach their own close on grant
	// expiry / lock / idle-timeout / explicit operator disconnect.
	// Without this, a pod bounce kills every live session mid-flight.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		s := <-sigCh
		grace := 30 * time.Second
		if v := env("JESS_DRAIN_GRACE_SECONDS", ""); v != "" {
			if d, derr := time.ParseDuration(v + "s"); derr == nil && d > 0 {
				grace = d
			}
		}
		log.Printf("jess-controller: caught %s — drain mode ENGAGED; new opens denied; grace=%s", s, grace)
		ctrl.Drain()
		time.Sleep(grace)
		log.Printf("jess-controller: drain grace elapsed — exiting")
		os.Exit(0)
	}()
	go func() { log.Fatalf("worker loop: %v", ctrl.ServeWorkers(workerL, idFn)) }()
	log.Fatalf("operator loop: %v", ctrl.ServeOperators(operatorL))
}

// refreshLockGauges polls the current active-lock set and publishes a
// per-target_type snapshot to Prometheus (Phase 5j-1). Called on the
// 5-min expirer tick. A list-then-bucket walk is fine because the
// expected steady-state population is single-digit locks at most; if
// that ever grows past hundreds we should add a CountByType to the
// LockStore interface and skip the list. Errors are logged + skipped
// — a transient ListLocks failure leaves the prior gauge values in
// place, which is preferable to flapping them to zero.
func refreshLockGauges(ls jit.LockStore, m *metrics.Metrics) {
	locks, err := ls.ListLocks(context.Background())
	if err != nil {
		log.Printf("locks gauge refresh: %v", err)
		return
	}
	perType := map[string]int{}
	for _, l := range locks {
		perType[string(l.TargetType)]++
	}
	m.JITLocksActive(perType)
}

// isPhishingResistantAMR reports whether the RFC 8176 AMR value
// qualifies as phishing-resistant per NIST SP 800-63B-4 §3.2.5 (Final,
// 2025-07-31). The standard recognises two methods: channel binding
// (PIV / CAC client-auth TLS) and verifier name binding (WebAuthn /
// FIDO2 DNS-bound). OTP / TOTP / out-of-band / generic "mfa" do NOT
// qualify even when present in the amr array.
func isPhishingResistantAMR(amr string) bool {
	// Single source of truth: the canonical allowlist in internal/stepup
	// (shared with the spine per-session step-up gate, P2.5).
	return stepup.IsPhishingResistant(amr)
}
