// SPDX-License-Identifier: AGPL-3.0-or-later

// Command jess-worker is an outbound-only Jess data-plane worker (ADR 0030
// Phase 5a): it dials the controller (mTLS), and for each authorized session
// the controller opens, brokers raw TCP to the target. SSH/DB (5b/5c) and
// rendering (5e, jess-web) add protocol handlers.
//
// Config via env:
//
//	JESS_CONTROLLER_ADDR  controller worker-facing addr        default :7100
//	JESS_WORKER_ID        identity (must match cert CN / SVID) default worker-1
//	JESS_SERVER_NAME      TLS server name to verify            default controller
//	JESS_TLS_CERT/KEY/CA  PEM paths for the client mTLS (file-PEM path)
//	JESS_TARGETS          path to a JSON array of targets      (optional)
//
// The controller link is dual-auth, selected by JESS_SPIRE_SVID (default OFF =
// legacy file-PEM mTLS above):
//
//	JESS_SPIRE_SVID          "1"/"true" to prefer SPIRE X.509-SVID mTLS  default off
//	JESS_SPIRE_SOCKET        SPIRE Agent Workload API address  default unix:///spiffe-workload-api/spire-agent.sock
//	JESS_SPIRE_TRUST_DOMAIN  SPIFFE trust domain               default prod.hexxlock
//	JESS_SPIRE_CONTROLLER_ID controller SPIFFE ID the worker pins (AuthorizeID)
//	                         default spiffe://prod.hexxlock/ns/jess/sa/jess/controller
//
// The SVID path activates ONLY when SPIRE is deployed (Workload API socket
// present) AND JESS_SPIRE_SVID is on; otherwise the worker stays on file-PEM and
// never hard-fails because SPIRE is down. Retires ADR-0038's deferred plan.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/catalog/prober"
	"github.com/dogukanturhal/jess/internal/diag"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/spine"
	"github.com/dogukanturhal/jess/internal/transport"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean env var (strconv.ParseBool), returning def when unset
// or unparseable. Used for the JESS_SPIRE_SVID dual-auth gate.
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

func splitAddrs(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolveControllerDNS expands a single "hostname:port" into a list of
// "ip:port" by looking up the hostname's A records. Used with a
// Kubernetes headless Service for the controller (clusterIP: None) so
// each pod IP is returned and the worker dials each — true active-active
// HA, not "kube-proxy round-robin per connection" which would register
// the worker on only one controller pod.
//
// Returns the original "host:port" unchanged if hostname is already a
// literal IP (or DNS lookup yields zero results) — defensive fallback,
// caller's existing dial behaviour is preserved.
func resolveControllerDNS(addr string) []string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	if ip := net.ParseIP(host); ip != nil {
		// Already an IP; pass through unchanged.
		return []string{addr}
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return []string{addr}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip.String(), port))
	}
	return out
}

func main() {
	// All controllers this worker serves (comma-separated) — dialing every one
	// is how ≥2 controllers behind an LB each route sessions here (HA).
	//
	// JESS_CONTROLLER_DNS (optional) is a single "hostname:port" pointing
	// at a Kubernetes headless Service (clusterIP: None) for the controller.
	// The hostname's A records resolve to every controller pod IP; the
	// worker dials each so it registers on every replica — the active-active
	// property the explicit comma-list provides, without operators having to
	// keep the list in sync with the controller's replica count.
	var controllerAddrs []string
	if dns := env("JESS_CONTROLLER_DNS", ""); dns != "" {
		controllerAddrs = resolveControllerDNS(dns)
		log.Printf("jess-worker: resolved %s → %d controller(s): %v", dns, len(controllerAddrs), controllerAddrs)
	} else {
		controllerAddrs = splitAddrs(env("JESS_CONTROLLER_ADDRS", env("JESS_CONTROLLER_ADDR", ":7100")))
	}
	workerID := env("JESS_WORKER_ID", "worker-1")
	serverName := env("JESS_SERVER_NAME", "controller")
	// Controller-link mTLS is dual-auth: SPIRE X.509-SVID when JESS_SPIRE_SVID is
	// on AND a SPIRE Workload API socket is present, else the legacy file-PEM
	// path (default; also the graceful fallback when SPIRE isn't reachable).
	var (
		cliCfg *tls.Config
		err    error
	)
	if envBool("JESS_SPIRE_SVID", false) {
		trustDomain := env("JESS_SPIRE_TRUST_DOMAIN", transport.DefaultSpireTrustDomain)
		controllerID := env("JESS_SPIRE_CONTROLLER_ID", transport.DefaultControllerSPIFFEID)
		// Pin the peer to the controller's exact SPIFFE ID (AuthorizeID).
		authz, aerr := transport.AuthorizeSPIFFEID(controllerID)
		if aerr != nil {
			log.Fatalf("jess-worker: JESS_SPIRE_CONTROLLER_ID=%q invalid: %v", controllerID, aerr)
		}
		socket := env("JESS_SPIRE_SOCKET", transport.DefaultSpireSocket)
		src, active, serr := transport.AcquireSVIDSource(context.Background(), true, socket, transport.DefaultSVIDDialTimeout)
		if serr != nil {
			log.Fatalf("jess-worker: SPIRE SVID source: %v", serr)
		}
		if active {
			defer src.Close()
			cliCfg = transport.SVIDClientConfig(src, authz)
			log.Printf("jess-worker: controller mTLS = SPIRE X.509-SVID (trust-domain=%s, authorized controller=%s, socket=%s)", trustDomain, controllerID, socket)
		}
		// active == false: AcquireSVIDSource logged the fallback reason.
	}
	if cliCfg == nil {
		certFile, keyFile, caFile := os.Getenv("JESS_TLS_CERT"), os.Getenv("JESS_TLS_KEY"), os.Getenv("JESS_TLS_CA")
		if certFile == "" || keyFile == "" || caFile == "" {
			log.Fatal("set JESS_SPIRE_SVID=1 (with SPIRE deployed), or JESS_TLS_CERT/KEY/CA (client mTLS)")
		}
		if cliCfg, err = transport.LoadClientConfig(certFile, keyFile, caFile, serverName); err != nil {
			log.Fatalf("client mTLS: %v", err)
		}
	}

	var targets []*catalog.Target
	if p := os.Getenv("JESS_TARGETS"); p != "" {
		if targets, err = catalog.LoadFile(p); err != nil {
			log.Fatalf("targets: %v", err)
		}
	}

	// Workers MUST share the controller's grant store so their independent
	// grant re-check (defense in depth) sees grants issued by any controller.
	var grants jit.GrantStore
	if dsn := os.Getenv("JESS_DB_DSN"); dsn != "" {
		ps, perr := jit.NewPostgresStore(context.Background(), dsn)
		if perr != nil {
			log.Fatalf("postgres grant store: %v", perr)
		}
		grants = ps
	} else {
		log.Print("warning: JESS_DB_DSN unset — in-memory grants; a worker's grant re-check will be EMPTY in a real multi-process deploy")
		grants = jit.NewMemoryBroker()
	}

	wr := &spine.WorkerRuntime{
		ID:    workerID,
		Cat:   catalog.NewMemoryCatalog(targets...),
		JIT:   grants,
		Audit: audit.NewJSONSink(os.Stdout),
	}

	// Production credential brokering (ADR 0030 Phase 5b/5c/5d), all env-gated:
	// SSH cert injection (Vault SSH CA), Postgres dynamic creds (Vault DB engine),
	// and signed WORM recording (MinIO Object-Lock + Vault Transit). Unset env =
	// the worker stays raw-TCP-only, exactly as it deploys by default.
	vc, verr := newVaultClient()
	if verr != nil {
		log.Fatalf("vault client: %v", verr)
	}
	var recSpool *recording.SpoolStore // DDIL P3.6 WORM store-and-forward handle; started under ctx below
	if vc != nil {
		sshCfg, serr := sshConfigFromVault(vc)
		if serr != nil {
			log.Fatalf("ssh brokering: %v", serr)
		}
		if sshCfg != nil {
			wr.SSH = sshCfg
			log.Print("jess-worker: SSH cert-injection enabled (Vault SSH CA)")
		}
		if dbCfg := dbConfigFromVault(vc); dbCfg != nil {
			wr.DB = dbCfg
			log.Print("jess-worker: Postgres dynamic-creds brokering enabled (Vault DB engine)")
		}
		if myCfg := mysqlConfigFromVault(vc); myCfg != nil {
			wr.MySQL = myCfg
			log.Print("jess-worker: MySQL dynamic-creds brokering enabled (Vault DB engine)")
		}
		rec, spoolStore, rerr := recorderFromVault(context.Background(), vc)
		if rerr != nil {
			log.Fatalf("recorder: %v", rerr)
		}
		if rec != nil {
			wr.Recorder = rec
			log.Print("jess-worker: signed WORM recording enabled (MinIO Object-Lock + Vault Transit)")
		}
		recSpool = spoolStore
	} else {
		log.Print("jess-worker: JESS_VAULT_ADDR unset — raw-TCP brokering only (no SSH/DB/recording)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if recSpool != nil {
		// DDIL P3.6: drain buffered recordings to WORM in the background, bound to
		// the process lifetime. A must-record session whose seal can't reach MinIO
		// is now buffered durably and reconciled on reconnect instead of lost.
		go recSpool.Run(ctx)
		log.Print("jess-worker: WORM store-and-forward spool ENABLED (DDIL P3.6 — buffers recordings on MinIO outage, reconciles on reconnect)")
	}

	// Diagnostics: /healthz (liveness) + /readyz. (Metrics live on the controller.)
	diagAddr := env("JESS_DIAG_ADDR", ":7110")
	go func() {
		log.Printf("jess-worker: diagnostics on %s (/healthz /readyz)", diagAddr)
		if derr := diag.Serve(context.Background(), diagAddr, diag.Handler(nil, nil)); derr != nil {
			log.Printf("diagnostics server: %v", derr)
		}
	}()

	// Gap audit #9 — catalog drift / health prober. Periodic probe
	// against every catalog target using the EXACT broker code paths
	// the worker uses for real sessions: ProtoSSH → sshproxy.Config.
	// DialTarget (Vault SSH-CA cert mint + ssh.Dial + cert auth);
	// ProtoPostgres → dbproxy.Config.CredsFor + pgconn.Connect;
	// ProtoMySQL → mysqlproxy.Config.CredsFor + tcp; ProtoRDP → X.224
	// nego (already protocol-level). Raw TCP falls back when the
	// protocol config isn't wired (dev mode).
	//
	// Deep-research workflow wf_4faa27c1-35a (2026-06-06) confirmed
	// NO surveyed tier-1 PAM broker (Teleport, Boundary, CyberArk,
	// StrongDM, Microsoft Entra, Pomerium, OpenZiti) probes via the
	// actual brokering protocol — they all use raw-TCP or session-
	// failure telemetry. jess is shipping past that bar deliberately.
	//
	// Audit posture: protocol-handshake probes WILL appear in target
	// audit logs (e.g. sshd accepts the probe principal, then closes
	// immediately). Stage 2 backlog adds a probe-specific Vault role
	// so targets can opt-in/out independently of operator certs.
	if v := env("JESS_CATALOG_PROBE_INTERVAL", "5m"); v != "" {
		if d, derr := time.ParseDuration(v); derr == nil && d > 0 {
			p := &prober.Prober{
				Catalog:  wr.Cat,
				Interval: d,
				SSH:      wr.SSH,
				DB:       wr.DB,
				MySQL:    wr.MySQL,
			}
			go p.Run(context.Background())
			log.Printf("jess-worker: catalog drift prober ENABLED interval=%s (gap audit #9, protocol-handshake mode)", d)
		} else {
			log.Printf("jess-worker: invalid JESS_CATALOG_PROBE_INTERVAL=%q (parse=%v) — prober disabled", v, derr)
		}
	}

	log.Printf("jess-worker %s dialing controllers %v (server-name %s)", workerID, controllerAddrs, serverName)
	// Run maintains a connection to each controller with its own reconnect loop;
	// it blocks until ctx is cancelled (SIGINT/SIGTERM).
	if err := wr.Run(ctx, controllerAddrs, cliCfg); err != nil && ctx.Err() == nil {
		log.Fatalf("jess-worker: %v", err)
	}
	log.Print("jess-worker: shutting down")
}
