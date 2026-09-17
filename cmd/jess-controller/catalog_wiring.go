// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 7c — Catalog wiring (env-gated).
//
// Default (no JESS_K8S_DISCOVERY env): the controller wires the same
// MemoryCatalog backed by JESS_TARGETS that it used pre-Phase-7. Zero
// behavior change.
//
// Opt-in (JESS_K8S_DISCOVERY=true): the controller builds a
// catalog.Aggregator with the StaticProvider PLUS the Kubernetes
// Node-watch provider. The Aggregator implements catalog.Catalog so
// spine.Controller continues to consume the same interface.
//
// Adapter glue (catalogAudit) bridges catalog.DiffEvent into the
// existing audit.Sink — every discovered Node add/remove/change is
// recorded as one row in the same JSONL stream the rest of jess
// already emits (SOC2 evidence single source of truth).

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/catalog/providers/adminapi"
	crdprovider "github.com/dogukanturhal/jess/internal/catalog/providers/jesstargetcrd"
	k8sprovider "github.com/dogukanturhal/jess/internal/catalog/providers/kubernetes"
	k8ssvcprovider "github.com/dogukanturhal/jess/internal/catalog/providers/kubernetesservices"
	ldapprovider "github.com/dogukanturhal/jess/internal/catalog/providers/ldap"
	proxmoxprovider "github.com/dogukanturhal/jess/internal/catalog/providers/proxmox"
	"github.com/dogukanturhal/jess/internal/lifecycle/pending"
)

// buildCatalog returns the catalog implementation handed to
// spine.Controller. When JESS_K8S_DISCOVERY=true, it's an Aggregator
// with static + k8s providers; otherwise it's the plain MemoryCatalog.
// The optional returned shutdown func gracefully drains the Aggregator's
// goroutines on process exit.
func buildCatalog(ctx context.Context, staticTargets []*catalog.Target, sink audit.Sink) (catalog.Catalog, *adminapi.Provider, func()) {
	mem := catalog.NewMemoryCatalog(staticTargets...)

	k8sOn := os.Getenv("JESS_K8S_DISCOVERY") == "true"
	k8sSvcOn := os.Getenv("JESS_K8S_SERVICES_DISCOVERY") == "true"
	proxOn := os.Getenv("JESS_PROXMOX_DISCOVERY") == "true"
	crdOn := os.Getenv("JESS_CRD_DISCOVERY") == "true"
	ldapOn := os.Getenv("JESS_LDAP_DISCOVERY") == "true"
	adminOn := os.Getenv("JESS_ADMIN_TARGETS_API") != "false" // default ON when aggregator is built
	if !k8sOn && !k8sSvcOn && !proxOn && !crdOn && !ldapOn {
		// Default path. Same behavior as pre-Phase-7 (no admin-api
		// either — without a real provider in the chain there'd be
		// nothing to compare against on the precedence ladder).
		return mem, nil, func() {}
	}

	// Aggregator path. AuditEmitter bridge stamps every diff into the
	// existing audit.Sink — same SOC2 trail as session-open / revoke
	// rows; catalog diffs are differentiated by Action="catalog.diff".
	agg := catalog.NewAggregator(catalogAudit{sink: sink}, nil)

	// Precedence (Phase 7f): admin-api FIRST so break-glass operator
	// additions outrank any cloud / static discovery on id collision.
	// Then static (ConfigMap-pinned overrides), then dynamic
	// providers in the order operators enabled them.
	var adminProv *adminapi.Provider
	if adminOn {
		adminProv = adminapi.New(agg)
		agg.AddProvider(adminProv, -1) // event-driven; mutations push via IngestSnapshot
	}
	agg.AddProvider(catalog.NewStaticProvider(mem), -1) // event-less; ConfigMap reload is the change signal

	enabled := []string{"static"}
	if adminProv != nil {
		enabled = append([]string{"admin-api"}, enabled...)
	}
	runCtx, cancel := context.WithCancel(ctx)

	// ADR 0052 Phase F — shared audit-only sink. When ANY provider's
	// *_DISCOVERY_PENDING flag is set, its discoveries route to the
	// JessPendingTarget review queue (manual approval) instead of the live
	// catalog. Created once; nil when no provider is in pending mode.
	var psink *pending.DiscoverySink
	if os.Getenv("JESS_LDAP_DISCOVERY_PENDING") == "true" ||
		os.Getenv("JESS_PROXMOX_DISCOVERY_PENDING") == "true" ||
		os.Getenv("JESS_K8S_DISCOVERY_PENDING") == "true" ||
		os.Getenv("JESS_K8S_SERVICES_DISCOVERY_PENDING") == "true" {
		dyn, derr := pending.NewInCluster()
		if derr != nil {
			log.Fatalf("jess-controller: *_DISCOVERY_PENDING set but dynamic client init failed: %v", derr)
		}
		psink = pending.NewDiscoverySink(dyn, pendingAuditBridge{sink: sink}, nil)
	}

	// Phase 7c — Kubernetes Node-watch provider (event-driven).
	if k8sOn {
		client, err := k8sprovider.NewInCluster()
		if err != nil {
			log.Fatalf("jess-controller: JESS_K8S_DISCOVERY=true but in-cluster client init failed: %v", err)
		}
		k8sCfg := k8sprovider.Config{
			Client:             client,
			ResyncInterval:     durationFromEnv("JESS_K8S_DISCOVERY_RESYNC", 5*time.Minute),
			SSHPort:            intFromEnv("JESS_K8S_DISCOVERY_SSH_PORT", 22),
			DefaultCriticality: envOr("JESS_K8S_DISCOVERY_DEFAULT_CRITICALITY", "high"),
			ExtraTags:          splitCSV(os.Getenv("JESS_K8S_DISCOVERY_EXTRA_TAGS")),
		}
		// ADR 0052 Phase F — route to the pending review queue (audit-only)
		// instead of the live catalog when JESS_K8S_DISCOVERY_PENDING=true. The
		// provider pushes to whichever Sink we hand it; in pending mode we do NOT
		// register it with the Aggregator (it doesn't feed the catalog).
		var k8sSink k8sprovider.Sink = agg
		k8sPending := os.Getenv("JESS_K8S_DISCOVERY_PENDING") == "true" && psink != nil
		if k8sPending {
			k8sSink = pendingIngester{sink: psink}
		}
		k8sProv, err := k8sprovider.New(k8sCfg, k8sSink)
		if err != nil {
			log.Fatalf("jess-controller: kubernetes provider init: %v", err)
		}
		if !k8sPending {
			// interval=-1: the informer's watch is the change signal, no poll.
			agg.AddProvider(k8sProv, -1)
			if ttl := durationFromEnv("JESS_K8S_RETIREMENT_TTL", 0); ttl > 0 {
				agg.SetRetirementTTL(k8sProv.Name(), ttl)
			}
		}
		go func() {
			if err := k8sProv.Run(runCtx); err != nil && !errIsContextCanceled(err) {
				log.Printf("jess-controller: kubernetes provider exited: %v", err)
			}
		}()
		enabled = append(enabled, label("k8s-nodes", k8sPending))
	}

	// Phase B (auto-discovery program) — Kubernetes Service+annotation
	// provider. Watches v1.Service objects annotated with
	// jess.hexxlock.com/protocol=ssh|postgres|mysql|rdp|tcp. Cluster-wide
	// by default; JESS_K8S_SERVICES_DISCOVERY_NAMESPACE narrows to one ns.
	if k8sSvcOn {
		client, err := k8ssvcprovider.NewInCluster()
		if err != nil {
			log.Fatalf("jess-controller: JESS_K8S_SERVICES_DISCOVERY=true but in-cluster client init failed: %v", err)
		}
		svcCfg := k8ssvcprovider.Config{
			Client:             client,
			ResyncInterval:     durationFromEnv("JESS_K8S_SERVICES_DISCOVERY_RESYNC", 5*time.Minute),
			DefaultCriticality: envOr("JESS_K8S_SERVICES_DISCOVERY_DEFAULT_CRITICALITY", "medium"),
			ExtraTags:          splitCSV(os.Getenv("JESS_K8S_SERVICES_DISCOVERY_EXTRA_TAGS")),
			Namespace:          os.Getenv("JESS_K8S_SERVICES_DISCOVERY_NAMESPACE"),
		}
		var svcSink k8ssvcprovider.Sink = agg
		svcPending := os.Getenv("JESS_K8S_SERVICES_DISCOVERY_PENDING") == "true" && psink != nil
		if svcPending {
			svcSink = pendingIngester{sink: psink} // ADR 0052 Phase F — audit-only
		}
		svcProv, err := k8ssvcprovider.New(svcCfg, svcSink)
		if err != nil {
			log.Fatalf("jess-controller: kubernetesservices provider init: %v", err)
		}
		if !svcPending {
			agg.AddProvider(svcProv, -1)
			if ttl := durationFromEnv("JESS_K8S_SERVICES_RETIREMENT_TTL", 0); ttl > 0 {
				agg.SetRetirementTTL(svcProv.Name(), ttl)
			}
		}
		go func() {
			if err := svcProv.Run(runCtx); err != nil && !errIsContextCanceled(err) {
				log.Printf("jess-controller: kubernetesservices provider exited: %v", err)
			}
		}()
		enabled = append(enabled, label("k8s-services", svcPending))
	}

	// Phase 7e — JessTarget CRD watch provider (event-driven; same
	// dynamic-client pattern as the k8s Node informer above).
	if crdOn {
		client, err := crdprovider.NewInCluster()
		if err != nil {
			log.Fatalf("jess-controller: JESS_CRD_DISCOVERY=true but dynamic client init failed: %v", err)
		}
		crdCfg := crdprovider.Config{
			Client:         client,
			ResyncInterval: durationFromEnv("JESS_CRD_DISCOVERY_RESYNC", 5*time.Minute),
		}
		crdProv, err := crdprovider.New(crdCfg, agg)
		if err != nil {
			log.Fatalf("jess-controller: jess-target-crd provider init: %v", err)
		}
		// interval=-1: the informer's watch is the change signal,
		// not an Aggregator poll.
		agg.AddProvider(crdProv, -1)
		if ttl := durationFromEnv("JESS_CRD_RETIREMENT_TTL", 0); ttl > 0 {
			agg.SetRetirementTTL(crdProv.Name(), ttl)
		}
		go func() {
			if err := crdProv.Run(runCtx); err != nil && !errIsContextCanceled(err) {
				log.Printf("jess-controller: jess-target-crd provider exited: %v", err)
			}
		}()
		enabled = append(enabled, "jess-target-crd")
	}

	// Phase 7b — Proxmox provider (5-min poll).
	if proxOn {
		endpoint := os.Getenv("JESS_PROXMOX_ENDPOINT")
		tokenID := os.Getenv("JESS_PROXMOX_TOKEN_ID")
		tokenSecret := os.Getenv("JESS_PROXMOX_TOKEN_SECRET")
		if endpoint == "" || tokenID == "" || tokenSecret == "" {
			log.Fatal("jess-controller: JESS_PROXMOX_DISCOVERY=true requires JESS_PROXMOX_ENDPOINT + JESS_PROXMOX_TOKEN_ID + JESS_PROXMOX_TOKEN_SECRET")
		}
		proxCfg := proxmoxprovider.Config{
			Endpoint:           endpoint,
			TokenID:            tokenID,
			TokenSecret:        tokenSecret,
			InsecureSkipVerify: envOr("JESS_PROXMOX_INSECURE_SKIP_VERIFY", "true") == "true",
			MatchTag:           envOr("JESS_PROXMOX_MATCH_TAG", proxmoxprovider.DefaultMatchTag),
			SSHPort:            intFromEnv("JESS_PROXMOX_SSH_PORT", 22),
			DefaultCriticality: envOr("JESS_PROXMOX_DEFAULT_CRITICALITY", "medium"),
			ExtraTags:          splitCSV(os.Getenv("JESS_PROXMOX_EXTRA_TAGS")),
		}
		proxProv, err := proxmoxprovider.New(proxCfg)
		if err != nil {
			log.Fatalf("jess-controller: proxmox provider init: %v", err)
		}
		if os.Getenv("JESS_PROXMOX_DISCOVERY_PENDING") == "true" && psink != nil {
			// ADR 0052 Phase F — audit-only: poll Proxmox into the review queue.
			runPollToPending(runCtx, "proxmox", proxProv.Discover,
				durationFromEnv("JESS_PROXMOX_DISCOVERY_INTERVAL", 5*time.Minute), psink)
			enabled = append(enabled, "proxmox→pending(audit-only)")
		} else {
			// Polled by the Aggregator at the operator's chosen cadence
			// (default 5min — Teleport baseline). Use 0 to fall back to
			// catalog.DefaultRefreshInterval.
			agg.AddProvider(proxProv, durationFromEnv("JESS_PROXMOX_DISCOVERY_INTERVAL", 0))
			// Phase D — Proxmox is poll-based; the 5min poll cadence means a
			// 15min default retirement TTL gives ~3 poll cycles of grace before
			// surfacing a sustained outage as retired-target audit events.
			if ttl := durationFromEnv("JESS_PROXMOX_RETIREMENT_TTL", 0); ttl > 0 {
				agg.SetRetirementTTL(proxProv.Name(), ttl)
			}
			enabled = append(enabled, "proxmox")
		}
	}

	// Phase C (auto-discovery program) — LDAP/AD Computer-object provider.
	// 5-min poll; reads Computer objects from a list of search bases,
	// emits SSH + RDP targets per host. Bind credentials via env (or
	// Vault-mounted secret in the manifests overlay).
	if ldapOn {
		// SEMICOLON-separated (NOT comma): an LDAP DN itself contains commas
		// ("DC=hexxlock,DC=corp"), so comma-splitting shreds a single base into
		// invalid fragments ("DC=hexxlock" → LDAP referral). Multiple bases are
		// separated with ';'. Back-compat: a value with no ';' is one base DN.
		baseDNs := splitOn(os.Getenv("JESS_LDAP_BASE_DNS"), ";")
		if len(baseDNs) == 0 {
			log.Fatal("jess-controller: JESS_LDAP_DISCOVERY=true requires JESS_LDAP_BASE_DNS (semicolon-separated search bases, e.g. \"DC=hexxlock,DC=corp\")")
		}
		var critRules []ldapprovider.CriticalityRule
		// Convention: JESS_LDAP_CRITICALITY_RULES = "Domain Controllers=critical,Exchange=high"
		for _, kv := range splitCSV(os.Getenv("JESS_LDAP_CRITICALITY_RULES")) {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				critRules = append(critRules, ldapprovider.CriticalityRule{
					OUSubstring: strings.TrimSpace(parts[0]),
					Criticality: strings.TrimSpace(parts[1]),
				})
			}
		}
		// LDAPS trust anchor: JESS_LDAP_CA_FILE (PEM) → CABundle so the bind
		// validates the DC's AD-CA-signed cert (drop InsecureSkipVerify). If set
		// but unreadable, fail fast rather than silently falling back to no
		// validation.
		var ldapCA []byte
		if caFile := os.Getenv("JESS_LDAP_CA_FILE"); caFile != "" {
			b, rerr := os.ReadFile(caFile)
			if rerr != nil {
				log.Fatalf("jess-controller: JESS_LDAP_CA_FILE=%q read: %v", caFile, rerr)
			}
			ldapCA = b
		}
		ldapCfg := ldapprovider.Config{
			URL:                envOr("JESS_LDAP_URL", ""),
			BindDN:             os.Getenv("JESS_LDAP_BIND_DN"),
			BindPassword:       os.Getenv("JESS_LDAP_BIND_PASSWORD"),
			BaseDNs:            baseDNs,
			Filter:             os.Getenv("JESS_LDAP_FILTER"),
			InsecureSkipVerify: os.Getenv("JESS_LDAP_INSECURE_SKIP_VERIFY") == "true",
			CABundle:           ldapCA,
			AllowPlaintext:     os.Getenv("JESS_LDAP_ALLOW_PLAINTEXT") == "true",
			EnableSSH:          envOr("JESS_LDAP_ENABLE_SSH", "true") == "true",
			EnableRDP:          envOr("JESS_LDAP_ENABLE_RDP", "true") == "true",
			SSHPort:            intFromEnv("JESS_LDAP_SSH_PORT", 22),
			RDPPort:            intFromEnv("JESS_LDAP_RDP_PORT", 3389),
			DefaultCriticality: envOr("JESS_LDAP_DEFAULT_CRITICALITY", "medium"),
			CriticalityByOU:    critRules,
			ExtraTags:          splitCSV(os.Getenv("JESS_LDAP_EXTRA_TAGS")),
		}
		ldapProv, err := ldapprovider.New(ldapCfg)
		if err != nil {
			log.Fatalf("jess-controller: ldap provider init: %v", err)
		}
		if os.Getenv("JESS_LDAP_DISCOVERY_PENDING") == "true" && psink != nil {
			// ADR 0052 Phase F — AUDIT-ONLY. LDAP discoveries become
			// JessPendingTarget CRs (manual-review queue) instead of brokerable
			// catalog entries. The pending reconciler (Rego) is the ONLY path
			// from discovered → brokerable, so nothing is silently onboarded.
			// Requires JESS_PENDING_RECONCILER_ENABLED (the reconciler) +
			// JESS_CRD_DISCOVERY (so approved JessTargets are read back into the
			// catalog). The poll loop mirrors the Aggregator's cadence.
			runPollToPending(runCtx, "ldap", ldapProv.Discover,
				durationFromEnv("JESS_LDAP_DISCOVERY_INTERVAL", 5*time.Minute), psink)
			enabled = append(enabled, "ldap→pending(audit-only)")
		} else {
			agg.AddProvider(ldapProv, durationFromEnv("JESS_LDAP_DISCOVERY_INTERVAL", 0))
			// Phase D — LDAP/AD is poll-based (5min default); 15min default
			// retirement TTL captures real removal-from-AD events without
			// flapping on a single missed poll.
			if ttl := durationFromEnv("JESS_LDAP_RETIREMENT_TTL", 0); ttl > 0 {
				agg.SetRetirementTTL(ldapProv.Name(), ttl)
			}
			enabled = append(enabled, "ldap")
		}
	}

	go func() {
		// Aggregator.Run owns the poll goroutines for any provider
		// added with positive interval. With everything at -1 or
		// the default it spins until ctx cancel.
		_ = agg.Run(runCtx)
	}()

	log.Printf("jess-controller: catalog Aggregator ENABLED with providers=%v (Phase 7)", enabled)
	return agg, adminProv, func() { cancel() }
}

// catalogAudit bridges catalog.DiffEvent into the existing audit.Sink.
// Action naming follows the rest of jess's convention:
//
//	catalog.diff.added    — provider surfaced a new target
//	catalog.diff.removed  — provider stopped listing a target
//	catalog.diff.changed  — provider re-listed with semantic change
type catalogAudit struct {
	sink audit.Sink
}

func (a catalogAudit) EmitCatalogDiff(ctx context.Context, ev catalog.DiffEvent) {
	if a.sink == nil {
		return
	}
	_ = a.sink.Emit(ctx, audit.Event{
		Time:     ev.At,
		Action:   "catalog.diff." + ev.ChangeType,
		Subject:  "system:catalog-aggregator",
		TargetID: ev.TargetID,
		Err: fmt.Sprintf("provider=%s change=%s id=%s",
			ev.Provider, ev.ChangeType, ev.TargetID),
	})
}

func durationFromEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

func intFromEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string { return splitOn(s, ",") }

// splitOn splits on sep, trims each element, and drops empties. Used with ";"
// for values whose elements themselves contain commas (LDAP base DNs).
func splitOn(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func errIsContextCanceled(err error) bool {
	return err != nil && err.Error() == context.Canceled.Error()
}

// pendingIngester adapts a pending.DiscoverySink to the event-driven providers'
// Sink interface (IngestSnapshot) — so k8s node/service discoveries route to the
// JessPendingTarget review queue (audit-only) instead of the live catalog. The
// k8s providers' Sink interfaces are structurally identical, so one type serves
// both (ADR 0052 Phase F).
type pendingIngester struct{ sink *pending.DiscoverySink }

func (p pendingIngester) IngestSnapshot(ctx context.Context, providerName string, targets []catalog.Target) {
	if _, err := p.sink.Sync(ctx, providerName, targets); err != nil {
		log.Printf("jess-controller: %s pending sync: %v", providerName, err)
	}
}

// runPollToPending polls a poll-based provider's Discover() on interval and
// routes each snapshot into the pending review queue (audit-only). Shared by the
// ldap + proxmox pending paths so the loop lives in one place.
func runPollToPending(runCtx context.Context, name string, discover func(context.Context) ([]catalog.Target, error), interval time.Duration, psink *pending.DiscoverySink) {
	go func() {
		syncOnce := func() {
			cctx, cancel := context.WithTimeout(runCtx, 2*time.Minute)
			defer cancel()
			tgts, err := discover(cctx)
			if err != nil {
				log.Printf("jess-controller: %s pending discover: %v", name, err)
				return
			}
			if _, err := psink.Sync(cctx, name, tgts); err != nil {
				log.Printf("jess-controller: %s pending sync: %v", name, err)
			}
		}
		syncOnce() // initial sweep on startup
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-tk.C:
				syncOnce()
			}
		}
	}()
}

// label suffixes a provider's display name with the audit-only marker when it's
// routed to the pending review queue rather than the live catalog.
func label(name string, auditOnly bool) string {
	if auditOnly {
		return name + "→pending(audit-only)"
	}
	return name
}
