// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jesstargetcrd is the Phase 7e discovery provider that
// surfaces JessTarget CustomResources as catalog targets.
//
// Why a CRD at all
// ================
// 7c (Kubernetes Node watch) + 7b (Proxmox API) handle compute that
// already exists in another inventory. But a customer running
// Terraform / Cluster-API / cluster-autoscaler creates infrastructure
// resources alongside their config; they want jess to KNOW about
// those targets at the same time, from the same git push, without a
// second hop through a ConfigMap MR.
//
// The CR is the source of truth. This provider just watches it and
// projects the spec into a catalog.Target.
//
// Implementation choice: dynamic client over the JessTarget GVR. No
// generated client code (kubebuilder/code-generator are heavyweight
// for a 1-Kind API). The unstructured.Unstructured shape is decoded
// inline through a small `unstructuredToTarget` helper — short
// enough that the maintenance cost matches a code-generated path
// without the toolchain overhead.
//
// Watch-based: same pattern as the 7c Node watcher. Every CR
// add/update/delete republishes a snapshot to the Aggregator via
// IngestSnapshot. Sub-second propagation when CRs are kubectl-applied.
//
// Target shape (one per JessTarget CR):
//
//	id:                     <metadata.name>      (cluster-unique by k8s)
//	name:                   spec.name OR <metadata.name>
//	protocol:               spec.protocol         (ssh/postgres/...)
//	address:                spec.address
//	region:                 spec.region
//	required_roles:         spec.required_roles
//	recorded:               spec.recorded (default true)
//	host_key:               spec.host_key
//	database:               spec.database
//	criticality:            spec.criticality (default medium)
//	tags:                   ["jess-target-crd", ...spec.tags]
//	require_device_claims:  spec.require_device_claims
//
// Missing or malformed CRs are skipped with a once-per-name warn log
// (avoid spamming the controller log on every resync). The Aggregator
// still serves the rest of the cache; partial visibility > total
// blackout.
package jesstargetcrd

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// GroupVersionResource for the JessTarget CRD. Cluster-scoped.
var GVR = schema.GroupVersionResource{
	Group:    "jess.hexxlock.com",
	Version:  "v1alpha1",
	Resource: "jesstargets",
}

// Sink mirrors the contract used by other event-driven providers
// (7c Kubernetes, 7f admin-api). Allows tests to mock without
// pulling the full Aggregator.
type Sink interface {
	IngestSnapshot(ctx context.Context, providerName string, targets []catalog.Target)
}

// Config tunes the provider.
type Config struct {
	// Client is the dynamic.Interface used for the informer. In
	// production this is built via rest.InClusterConfig +
	// dynamic.NewForConfig. Tests inject a fake dynamic client.
	Client dynamic.Interface

	// ResyncInterval bounds how often the informer re-lists even
	// when no watch events fire. Defaults to 5min. 0 disables (watch
	// alone drives changes).
	ResyncInterval time.Duration

	// Logger optional; defaults to log.Default().
	Logger *log.Logger
}

// Provider implements catalog.DiscoveryProvider over a JessTarget
// dynamic informer.
type Provider struct {
	cfg       Config
	sink      Sink
	informer  cache.SharedIndexInformer
	stopper   chan struct{}
	mu        sync.Mutex
	skipped   map[string]struct{} // names we've already warned about (malformed CRs)
	publishMu sync.Mutex
}

// New constructs the Provider.
func New(cfg Config, sink Sink) (*Provider, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("jesstargetcrd: Config.Client is nil")
	}
	if sink == nil {
		return nil, fmt.Errorf("jesstargetcrd: Sink is nil")
	}
	if cfg.ResyncInterval == 0 {
		cfg.ResyncInterval = 5 * time.Minute
	}
	p := &Provider{
		cfg:     cfg,
		sink:    sink,
		stopper: make(chan struct{}),
		skipped: map[string]struct{}{},
	}
	factory := dynamicinformer.NewDynamicSharedInformerFactory(cfg.Client, cfg.ResyncInterval)
	p.informer = factory.ForResource(GVR).Informer()
	_, _ = p.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ any) { p.republish() },
		UpdateFunc: func(_, _ any) { p.republish() },
		DeleteFunc: func(_ any) { p.republish() },
	})
	return p, nil
}

// NewInCluster builds a dynamic client from the pod's SA token + the
// cluster CA. Wraps rest.InClusterConfig + dynamic.NewForConfig.
func NewInCluster() (dynamic.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("jesstargetcrd: in-cluster config: %w", err)
	}
	cli, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("jesstargetcrd: dynamic client: %w", err)
	}
	return cli, nil
}

// Name implements catalog.DiscoveryProvider.
func (*Provider) Name() string { return "jess-target-crd" }

// Discover implements catalog.DiscoveryProvider. Returns the current
// snapshot of the informer's cache — synchronous, no API call.
func (p *Provider) Discover(_ context.Context) ([]catalog.Target, error) {
	return p.snapshot(), nil
}

// Run starts the informer + blocks until ctx cancels. Mirrors
// client-go's standard pattern.
func (p *Provider) Run(ctx context.Context) error {
	go p.informer.Run(p.stopper)
	if !cache.WaitForCacheSync(ctx.Done(), p.informer.HasSynced) {
		close(p.stopper)
		return fmt.Errorf("jesstargetcrd: cache sync failed")
	}
	// Initial snapshot once the informer has populated its cache —
	// gives the Aggregator the steady-state view without waiting
	// for the next CR event.
	p.republish()
	<-ctx.Done()
	close(p.stopper)
	return ctx.Err()
}

// republish serialises pushes to the Aggregator so two near-
// simultaneous informer events can't interleave a partial snapshot.
func (p *Provider) republish() {
	p.publishMu.Lock()
	defer p.publishMu.Unlock()
	p.sink.IngestSnapshot(context.Background(), p.Name(), p.snapshot())
}

// snapshot reads the informer cache into Targets.
func (p *Provider) snapshot() []catalog.Target {
	items := p.informer.GetStore().List()
	out := make([]catalog.Target, 0, len(items))
	for _, item := range items {
		u, ok := item.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		t, ok := p.unstructuredToTarget(u)
		if !ok {
			continue
		}
		out = append(out, t)
	}
	return out
}

// unstructuredToTarget decodes a JessTarget CR into a catalog.Target.
// Returns (Target, false) on missing required fields so the caller
// drops the entry.
func (p *Provider) unstructuredToTarget(u *unstructured.Unstructured) (catalog.Target, bool) {
	name := u.GetName()
	if name == "" {
		// Defensive; the API server doesn't admit a CR without metadata.name.
		return catalog.Target{}, false
	}
	spec, ok, _ := unstructured.NestedMap(u.Object, "spec")
	if !ok {
		p.warnSkipOnce(name, "missing spec")
		return catalog.Target{}, false
	}
	protocol, _, _ := unstructured.NestedString(spec, "protocol")
	address, _, _ := unstructured.NestedString(spec, "address")
	if protocol == "" || address == "" {
		p.warnSkipOnce(name, "spec.protocol and spec.address are required")
		return catalog.Target{}, false
	}
	displayName, _, _ := unstructured.NestedString(spec, "name")
	if displayName == "" {
		displayName = name
	}
	region, _, _ := unstructured.NestedString(spec, "region")
	hostKey, _, _ := unstructured.NestedString(spec, "host_key")
	hostKeyCASigned, _, _ := unstructured.NestedBool(spec, "host_key_ca_signed")
	sshLoginUser, _, _ := unstructured.NestedString(spec, "ssh_login_user")
	database, _, _ := unstructured.NestedString(spec, "database")
	criticality, _, _ := unstructured.NestedString(spec, "criticality")
	if criticality == "" {
		criticality = "medium"
	}

	// recorded — default true (matches CRD schema default + the
	// fail-closed posture of the rest of jess).
	recorded := true
	if v, found, _ := unstructured.NestedBool(spec, "recorded"); found {
		recorded = v
	}

	requiredRoles, _, _ := unstructured.NestedStringSlice(spec, "required_roles")
	if requiredRoles == nil {
		requiredRoles = []string{}
	}

	tags, _, _ := unstructured.NestedStringSlice(spec, "tags")
	combinedTags := append([]string{"jess-target-crd"}, tags...)

	// offline_credentials — DDIL P3.8 opt-in (ADR 0062). Absent ⇒ nil ⇒ not
	// eligible (the safe default). A malformed sub-field degrades to the zero
	// value for that field rather than dropping the whole target.
	var offlineCreds *catalog.OfflineCredentialsPolicy
	if oc, found, _ := unstructured.NestedMap(spec, "offline_credentials"); found {
		enabled, _, _ := unstructured.NestedBool(oc, "enabled")
		maxUses64, _, _ := unstructured.NestedInt64(oc, "max_uses")
		// max_ttl is a Go duration string (e.g. "4h", "90m"); ParseDuration
		// failures leave it 0 ⇒ the manager applies its default.
		var maxTTL time.Duration
		if s, _, _ := unstructured.NestedString(oc, "max_ttl"); s != "" {
			if d, perr := time.ParseDuration(s); perr == nil {
				maxTTL = d
			} else {
				p.warnSkipOnce(name+"/offline_credentials.max_ttl", "invalid duration "+s+" (ignored)")
			}
		}
		offlineCreds = &catalog.OfflineCredentialsPolicy{
			Enabled: enabled,
			MaxTTL:  maxTTL,
			MaxUses: int(maxUses64),
		}
	}

	// require_device_claims — array of {claim, valuesAnyOf} objects.
	var deviceClaims []catalog.DeviceClaimRequirement
	if rawDC, found, _ := unstructured.NestedSlice(spec, "require_device_claims"); found {
		for _, raw := range rawDC {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			claim, _ := m["claim"].(string)
			if claim == "" {
				continue
			}
			var vals []string
			if rawVals, isSlice := m["valuesAnyOf"].([]any); isSlice {
				for _, v := range rawVals {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
			}
			deviceClaims = append(deviceClaims, catalog.DeviceClaimRequirement{
				Claim:       claim,
				ValuesAnyOf: vals,
			})
		}
	}

	return catalog.Target{
		ID:                  name,
		Name:                displayName,
		Protocol:            catalog.Protocol(protocol),
		Address:             address,
		Region:              region,
		RequiredRoles:       requiredRoles,
		Recorded:            recorded,
		HostKey:             hostKey,
		HostKeyCASigned:     hostKeyCASigned,
		SSHLoginUser:        sshLoginUser,
		Database:            database,
		Criticality:         criticality,
		Tags:                combinedTags,
		RequireDeviceClaims: deviceClaims,
		OfflineCredentials:  offlineCreds,
	}, true
}

// warnSkipOnce logs once per CR name per process lifetime. Stops a
// chronically-malformed CR from spamming every resync.
func (p *Provider) warnSkipOnce(name, reason string) {
	p.mu.Lock()
	if _, seen := p.skipped[name]; seen {
		p.mu.Unlock()
		return
	}
	p.skipped[name] = struct{}{}
	p.mu.Unlock()
	logger := p.cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("jesstargetcrd: skipping JessTarget %q: %s", name, reason)
}

// HasSynced surfaces the informer state for tests + readiness checks.
// Returns false until the initial LIST is complete and cached.
func (p *Provider) HasSynced() bool {
	if p.informer == nil {
		return false
	}
	return p.informer.HasSynced()
}

// metav1 import kept alive (we use it transitively via unstructured).
var _ = metav1.ObjectMeta{}
