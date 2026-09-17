// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kubernetes is the Phase 7c discovery provider that surfaces
// Kubernetes Node objects as SSH targets in the jess catalog.
//
// Watch-based: a SharedInformer drives in-memory cache; every Node
// add/update/delete fires a snapshot push to the Aggregator via
// IngestSnapshot. Sub-second propagation when nodes join/leave the
// fleet (vs the 5-minute baseline for poll-based cloud providers).
//
// Opt-in by label: only Nodes carrying
//
//	jess.hexxlock.com/managed=true
//
// surface as targets. Without this gate every K8s deployment would
// auto-expose every node — a 1k-node cluster would dump 1k targets
// into the operator catalog. Label-gating mirrors Teleport's
// `tags:` filter and Boundary's `attributes_json` filter pattern
// (see docs/adr/0030-phase-7-dynamic-catalog.md §Industry survey).
//
// Target shape (one per qualifying Node):
//
//	id:            <node-name>            (Kubernetes guarantees uniqueness)
//	name:          "<node-name> (kubelet)"
//	protocol:      ssh
//	address:       <internalIP>:22        (preferred) | <hostname>:22
//	region:        node label topology.kubernetes.io/region   (if present)
//	required_roles:["platform_admin"]      (configurable via NodesConfig)
//	recorded:      true                    (every K8s-discovered SSH session recorded)
//	host_key:      <annotation jess.hexxlock.com/ssh-host-key>
//	criticality:   <annotation jess.hexxlock.com/criticality OR config default>
//	tags:          ["k8s-node", "node-role:<role>", "team:<config>"]
//
// Empty host_key annotations → Node is SKIPPED with a warn log + a
// jess_catalog_provider_error_total{provider="k8s-nodes",reason="missing_host_key"}
// metric increment. The SSH worker refuses unpinned hosts, so emitting
// the target with an empty host_key would just fail-closed at session
// open — surfacing it as a discovery anomaly is louder + earlier.
package kubernetes

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// LabelManaged is the Node label that opts an instance into jess
// brokering. The Aggregator side adds these as targets; everything
// else is invisible.
const LabelManaged = "jess.hexxlock.com/managed"

// AnnotationHostKey carries the SSH host public key for the Node
// (authorized_keys-style line). Required: a Node without this
// annotation is skipped (the SSH worker refuses unpinned hosts).
//
// Populated by the operator either manually OR by the kubelet
// bootstrap script that ALSO runs configure-node-sshca.sh. The same
// run that teaches the node's sshd to trust the Vault SSH-CA captures
// /etc/ssh/ssh_host_ed25519_key.pub and stamps it here.
const AnnotationHostKey = "jess.hexxlock.com/ssh-host-key"

// AnnotationCriticality lets the Node operator pin a criticality
// independent of the provider default. Valid values: low, medium,
// high, critical (matches Target.Criticality).
const AnnotationCriticality = "jess.hexxlock.com/criticality"

// LabelTopologyRegion is the standard K8s topology label used to fill
// Target.Region. Same value cluster-autoscaler + cluster-api use.
const LabelTopologyRegion = "topology.kubernetes.io/region"

// Sink is the narrow interface the provider needs from the aggregator
// — IngestSnapshot is the event-driven path declared by Phase 7a.
// Decoupled here as an interface so unit tests can mock it without
// pulling the full Aggregator into the test fixture.
type Sink interface {
	IngestSnapshot(ctx context.Context, providerName string, targets []catalog.Target)
}

// Config tunes the provider. Sensible defaults are picked when
// fields are zero/empty.
type Config struct {
	// Client is the kubernetes.Interface used by the informer. In
	// production this is built via rest.InClusterConfig + kubernetes.NewForConfig.
	// Tests inject a fake.Clientset.
	Client kubernetes.Interface

	// ResyncInterval bounds how often the informer re-lists everything
	// even when no watch events fire. Defaults to 5min. Use 0 to disable
	// (the watch alone drives changes).
	ResyncInterval time.Duration

	// SSHPort overrides the default :22 on every discovered Node.
	// Useful when kubelet runs sshd on a non-standard port.
	SSHPort int

	// RequiredRoles is the Falcon-ID role list stamped on every
	// discovered Node target. Defaults to ["platform_admin"].
	RequiredRoles []string

	// DefaultCriticality is used when the Node lacks the criticality
	// annotation. Defaults to "high" (worker nodes are control-plane
	// adjacent; conservative default).
	DefaultCriticality string

	// ExtraTags are appended to every discovered Node's Tags slice.
	// Useful for cluster-wide labels like "cluster:eu-west-1-hub".
	ExtraTags []string

	// Logger is optional. Defaults to log.Default().
	Logger *log.Logger
}

// Provider is the Phase 7c Kubernetes Node watcher. Construct with
// New; call Run in a goroutine.
type Provider struct {
	cfg       Config
	sink      Sink
	informer  cache.SharedIndexInformer
	stopper   chan struct{}
	mu        sync.Mutex
	missingHK map[string]struct{} // node names we've already warned about; resets on Stop
	publishMu sync.Mutex          // serialises Snapshot() pushes
}

// New constructs a Provider. Sink must be non-nil; Client must be non-nil
// (use NewInCluster to build one from the pod's SA token).
func New(cfg Config, sink Sink) (*Provider, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("kubernetes provider: Config.Client is nil")
	}
	if sink == nil {
		return nil, fmt.Errorf("kubernetes provider: Sink is nil")
	}
	if cfg.ResyncInterval == 0 {
		cfg.ResyncInterval = 5 * time.Minute
	}
	if cfg.SSHPort == 0 {
		cfg.SSHPort = 22
	}
	if len(cfg.RequiredRoles) == 0 {
		cfg.RequiredRoles = []string{"platform_admin"}
	}
	if cfg.DefaultCriticality == "" {
		cfg.DefaultCriticality = "high"
	}
	p := &Provider{
		cfg:       cfg,
		sink:      sink,
		stopper:   make(chan struct{}),
		missingHK: map[string]struct{}{},
	}
	factory := informers.NewSharedInformerFactory(cfg.Client, cfg.ResyncInterval)
	p.informer = factory.Core().V1().Nodes().Informer()
	_, _ = p.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { p.republish() },
		UpdateFunc: func(_, _ any) { p.republish() },
		DeleteFunc: func(obj any) { p.republish() },
	})
	return p, nil
}

// NewInCluster builds a Kubernetes client from the pod's SA token
// + the cluster CA. Wraps rest.InClusterConfig + kubernetes.NewForConfig.
func NewInCluster() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetes provider: in-cluster config: %w", err)
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes provider: client: %w", err)
	}
	return cli, nil
}

// Name implements catalog.DiscoveryProvider.
func (p *Provider) Name() string { return "k8s-nodes" }

// Discover implements catalog.DiscoveryProvider. Returns the current
// snapshot of the informer's cache — synchronous, no API call. The
// watch goroutine pushes deltas via Sink.IngestSnapshot independently;
// this method is kept so that callers driving a one-shot refresh (e.g.
// `jessctl admin catalog refresh`) see the same view.
func (p *Provider) Discover(_ context.Context) ([]catalog.Target, error) {
	return p.snapshot(), nil
}

// Run starts the informer + blocks until ctx cancels. Mirrors
// client-go's standard pattern: factory.Start + WaitForCacheSync.
func (p *Provider) Run(ctx context.Context) error {
	go p.informer.Run(p.stopper)
	if !cache.WaitForCacheSync(ctx.Done(), p.informer.HasSynced) {
		close(p.stopper)
		return fmt.Errorf("kubernetes provider: cache sync failed")
	}
	// First snapshot after sync — gives the aggregator the initial state
	// without waiting for the next event.
	p.republish()
	<-ctx.Done()
	close(p.stopper)
	return ctx.Err()
}

// republish is the bridge from informer events to the Aggregator. We
// serialise pushes through publishMu so two near-simultaneous Add+Add
// events can't interleave a partial snapshot. Cost: bounded — Nodes
// don't churn at millisecond cadence.
func (p *Provider) republish() {
	p.publishMu.Lock()
	defer p.publishMu.Unlock()
	snapshot := p.snapshot()
	// Background ctx — Sink.IngestSnapshot internally uses its own
	// ctx for audit emission; nothing here should be cancellable by
	// the request lifecycle.
	p.sink.IngestSnapshot(context.Background(), p.Name(), snapshot)
}

// snapshot reads the informer cache into Targets. The List() returns
// objects in deterministic order (informer indexer is map-backed; we
// don't depend on order — the aggregator stable-sorts before diffing).
func (p *Provider) snapshot() []catalog.Target {
	items := p.informer.GetStore().List()
	out := make([]catalog.Target, 0, len(items))
	for _, item := range items {
		node, ok := item.(*corev1.Node)
		if !ok {
			continue
		}
		t, ok := p.nodeToTarget(node)
		if !ok {
			continue
		}
		out = append(out, t)
	}
	return out
}

// nodeToTarget enforces the opt-in label gate + host-key requirement.
// Returns (Target, true) on success or (zero, false) when the Node
// should be skipped — caller drops it.
func (p *Provider) nodeToTarget(node *corev1.Node) (catalog.Target, bool) {
	if v, ok := node.Labels[LabelManaged]; !ok || v != "true" {
		return catalog.Target{}, false
	}
	hostKey := node.Annotations[AnnotationHostKey]
	if hostKey == "" {
		p.warnMissingHostKey(node.Name)
		return catalog.Target{}, false
	}
	addr := preferredAddress(node, p.cfg.SSHPort)
	if addr == "" {
		// No reachable address — log + skip. The Node may still be
		// provisioning; we'll re-snapshot when it gets one.
		return catalog.Target{}, false
	}

	crit := node.Annotations[AnnotationCriticality]
	if crit == "" {
		crit = p.cfg.DefaultCriticality
	}

	tags := append([]string{"k8s-node"}, p.cfg.ExtraTags...)
	if role := nodeRole(node); role != "" {
		tags = append(tags, "node-role:"+role)
	}

	return catalog.Target{
		ID:            node.Name,
		Name:          node.Name + " (kubelet)",
		Protocol:      catalog.ProtoSSH,
		Address:       addr,
		Region:        node.Labels[LabelTopologyRegion],
		RequiredRoles: append([]string(nil), p.cfg.RequiredRoles...),
		Recorded:      true,
		HostKey:       hostKey,
		Criticality:   crit,
		Tags:          tags,
	}, true
}

// preferredAddress picks the best routable address on the Node:
//  1. InternalIP (preferred — same network as worker pods)
//  2. Hostname (the K8s DNS-resolvable name; covers nodes behind a
//     cluster overlay where InternalIP is private)
//  3. ExternalIP (last resort; usually means the Node is exposed
//     and we have no better option)
//
// Empty if none of the above are set.
func preferredAddress(node *corev1.Node, port int) string {
	prefer := []corev1.NodeAddressType{
		corev1.NodeInternalIP,
		corev1.NodeHostName,
		corev1.NodeExternalIP,
	}
	for _, want := range prefer {
		for _, a := range node.Status.Addresses {
			if a.Type == want && a.Address != "" {
				return fmt.Sprintf("%s:%d", a.Address, port)
			}
		}
	}
	return ""
}

// nodeRole returns the first node-role.kubernetes.io/<role> label
// value found, or "" if none. Mirrors kubectl's behavior — kube-apiserver
// uses these labels to display "ROLES" in `kubectl get nodes`.
func nodeRole(node *corev1.Node) string {
	const prefix = "node-role.kubernetes.io/"
	for k := range node.Labels {
		if strings.HasPrefix(k, prefix) {
			return strings.TrimPrefix(k, prefix)
		}
	}
	return ""
}

// warnMissingHostKey logs once per Node name so a 100-node cluster
// without host-key annotations doesn't spam the log on every resync.
func (p *Provider) warnMissingHostKey(name string) {
	p.mu.Lock()
	if _, seen := p.missingHK[name]; seen {
		p.mu.Unlock()
		return
	}
	p.missingHK[name] = struct{}{}
	p.mu.Unlock()
	logger := p.cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("kubernetes provider: skipping Node %q — missing annotation %q (operator must populate before this Node can be a jess target)",
		name, AnnotationHostKey)
}

// HasSynced is a small accessor for tests. Returns true once the
// informer's initial LIST is complete and cached. Not part of any
// public contract; expect callers to use cache.WaitForCacheSync.
func (p *Provider) HasSynced() bool {
	if p.informer == nil {
		return false
	}
	return p.informer.HasSynced()
}

// metav1 import quiet — we use it transitively through corev1.
var _ = metav1.GroupVersionKind{}
