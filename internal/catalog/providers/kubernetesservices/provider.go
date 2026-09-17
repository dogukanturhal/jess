// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kubernetesservices is the Phase B (auto-discovery) provider that
// surfaces Kubernetes Service objects as jess catalog targets — covering the
// "in-cluster privileged endpoint" case the existing providers/kubernetes
// (Node-only) provider doesn't.
//
// Most operator-tier targets in jess's estate live as in-cluster Services:
// CNPG Postgres clusters, MySQL pools, Redis primaries, internal HTTPS admin
// surfaces. Each ships a v1.Service with a stable ClusterIP. Annotating it
// with `jess.hexxlock.com/protocol=postgres|mysql|ssh|rdp|tcp` makes the
// service auto-onboard into the catalog with zero configmap edits.
//
// Watch-based: SharedInformer drives the cache; every Service add/update/
// delete pushes a snapshot to the Aggregator via Sink.IngestSnapshot.
// Sub-second propagation matches the existing providers/kubernetes pattern.
//
// Annotation surface:
//
//	jess.hexxlock.com/protocol         REQUIRED: ssh, postgres, mysql, rdp, tcp
//	jess.hexxlock.com/port-name        OPTIONAL: name of Service.spec.ports[*]
//	                                   to use (default: first port; if multiple,
//	                                   provider warns once + uses first)
//	jess.hexxlock.com/criticality      OPTIONAL: low, medium, high, critical
//	                                   (default: medium for in-cluster targets;
//	                                   they typically live ≥ a node hop behind
//	                                   meshed mTLS, not at the root of trust)
//	jess.hexxlock.com/required-roles   OPTIONAL: comma-separated Falcon-ID role
//	                                   names (default: ["platform_admin"])
//	jess.hexxlock.com/recorded         OPTIONAL: "true"/"false" (default: true)
//	jess.hexxlock.com/database         OPTIONAL: default db/schema for DB targets
//	jess.hexxlock.com/host-key         OPTIONAL: SSH authorized_keys line (for ssh)
//	jess.hexxlock.com/host-key-ca-signed OPTIONAL: "true" → ADR 0044 CA mode
//	jess.hexxlock.com/tags             OPTIONAL: comma-separated tags (appended
//	                                             to the always-on ["k8s-service",
//	                                             "ns:<ns>"])
//	jess.hexxlock.com/region           OPTIONAL: multi-region scope
//
// SSH targets need either host-key OR host-key-ca-signed=true — otherwise the
// service is SKIPPED with a warn log + metric increment (mirrors the kubelet-
// node provider's missing-host-key handling). DB / RDP / TCP don't need
// host-key annotations.
//
// Why annotation-driven instead of a CRD-watch?
//   - Services already exist in every namespace; annotating one is a single
//     line in the existing Helm chart / kustomize patch.
//   - A CRD (JessTarget) is the right surface for STANDALONE catalog entries
//     that aren't backed by a Service (external SSH hosts, Proxmox VMs); the
//     two providers compose cleanly via the Aggregator's first-wins ordering.
//
// Target ID shape: `k8s-svc-<namespace>-<service-name>` — cluster-unique
// because (namespace, name) is unique in K8s.
package kubernetesservices

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/dogukanturhal/jess/internal/catalog"
)

const (
	AnnotationProtocol        = "jess.hexxlock.com/protocol"
	AnnotationPortName        = "jess.hexxlock.com/port-name"
	AnnotationCriticality     = "jess.hexxlock.com/criticality"
	AnnotationRequiredRoles   = "jess.hexxlock.com/required-roles"
	AnnotationRecorded        = "jess.hexxlock.com/recorded"
	AnnotationDatabase        = "jess.hexxlock.com/database"
	AnnotationHostKey         = "jess.hexxlock.com/host-key"
	AnnotationHostKeyCASigned = "jess.hexxlock.com/host-key-ca-signed"
	AnnotationSSHLoginUser    = "jess.hexxlock.com/ssh-login-user"
	AnnotationTags            = "jess.hexxlock.com/tags"
	AnnotationRegion          = "jess.hexxlock.com/region"
)

// Sink mirrors providers/kubernetes — narrowest interface from the Aggregator.
type Sink interface {
	IngestSnapshot(ctx context.Context, providerName string, targets []catalog.Target)
}

type Config struct {
	Client             kubernetes.Interface
	ResyncInterval     time.Duration
	DefaultCriticality string   // default "medium" — in-cluster targets sit behind mesh
	RequiredRoles      []string // default ["platform_admin"]
	ExtraTags          []string
	Namespace          string // optional namespace filter; "" = cluster-wide
	Logger             *log.Logger
}

type Provider struct {
	cfg      Config
	sink     Sink
	informer cache.SharedIndexInformer
	stopper  chan struct{}

	// Suppress repeated "missing required attribute" warns per service.
	mu              sync.Mutex
	missingProto    map[string]struct{} // services that have NO protocol annotation (silent skip)
	missingHostKey  map[string]struct{} // SSH services with no host-key + no CA-signed flag
	multiPortWarned map[string]struct{} // services with multi-port + no port-name annotation

	publishMu sync.Mutex
}

func New(cfg Config, sink Sink) (*Provider, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("kubernetesservices: Config.Client is nil")
	}
	if sink == nil {
		return nil, fmt.Errorf("kubernetesservices: Sink is nil")
	}
	if cfg.ResyncInterval == 0 {
		cfg.ResyncInterval = 5 * time.Minute
	}
	if cfg.DefaultCriticality == "" {
		cfg.DefaultCriticality = "medium"
	}
	if len(cfg.RequiredRoles) == 0 {
		cfg.RequiredRoles = []string{"platform_admin"}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	p := &Provider{
		cfg:             cfg,
		sink:            sink,
		stopper:         make(chan struct{}),
		missingProto:    map[string]struct{}{},
		missingHostKey:  map[string]struct{}{},
		multiPortWarned: map[string]struct{}{},
	}
	var factory informers.SharedInformerFactory
	if cfg.Namespace != "" {
		factory = informers.NewSharedInformerFactoryWithOptions(
			cfg.Client, cfg.ResyncInterval, informers.WithNamespace(cfg.Namespace))
	} else {
		factory = informers.NewSharedInformerFactory(cfg.Client, cfg.ResyncInterval)
	}
	p.informer = factory.Core().V1().Services().Informer()
	_, _ = p.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ any) { p.republish() },
		UpdateFunc: func(_, _ any) { p.republish() },
		DeleteFunc: func(_ any) { p.republish() },
	})
	return p, nil
}

// NewInCluster builds a Kubernetes client from the pod's SA token.
func NewInCluster() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetesservices: in-cluster config: %w", err)
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetesservices: client: %w", err)
	}
	return cli, nil
}

// Name implements catalog.DiscoveryProvider.
func (*Provider) Name() string { return "k8s-services" }

// Discover implements catalog.DiscoveryProvider — synchronous snapshot of
// the informer cache.
func (p *Provider) Discover(_ context.Context) ([]catalog.Target, error) {
	return p.snapshot(), nil
}

// Run blocks until ctx is cancelled. Mirrors the providers/kubernetes pattern.
func (p *Provider) Run(ctx context.Context) error {
	go p.informer.Run(p.stopper)
	if !cache.WaitForCacheSync(ctx.Done(), p.informer.HasSynced) {
		close(p.stopper)
		return fmt.Errorf("kubernetesservices: cache sync failed")
	}
	p.republish()
	<-ctx.Done()
	close(p.stopper)
	return ctx.Err()
}

func (p *Provider) republish() {
	p.publishMu.Lock()
	defer p.publishMu.Unlock()
	p.sink.IngestSnapshot(context.Background(), p.Name(), p.snapshot())
}

func (p *Provider) snapshot() []catalog.Target {
	items := p.informer.GetStore().List()
	out := make([]catalog.Target, 0, len(items))
	for _, item := range items {
		svc, ok := item.(*corev1.Service)
		if !ok {
			continue
		}
		t, ok := p.svcToTarget(svc)
		if !ok {
			continue
		}
		out = append(out, t)
	}
	return out
}

// svcToTarget maps an annotated Service into a Target. Returns ok=false to
// silently skip (no protocol annotation = not opted in).
func (p *Provider) svcToTarget(svc *corev1.Service) (catalog.Target, bool) {
	key := svc.Namespace + "/" + svc.Name
	protoRaw := strings.TrimSpace(svc.Annotations[AnnotationProtocol])
	if protoRaw == "" {
		// Not opted in — silent skip (no warning; most services are
		// genuinely uninteresting to jess).
		return catalog.Target{}, false
	}
	proto, ok := protocolFor(protoRaw)
	if !ok {
		p.warnInvalidProtoOnce(key, protoRaw)
		return catalog.Target{}, false
	}

	port, ok := p.resolvePort(svc, key)
	if !ok {
		return catalog.Target{}, false
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		// Headless or unallocated — addr would be empty. ClusterIP-based
		// addressing is the contract; headless services need
		// EndpointSlice-based resolution (future-work).
		return catalog.Target{}, false
	}
	addr := fmt.Sprintf("%s:%d", svc.Spec.ClusterIP, port)

	hostKey := strings.TrimSpace(svc.Annotations[AnnotationHostKey])
	caSigned := strings.EqualFold(strings.TrimSpace(svc.Annotations[AnnotationHostKeyCASigned]), "true")
	if proto == catalog.ProtoSSH && hostKey == "" && !caSigned {
		p.warnMissingHostKeyOnce(key)
		return catalog.Target{}, false
	}

	crit := strings.TrimSpace(svc.Annotations[AnnotationCriticality])
	if crit == "" {
		crit = p.cfg.DefaultCriticality
	}

	roles := splitCSV(svc.Annotations[AnnotationRequiredRoles])
	if len(roles) == 0 {
		roles = append([]string(nil), p.cfg.RequiredRoles...)
	}

	recorded := true
	if v := strings.TrimSpace(svc.Annotations[AnnotationRecorded]); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			recorded = b
		}
	}

	tags := append([]string{"k8s-service", "ns:" + svc.Namespace}, p.cfg.ExtraTags...)
	tags = append(tags, splitCSV(svc.Annotations[AnnotationTags])...)

	return catalog.Target{
		ID:              "k8s-svc-" + svc.Namespace + "-" + svc.Name,
		Name:            fmt.Sprintf("%s/%s (k8s Service)", svc.Namespace, svc.Name),
		Protocol:        proto,
		Address:         addr,
		Region:          strings.TrimSpace(svc.Annotations[AnnotationRegion]),
		RequiredRoles:   roles,
		Recorded:        recorded,
		HostKey:         hostKey,
		HostKeyCASigned: caSigned,
		SSHLoginUser:    strings.TrimSpace(svc.Annotations[AnnotationSSHLoginUser]),
		Database:        strings.TrimSpace(svc.Annotations[AnnotationDatabase]),
		Criticality:     crit,
		Tags:            tags,
	}, true
}

// resolvePort picks the Service port to dial. If the annotation pins a port
// by name, use that exactly. Otherwise pick the first port — if there's more
// than one we warn once so operators know to disambiguate.
func (p *Provider) resolvePort(svc *corev1.Service, key string) (int32, bool) {
	if len(svc.Spec.Ports) == 0 {
		return 0, false
	}
	if pinned := strings.TrimSpace(svc.Annotations[AnnotationPortName]); pinned != "" {
		for _, sp := range svc.Spec.Ports {
			if sp.Name == pinned {
				return sp.Port, true
			}
		}
		// Pinned port name doesn't exist — fail closed (don't silently use port 0).
		p.warnInvalidPortOnce(key, pinned)
		return 0, false
	}
	if len(svc.Spec.Ports) > 1 {
		p.warnMultiPortOnce(key)
	}
	return svc.Spec.Ports[0].Port, true
}

func protocolFor(s string) (catalog.Protocol, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ssh":
		return catalog.ProtoSSH, true
	case "postgres", "postgresql":
		return catalog.ProtoPostgres, true
	case "mysql":
		return catalog.ProtoMySQL, true
	case "rdp":
		return catalog.ProtoRDP, true
	case "tcp":
		return catalog.ProtoTCP, true
	}
	return "", false
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (p *Provider) warnInvalidProtoOnce(key, val string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.missingProto[key]; seen {
		return
	}
	p.missingProto[key] = struct{}{}
	p.cfg.Logger.Printf("kubernetesservices: %s — invalid protocol %q (expected ssh/postgres/mysql/rdp/tcp)", key, val)
}

func (p *Provider) warnMissingHostKeyOnce(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.missingHostKey[key]; seen {
		return
	}
	p.missingHostKey[key] = struct{}{}
	p.cfg.Logger.Printf("kubernetesservices: %s — SSH service missing host-key annotation (and host-key-ca-signed!=true) — skipping (jess refuses unpinned SSH hosts)", key)
}

func (p *Provider) warnMultiPortOnce(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.multiPortWarned[key]; seen {
		return
	}
	p.multiPortWarned[key] = struct{}{}
	p.cfg.Logger.Printf("kubernetesservices: %s — multiple Service ports + no jess.hexxlock.com/port-name annotation; using ports[0]", key)
}

func (p *Provider) warnInvalidPortOnce(key, pinned string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.multiPortWarned[key+"|"+pinned]; seen {
		return
	}
	p.multiPortWarned[key+"|"+pinned] = struct{}{}
	p.cfg.Logger.Printf("kubernetesservices: %s — jess.hexxlock.com/port-name=%q does not match any Service port; skipping", key, pinned)
}
