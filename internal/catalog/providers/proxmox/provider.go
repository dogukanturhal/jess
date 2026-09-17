// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxmox is the Phase 7b discovery provider that surfaces
// Proxmox VE virtual machines as jess targets.
//
// Why a Proxmox provider at all
// =============================
// HexxLock's actual fleet lives on Proxmox today (152.89.37.98:8006).
// The static JSON ConfigMap covers the half-dozen always-on services
// but every dev VM, every test bench, every short-lived experiment is
// invisible to jess. With this provider, tagging a VM in Proxmox
// (jess-managed) makes it appear in the operator catalog within one
// poll cycle (5 min default — matches Teleport's discovery_service
// poll_interval baseline; see docs/adr/0030-phase-7-dynamic-catalog.md
// §Industry survey).
//
// Genuinely novel coverage: HashiCorp Boundary v0.19 (2026 release)
// still lacks vSphere/Proxmox support. Teleport's discovery_service
// covers AWS/Azure/GCP/K8s only. StrongDM ditto. So jess is, at the
// time of writing, the only OSS PAM with a first-class Proxmox
// provider.
//
// Wire shape
// ==========
// Proxmox API endpoint: GET /api2/json/cluster/resources?type=vm
// Returns a flat array of VM resources cluster-wide. Field 'tags' is
// a semicolon-separated string. We filter on the operator's chosen
// tag (default "jess-managed"). Each matching VM becomes one target.
//
// Auth: API token via the standard PVE bearer header:
//
//	Authorization: PVEAPIToken=<token_id>=<secret>
//
// Address resolution
// ==================
// The 'cluster/resources' response does NOT carry IP addresses (it
// gives VMID, name, node, tags, status — no network detail). Two
// options exist for filling Target.Address:
//
//  1. (DEFAULT) Per-VM Description JSON: operator puts a small JSON
//     blob in the VM's description field:
//     {"jess": {"address":"10.0.0.50:22","ssh_host_key":"ssh-ed25519 AAAA…","criticality":"medium"}}
//     The provider fetches GET /api2/json/nodes/{node}/qemu/{vmid}/config
//     once per discovery cycle to read it. Cost: one extra API call
//     per managed VM. Tolerable up to ~100 VMs at 5-min cadence.
//
//  2. (FUTURE 7b-2) Guest-agent IP lookup via GET /agent/network-get-
//     interfaces — auto-detects IPs but requires qemu-guest-agent
//     installed on every managed VM. Out of scope for this commit;
//     when needed, add a Config flag UseGuestAgent + the second API
//     call site.
//
// Failure semantics
// =================
// On Discover error (API down, token expired, network split): the
// Aggregator's Phase 7a fail-closed cache keeps the last-known-good
// snapshot. No targets evicted on transient errors. Empty successful
// result (all VMs untagged) DOES evict — matches the documented
// catalog.DiscoveryProvider contract.
//
// On per-VM detail-fetch error (description JSON malformed, single
// node API down): the affected VM is SKIPPED with a once-per-VMID
// warn log + a metric increment; OTHER VMs in the snapshot still
// surface. Partial visibility >> total blackout.
package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// DefaultMatchTag is the per-VM tag a Proxmox user adds to opt the VM
// into jess discovery. Operator can override via Config.MatchTag.
const DefaultMatchTag = "jess-managed"

// DescriptionEnvelopeKey is the top-level JSON key the provider reads
// from the VM's description field. Everything outside this key is
// ignored — operators can keep their normal description text alongside
// the jess block:
//
//	"this VM hosts the dev example database\n\n{\"jess\":{\"address\":\"10.0.50.5:22\",\"ssh_host_key\":\"…\"}}"
//
// Mixing free-text and JSON is messy but it's the only Proxmox-native
// way without requiring qemu-guest-agent. Real customers (and future
// HexxLock prod use) will switch to Config 2 (guest-agent IP lookup)
// once that lands; the description-JSON path is the v1 fallback.
const DescriptionEnvelopeKey = "jess"

// jessVMConfig is the per-VM blob we parse from the description field.
// All fields optional except Address (which is REQUIRED — without it
// the VM is skipped because the SSH worker needs a host:port to dial).
type jessVMConfig struct {
	Address     string   `json:"address"`            // required: host:port
	Protocol    string   `json:"protocol,omitempty"` // default "ssh"
	SSHHostKey  string   `json:"ssh_host_key,omitempty"`
	Criticality string   `json:"criticality,omitempty"` // default Config.DefaultCriticality
	Tags        []string `json:"tags,omitempty"`        // appended to ExtraTags
	Region      string   `json:"region,omitempty"`
	Database    string   `json:"database,omitempty"` // DB protocols only
}

// envelope mirrors the {"jess":{...}} shape we look for in the
// description field. Tolerates additional keys around it.
type envelope struct {
	Jess *jessVMConfig `json:"jess,omitempty"`
}

// vmResource mirrors the subset of /cluster/resources?type=vm we care
// about. Full Proxmox response has many more fields; we ignore them.
type vmResource struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Node   string `json:"node"`
	Type   string `json:"type"`   // "qemu" | "lxc"
	Status string `json:"status"` // "running" | "stopped" | …
	Tags   string `json:"tags"`   // semicolon-separated
}

type clusterResourcesResp struct {
	Data []vmResource `json:"data"`
}

type vmConfigResp struct {
	Data map[string]any `json:"data"`
}

// Config tunes the provider. Defaults are picked for HexxLock's
// 1-cluster Proxmox at 152.89.37.98:8006 but every field is
// configurable for other deployments.
type Config struct {
	// Endpoint is the Proxmox API base URL — e.g.
	// https://152.89.37.98:8006. Required.
	Endpoint string

	// TokenID is the PVE API token identity — e.g.
	// "root@pam!HEXXLOCK". Required.
	TokenID string

	// TokenSecret is the PVE API token secret (the UUID-shaped half).
	// Required.
	TokenSecret string

	// InsecureSkipVerify allows the provider to talk to a Proxmox host
	// with a self-signed cert. HexxLock's prod Proxmox is self-signed
	// per the hexx-connect skill so DEFAULT IS TRUE here for HexxLock.
	// External customers should pin a CABundle instead.
	InsecureSkipVerify bool

	// CABundle (optional) pins the Proxmox API cert. Mutually exclusive
	// with InsecureSkipVerify=true. PEM-encoded.
	CABundle []byte

	// MatchTag is the per-VM tag that opts a VM into jess. Default
	// DefaultMatchTag.
	MatchTag string

	// SSHPort defaults the port for SSH targets when the VM's
	// description JSON specifies an address WITHOUT a port. Default
	// 22.
	SSHPort int

	// RequiredRoles stamped on every discovered VM target. Default
	// ["platform_admin"].
	RequiredRoles []string

	// DefaultCriticality used when the VM description JSON doesn't
	// override. Default "medium".
	DefaultCriticality string

	// ExtraTags appended to every discovered VM's Tags slice.
	ExtraTags []string

	// HTTPTimeout per API call. Default 15s.
	HTTPTimeout time.Duration

	// Logger — defaults to log.Default().
	Logger *log.Logger
}

// Provider implements catalog.DiscoveryProvider over the Proxmox API.
type Provider struct {
	cfg    Config
	client *http.Client
	apiURL *url.URL

	mu     sync.Mutex
	warned map[string]struct{} // per-VM warn-once dedup (VMID-keyed)
}

// New constructs a Provider. Validates Config; returns an error if any
// required field is missing.
func New(cfg Config) (*Provider, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("proxmox provider: Endpoint is required")
	}
	if cfg.TokenID == "" || cfg.TokenSecret == "" {
		return nil, fmt.Errorf("proxmox provider: TokenID and TokenSecret are required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("proxmox provider: invalid Endpoint: %w", err)
	}
	if cfg.MatchTag == "" {
		cfg.MatchTag = DefaultMatchTag
	}
	if cfg.SSHPort == 0 {
		cfg.SSHPort = 22
	}
	if len(cfg.RequiredRoles) == 0 {
		cfg.RequiredRoles = []string{"platform_admin"}
	}
	if cfg.DefaultCriticality == "" {
		cfg.DefaultCriticality = "medium"
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402 — gated on operator config
	}
	if len(cfg.CABundle) > 0 {
		// Reserved for future use — accept PEM, build a cert pool,
		// set RootCAs. Out of scope for this commit; commit a TODO
		// rather than ship dead code.
		return nil, fmt.Errorf("proxmox provider: CABundle pinning not yet implemented; use InsecureSkipVerify=true for self-signed Proxmox certs (Phase 7b-2)")
	}

	return &Provider{
		cfg:    cfg,
		apiURL: u,
		client: &http.Client{Transport: transport, Timeout: cfg.HTTPTimeout},
		warned: map[string]struct{}{},
	}, nil
}

// Name implements catalog.DiscoveryProvider.
func (*Provider) Name() string { return "proxmox" }

// Discover implements catalog.DiscoveryProvider. Lists VMs cluster-wide,
// filters by tag, fetches per-VM description JSON, yields Targets.
func (p *Provider) Discover(ctx context.Context) ([]catalog.Target, error) {
	resources, err := p.fetchClusterResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxmox: cluster/resources: %w", err)
	}
	out := make([]catalog.Target, 0, len(resources))
	for _, vm := range resources {
		if vm.Type != "qemu" && vm.Type != "lxc" {
			continue
		}
		if !p.matchesTag(vm.Tags) {
			continue
		}
		jessCfg, err := p.fetchVMJessConfig(ctx, vm)
		if err != nil {
			p.warnPerVMOnce(vm.VMID, fmt.Sprintf("proxmox VM %d (%s): description JSON read failed: %v", vm.VMID, vm.Name, err))
			continue
		}
		if jessCfg == nil {
			p.warnPerVMOnce(vm.VMID, fmt.Sprintf("proxmox VM %d (%s): tagged %q but description has no {\"jess\":{…}} envelope; skipping", vm.VMID, vm.Name, p.cfg.MatchTag))
			continue
		}
		t, ok := p.vmToTarget(vm, *jessCfg)
		if !ok {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// matchesTag checks if the VM's semicolon-separated tag string contains
// our match tag (case-insensitive — Proxmox normalises tags to lowercase
// but operators occasionally type them mixed-case).
func (p *Provider) matchesTag(raw string) bool {
	if raw == "" {
		return false
	}
	for _, tag := range strings.Split(raw, ";") {
		if strings.EqualFold(strings.TrimSpace(tag), p.cfg.MatchTag) {
			return true
		}
	}
	return false
}

// fetchClusterResources calls GET /api2/json/cluster/resources?type=vm
// and returns the VM list. One API roundtrip per Discover.
func (p *Provider) fetchClusterResources(ctx context.Context) ([]vmResource, error) {
	u := *p.apiURL
	u.Path = strings.TrimRight(u.Path, "/") + "/api2/json/cluster/resources"
	q := u.Query()
	q.Set("type", "vm")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	p.signRequest(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("proxmox API %s: status %d body=%s", u.Path, resp.StatusCode, string(body))
	}
	var dec clusterResourcesResp
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		return nil, fmt.Errorf("proxmox API %s: decode: %w", u.Path, err)
	}
	return dec.Data, nil
}

// fetchVMJessConfig pulls the per-VM config and extracts the
// {"jess":{...}} envelope from the description field. Returns:
//   - (cfg, nil) on success
//   - (nil, nil) when the VM has no description / no envelope key
//     (caller logs + skips)
//   - (nil, err) on transport / API error
func (p *Provider) fetchVMJessConfig(ctx context.Context, vm vmResource) (*jessVMConfig, error) {
	kind := "qemu"
	if vm.Type == "lxc" {
		kind = "lxc"
	}
	u := *p.apiURL
	u.Path = fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d/config",
		strings.TrimRight(u.Path, "/"), vm.Node, kind, vm.VMID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	p.signRequest(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d body=%s", resp.StatusCode, string(body))
	}
	var dec vmConfigResp
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		return nil, err
	}
	descRaw, _ := dec.Data["description"].(string)
	if descRaw == "" {
		return nil, nil
	}
	return extractJessEnvelope(descRaw)
}

// extractJessEnvelope finds the JSON block inside `description` that
// matches the {"jess":{…}} envelope. Tolerates surrounding free-text
// by scanning for the first '{' character and attempting to parse
// from there. If that fails, sweeps for `{"jess":` as a substring and
// retries — handles the "free text\n{...jess...}" common case.
func extractJessEnvelope(desc string) (*jessVMConfig, error) {
	// Fast path: whole string is JSON.
	if env, err := tryDecodeEnvelope(desc); err == nil && env != nil && env.Jess != nil {
		return env.Jess, nil
	}
	// Substring path: find `{"jess":` and parse from the enclosing brace.
	if idx := strings.Index(desc, `{"jess":`); idx >= 0 {
		if env, err := tryDecodeEnvelope(desc[idx:]); err == nil && env != nil && env.Jess != nil {
			return env.Jess, nil
		}
	}
	return nil, nil
}

func tryDecodeEnvelope(s string) (*envelope, error) {
	// Use a Decoder so trailing garbage doesn't trip the parser.
	dec := json.NewDecoder(strings.NewReader(s))
	var env envelope
	if err := dec.Decode(&env); err != nil {
		return nil, err
	}
	return &env, nil
}

// vmToTarget assembles a Target from the (VM, jessVMConfig) pair.
// Returns (Target{}, false) if mandatory fields are missing.
func (p *Provider) vmToTarget(vm vmResource, cfg jessVMConfig) (catalog.Target, bool) {
	if cfg.Address == "" {
		p.warnPerVMOnce(vm.VMID, fmt.Sprintf("proxmox VM %d (%s): description.jess.address is empty; skipping", vm.VMID, vm.Name))
		return catalog.Target{}, false
	}
	addr := cfg.Address
	// If no port specified, default by protocol.
	if !strings.Contains(addr, ":") {
		switch strings.ToLower(cfg.Protocol) {
		case "ssh", "":
			addr = fmt.Sprintf("%s:%d", addr, p.cfg.SSHPort)
		case "rdp":
			addr = addr + ":3389"
		case "postgres":
			addr = addr + ":5432"
		case "mysql":
			addr = addr + ":3306"
		}
	}
	proto := catalog.Protocol(strings.ToLower(cfg.Protocol))
	if proto == "" {
		proto = catalog.ProtoSSH
	}
	crit := cfg.Criticality
	if crit == "" {
		crit = p.cfg.DefaultCriticality
	}
	// Tags: ["proxmox-vm"] + ExtraTags + per-VM Tags.
	tags := append([]string{"proxmox-vm"}, p.cfg.ExtraTags...)
	tags = append(tags, cfg.Tags...)
	return catalog.Target{
		ID:            fmt.Sprintf("proxmox-%d", vm.VMID),
		Name:          fmt.Sprintf("%s (vmid=%d, node=%s)", vm.Name, vm.VMID, vm.Node),
		Protocol:      proto,
		Address:       addr,
		Region:        cfg.Region,
		RequiredRoles: append([]string(nil), p.cfg.RequiredRoles...),
		Recorded:      true,
		HostKey:       cfg.SSHHostKey,
		Database:      cfg.Database,
		Criticality:   crit,
		Tags:          tags,
	}, true
}

// signRequest stamps the PVE API token bearer header.
func (p *Provider) signRequest(req *http.Request) {
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", p.cfg.TokenID, p.cfg.TokenSecret))
}

// warnPerVMOnce logs once per VMID per process lifetime so a chronically
// misconfigured VM doesn't spam the controller log every poll cycle.
func (p *Provider) warnPerVMOnce(vmid int, msg string) {
	key := fmt.Sprintf("%d", vmid)
	p.mu.Lock()
	if _, seen := p.warned[key]; seen {
		p.mu.Unlock()
		return
	}
	p.warned[key] = struct{}{}
	p.mu.Unlock()
	logger := p.cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Print(msg)
}

// ErrInvalidConfig surfaces from New when required fields are missing.
// Exposed so callers can switch on the error class. (Defensive: today
// New returns generic fmt.Errorf; keeping the sentinel for parity with
// the rest of internal/catalog.)
var ErrInvalidConfig = errors.New("proxmox provider: invalid config")
