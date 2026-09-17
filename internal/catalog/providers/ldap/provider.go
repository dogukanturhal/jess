// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ldap is the Phase C discovery provider that surfaces Active
// Directory Computer objects as jess catalog targets — covering the
// Windows-server estate the existing k8s/proxmox/k8s-services providers
// don't touch.
//
// Why AD?
// =======
// Tier-1 PAM-discovery research (deep-research wf_eeb3aa50-3b5, 2026-06-06)
// confirmed AD/LDAP is the canonical source for Windows hosts in every
// surveyed legacy PAM stack (CyberArk DNA, BeyondTrust, Delinea Secret
// Server, Teleport Desktop). For HexxLock's estate this is the right
// shape — every Windows host (dc01, exchange-01, …) already exists as
// an AD Computer object; one bind credential makes the whole fleet
// auto-discoverable.
//
// Search shape (operator-configurable):
//   - One or more search bases (e.g. `OU=Servers,DC=internal,DC=example,DC=com`)
//   - Default filter `(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))`
//     — Computer objects, NOT disabled (UF_ACCOUNTDISABLE bit 0x2).
//   - Scope = sub (recurse) by default.
//
// Per Computer object, the provider emits:
//   - SSH target (if EnableSSH=true) at `<dNSHostName>:22`
//     — host_key_ca_signed=true (relies on ADR 0044 SSH host-CA enrollment
//     via configure-windows-ssh-host-cert.ps1)
//   - RDP target (if EnableRDP=true) at `<dNSHostName>:3389`
//     — recorded=false (RDP recording is Phase 5f-9 backlog)
//
// Both targets get:
//   - operatingSystem attr → `os:<sanitized>` tag (e.g. `os:windows-server-2022`)
//   - OU-derived criticality via CriticalityByOU (partial-match)
//   - description attr → Name (display)
//
// Polled cadence: 5min default (LDAP has no efficient watch primitive).
// First refresh = "discovery cycle 1"; aggregator stamps Source +
// LastSeen identically to other poll-based providers.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// DefaultFilter — Computer objects that are NOT disabled. The OID
// 1.2.840.113556.1.4.803 is LDAP_MATCHING_RULE_BIT_AND; ACCOUNTDISABLE
// is bit 0x2 in userAccountControl.
const DefaultFilter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

// Config carries all per-LDAP-source knobs. URL is required; everything
// else has a safe default.
type Config struct {
	// URL is the LDAP endpoint — `ldaps://dc01.internal.example.com:636`
	// or `ldap://...` (the provider rejects plaintext LDAP unless
	// AllowPlaintext is explicit — bind credentials in cleartext is
	// never a default).
	URL string

	// BindDN + BindPassword identify the service account that performs
	// the search. Read access to the targeted OUs is sufficient — no
	// write or directory-modify permission needed.
	BindDN       string
	BindPassword string

	// BaseDNs is the list of search bases. At least one entry required.
	// Example: ["OU=Servers,DC=internal,DC=example,DC=com"]
	BaseDNs []string

	// Filter overrides DefaultFilter. Use to scope to a specific OS or
	// to exclude lab hosts via custom attributes.
	Filter string

	// Scope: 0=base, 1=one, 2=sub (LDAP convention). Default sub.
	Scope int

	// CABundle is PEM-encoded CA bundle the provider trusts for
	// ldaps://. Empty = system CAs.
	CABundle []byte

	// InsecureSkipVerify disables TLS validation. NEVER set in production;
	// catches the "we use a self-signed cert internally" footgun
	// (operator must explicitly opt in).
	InsecureSkipVerify bool

	// AllowPlaintext permits ldap:// (port 389, no TLS). Without this
	// explicit opt-in, bind via plaintext is refused.
	AllowPlaintext bool

	// EnableSSH/EnableRDP toggle each protocol's target emission.
	// At least one must be true.
	EnableSSH bool
	EnableRDP bool

	// SuppressRDPForCriticality lists criticality levels for which NO RDP
	// target is emitted, even when EnableRDP is true (ADR 0052 Tier-0 RDP
	// hard-guard, layer 1). Default ["critical"]: a Domain Controller
	// (CriticalityByOU stamps DCs "critical") never even produces an RDP
	// candidate — RDP to a Tier-0 DC must never be brokered through this
	// lower-tier jump host. SSH to the DC is unaffected. Set to a non-nil
	// empty slice to disable suppression entirely.
	SuppressRDPForCriticality []string

	// SSHPort/RDPPort override the defaults 22/3389.
	SSHPort int
	RDPPort int

	// DefaultCriticality stamped on targets whose OU doesn't match any
	// CriticalityByOU rule. Default "medium" — Windows servers behind
	// LDAP are typically meshed (one tier above edge).
	DefaultCriticality string

	// CriticalityByOU is a sequence of {OUSubstring, Criticality}
	// rules, evaluated in order. First match wins. Useful pattern:
	//   {"Domain Controllers", "critical"}
	//   {"Exchange",            "high"}
	//   {"Production",          "high"}
	//   {"Lab",                 "low"}
	// Substring match (case-insensitive) against the Computer object's
	// DN.
	CriticalityByOU []CriticalityRule

	// RequiredRoles stamped on every target. Default ["platform_admin"].
	RequiredRoles []string

	// ExtraTags appended to every target's Tags after the always-on
	// ["ldap", "os:<sanitized>"].
	ExtraTags []string

	// PollInterval is the cadence the aggregator calls Discover() at.
	// Default 5min. Pass 0 to fall back to catalog.DefaultRefreshInterval.
	PollInterval time.Duration

	// Logger optional; defaults to log.Default().
	Logger *log.Logger
}

// CriticalityRule is one entry in the OU→criticality matcher.
type CriticalityRule struct {
	OUSubstring string // case-insensitive substring matched against the Computer's DN
	Criticality string // "low" | "medium" | "high" | "critical"
}

// Provider is the catalog.DiscoveryProvider implementation.
type Provider struct {
	cfg Config

	// Suppress repeated "missing dNSHostName" warnings per CN.
	mu               sync.Mutex
	missingHostnames map[string]struct{}
}

// New constructs the provider after validating config.
func New(cfg Config) (*Provider, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("ldap: Config.URL is required")
	}
	if cfg.BindDN == "" || cfg.BindPassword == "" {
		return nil, fmt.Errorf("ldap: Config.BindDN + Config.BindPassword are required")
	}
	if len(cfg.BaseDNs) == 0 {
		return nil, fmt.Errorf("ldap: Config.BaseDNs is empty (set at least one search base)")
	}
	if !cfg.EnableSSH && !cfg.EnableRDP {
		return nil, fmt.Errorf("ldap: at least one of EnableSSH or EnableRDP must be true")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap: invalid URL %q: %w", cfg.URL, err)
	}
	if u.Scheme == "ldap" && !cfg.AllowPlaintext {
		return nil, fmt.Errorf("ldap: refusing ldap:// URL (plaintext bind credentials); use ldaps:// or set AllowPlaintext=true if absolutely required")
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("ldap: scheme %q must be ldap or ldaps", u.Scheme)
	}
	if cfg.Filter == "" {
		cfg.Filter = DefaultFilter
	}
	if cfg.Scope == 0 {
		cfg.Scope = ldapv3.ScopeWholeSubtree
	}
	if cfg.SSHPort == 0 {
		cfg.SSHPort = 22
	}
	if cfg.RDPPort == 0 {
		cfg.RDPPort = 3389
	}
	if cfg.SuppressRDPForCriticality == nil {
		// ADR 0052 Tier-0 RDP hard-guard: default-suppress RDP for critical
		// (DC) hosts. nil → this default; non-nil empty → suppression disabled.
		cfg.SuppressRDPForCriticality = []string{"critical"}
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
	return &Provider{
		cfg:              cfg,
		missingHostnames: map[string]struct{}{},
	}, nil
}

// Name implements catalog.DiscoveryProvider.
func (*Provider) Name() string { return "ldap" }

// Discover implements catalog.DiscoveryProvider. Opens a fresh LDAP
// connection per call (LDAP connection-pooling adds complexity for a
// 5-min cadence; one short-lived bind per cycle is the cleanest shape).
func (p *Provider) Discover(ctx context.Context) ([]catalog.Target, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", p.cfg.URL, err)
	}
	defer conn.Close()
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: bind %s: %w", p.cfg.BindDN, err)
	}

	var all []catalog.Target
	for _, base := range p.cfg.BaseDNs {
		req := ldapv3.NewSearchRequest(
			base,
			p.cfg.Scope,
			ldapv3.NeverDerefAliases,
			0,     // sizeLimit 0 = server default
			30,    // timeLimit (s)
			false, // typesOnly
			p.cfg.Filter,
			[]string{
				"cn",
				"name",
				"dNSHostName",
				"operatingSystem",
				"operatingSystemVersion",
				"description",
				"distinguishedName",
			},
			nil, // controls
		)
		resp, err := conn.SearchWithPaging(req, 100)
		if err != nil {
			return nil, fmt.Errorf("ldap: search base=%q: %w", base, err)
		}
		for _, entry := range resp.Entries {
			all = append(all, p.entryToTargets(entry)...)
		}
	}
	return all, nil
}

// dial opens the LDAP/LDAPS connection.
func (p *Provider) dial(ctx context.Context) (*ldapv3.Conn, error) {
	u, _ := url.Parse(p.cfg.URL) // already validated in New
	if u.Scheme == "ldaps" {
		tlsCfg := &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: p.cfg.InsecureSkipVerify, //nolint:gosec — explicit opt-in via Config
		}
		if len(p.cfg.CABundle) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(p.cfg.CABundle) {
				return nil, fmt.Errorf("ldap: CABundle is not valid PEM")
			}
			tlsCfg.RootCAs = pool
		}
		return ldapv3.DialURL(p.cfg.URL, ldapv3.DialWithTLSConfig(tlsCfg))
	}
	return ldapv3.DialURL(p.cfg.URL)
}

// entryToTargets projects one Computer entry into 0–2 Targets (SSH +
// RDP, gated by EnableSSH/EnableRDP).
func (p *Provider) entryToTargets(entry *ldapv3.Entry) []catalog.Target {
	cn := entry.GetAttributeValue("cn")
	if cn == "" {
		cn = entry.GetAttributeValue("name")
	}
	if cn == "" {
		return nil
	}
	dnsName := strings.TrimSpace(entry.GetAttributeValue("dNSHostName"))
	if dnsName == "" {
		p.warnMissingHostnameOnce(cn)
		return nil
	}
	dn := entry.GetAttributeValue("distinguishedName")
	crit := p.criticalityFor(dn)
	tags := append([]string{"ldap"}, p.cfg.ExtraTags...)
	if os := entry.GetAttributeValue("operatingSystem"); os != "" {
		tags = append(tags, "os:"+sanitizeOSTag(os))
	}
	if osv := entry.GetAttributeValue("operatingSystemVersion"); osv != "" {
		tags = append(tags, "os-version:"+sanitizeOSTag(osv))
	}
	desc := entry.GetAttributeValue("description")

	roles := append([]string(nil), p.cfg.RequiredRoles...)
	out := make([]catalog.Target, 0, 2)
	if p.cfg.EnableSSH {
		out = append(out, catalog.Target{
			ID:              "ldap-" + sanitizeID(cn) + "-ssh",
			Name:            displayName(cn, desc, "SSH"),
			Protocol:        catalog.ProtoSSH,
			Address:         fmt.Sprintf("%s:%d", dnsName, p.cfg.SSHPort),
			RequiredRoles:   roles,
			Recorded:        true,
			HostKeyCASigned: true, // ADR 0044 — Windows OpenSSH host-cert enrollment is the trust path
			Criticality:     crit,
			Tags:            tags,
		})
	}
	if p.cfg.EnableRDP && !p.rdpSuppressed(crit) {
		out = append(out, catalog.Target{
			ID:            "ldap-" + sanitizeID(cn) + "-rdp",
			Name:          displayName(cn, desc, "RDP"),
			Protocol:      catalog.ProtoRDP,
			Address:       fmt.Sprintf("%s:%d", dnsName, p.cfg.RDPPort),
			RequiredRoles: roles,
			Recorded:      false, // Phase 5f-9 backlog
			Criticality:   crit,
			Tags:          tags,
		})
	}
	return out
}

// rdpSuppressed reports whether RDP emission is suppressed for a host of the
// given criticality (ADR 0052 Tier-0 RDP hard-guard, layer 1). Defaults to
// suppressing "critical" (DCs) so a Tier-0 host never produces an RDP candidate.
func (p *Provider) rdpSuppressed(crit string) bool {
	for _, c := range p.cfg.SuppressRDPForCriticality {
		if strings.EqualFold(strings.TrimSpace(c), crit) {
			return true
		}
	}
	return false
}

func (p *Provider) criticalityFor(dn string) string {
	dnLower := strings.ToLower(dn)
	for _, rule := range p.cfg.CriticalityByOU {
		if rule.OUSubstring == "" {
			continue
		}
		if strings.Contains(dnLower, strings.ToLower(rule.OUSubstring)) {
			return rule.Criticality
		}
	}
	return p.cfg.DefaultCriticality
}

func (p *Provider) warnMissingHostnameOnce(cn string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.missingHostnames[cn]; seen {
		return
	}
	p.missingHostnames[cn] = struct{}{}
	p.cfg.Logger.Printf("ldap: Computer %q missing dNSHostName attribute — skipping", cn)
}

func displayName(cn, desc, proto string) string {
	if desc != "" {
		return fmt.Sprintf("%s — %s (AD, %s)", cn, desc, proto)
	}
	return fmt.Sprintf("%s (AD, %s)", cn, proto)
}

// sanitizeIDre matches characters that aren't safe inside a catalog ID
// (must be DNS-label-safe: lowercase, digits, dashes).
var sanitizeIDre = regexp.MustCompile(`[^a-z0-9-]+`)

func sanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = sanitizeIDre.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// sanitizeOSTagre also keeps dots (for version strings) + colons not needed.
var sanitizeOSTagre = regexp.MustCompile(`[^a-z0-9.-]+`)

func sanitizeOSTag(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = sanitizeOSTagre.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}
