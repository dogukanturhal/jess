// SPDX-License-Identifier: AGPL-3.0-or-later

package ldap

import (
	"strings"
	"testing"

	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// makeEntry builds an ldapv3.Entry by attribute pairs — saves the
// stdlib testing pattern from looking like a wall of structs.
func makeEntry(dn string, attrs map[string]string) *ldapv3.Entry {
	out := make([]*ldapv3.EntryAttribute, 0, len(attrs))
	for k, v := range attrs {
		out = append(out, &ldapv3.EntryAttribute{Name: k, Values: []string{v}})
	}
	return &ldapv3.Entry{DN: dn, Attributes: out}
}

func newP(t *testing.T, cfg Config) *Provider {
	t.Helper()
	if cfg.URL == "" {
		cfg.URL = "ldaps://test:636"
	}
	if cfg.BindDN == "" {
		cfg.BindDN = "CN=svc,DC=test"
	}
	if cfg.BindPassword == "" {
		cfg.BindPassword = "x"
	}
	if len(cfg.BaseDNs) == 0 {
		cfg.BaseDNs = []string{"DC=test"}
	}
	if !cfg.EnableSSH && !cfg.EnableRDP {
		cfg.EnableSSH = true
		cfg.EnableRDP = true
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestEntryToTargets_SSH_and_RDP_emitted(t *testing.T) {
	p := newP(t, Config{})
	entry := makeEntry("CN=dc01,OU=Domain Controllers,DC=internal,DC=example,DC=com",
		map[string]string{
			"cn":                     "dc01",
			"dNSHostName":            "dc01.internal.example.com",
			"operatingSystem":        "Windows Server 2022 Datacenter",
			"operatingSystemVersion": "10.0 (20348)",
			"description":            "AD DC + Forest Root",
		})
	got := p.entryToTargets(entry)
	if len(got) != 2 {
		t.Fatalf("expected 2 targets (SSH + RDP), got %d: %#v", len(got), got)
	}
	bySuffix := map[string]catalog.Target{}
	for _, t0 := range got {
		bySuffix[string(t0.Protocol)] = t0
	}
	ssh := bySuffix["ssh"]
	rdp := bySuffix["rdp"]
	if ssh.ID != "ldap-dc01-ssh" || ssh.Address != "dc01.internal.example.com:22" {
		t.Errorf("SSH: id=%q addr=%q", ssh.ID, ssh.Address)
	}
	if !ssh.HostKeyCASigned {
		t.Error("SSH target should default to HostKeyCASigned=true (ADR 0044)")
	}
	if ssh.Recorded != true {
		t.Error("SSH should be recorded=true")
	}
	if rdp.ID != "ldap-dc01-rdp" || rdp.Address != "dc01.internal.example.com:3389" {
		t.Errorf("RDP: id=%q addr=%q", rdp.ID, rdp.Address)
	}
	if rdp.Recorded {
		t.Error("RDP recording defers to Phase 5f-9 — expected recorded=false")
	}
}

func TestEntryToTargets_CriticalityByOU(t *testing.T) {
	p := newP(t, Config{
		CriticalityByOU: []CriticalityRule{
			{OUSubstring: "Domain Controllers", Criticality: "critical"},
			{OUSubstring: "Exchange", Criticality: "high"},
		},
		DefaultCriticality: "medium",
	})
	cases := []struct {
		dn   string
		want string
	}{
		{"CN=dc01,OU=Domain Controllers,DC=corp", "critical"},
		{"CN=exch-1,OU=Exchange Servers,DC=corp", "high"},
		{"CN=lab-1,OU=Lab,DC=corp", "medium"},
		{"CN=app-1,OU=Production,DC=corp", "medium"}, // no rule = default
	}
	for _, c := range cases {
		got := p.criticalityFor(c.dn)
		if got != c.want {
			t.Errorf("criticalityFor(%q): got %q want %q", c.dn, got, c.want)
		}
	}
}

func TestEntryToTargets_OSAndOSVersionTagged(t *testing.T) {
	p := newP(t, Config{})
	entry := makeEntry("CN=app,DC=corp",
		map[string]string{
			"cn":                     "app",
			"dNSHostName":            "app.corp",
			"operatingSystem":        "Windows Server 2019 Standard",
			"operatingSystemVersion": "10.0 (17763)",
		})
	got := p.entryToTargets(entry)
	if len(got) == 0 {
		t.Fatal("expected at least one target")
	}
	want := map[string]bool{
		"ldap":                            false,
		"os:windows-server-2019-standard": false,
		"os-version:10.0-17763":           false,
	}
	for _, tag := range got[0].Tags {
		if _, ok := want[tag]; ok {
			want[tag] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing tag %q (have %v)", k, got[0].Tags)
		}
	}
}

func TestEntryToTargets_MissingDNSHostNameSkipped(t *testing.T) {
	p := newP(t, Config{})
	entry := makeEntry("CN=ghost,DC=corp", map[string]string{"cn": "ghost"})
	if got := p.entryToTargets(entry); len(got) != 0 {
		t.Fatalf("expected skip on missing dNSHostName; got %#v", got)
	}
}

func TestEntryToTargets_OnlySSHWhenRDPDisabled(t *testing.T) {
	p := newP(t, Config{EnableSSH: true, EnableRDP: false})
	entry := makeEntry("CN=linux,DC=corp",
		map[string]string{"cn": "linux", "dNSHostName": "linux.corp", "operatingSystem": "Ubuntu 24.04"})
	got := p.entryToTargets(entry)
	if len(got) != 1 || got[0].Protocol != catalog.ProtoSSH {
		t.Fatalf("expected 1 SSH target, got %#v", got)
	}
}

// ADR 0052 Tier-0 RDP hard-guard (layer 1): a DC (criticality=critical) emits
// SSH ONLY — never an RDP candidate — even with EnableRDP=true. A non-critical
// member server still gets RDP.
func TestEntryToTargets_Tier0RDPSuppressed(t *testing.T) {
	p := newP(t, Config{
		EnableSSH: true,
		EnableRDP: true,
		CriticalityByOU: []CriticalityRule{
			{OUSubstring: "Domain Controllers", Criticality: "critical"},
		},
		DefaultCriticality: "medium",
	})
	// criticalityFor matches the `distinguishedName` ATTRIBUTE (not entry.DN).
	dc := makeEntry("CN=dc01,OU=Domain Controllers,DC=internal,DC=example,DC=com",
		map[string]string{
			"cn":                "dc01",
			"dNSHostName":       "dc01.internal.example.com",
			"distinguishedName": "CN=dc01,OU=Domain Controllers,DC=internal,DC=example,DC=com",
		})
	got := p.entryToTargets(dc)
	if len(got) != 1 {
		t.Fatalf("DC must emit SSH only (RDP suppressed), got %d: %#v", len(got), got)
	}
	if got[0].Protocol != catalog.ProtoSSH {
		t.Errorf("DC sole target must be SSH, got %q", got[0].Protocol)
	}

	member := makeEntry("CN=exch-1,OU=Exchange Servers,DC=internal,DC=example,DC=com",
		map[string]string{
			"cn":                "exch-1",
			"dNSHostName":       "exch-1.internal.hexxlock.com",
			"distinguishedName": "CN=exch-1,OU=Exchange Servers,DC=internal,DC=example,DC=com",
		})
	if got := p.entryToTargets(member); len(got) != 2 {
		t.Fatalf("non-critical member should emit SSH+RDP, got %d: %#v", len(got), got)
	}
}

// SuppressRDPForCriticality is overridable: a non-nil EMPTY slice disables the
// guard (nil → the ["critical"] default). Confirms the nil-vs-empty contract.
func TestEntryToTargets_RDPSuppressionDisablable(t *testing.T) {
	p := newP(t, Config{
		EnableSSH:                 true,
		EnableRDP:                 true,
		SuppressRDPForCriticality: []string{}, // explicit empty = no suppression
		CriticalityByOU: []CriticalityRule{
			{OUSubstring: "Domain Controllers", Criticality: "critical"},
		},
	})
	dc := makeEntry("CN=dc01,OU=Domain Controllers,DC=corp",
		map[string]string{
			"cn":                "dc01",
			"dNSHostName":       "dc01.corp",
			"distinguishedName": "CN=dc01,OU=Domain Controllers,DC=corp",
		})
	if got := p.entryToTargets(dc); len(got) != 2 {
		t.Fatalf("suppression disabled → DC emits SSH+RDP, got %d: %#v", len(got), got)
	}
}

func TestNew_RejectsPlaintextWithoutAllow(t *testing.T) {
	_, err := New(Config{
		URL:          "ldap://test:389",
		BindDN:       "x",
		BindPassword: "x",
		BaseDNs:      []string{"DC=test"},
		EnableSSH:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing ldap://") {
		t.Fatalf("expected refuse-plaintext error, got %v", err)
	}
}

func TestNew_AcceptsPlaintextWithAllow(t *testing.T) {
	_, err := New(Config{
		URL:            "ldap://test:389",
		BindDN:         "x",
		BindPassword:   "x",
		BaseDNs:        []string{"DC=test"},
		EnableSSH:      true,
		AllowPlaintext: true,
	})
	if err != nil {
		t.Fatalf("expected accept with AllowPlaintext; got %v", err)
	}
}

func TestNew_RejectsBadScheme(t *testing.T) {
	_, err := New(Config{
		URL:          "https://test:443",
		BindDN:       "x",
		BindPassword: "x",
		BaseDNs:      []string{"DC=test"},
		EnableSSH:    true,
	})
	if err == nil {
		t.Fatal("expected scheme rejection")
	}
}

func TestNew_RequiresAtLeastOneProtocol(t *testing.T) {
	_, err := New(Config{
		URL:          "ldaps://test:636",
		BindDN:       "x",
		BindPassword: "x",
		BaseDNs:      []string{"DC=test"},
	})
	if err == nil {
		t.Fatal("expected error when both protocols disabled")
	}
}

func TestSanitizeID(t *testing.T) {
	cases := map[string]string{
		"dc01":         "dc01",
		"DC01":         "dc01",
		"WIN-HOST-01!": "win-host-01",
		"":             "unknown",
		"---":          "unknown",
		"server name":  "server-name",
	}
	for in, want := range cases {
		if got := sanitizeID(in); got != want {
			t.Errorf("sanitizeID(%q): got %q want %q", in, got, want)
		}
	}
}

func TestSanitizeOSTag(t *testing.T) {
	cases := map[string]string{
		"Windows Server 2022 Datacenter": "windows-server-2022-datacenter",
		"10.0 (20348)":                   "10.0-20348",
		"  Ubuntu  24.04  LTS":           "ubuntu-24.04-lts",
	}
	for in, want := range cases {
		if got := sanitizeOSTag(in); got != want {
			t.Errorf("sanitizeOSTag(%q): got %q want %q", in, got, want)
		}
	}
}

func TestName(t *testing.T) {
	p := newP(t, Config{})
	if got := p.Name(); got != "ldap" {
		t.Errorf("Name() = %q, want ldap", got)
	}
}
