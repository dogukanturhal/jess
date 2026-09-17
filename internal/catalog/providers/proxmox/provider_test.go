// SPDX-License-Identifier: AGPL-3.0-or-later

package proxmox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// fakeProxmox stands up an httptest server mimicking the two PVE API
// endpoints the provider hits: GET /cluster/resources?type=vm and
// GET /nodes/<n>/qemu/<vmid>/config.
type fakeProxmox struct {
	t              *testing.T
	server         *httptest.Server
	resources      []vmResource
	descriptionFor map[int]string // VMID → description string
	expectedToken  string         // exact "Authorization" header to require
	requests       []string       // observed request paths (for assertions)
}

func newFakeProxmox(t *testing.T) *fakeProxmox {
	f := &fakeProxmox{
		t:              t,
		descriptionFor: map[int]string{},
		expectedToken:  "PVEAPIToken=root@pam!HEXXLOCK=secret-uuid",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/cluster/resources", func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		if got := r.Header.Get("Authorization"); got != f.expectedToken {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(clusterResourcesResp{Data: f.resources})
	})
	mux.HandleFunc("/api2/json/nodes/", func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		if got := r.Header.Get("Authorization"); got != f.expectedToken {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		// Path looks like /api2/json/nodes/<n>/qemu/<vmid>/config
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		// parts: api2 json nodes <n> qemu <vmid> config
		if len(parts) != 7 || parts[6] != "config" {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		var vmid int
		if err := json.Unmarshal([]byte(parts[5]), &vmid); err != nil {
			http.Error(w, "bad vmid", http.StatusBadRequest)
			return
		}
		body := map[string]any{}
		if d, ok := f.descriptionFor[vmid]; ok {
			body["description"] = d
		}
		_ = json.NewEncoder(w).Encode(vmConfigResp{Data: body})
	})
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeProxmox) close() { f.server.Close() }

func newTestProvider(t *testing.T, f *fakeProxmox) *Provider {
	p, err := New(Config{
		Endpoint:    f.server.URL,
		TokenID:     "root@pam!HEXXLOCK",
		TokenSecret: "secret-uuid",
		MatchTag:    "jess-managed",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestProvider_FiltersOnTag(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "tagged-vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed;production"},
		{VMID: 101, Name: "untagged-vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "production"},
	}
	f.descriptionFor[100] = `{"jess":{"address":"10.0.0.1","ssh_host_key":"ssh-ed25519 AAAA root@tagged-vm"}}`

	p := newTestProvider(t, f)
	out, err := p.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(out) != 1 || out[0].ID != "proxmox-100" {
		t.Fatalf("expected only tagged VM, got %+v", out)
	}
	if out[0].Address != "10.0.0.1:22" {
		t.Errorf("address default port = %q, want 10.0.0.1:22", out[0].Address)
	}
}

func TestProvider_RespectsExplicitPortInAddress(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed"},
	}
	f.descriptionFor[100] = `{"jess":{"address":"10.0.0.1:2222","ssh_host_key":"ssh-ed25519 AAAA"}}`
	p := newTestProvider(t, f)
	out, _ := p.Discover(context.Background())
	if out[0].Address != "10.0.0.1:2222" {
		t.Errorf("address = %q, want 10.0.0.1:2222 (explicit port respected)", out[0].Address)
	}
}

func TestProvider_DefaultPortPerProtocol(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	cases := []struct {
		vmid  int
		proto string
		want  string
	}{
		{100, "ssh", "10.0.0.1:22"},
		{101, "rdp", "10.0.0.2:3389"},
		{102, "postgres", "10.0.0.3:5432"},
		{103, "mysql", "10.0.0.4:3306"},
	}
	for _, c := range cases {
		ip := "10.0.0." + string(rune('0'+c.vmid-99))
		f.resources = append(f.resources, vmResource{
			VMID: c.vmid, Name: c.proto + "-vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed",
		})
		f.descriptionFor[c.vmid] = `{"jess":{"address":"` + ip + `","protocol":"` + c.proto + `"}}`
	}
	p := newTestProvider(t, f)
	out, _ := p.Discover(context.Background())
	addrByID := map[string]string{}
	for _, tt := range out {
		addrByID[tt.ID] = tt.Address
	}
	for _, c := range cases {
		id := "proxmox-" + string(rune('0'+(c.vmid-100))) // proxmox-100/101/...
		_ = id
	}
	// Easier assertions: build want map directly
	want := map[string]string{
		"proxmox-100": "10.0.0.1:22",
		"proxmox-101": "10.0.0.2:3389",
		"proxmox-102": "10.0.0.3:5432",
		"proxmox-103": "10.0.0.4:3306",
	}
	for id, w := range want {
		if got := addrByID[id]; got != w {
			t.Errorf("%s address = %q, want %q", id, got, w)
		}
	}
}

func TestProvider_SkipsVMWithoutJessEnvelope(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "bare", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed"},
	}
	// No description set → no envelope.
	p := newTestProvider(t, f)
	out, _ := p.Discover(context.Background())
	if len(out) != 0 {
		t.Errorf("expected 0 targets (no envelope), got %+v", out)
	}
}

func TestProvider_SkipsWhenAddressMissing(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "noaddr", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed"},
	}
	f.descriptionFor[100] = `{"jess":{"ssh_host_key":"ssh-ed25519 AAAA"}}` // no address
	p := newTestProvider(t, f)
	out, _ := p.Discover(context.Background())
	if len(out) != 0 {
		t.Errorf("expected 0 (missing address skips), got %+v", out)
	}
}

func TestProvider_HandlesFreeTextAroundJessJSON(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed"},
	}
	f.descriptionFor[100] = "Free-text description for humans.\n\n{\"jess\":{\"address\":\"10.0.0.1:22\",\"ssh_host_key\":\"ssh-ed25519 AAAA\"}}\n\nMore notes below."
	p := newTestProvider(t, f)
	out, err := p.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(out) != 1 || out[0].Address != "10.0.0.1:22" {
		t.Errorf("free-text-around-json parse failed: %+v", out)
	}
}

func TestProvider_FailsClosedOnAPIError(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.expectedToken = "intentionally-mismatched" // make every call 401
	p := newTestProvider(t, f)
	_, err := p.Discover(context.Background())
	if err == nil {
		t.Fatalf("expected error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want it to mention 401", err)
	}
}

func TestProvider_NewRejectsMissingConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"endpoint missing", Config{TokenID: "id", TokenSecret: "s"}},
		{"token-id missing", Config{Endpoint: "http://x", TokenSecret: "s"}},
		{"token-secret missing", Config{Endpoint: "http://x", TokenID: "id"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.cfg)
			if err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}

func TestProvider_CriticalityOverrideFromDescription(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed"},
	}
	f.descriptionFor[100] = `{"jess":{"address":"10.0.0.1:22","criticality":"critical","ssh_host_key":"ssh-ed25519 AAAA"}}`
	p := newTestProvider(t, f)
	out, _ := p.Discover(context.Background())
	if out[0].Criticality != "critical" {
		t.Errorf("criticality = %q, want critical (description override)", out[0].Criticality)
	}
}

func TestProvider_DefaultCriticalityWhenNotInDescription(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "vm", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed"},
	}
	f.descriptionFor[100] = `{"jess":{"address":"10.0.0.1:22","ssh_host_key":"ssh-ed25519 AAAA"}}`
	p, err := New(Config{
		Endpoint:           f.server.URL,
		TokenID:            "root@pam!HEXXLOCK",
		TokenSecret:        "secret-uuid",
		DefaultCriticality: "low",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, _ := p.Discover(context.Background())
	if out[0].Criticality != "low" {
		t.Errorf("criticality default = %q, want low (Config.DefaultCriticality)", out[0].Criticality)
	}
}

func TestProvider_StampsTagsAndIDFormat(t *testing.T) {
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 200, Name: "node-app-01", Node: "pve-01", Type: "qemu", Status: "running", Tags: "jess-managed;production"},
	}
	f.descriptionFor[200] = `{"jess":{"address":"10.0.0.1:22","ssh_host_key":"ssh-ed25519 AAAA","tags":["per-vm-extra"]}}`
	p, err := New(Config{
		Endpoint:    f.server.URL,
		TokenID:     "root@pam!HEXXLOCK",
		TokenSecret: "secret-uuid",
		ExtraTags:   []string{"cluster:eu-west-1"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, _ := p.Discover(context.Background())
	if out[0].ID != "proxmox-200" {
		t.Errorf("ID = %q, want proxmox-200", out[0].ID)
	}
	have := strings.Join(out[0].Tags, ",")
	for _, want := range []string{"proxmox-vm", "cluster:eu-west-1", "per-vm-extra"} {
		if !strings.Contains(have, want) {
			t.Errorf("expected tag %q in %q", want, have)
		}
	}
}

func TestProvider_SkipsLXCEvenWhenTagged(t *testing.T) {
	// First version supports qemu + lxc. Confirm lxc IS supported
	// (some homelab Proxmox users put PG containers in LXC).
	f := newFakeProxmox(t)
	defer f.close()
	f.resources = []vmResource{
		{VMID: 100, Name: "ct-pg", Node: "pve-01", Type: "lxc", Status: "running", Tags: "jess-managed"},
	}
	f.descriptionFor[100] = `{"jess":{"address":"10.0.0.1:5432","protocol":"postgres","database":"appdb"}}`
	// The fake's path matches /api2/json/nodes/<n>/qemu/<vmid>/config; we need lxc too.
	// Register the lxc path explicitly.
	f.server.Config.Handler.(*http.ServeMux).HandleFunc("/api2/json/nodes/pve-01/lxc/100/config",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != f.expectedToken {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(vmConfigResp{Data: map[string]any{"description": f.descriptionFor[100]}})
		})
	p := newTestProvider(t, f)
	out, err := p.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(out) != 1 || out[0].Protocol != catalog.ProtoPostgres || out[0].Database != "appdb" {
		t.Errorf("lxc CT not surfaced as postgres target: %+v", out)
	}
}
