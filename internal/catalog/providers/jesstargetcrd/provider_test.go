// SPDX-License-Identifier: AGPL-3.0-or-later

package jesstargetcrd

import (
	"context"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	"github.com/dogukanturhal/jess/internal/catalog"
)

type recSink struct {
	mu        sync.Mutex
	snapshots [][]catalog.Target
	notify    chan struct{}
}

func newRecSink() *recSink { return &recSink{notify: make(chan struct{}, 16)} }

func (r *recSink) IngestSnapshot(_ context.Context, _ string, ts []catalog.Target) {
	r.mu.Lock()
	cp := make([]catalog.Target, len(ts))
	copy(cp, ts)
	r.snapshots = append(r.snapshots, cp)
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}
func (r *recSink) latest() []catalog.Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.snapshots) == 0 {
		return nil
	}
	out := make([]catalog.Target, len(r.snapshots[len(r.snapshots)-1]))
	copy(out, r.snapshots[len(r.snapshots)-1])
	return out
}

// mkCR builds a *unstructured.Unstructured for a JessTarget CR. Spec is
// passed verbatim — callers control what's missing/present per test.
func mkCR(name string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "jess.hexxlock.com/v1alpha1",
		"kind":       "JessTarget",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	}}
	u.SetGroupVersionKind(GVR.GroupVersion().WithKind("JessTarget"))
	return u
}

// newFakeProvider wires a fake dynamic client preloaded with the
// given CRs, then constructs + Run()s the provider in a goroutine.
func newFakeProvider(t *testing.T, crs ...*unstructured.Unstructured) (*Provider, *recSink, context.CancelFunc) {
	t.Helper()
	scheme := runtime.NewScheme()
	// dynamic.fake needs the GVR-to-list-kind mapping registered.
	listKinds := map[schema.GroupVersionResource]string{GVR: "JessTargetList"}
	objs := make([]runtime.Object, 0, len(crs))
	for _, u := range crs {
		objs = append(objs, u)
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, objs...)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	return p, sink, cancel
}

func waitForSnapshot(t *testing.T, r *recSink, atLeast int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.snapshots)
		r.mu.Unlock()
		if n >= atLeast {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d snapshots; have %d", atLeast, n)
		case <-r.notify:
		}
	}
}

func TestProvider_DecodesCRIntoTarget(t *testing.T) {
	cr := mkCR("dev-vm-1", map[string]any{
		"protocol":       "ssh",
		"address":        "10.0.0.50:22",
		"host_key":       "ssh-ed25519 AAAA root@dev",
		"region":         "eu-tr",
		"required_roles": []any{"platform_admin", "soc"},
		"recorded":       true,
		"criticality":    "high",
		"tags":           []any{"team:platform", "production"},
	})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)

	got := sink.latest()
	if len(got) != 1 {
		t.Fatalf("expected 1 target, got %d", len(got))
	}
	tt := got[0]
	if tt.ID != "dev-vm-1" || tt.Protocol != catalog.ProtoSSH || tt.Address != "10.0.0.50:22" {
		t.Errorf("decoded target wrong: %+v", tt)
	}
	if tt.Region != "eu-tr" || tt.Criticality != "high" {
		t.Errorf("metadata fields wrong: %+v", tt)
	}
	if len(tt.RequiredRoles) != 2 || tt.RequiredRoles[0] != "platform_admin" {
		t.Errorf("required_roles decode: %+v", tt.RequiredRoles)
	}
	if !contains(tt.Tags, "jess-target-crd") || !contains(tt.Tags, "team:platform") {
		t.Errorf("tags merge broken: %+v", tt.Tags)
	}
}

func TestProvider_SkipsCRMissingRequiredFields(t *testing.T) {
	bad := mkCR("missing-proto", map[string]any{
		"address": "10.0.0.1:22",
		// no protocol
	})
	good := mkCR("ok", map[string]any{
		"protocol": "ssh",
		"address":  "10.0.0.2:22",
	})
	_, sink, cancel := newFakeProvider(t, bad, good)
	defer cancel()
	waitForSnapshot(t, sink, 1)

	got := sink.latest()
	if len(got) != 1 || got[0].ID != "ok" {
		t.Errorf("expected only 'ok' to surface; got %+v", got)
	}
}

func TestProvider_DefaultsCriticalityAndRecorded(t *testing.T) {
	cr := mkCR("minimal", map[string]any{
		"protocol": "ssh",
		"address":  "10.0.0.1:22",
		// no criticality / no recorded
	})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	got := sink.latest()[0]
	if got.Criticality != "medium" {
		t.Errorf("criticality default = %q, want medium", got.Criticality)
	}
	if !got.Recorded {
		t.Errorf("recorded default = %v, want true (fail-closed)", got.Recorded)
	}
}

func TestProvider_HonorsRecordedFalse(t *testing.T) {
	cr := mkCR("non-recorded", map[string]any{
		"protocol": "postgres",
		"address":  "10.0.0.1:5432",
		"database": "dev",
		"recorded": false,
	})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	got := sink.latest()[0]
	if got.Recorded {
		t.Errorf("recorded override broke: %v", got.Recorded)
	}
	if got.Database != "dev" {
		t.Errorf("database decode: %q", got.Database)
	}
}

func TestProvider_DecodesRequireDeviceClaims(t *testing.T) {
	cr := mkCR("device-gated", map[string]any{
		"protocol": "ssh",
		"address":  "10.0.0.1:22",
		"require_device_claims": []any{
			map[string]any{
				"claim":       "device_compliant",
				"valuesAnyOf": []any{"true"},
			},
			map[string]any{
				"claim":       "device_managed_by_mdm",
				"valuesAnyOf": []any{"true"},
			},
		},
	})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	got := sink.latest()[0]
	if len(got.RequireDeviceClaims) != 2 {
		t.Fatalf("device-claims decode = %d, want 2", len(got.RequireDeviceClaims))
	}
	if got.RequireDeviceClaims[0].Claim != "device_compliant" ||
		got.RequireDeviceClaims[0].ValuesAnyOf[0] != "true" {
		t.Errorf("first claim wrong: %+v", got.RequireDeviceClaims[0])
	}
}

func TestProvider_DecodesOfflineCredentials(t *testing.T) {
	cr := mkCR("offline-optin", map[string]any{
		"protocol": "rdp",
		"address":  "10.0.0.9:3389",
		"offline_credentials": map[string]any{
			"enabled":  true,
			"max_ttl":  "2h",
			"max_uses": int64(2),
		},
	})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	got := sink.latest()[0]
	if got.OfflineCredentials == nil {
		t.Fatal("offline_credentials should decode to a non-nil policy")
	}
	if !got.OfflineCredentials.Enabled {
		t.Error("offline_credentials.enabled should decode true")
	}
	if got.OfflineCredentials.MaxTTL != 2*time.Hour {
		t.Errorf("max_ttl = %s, want 2h", got.OfflineCredentials.MaxTTL)
	}
	if got.OfflineCredentials.MaxUses != 2 {
		t.Errorf("max_uses = %d, want 2", got.OfflineCredentials.MaxUses)
	}
}

// A target with no offline_credentials block decodes to a nil policy (the safe
// default: not eligible).
func TestProvider_OfflineCredentialsAbsentIsNil(t *testing.T) {
	cr := mkCR("plain", map[string]any{"protocol": "ssh", "address": "10.0.0.1:22"})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	if got := sink.latest()[0]; got.OfflineCredentials != nil {
		t.Errorf("absent offline_credentials should be nil, got %+v", got.OfflineCredentials)
	}
}

func TestProvider_RejectsNilClient(t *testing.T) {
	_, err := New(Config{}, newRecSink())
	if err == nil {
		t.Fatalf("expected error on nil client")
	}
}

func TestProvider_RejectsNilSink(t *testing.T) {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{GVR: "JessTargetList"}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)
	_, err := New(Config{Client: client}, nil)
	if err == nil {
		t.Fatalf("expected error on nil sink")
	}
}

func TestProvider_DiscoverReturnsCurrentSnapshot(t *testing.T) {
	cr := mkCR("t1", map[string]any{
		"protocol": "ssh", "address": "10.0.0.1:22",
	})
	p, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	got, err := p.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 || got[0].ID != "t1" {
		t.Errorf("Discover snapshot = %+v, want 1 target id=t1", got)
	}
}

func TestProvider_FallsBackToMetadataNameWhenSpecNameEmpty(t *testing.T) {
	cr := mkCR("metaname", map[string]any{
		"protocol": "ssh", "address": "10.0.0.1:22",
		// spec.name omitted
	})
	_, sink, cancel := newFakeProvider(t, cr)
	defer cancel()
	waitForSnapshot(t, sink, 1)
	got := sink.latest()[0]
	if got.Name != "metaname" {
		t.Errorf("Name fallback = %q, want metaname", got.Name)
	}
}

// ---- helpers --------------------------------------------------------

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

var _ = metav1.ObjectMeta{} // keep import alive across edits
