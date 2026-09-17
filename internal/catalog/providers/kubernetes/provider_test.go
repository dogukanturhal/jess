// SPDX-License-Identifier: AGPL-3.0-or-later

package kubernetes

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// recSink records every IngestSnapshot push so tests can assert event
// sequences without pulling in the full Aggregator.
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

func managedNode(name, internalIP, hostKey string, opts ...func(*corev1.Node)) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				LabelManaged: "true",
			},
			Annotations: map[string]string{
				AnnotationHostKey: hostKey,
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: internalIP},
			},
		},
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

func waitForSnapshot(t *testing.T, r *recSink, atLeast int) {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.snapshots)
		r.mu.Unlock()
		if n >= atLeast {
			return
		}
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for %d snapshots; have %d", atLeast, n)
		case <-r.notify:
		}
	}
}

func TestProvider_OnlyManagedNodesAppear(t *testing.T) {
	managed := managedNode("worker-1", "10.0.0.1", "ssh-ed25519 AAAA root@worker-1")
	unmanaged := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-2"}, // no LabelManaged
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.2"}},
		},
	}
	client := fake.NewSimpleClientset(managed, unmanaged)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)

	got := sink.latest()
	if len(got) != 1 {
		t.Fatalf("expected 1 managed target, got %d: %+v", len(got), got)
	}
	if got[0].ID != "worker-1" {
		t.Errorf("unexpected target: %+v", got[0])
	}
}

func TestProvider_MissingHostKeyAnnotationDrops(t *testing.T) {
	bad := managedNode("worker-1", "10.0.0.1", "") // host key empty
	client := fake.NewSimpleClientset(bad)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	if got := sink.latest(); len(got) != 0 {
		t.Errorf("missing host-key Node leaked through: %+v", got)
	}
}

func TestProvider_PrefersInternalIP(t *testing.T) {
	n := managedNode("worker-1", "10.0.0.1", "ssh-ed25519 AAAA root@worker-1", func(n *corev1.Node) {
		n.Status.Addresses = []corev1.NodeAddress{
			{Type: corev1.NodeExternalIP, Address: "203.0.113.5"},
			{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			{Type: corev1.NodeHostName, Address: "worker-1.local"},
		}
	})
	client := fake.NewSimpleClientset(n)
	sink := newRecSink()
	p, _ := New(Config{Client: client}, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	got := sink.latest()
	if len(got) != 1 || got[0].Address != "10.0.0.1:22" {
		t.Errorf("address = %q, want 10.0.0.1:22 (InternalIP preferred); got=%+v", got[0].Address, got)
	}
}

func TestProvider_FallsBackToHostnameWhenNoInternalIP(t *testing.T) {
	n := managedNode("worker-1", "", "ssh-ed25519 AAAA root@worker-1", func(n *corev1.Node) {
		n.Status.Addresses = []corev1.NodeAddress{
			{Type: corev1.NodeHostName, Address: "worker-1.example"},
		}
	})
	client := fake.NewSimpleClientset(n)
	sink := newRecSink()
	p, _ := New(Config{Client: client}, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	got := sink.latest()
	if got[0].Address != "worker-1.example:22" {
		t.Errorf("hostname fallback broke: addr=%q", got[0].Address)
	}
}

func TestProvider_StampsRegionFromTopologyLabel(t *testing.T) {
	n := managedNode("worker-1", "10.0.0.1", "ssh-ed25519 AAAA root@worker-1", func(n *corev1.Node) {
		n.Labels[LabelTopologyRegion] = "eu-tr"
		n.Labels["node-role.kubernetes.io/worker"] = ""
	})
	client := fake.NewSimpleClientset(n)
	sink := newRecSink()
	p, _ := New(Config{Client: client}, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	got := sink.latest()[0]
	if got.Region != "eu-tr" {
		t.Errorf("region = %q, want eu-tr", got.Region)
	}
	found := false
	for _, tag := range got.Tags {
		if tag == "node-role:worker" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected node-role:worker tag, got %+v", got.Tags)
	}
}

func TestProvider_HonorsAnnotationCriticality(t *testing.T) {
	n := managedNode("worker-1", "10.0.0.1", "ssh-ed25519 AAAA root@worker-1", func(n *corev1.Node) {
		n.Annotations[AnnotationCriticality] = "critical"
	})
	client := fake.NewSimpleClientset(n)
	sink := newRecSink()
	p, _ := New(Config{Client: client}, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	if got := sink.latest()[0].Criticality; got != "critical" {
		t.Errorf("criticality = %q, want critical (annotation override)", got)
	}
}

func TestProvider_DefaultCriticalityWhenAnnotationAbsent(t *testing.T) {
	n := managedNode("worker-1", "10.0.0.1", "ssh-ed25519 AAAA root@worker-1")
	client := fake.NewSimpleClientset(n)
	sink := newRecSink()
	p, _ := New(Config{Client: client, DefaultCriticality: "medium"}, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	if got := sink.latest()[0].Criticality; got != "medium" {
		t.Errorf("criticality = %q, want medium (config default)", got)
	}
}

func TestProvider_NewRejectsNilClient(t *testing.T) {
	_, err := New(Config{}, newRecSink())
	if err == nil {
		t.Fatalf("expected error on nil client")
	}
}

func TestProvider_NewRejectsNilSink(t *testing.T) {
	_, err := New(Config{Client: fake.NewSimpleClientset()}, nil)
	if err == nil {
		t.Fatalf("expected error on nil sink")
	}
}

func TestProvider_DiscoverReturnsCurrentSnapshot(t *testing.T) {
	// Discover() is the synchronous catalog.DiscoveryProvider entry
	// point. It MUST return the same view that the watch path would
	// have pushed via IngestSnapshot.
	n := managedNode("worker-1", "10.0.0.1", "ssh-ed25519 AAAA root@worker-1")
	client := fake.NewSimpleClientset(n)
	sink := newRecSink()
	p, _ := New(Config{Client: client}, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	got, err := p.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 || got[0].ID != "worker-1" {
		t.Errorf("Discover snapshot = %+v, want 1 managed target", got)
	}
}
