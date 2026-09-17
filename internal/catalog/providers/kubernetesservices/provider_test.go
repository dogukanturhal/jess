// SPDX-License-Identifier: AGPL-3.0-or-later

package kubernetesservices

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
		case <-r.notify:
		case <-timeout:
			t.Fatalf("timed out waiting for %d snapshots; got %d", atLeast, n)
		}
	}
}

// annotatedSvc returns a ClusterIP Service with the given protocol annotation.
func annotatedSvc(ns, name, clusterIP string, port int32, anns map[string]string) *corev1.Service {
	merged := map[string]string{AnnotationProtocol: "tcp"}
	for k, v := range anns {
		merged[k] = v
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			Annotations: merged,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: clusterIP,
			Ports:     []corev1.ServicePort{{Name: "tcp", Port: port}},
		},
	}
}

func TestServices_OptInByProtocolAnnotation(t *testing.T) {
	// Two services: one annotated (postgres), one bare. Only the annotated one
	// should surface.
	annotated := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "jess-pg-rw", Namespace: "cnpg-clusters",
			Annotations: map[string]string{
				AnnotationProtocol:    "postgres",
				AnnotationDatabase:    "jess",
				AnnotationCriticality: "low",
				AnnotationTags:        "production,team:platform",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.43.5.10",
			Ports:     []corev1.ServicePort{{Name: "postgres", Port: 5432}},
		},
	}
	bare := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated-svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.43.0.1",
			Ports:     []corev1.ServicePort{{Port: 80}},
		},
	}

	client := fake.NewSimpleClientset(annotated, bare)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	targets := sink.latest()

	if len(targets) != 1 {
		t.Fatalf("expected 1 surfaced target, got %d: %#v", len(targets), targets)
	}
	got := targets[0]
	if got.ID != "k8s-svc-cnpg-clusters-jess-pg-rw" {
		t.Errorf("ID: got %q", got.ID)
	}
	if got.Address != "10.43.5.10:5432" {
		t.Errorf("Address: got %q", got.Address)
	}
	if got.Protocol != catalog.ProtoPostgres {
		t.Errorf("Protocol: got %q", got.Protocol)
	}
	if got.Database != "jess" {
		t.Errorf("Database: got %q", got.Database)
	}
	if got.Criticality != "low" {
		t.Errorf("Criticality: got %q", got.Criticality)
	}
	// Tags: always-on prefix + annotation-driven addons
	want := map[string]bool{"k8s-service": false, "ns:cnpg-clusters": false, "production": false, "team:platform": false}
	for _, tag := range got.Tags {
		if _, ok := want[tag]; ok {
			want[tag] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing tag: %q (have %v)", k, got.Tags)
		}
	}
}

func TestServices_SSHWithoutHostKeyOrCASignedIsSkipped(t *testing.T) {
	svc := annotatedSvc("kube-system", "ssh-jumphost", "10.43.6.5", 22, map[string]string{
		AnnotationProtocol: "ssh",
	})

	client := fake.NewSimpleClientset(svc)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)

	if got := sink.latest(); len(got) != 0 {
		t.Fatalf("expected SSH service without host-key/CA-signed to be skipped; got %#v", got)
	}
}

func TestServices_SSHWithCASignedAccepted(t *testing.T) {
	svc := annotatedSvc("kube-system", "ssh-jumphost", "10.43.6.5", 22, map[string]string{
		AnnotationProtocol:        "ssh",
		AnnotationHostKeyCASigned: "true",
	})

	client := fake.NewSimpleClientset(svc)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	targets := sink.latest()
	if len(targets) != 1 {
		t.Fatalf("expected 1, got %d", len(targets))
	}
	if !targets[0].HostKeyCASigned {
		t.Error("HostKeyCASigned should be true")
	}
}

func TestServices_HeadlessServiceSkipped(t *testing.T) {
	svc := annotatedSvc("default", "headless", "None", 80, map[string]string{
		AnnotationProtocol: "tcp",
	})
	svc.Spec.ClusterIP = "None"

	client := fake.NewSimpleClientset(svc)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	if got := sink.latest(); len(got) != 0 {
		t.Fatalf("headless service should be skipped; got %#v", got)
	}
}

func TestServices_PortNameAnnotationPicksSpecificPort(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "multi-port", Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol: "postgres",
				AnnotationPortName: "postgres-rw",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.43.0.5",
			Ports: []corev1.ServicePort{
				{Name: "metrics", Port: 9090},
				{Name: "postgres-rw", Port: 5432},
				{Name: "postgres-ro", Port: 5433},
			},
		},
	}
	client := fake.NewSimpleClientset(svc)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	targets := sink.latest()
	if len(targets) != 1 || targets[0].Address != "10.43.0.5:5432" {
		t.Fatalf("expected addr 10.43.0.5:5432, got %#v", targets)
	}
}

func TestServices_InvalidProtocolSkipped(t *testing.T) {
	svc := annotatedSvc("default", "broken", "10.43.0.6", 80, map[string]string{
		AnnotationProtocol: "ftp", // unsupported
	})
	client := fake.NewSimpleClientset(svc)
	sink := newRecSink()
	p, err := New(Config{Client: client}, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	waitForSnapshot(t, sink, 1)
	if got := sink.latest(); len(got) != 0 {
		t.Fatalf("invalid protocol should be skipped; got %#v", got)
	}
}

func TestServices_NameRegistered(t *testing.T) {
	p, err := New(Config{Client: fake.NewSimpleClientset()}, newRecSink())
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Name(); got != "k8s-services" {
		t.Errorf("Name(): got %q, want k8s-services", got)
	}
}
