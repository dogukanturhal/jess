// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pending is the Phase E (auto-discovery program) reconciler for
// JessPendingTarget CRs. Discovery providers write candidates here instead
// of (or in addition to) the live catalog; the reconciler evaluates a Rego
// policy and either:
//
//   - promotes the candidate by creating the corresponding JessTarget CR
//     (the jesstargetcrd provider picks it up on the next informer tick)
//     and deleting the PendingTarget, OR
//   - rejects with a policy reason in status.policy_reason.
//
// Deep-research wf_eeb3aa50-3b5 confirmed this state machine is a genuine
// market gap among tier-1 PAM brokers — closing it gives operators the
// "discovered 47 candidates, 31 promoted, 9 rejected, 7 pending" dashboard
// shape Boundary/StrongDM/CyberArk all lack.
//
// Policy contract (Rego):
//
//	package jess.discovery
//
//	default allow = false
//	default reason = "default-deny: no rule matched"
//
//	allow if {
//	  input.candidate.source == "k8s-services"
//	  input.candidate.criticality != "critical"
//	}
//	reason := "k8s-services + non-critical → auto-promote" if {
//	  input.candidate.source == "k8s-services"
//	  input.candidate.criticality != "critical"
//	}
//
// `allow=true` → reconciler creates the JessTarget; `allow=false` → status
// gets the policy_reason. Rego compile errors at controller startup fail
// the controller (refuse to start with broken policy).
package pending

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Group/Version/Resource for the CRDs this reconciler manages.
var (
	GVRPending = schema.GroupVersionResource{
		Group: "jess.hexxlock.com", Version: "v1alpha1", Resource: "jesspendingtargets",
	}
	GVRTarget = schema.GroupVersionResource{
		Group: "jess.hexxlock.com", Version: "v1alpha1", Resource: "jesstargets",
	}
)

// Decision is the reconciler's verdict, distilled from the Rego output.
type Decision struct {
	Allow bool
	// Hold, when true on a non-Allow decision, means "await operator review"
	// (phase=Pending, NON-terminal) rather than "policy denied" (phase=Rejected,
	// terminal). The strict initial policy sets hold=true for everything so a
	// human approves each candidate; only an explicit hard-deny (e.g. Tier-0 RDP)
	// sets hold=false → terminal Rejected. Default false = legacy reject-on-deny.
	Hold   bool
	Reason string
}

// AuditEmitter mirrors the catalog.AuditEmitter shape for discovery-
// lifecycle events. Wire to the same audit.Sink as the rest of jess.
type AuditEmitter interface {
	EmitDiscoveryEvent(ctx context.Context, providerName, phase, targetID, reason string)
}

// Config tunes the reconciler.
type Config struct {
	// Client is the dynamic Kubernetes client (cluster-scoped CRDs).
	Client dynamic.Interface

	// RegoModule is the Rego policy text. Compiled at construction time;
	// errors fail New() so the controller refuses to start with a
	// broken policy.
	RegoModule string

	// ResyncInterval bounds informer re-list cadence. Default 5min.
	ResyncInterval time.Duration

	// Audit is optional. nil → no discovery-event emission.
	Audit AuditEmitter

	Logger *log.Logger
}

// Reconciler watches JessPendingTarget CRs and promotes/rejects per
// Rego.
type Reconciler struct {
	cfg      Config
	informer cache.SharedIndexInformer
	query    rego.PreparedEvalQuery
	stopper  chan struct{}

	mu       sync.Mutex
	inFlight map[string]struct{} // name → "currently reconciling" (debounce)
}

// New constructs the reconciler. Compiles the Rego policy at construction
// time — malformed Rego fails fast.
func New(ctx context.Context, cfg Config) (*Reconciler, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("pending: Config.Client is nil")
	}
	if cfg.RegoModule == "" {
		return nil, fmt.Errorf("pending: Config.RegoModule is empty (default-deny policy required)")
	}
	if cfg.ResyncInterval == 0 {
		cfg.ResyncInterval = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	q, err := rego.New(
		rego.Query("data.jess.discovery"),
		rego.Module("jess_discovery.rego", cfg.RegoModule),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("pending: opa compile: %w", err)
	}
	r := &Reconciler{
		cfg:      cfg,
		query:    q,
		stopper:  make(chan struct{}),
		inFlight: map[string]struct{}{},
	}
	factory := dynamicinformer.NewDynamicSharedInformerFactory(cfg.Client, cfg.ResyncInterval)
	r.informer = factory.ForResource(GVRPending).Informer()
	_, _ = r.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { r.enqueue(obj) },
		UpdateFunc: func(_, obj any) { r.enqueue(obj) },
	})
	return r, nil
}

// NewInCluster builds a dynamic client from the pod's SA token.
func NewInCluster() (dynamic.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("pending: in-cluster: %w", err)
	}
	return dynamic.NewForConfig(cfg)
}

// LoadRegoModule reads a Rego policy from disk. Convenience wrapper for the
// controller-startup pattern (mount a ConfigMap into the controller pod).
func LoadRegoModule(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("pending: rego module path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("pending: read rego module %s: %w", path, err)
	}
	return string(b), nil
}

// Run starts the informer + blocks until ctx cancels.
func (r *Reconciler) Run(ctx context.Context) error {
	go r.informer.Run(r.stopper)
	if !cache.WaitForCacheSync(ctx.Done(), r.informer.HasSynced) {
		close(r.stopper)
		return fmt.Errorf("pending: cache sync failed")
	}
	<-ctx.Done()
	close(r.stopper)
	return ctx.Err()
}

// enqueue debounces — if a reconcile for `name` is in flight, the
// update is dropped (the in-flight one will read the latest spec on
// its next Get). Avoids the "watch event during reconcile races
// itself" pattern.
func (r *Reconciler) enqueue(obj any) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	name := u.GetName()
	r.mu.Lock()
	if _, busy := r.inFlight[name]; busy {
		r.mu.Unlock()
		return
	}
	r.inFlight[name] = struct{}{}
	r.mu.Unlock()
	go r.reconcileOnce(name)
}

// reconcileOnce is the single iteration: Get the candidate, evaluate
// Rego, take action, update status (or delete on promotion).
func (r *Reconciler) reconcileOnce(name string) {
	defer func() {
		r.mu.Lock()
		delete(r.inFlight, name)
		r.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	u, err := r.cfg.Client.Resource(GVRPending).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		r.cfg.Logger.Printf("pending: get %s: %v", name, err)
		return
	}
	// Skip terminal phases — promotion has already happened, or operator
	// has explicitly Rejected. Re-evaluation requires the operator to
	// delete + re-create the PendingTarget (matches CyberArk Pending
	// Accounts model — promotion is once per candidate).
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	if phase == "Promoted" || phase == "Rejected" {
		return
	}

	spec, found, _ := unstructured.NestedMap(u.Object, "spec")
	if !found {
		r.cfg.Logger.Printf("pending: %s missing spec; skipping", name)
		return
	}
	source, _, _ := unstructured.NestedString(spec, "source")

	decision, err := r.evaluate(ctx, spec)
	if err != nil {
		r.cfg.Logger.Printf("pending: %s rego eval error: %v (leaving Pending)", name, err)
		return
	}

	if decision.Allow {
		if err := r.promote(ctx, name, u, spec); err != nil {
			r.cfg.Logger.Printf("pending: %s promote failed: %v (leaving Pending)", name, err)
			r.bumpAttempts(ctx, u)
			return
		}
		r.cfg.Logger.Printf("pending: %s PROMOTED (source=%s, reason=%q)", name, source, decision.Reason)
		if r.cfg.Audit != nil {
			r.cfg.Audit.EmitDiscoveryEvent(ctx, source, "promoted", name, decision.Reason)
		}
		return
	}

	// Not allowed. Two outcomes:
	//   Hold=true  → AWAIT operator review (phase=Pending, NON-terminal). The
	//                candidate stays visible + re-evaluated, so a later policy
	//                change or an operator approve/tag can still promote it.
	//   Hold=false → explicit policy deny (phase=Rejected, terminal).
	if decision.Hold {
		changed, err := r.setPending(ctx, u, decision.Reason)
		if err != nil {
			r.cfg.Logger.Printf("pending: %s set-pending status update failed: %v", name, err)
			return
		}
		if changed {
			r.cfg.Logger.Printf("pending: %s PENDING review (source=%s, reason=%q)", name, source, decision.Reason)
			if r.cfg.Audit != nil {
				r.cfg.Audit.EmitDiscoveryEvent(ctx, source, "pending", name, decision.Reason)
			}
		}
		return
	}

	if err := r.reject(ctx, u, decision.Reason); err != nil {
		r.cfg.Logger.Printf("pending: %s reject status update failed: %v", name, err)
		return
	}
	r.cfg.Logger.Printf("pending: %s REJECTED (source=%s, reason=%q)", name, source, decision.Reason)
	if r.cfg.Audit != nil {
		r.cfg.Audit.EmitDiscoveryEvent(ctx, source, "rejected", name, decision.Reason)
	}
}

// setPending marks a candidate awaiting operator review. Idempotent: returns
// changed=false (and writes nothing) when the candidate is already phase=Pending
// with the same reason, so the 5-min resync doesn't churn status or audit rows.
func (r *Reconciler) setPending(ctx context.Context, u *unstructured.Unstructured, reason string) (bool, error) {
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	prevReason, _, _ := unstructured.NestedString(u.Object, "status", "policy_reason")
	if phase == "Pending" && prevReason == reason {
		return false, nil
	}
	return true, r.updateStatus(ctx, u, map[string]any{
		"phase":         "Pending",
		"decision_at":   time.Now().UTC().Format(time.RFC3339),
		"policy_reason": reason,
	})
}

// evaluate runs Rego against the candidate spec.
func (r *Reconciler) evaluate(ctx context.Context, spec map[string]any) (Decision, error) {
	rs, err := r.query.Eval(ctx, rego.EvalInput(map[string]any{
		"candidate": spec,
	}))
	if err != nil {
		return Decision{}, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{}, errors.New("rego returned no result")
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("rego returned %T, expected object", rs[0].Expressions[0].Value)
	}
	d := Decision{}
	if v, ok := m["allow"].(bool); ok {
		d.Allow = v
	}
	if v, ok := m["hold"].(bool); ok {
		d.Hold = v
	}
	if v, ok := m["reason"].(string); ok {
		d.Reason = v
	}
	if d.Reason == "" {
		if d.Allow {
			d.Reason = "rego allow (no reason field)"
		} else {
			d.Reason = "rego default-deny (no reason field)"
		}
	}
	return d, nil
}

// promote creates a JessTarget CR from the PendingTarget's spec and deletes
// the PendingTarget. The promoted CR's metadata.name is the PendingTarget's
// name (1:1 mapping; if a JessTarget already exists with that name, promote
// surfaces a conflict + leaves the Pending alone).
func (r *Reconciler) promote(ctx context.Context, name string, u *unstructured.Unstructured, spec map[string]any) error {
	// Strip the Phase E provenance fields — they're not part of JessTarget's
	// schema. Anything not in JessTarget's spec.* is dropped silently.
	promotedSpec := stripPendingFields(spec)
	jt := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "jess.hexxlock.com/v1alpha1",
			"kind":       "JessTarget",
			"metadata": map[string]any{
				"name": name,
				"labels": map[string]any{
					"jess.hexxlock.com/promoted-from": "JessPendingTarget",
				},
				"annotations": map[string]any{
					"jess.hexxlock.com/source":        valueOrEmpty(spec, "source"),
					"jess.hexxlock.com/source-ref":    valueOrEmpty(spec, "source_ref"),
					"jess.hexxlock.com/discovered-at": valueOrEmpty(spec, "discovered_at"),
				},
			},
			"spec": promotedSpec,
		},
	}
	if _, err := r.cfg.Client.Resource(GVRTarget).Create(ctx, jt, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create JessTarget %s: %w", name, err)
	}
	// Mark Promoted on the Pending status before delete so observers
	// (admin UI) can see the trail. Best-effort — delete is the
	// terminal step.
	_ = r.updateStatus(ctx, u, map[string]any{
		"phase":               "Promoted",
		"decision_at":         time.Now().UTC().Format(time.RFC3339),
		"promoted_target_ref": name,
		"policy_reason":       "promoted",
	})
	return r.cfg.Client.Resource(GVRPending).Delete(ctx, name, metav1.DeleteOptions{})
}

func (r *Reconciler) reject(ctx context.Context, u *unstructured.Unstructured, reason string) error {
	return r.updateStatus(ctx, u, map[string]any{
		"phase":         "Rejected",
		"decision_at":   time.Now().UTC().Format(time.RFC3339),
		"policy_reason": reason,
	})
}

func (r *Reconciler) bumpAttempts(ctx context.Context, u *unstructured.Unstructured) {
	attempts := int64(0)
	if v, found, _ := unstructured.NestedInt64(u.Object, "status", "attempts"); found {
		attempts = v
	}
	_ = r.updateStatus(ctx, u, map[string]any{
		"attempts":    attempts + 1,
		"decision_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// updateStatus merges patch fields into status. Uses the status subresource
// path so RBAC can scope status-write separately from spec-write.
func (r *Reconciler) updateStatus(ctx context.Context, u *unstructured.Unstructured, patch map[string]any) error {
	status, found, _ := unstructured.NestedMap(u.Object, "status")
	if !found {
		status = map[string]any{}
	}
	for k, v := range patch {
		status[k] = v
	}
	cp := u.DeepCopy()
	if err := unstructured.SetNestedMap(cp.Object, status, "status"); err != nil {
		return err
	}
	_, err := r.cfg.Client.Resource(GVRPending).UpdateStatus(ctx, cp, metav1.UpdateOptions{})
	return err
}

// stripPendingFields removes the Phase E-only provenance fields from a
// PendingTarget spec so what's left is a valid JessTarget spec.
func stripPendingFields(spec map[string]any) map[string]any {
	out := make(map[string]any, len(spec))
	for k, v := range spec {
		switch k {
		case "source", "source_ref", "discovered_at":
			continue
		}
		out[k] = v
	}
	return out
}

func valueOrEmpty(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// EncodePolicyInput is a convenience for callers writing tests against the
// Rego policy without going through the reconciler.
func EncodePolicyInput(spec map[string]any) string {
	b, _ := json.Marshal(map[string]any{"candidate": spec})
	return string(b)
}
