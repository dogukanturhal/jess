// SPDX-License-Identifier: AGPL-3.0-or-later

package pending

// Operator-initiated review actions on the JessPendingTarget queue (ADR 0052
// Phase F). The reconciler is policy-driven; these are the manual approve/reject
// path the admin API + UI call. Kept in this package so they share the GVRs +
// spec-mapping with the reconciler.

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// PendingInfo is the admin-API projection of a JessPendingTarget candidate.
type PendingInfo struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	Criticality  string `json:"criticality,omitempty"`
	Source       string `json:"source,omitempty"`
	Phase        string `json:"phase,omitempty"`  // Pending | Rejected | Promoted | ""
	Reason       string `json:"reason,omitempty"` // status.policy_reason
	DiscoveredAt string `json:"discovered_at,omitempty"`
}

// ListPending returns every JessPendingTarget for the admin review queue.
func ListPending(ctx context.Context, client dynamic.Interface) ([]PendingInfo, error) {
	l, err := client.Resource(GVRPending).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]PendingInfo, 0, len(l.Items))
	for i := range l.Items {
		u := &l.Items[i]
		spec, _, _ := unstructured.NestedMap(u.Object, "spec")
		proto, _, _ := unstructured.NestedString(spec, "protocol")
		addr, _, _ := unstructured.NestedString(spec, "address")
		crit, _, _ := unstructured.NestedString(spec, "criticality")
		src, _, _ := unstructured.NestedString(spec, "source")
		disc, _, _ := unstructured.NestedString(spec, "discovered_at")
		phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
		reason, _, _ := unstructured.NestedString(u.Object, "status", "policy_reason")
		out = append(out, PendingInfo{
			Name: u.GetName(), Protocol: proto, Address: addr, Criticality: crit,
			Source: src, Phase: phase, Reason: reason, DiscoveredAt: disc,
		})
	}
	return out, nil
}

// ApprovePending promotes a candidate to a JessTarget by explicit operator
// decision (bypassing the Rego auto-promote rules — this IS the human review),
// then deletes the PendingTarget. It STILL refuses a Tier-0 RDP target: the
// ADR 0052 hard-guard is an invariant no operator override can cross.
func ApprovePending(ctx context.Context, client dynamic.Interface, name, approvedBy string) error {
	u, err := client.Resource(GVRPending).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	spec, found, _ := unstructured.NestedMap(u.Object, "spec")
	if !found {
		return fmt.Errorf("pending %s has no spec", name)
	}
	proto, _, _ := unstructured.NestedString(spec, "protocol")
	crit, _, _ := unstructured.NestedString(spec, "criticality")
	if proto == "rdp" && crit == "critical" {
		return fmt.Errorf("refusing to approve Tier-0 RDP target %s — DC RDP is never brokered (ADR 0052 hard-guard)", name)
	}
	jt := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "jess.hexxlock.com/v1alpha1",
		"kind":       "JessTarget",
		"metadata": map[string]any{
			"name":   name,
			"labels": map[string]any{"jess.hexxlock.com/promoted-from": "JessPendingTarget"},
			"annotations": map[string]any{
				"jess.hexxlock.com/source":      valueOrEmpty(spec, "source"),
				"jess.hexxlock.com/source-ref":  valueOrEmpty(spec, "source_ref"),
				"jess.hexxlock.com/approved-by": approvedBy,
				"jess.hexxlock.com/approved-at": time.Now().UTC().Format(time.RFC3339),
			},
		},
		"spec": stripPendingFields(spec),
	}}
	if _, err := client.Resource(GVRTarget).Create(ctx, jt, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create JessTarget %s: %w", name, err)
	}
	return client.Resource(GVRPending).Delete(ctx, name, metav1.DeleteOptions{})
}

// RejectPending marks a candidate terminally Rejected by operator decision.
func RejectPending(ctx context.Context, client dynamic.Interface, name, rejectedBy string) error {
	u, err := client.Resource(GVRPending).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	status, found, _ := unstructured.NestedMap(u.Object, "status")
	if !found || status == nil {
		status = map[string]any{}
	}
	status["phase"] = "Rejected"
	status["decision_at"] = time.Now().UTC().Format(time.RFC3339)
	status["policy_reason"] = "operator-rejected by " + rejectedBy
	if err := unstructured.SetNestedMap(u.Object, status, "status"); err != nil {
		return err
	}
	_, err = client.Resource(GVRPending).UpdateStatus(ctx, u, metav1.UpdateOptions{})
	return err
}
