// SPDX-License-Identifier: AGPL-3.0-or-later

package pending

// ADR 0052 Phase F — discovery → JessPendingTarget sink (the WRITE half of the
// lifecycle; the reconciler in this package is the READ/promote half).
//
// A discovery provider that opts into audit-only enrollment routes its
// Discover() snapshot through DiscoverySink instead of straight into the
// catalog Aggregator. Each discovered target becomes a JessPendingTarget CR
// (manual-review queue) — NEVER a brokerable catalog entry directly. The
// reconciler then evaluates the Rego policy: with the strict initial policy
// (discovery-strict.rego) nothing auto-promotes, so an operator approves each
// candidate before it can be brokered. This is the governance gate that keeps
// auto-discovery from silently onboarding targets (and a Tier-0 DC's RDP).
//
// Idempotent: a candidate is created only if neither a JessPendingTarget nor an
// already-promoted JessTarget of the same name exists. The sink does NOT delete
// vanished targets — retirement of brokerable targets is the Aggregator's TTL
// concern (ADR 0046 Phase D); a Pending CR that's no longer discovered simply
// stops being refreshed and can be pruned by the operator.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// DiscoverySink creates JessPendingTarget CRs from discovered targets.
type DiscoverySink struct {
	client dynamic.Interface
	audit  AuditEmitter // optional; nil → no discovery.discovered emission
	logger *log.Logger
	// now is injected for tests; defaults to time.Now.
	now func() time.Time
}

// NewDiscoverySink builds a sink against the cluster dynamic client.
func NewDiscoverySink(client dynamic.Interface, audit AuditEmitter, logger *log.Logger) *DiscoverySink {
	if logger == nil {
		logger = log.Default()
	}
	return &DiscoverySink{client: client, audit: audit, logger: logger, now: time.Now}
}

// Sync reconciles one provider snapshot into the Pending queue. Returns the
// number of NEW candidates created. Existing Pending/Target rows are left
// untouched (idempotent). A single target's failure is logged and skipped — one
// bad candidate never aborts the batch.
func (s *DiscoverySink) Sync(ctx context.Context, providerName string, targets []catalog.Target) (int, error) {
	created := 0
	for i := range targets {
		t := targets[i]
		name := pendingName(providerName, t.ID)
		if name == "" {
			continue
		}
		// Skip if already brokerable (promoted) or already queued.
		if s.exists(ctx, GVRTarget, name) || s.exists(ctx, GVRPending, name) {
			continue
		}
		cr := s.buildPendingCR(name, providerName, t)
		if _, err := s.client.Resource(GVRPending).Create(ctx, cr, metav1.CreateOptions{}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue // raced with another controller replica — fine
			}
			s.logger.Printf("pending sink: create %s: %v", name, err)
			continue
		}
		created++
		if s.audit != nil {
			s.audit.EmitDiscoveryEvent(ctx, providerName, "discovered", name,
				fmt.Sprintf("protocol=%s address=%s criticality=%s", t.Protocol, t.Address, t.Criticality))
		}
	}
	if created > 0 {
		s.logger.Printf("pending sink: %s queued %d new candidate(s) for review", providerName, created)
	}
	return created, nil
}

// exists reports whether a CR of the given resource + name exists. A non-NotFound
// error is treated as "exists" (fail-safe: never create a duplicate on a
// transient API error).
func (s *DiscoverySink) exists(ctx context.Context, gvr schema.GroupVersionResource, name string) bool {
	_, err := s.client.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	s.logger.Printf("pending sink: get %s/%s: %v (treating as exists)", gvr.Resource, name, err)
	return true
}

// buildPendingCR maps a catalog.Target to a JessPendingTarget CR. The spec
// mirrors JessTarget.spec (so promote() can strip provenance and create the
// JessTarget verbatim) plus the Phase E provenance fields.
func (s *DiscoverySink) buildPendingCR(name, providerName string, t catalog.Target) *unstructured.Unstructured {
	spec := map[string]any{
		"protocol": string(t.Protocol),
		"address":  t.Address,
		// Phase E provenance — stripped on promotion (stripPendingFields).
		"source":        providerName,
		"source_ref":    t.ID,
		"discovered_at": s.now().UTC().Format(time.RFC3339),
		// recorded is always set so the Tier-0 RDP Rego guard + audit policy can
		// reason about it deterministically.
		"recorded": t.Recorded,
	}
	if t.Name != "" {
		spec["name"] = t.Name
	}
	if t.Region != "" {
		spec["region"] = t.Region
	}
	if len(t.RequiredRoles) > 0 {
		spec["required_roles"] = toAnySlice(t.RequiredRoles)
	}
	if t.HostKey != "" {
		spec["host_key"] = t.HostKey
	}
	if t.HostKeyCASigned {
		spec["host_key_ca_signed"] = true
	}
	if t.SSHLoginUser != "" {
		spec["ssh_login_user"] = t.SSHLoginUser
	}
	if t.Database != "" {
		spec["database"] = t.Database
	}
	if t.Criticality != "" {
		spec["criticality"] = t.Criticality
	}
	if len(t.Tags) > 0 {
		spec["tags"] = toAnySlice(t.Tags)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "jess.hexxlock.com/v1alpha1",
		"kind":       "JessPendingTarget",
		"metadata": map[string]any{
			"name": name,
			"labels": map[string]any{
				"jess.hexxlock.com/source": providerName,
			},
		},
		"spec": spec,
	}}
}

// pendingName derives a deterministic, DNS-1123-safe CR name from the provider +
// target id. The target id (e.g. "ldap-dc01-ssh") is already mostly compliant;
// this guarantees it. Empty result means the id sanitised to nothing → skip.
func pendingName(providerName, targetID string) string {
	base := targetID
	if base == "" {
		base = providerName
	}
	base = strings.ToLower(base)
	var b strings.Builder
	prevDash := false
	for _, r := range base {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 253 {
		out = strings.Trim(out[:253], "-.")
	}
	return out
}

// toAnySlice converts a []string to the []any the unstructured codec requires.
func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
