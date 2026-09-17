# Phase F-1 INITIAL-ROLLOUT policy — "everything manual" (ADR 0052, option b).
#
# Same contract + package as discovery.rego (jess-controller queries
# data.jess.discovery → {allow, reason}). Deploy THIS file as the mounted
# ConfigMap for the first discovery soak: NOTHING auto-promotes — every
# discovered candidate lands in the manual-review queue regardless of source,
# criticality, or tags. Once the operator trusts the queue + the tier labels,
# switch the ConfigMap to discovery.rego (which adds the source/criticality
# auto-promote rules) — the Tier-0 RDP hard-guard below is identical in both, so
# graduating never weakens it.
#
# Input shape: input.candidate is the JessPendingTarget's spec.* — protocol,
# address, source, source_ref, criticality, tags, recorded, ...

package jess.discovery

import rego.v1

# Everything manual: default-deny, no allow rule. Operators promote from the
# review queue (admin UI / kubectl) one candidate at a time.
default allow := false

default reason := "manual-review (strict policy): all discovered candidates require operator approval"

# hold=true → the reconciler parks the candidate as phase=Pending (awaiting an
# operator approve/reject) instead of terminally Rejecting it. Strict mode holds
# EVERYTHING for review; only an explicit hard-deny below flips hold=false so a
# Tier-0 RDP candidate is terminally Rejected, never sitting in the queue.
default hold := true

hold := false if tier0_rdp_block

# =======================================================================
# HARD GUARD — Tier-0 RDP is NEVER brokered via discovery (ADR 0052).
# Identical to discovery.rego. Even in strict mode this is stated explicitly
# so the audit row on a DC RDP candidate names the invariant rather than the
# generic "manual-review" reason — and so a future graduation to a looser
# policy cannot silently drop it. There is intentionally NO allow rule here,
# so a Tier-0 RDP candidate is doubly denied (no promotion + named hard-deny).
# =======================================================================
tier0_rdp_block if {
	input.candidate.protocol == "rdp"
	input.candidate.criticality == "critical"
}

reason := "HARD-DENY: Tier-0 RDP never brokered via discovery (DC RDP forbidden, ADR 0052)" if {
	tier0_rdp_block
}
