# Phase E — JessPendingTarget auto-promote policy.
#
# Rule contract: jess-controller queries data.jess.discovery; expects a
# map with optional fields {allow: bool, reason: string}. Default-deny;
# every "allow=true" branch MUST also set a reason so the audit row +
# admin UI carry the rule that promoted the candidate.
#
# Input shape: input.candidate is the JessPendingTarget's spec.* —
# protocol, address, source, source_ref, criticality, tags, recorded,
# host_key, host_key_ca_signed, region, required_roles, database.
#
# Operators TUNE this file (mounted as a ConfigMap in the controller
# pod's filesystem) — code changes to the reconciler are NOT needed for
# new promotion rules.

package jess.discovery

import rego.v1

# Default: deny + a clear reason so the rejection audit row is
# actionable.
default allow := false

default reason := "default-deny: no allow rule matched for source"

# hold=true → the reconciler parks a non-allowed candidate as phase=Pending
# (awaiting operator review) instead of terminally Rejecting it. A candidate that
# simply didn't match an auto-promote rule should wait for a human, NOT be
# auto-rejected. Only the explicit Tier-0 RDP hard-deny flips hold=false →
# terminal Rejected (a DC RDP candidate never sits reviewable in the queue).
default hold := true

hold := false if tier0_rdp_block

# =======================================================================
# HARD GUARD — Tier-0 RDP is NEVER brokered via discovery (ADR 0052).
# This is an INVARIANT, not a tunable rule: RDP to a Tier-0 Domain
# Controller (criticality=critical) must never be brokered through this
# lower-tier jump host (Microsoft Enterprise Access / AD tiering). It
# OVERRIDES every allow rule below — including Rule 4's jess:auto-promote
# tag — because every `allow` requires `not tier0_rdp_block`. Editing or
# removing a promotion rule cannot regress this; only deleting this block
# could, which the reconciler unit test guards against.
# =======================================================================
tier0_rdp_block if {
	input.candidate.protocol == "rdp"
	input.candidate.criticality == "critical"
}

reason := "HARD-DENY: Tier-0 RDP never brokered via discovery (DC RDP forbidden, ADR 0052)" if {
	tier0_rdp_block
}

# -----------------------------------------------------------------------
# Rule 1 — k8s-services + non-critical.
# In-cluster services that aren't critical-tier auto-promote on
# discovery. CNPG postgres dev clusters, Redis dev pools, internal
# admin services that already sit behind the mesh.
# -----------------------------------------------------------------------
allow if {
	input.candidate.source == "k8s-services"
	input.candidate.criticality != "critical"
	not tier0_rdp_block
}

reason := "auto-promote: k8s-services + non-critical criticality" if {
	input.candidate.source == "k8s-services"
	input.candidate.criticality != "critical"
	not tier0_rdp_block
}

# -----------------------------------------------------------------------
# Rule 2 — LDAP + Domain Members + recorded.
# Standard AD-joined workstations (NOT Domain Controllers) that we plan
# to record. The CriticalityByOU rule in the LDAP provider already
# stamps DCs with criticality=critical, so Rule 1's exclusion combined
# with Rule 2's allow gives us the desired split:
#   DCs       → critical → manual review (no allow rule matches)
#   Workers   → high     → auto-promote here
#   Lab hosts → low      → auto-promote here
# -----------------------------------------------------------------------
allow if {
	input.candidate.source == "ldap"
	input.candidate.criticality != "critical"
	input.candidate.recorded == true
	not tier0_rdp_block
}

reason := "auto-promote: ldap + non-critical + recorded" if {
	input.candidate.source == "ldap"
	input.candidate.criticality != "critical"
	input.candidate.recorded == true
	not tier0_rdp_block
}

# -----------------------------------------------------------------------
# Rule 3 — Proxmox + tagged jess-managed.
# VMs the operator explicitly marked with the jess-managed tag in
# Proxmox. The opt-in tag plus the per-VM Description JSON together
# express full operator intent — auto-promote.
# -----------------------------------------------------------------------
allow if {
	input.candidate.source == "proxmox"
	"proxmox-vm" in input.candidate.tags
	not tier0_rdp_block
}

reason := "auto-promote: proxmox + jess-managed tag" if {
	input.candidate.source == "proxmox"
	"proxmox-vm" in input.candidate.tags
	not tier0_rdp_block
}

# -----------------------------------------------------------------------
# Rule 4 — Explicit operator-via-tag override.
# Any candidate carrying the `jess:auto-promote` tag (operator-stamped
# in the upstream source) bypasses source-specific rules and promotes —
# EXCEPT it can NOT override the Tier-0 RDP hard-guard above.
# Useful for one-off "I edited the AD Computer description" decisions.
# -----------------------------------------------------------------------
allow if {
	"jess:auto-promote" in input.candidate.tags
	not tier0_rdp_block
}

reason := "auto-promote: explicit jess:auto-promote tag" if {
	"jess:auto-promote" in input.candidate.tags
	not tier0_rdp_block
}
