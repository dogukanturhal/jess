# jess risk-score policy — Phase 5h-4b reference policy.
#
# Drop-in replacement for the built-in DefaultRulesEvaluator (rules-v1).
# Load via JESS_RISK_OPA_POLICY_FILE=/path/to/risk.rego.
#
# Input shape (set by internal/riskscore/opa.go::Evaluate):
#   input.subject               string
#   input.subject_roles         []string
#   input.subject_groups        []string
#   input.target_id             string
#   input.target_criticality    "low" | "medium" | "high" | "critical"
#   input.target_tags           []string
#   input.target_protocol       "ssh" | "postgres" | "mysql" | "rdp" | ...
#   input.requested_at          unix seconds (int)
#   input.requested_hour        0..23 (in controller TZ — env TZ)
#   input.request_reason        free-form text
#   input.recent_approval_count int
#   input.recent_denial_count   int
#
# Output (read by Evaluate):
#   decision           "auto_approve" | "require_human" | "auto_deny"
#   reason             string (audit log)
#   grant_ttl_seconds  int (caller may clamp)
#   policy_version     string (audit-log stamp)
#
# This file is RUNNABLE — exact mirror of rules-v1 semantics. Edit to
# fit your org's policy; the unit test in internal/riskscore/opa_test.go
# is a useful smoke-test harness for your edits.

package jess.risk

# Defaults — applied when no conditional rule binds.
default decision := "require_human"
default reason := "no rule matched for auto-approval"
default grant_ttl_seconds := 3600

policy_version := "opa-rules-v1"

# Rule 1: critical-criticality targets ALWAYS require human review.
decision := "require_human" if {
    input.target_criticality == "critical"
}
reason := "critical-criticality target requires human approval" if {
    input.target_criticality == "critical"
}

# Rule 2: any recent denial in 30d window taints the operator.
decision := "require_human" if {
    input.recent_denial_count > 0
    input.target_criticality != "critical"  # rule 1 already covers
}
reason := "operator has recent denials in 30d window" if {
    input.recent_denial_count > 0
    input.target_criticality != "critical"
}

# Rule 3: new operator (< 3 prior approvals) — phishing-resistance gate.
decision := "require_human" if {
    input.recent_approval_count < 3
    input.recent_denial_count == 0
    input.target_criticality != "critical"
}
reason := "operator has < 3 prior approvals (new operator review)" if {
    input.recent_approval_count < 3
    input.recent_denial_count == 0
    input.target_criticality != "critical"
}

# Rule 5: incident reference → fast-track with shorter TTL.
# (Rule 5 numbered ahead of Rule 4 because incident takes precedence
# over business-hours check.)
decision := "auto_approve" if {
    contains(lower(input.request_reason), "inc-")
    input.target_criticality != "critical"
    input.recent_denial_count == 0
    input.recent_approval_count >= 3
}
reason := "reason references incident ticket — break-glass auto-approve" if {
    contains(lower(input.request_reason), "inc-")
    input.target_criticality != "critical"
    input.recent_denial_count == 0
    input.recent_approval_count >= 3
}
grant_ttl_seconds := 1800 if {
    contains(lower(input.request_reason), "inc-")
    input.target_criticality != "critical"
    input.recent_denial_count == 0
    input.recent_approval_count >= 3
}

# Rule 6: low-criticality + tenured + business-hours → auto.
decision := "auto_approve" if {
    input.target_criticality == "low"
    input.recent_approval_count >= 3
    input.recent_denial_count == 0
    input.requested_hour >= 6
    input.requested_hour < 18
    not contains(lower(input.request_reason), "inc-")  # rule 5 above
}
reason := "low-criticality target, tenured operator, business hours" if {
    input.target_criticality == "low"
    input.recent_approval_count >= 3
    input.recent_denial_count == 0
    input.requested_hour >= 6
    input.requested_hour < 18
    not contains(lower(input.request_reason), "inc-")
}

# Rule 7: medium-criticality requires more tenure (10+ approvals).
decision := "auto_approve" if {
    input.target_criticality == "medium"
    input.recent_approval_count >= 10
    input.recent_denial_count == 0
    input.requested_hour >= 6
    input.requested_hour < 18
    not contains(lower(input.request_reason), "inc-")
}
reason := "medium-criticality target, well-tenured operator, business hours" if {
    input.target_criticality == "medium"
    input.recent_approval_count >= 10
    input.recent_denial_count == 0
    input.requested_hour >= 6
    input.requested_hour < 18
    not contains(lower(input.request_reason), "inc-")
}
