// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jit implements just-in-time, zero-standing-privilege grants:
// request -> approve -> time-boxed grant -> auto-revoke (ADR 0030 Phase 5c).
package jit

import (
	"context"
	"errors"
	"time"
)

// Grant is a time-boxed authorization to reach a target.
type Grant struct {
	ID         string
	Subject    string
	TargetID   string
	ApprovedBy string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// Active reports whether the grant is still valid at now.
func (g Grant) Active(now time.Time) bool { return now.Before(g.ExpiresAt) }

// Broker manages the request/approve/grant lifecycle (approver via chat/Falcon-ID).
type Broker interface {
	Request(ctx context.Context, subject, targetID, reason string) (requestID string, err error)
	Approve(ctx context.Context, requestID, approver string, ttl time.Duration) (Grant, error)
	ActiveGrant(ctx context.Context, subject, targetID string) (*Grant, error)
}

// GrantStore is the durable JIT-grant state the control + data planes depend on.
// Implemented by MemoryBroker (dev/tests) and PostgresStore (production: shared
// across stateless controllers AND workers, so a worker's independent grant
// re-check sees grants issued by any controller — the foundation for HA).
type GrantStore interface {
	AssertActiveID(ctx context.Context, grantID, targetID string) (*Grant, error)
}

// GrantIssuer is the optional capability for admin-direct-connect — the
// controller's spine type-asserts on this when an admin connects without
// a grant_id, mints one inline, and proceeds. Both PostgresStore and
// MemoryBroker implement IssueGrant via thin wrappers around their
// existing per-type Issue method (the signatures don't unify because
// PostgresStore needs ctx for the DB roundtrip and MemoryBroker doesn't,
// and renaming the long-standing MemoryBroker.Issue would churn every
// test that uses it).
//
// Custom GrantStore implementations that can't mint just skip the
// admin-direct-connect feature (caller sees 'cannot issue' deny).
type GrantIssuer interface {
	IssueGrant(ctx context.Context, subject, targetID string, ttl time.Duration) (Grant, error)
}

// ErrNoGrant is returned when a privileged target is accessed without an active grant.
var ErrNoGrant = errors.New("jess/jit: no active grant for target")
