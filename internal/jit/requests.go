// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RequestState is the lifecycle of a JIT grant request.
type RequestState string

const (
	RequestPending  RequestState = "pending"
	RequestApproved RequestState = "approved"
	RequestDenied   RequestState = "denied"
	RequestExpired  RequestState = "expired"
)

// Request is a single operator's ask for access to a target. Phase 5b
// approval workflow: operator runs `jessctl request` → row inserted with
// state=pending → approver runs `jessctl admin approve` → row transitions
// to approved AND a Grant is minted for the requested target/subject.
// ADR 0030 §"Phase 5b" + 2026-05-29 operator E2E runbook ("manual psql
// INSERT" gap).
type Request struct {
	ID            string
	Subject       string
	TargetID      string
	Reason        string
	RequestedAt   time.Time
	State         RequestState
	DecidedBy     string    // approver's sub (verified token claim)
	DecidedAt     time.Time // zero when state=pending
	DecidedReason string    // populated on deny (approver-supplied "why")
	GrantID       string    // populated on approve, links to jit_grants.id
	ExpiresAt     time.Time // request itself ages out (pending → expired) — independent of grant TTL
}

// ErrNoRequest is returned by request operations when the row is missing.
var ErrNoRequest = errors.New("jit: no such request")

// ErrRequestNotPending fires when approve/deny target a request whose state
// has already moved (idempotency guard — prevents an approver from
// re-deciding a denied request, or two approvers from racing on the same row).
var ErrRequestNotPending = errors.New("jit: request is no longer pending")

// MigrateRequests creates the jit_requests table if absent. Run alongside
// Migrate() at controller startup.
func (s *PostgresStore) MigrateRequests(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS jit_requests (
			id             text PRIMARY KEY,
			subject        text NOT NULL,
			target_id      text NOT NULL,
			reason         text NOT NULL DEFAULT '',
			requested_at   timestamptz NOT NULL DEFAULT now(),
			state          text NOT NULL DEFAULT 'pending',
			decided_by     text NOT NULL DEFAULT '',
			decided_at     timestamptz,
			decided_reason text NOT NULL DEFAULT '',
			grant_id       text NOT NULL DEFAULT '',
			expires_at     timestamptz NOT NULL
		);
		CREATE INDEX IF NOT EXISTS jit_requests_state_idx ON jit_requests (state, requested_at);
		CREATE INDEX IF NOT EXISTS jit_requests_subject_idx ON jit_requests (subject, requested_at);`)
	if err != nil {
		return fmt.Errorf("jit: migrate requests: %w", err)
	}
	return nil
}

// Submit inserts a new pending request. requestTTL bounds how long the
// request stays open before transitioning to expired (default 4h applies
// when zero) — covers the case where no approver acts.
func (s *PostgresStore) Submit(ctx context.Context, subject, targetID, reason string, requestTTL time.Duration) (Request, error) {
	if requestTTL <= 0 {
		requestTTL = 4 * time.Hour
	}
	r := Request{
		ID:          id("req"),
		Subject:     subject,
		TargetID:    targetID,
		Reason:      reason,
		RequestedAt: time.Now(),
		State:       RequestPending,
		ExpiresAt:   time.Now().Add(requestTTL),
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO jit_requests (id, subject, target_id, reason, requested_at, state, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		r.ID, r.Subject, r.TargetID, r.Reason, r.RequestedAt, string(r.State), r.ExpiresAt)
	if err != nil {
		return Request{}, fmt.Errorf("jit: insert request: %w", err)
	}
	return r, nil
}

// GetRequest returns a single request by id.
func (s *PostgresStore) GetRequest(ctx context.Context, id string) (Request, error) {
	return s.scanRequestRow(s.pool.QueryRow(ctx,
		`SELECT id, subject, target_id, reason, requested_at, state, decided_by, decided_at, decided_reason, grant_id, expires_at
		 FROM jit_requests WHERE id=$1`, id))
}

// ListRequests returns requests filtered by state. Empty state returns all
// states (subject to LIMIT 200, newest-first). Independent of List() for
// active grants — different lifecycle, different consumers.
func (s *PostgresStore) ListRequests(ctx context.Context, state RequestState) ([]Request, error) {
	const limit = 200
	var rows pgx.Rows
	var err error
	if state == "" {
		rows, err = s.pool.Query(ctx,
			`SELECT id, subject, target_id, reason, requested_at, state, decided_by, decided_at, decided_reason, grant_id, expires_at
			 FROM jit_requests ORDER BY requested_at DESC LIMIT $1`, limit)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, subject, target_id, reason, requested_at, state, decided_by, decided_at, decided_reason, grant_id, expires_at
			 FROM jit_requests WHERE state=$1 ORDER BY requested_at DESC LIMIT $2`, string(state), limit)
	}
	if err != nil {
		return nil, fmt.Errorf("jit: list requests: %w", err)
	}
	defer rows.Close()
	out := make([]Request, 0, 16)
	for rows.Next() {
		r, serr := s.scanRequestRow(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, r)
	}
	return out, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func (s *PostgresStore) scanRequestRow(row rowScanner) (Request, error) {
	var r Request
	var st string
	var decidedAt *time.Time
	if err := row.Scan(&r.ID, &r.Subject, &r.TargetID, &r.Reason, &r.RequestedAt, &st,
		&r.DecidedBy, &decidedAt, &r.DecidedReason, &r.GrantID, &r.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Request{}, ErrNoRequest
		}
		return Request{}, fmt.Errorf("jit: scan request: %w", err)
	}
	r.State = RequestState(st)
	if decidedAt != nil {
		r.DecidedAt = *decidedAt
	}
	return r, nil
}

// Approve transitions a pending request to approved AND inserts a Grant in
// the SAME transaction — so a partial failure can never leave a request
// flagged approved without an actual grant row to back it. The minted
// Grant's id is linked into jit_requests.grant_id.
//
// approverSub is the verified caller (from the OIDC token), recorded as
// decided_by. ttl is the lifetime of the issued grant (not the request).
func (s *PostgresStore) Approve(ctx context.Context, requestID, approverSub string, ttl time.Duration) (Request, Grant, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, Grant{}, fmt.Errorf("jit: approve begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock + read the request row (FOR UPDATE) so two concurrent approve
	// attempts can't both win the transition.
	var st string
	var subject, targetID string
	err = tx.QueryRow(ctx,
		`SELECT state, subject, target_id FROM jit_requests WHERE id=$1 FOR UPDATE`, requestID).
		Scan(&st, &subject, &targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, Grant{}, ErrNoRequest
	}
	if err != nil {
		return Request{}, Grant{}, fmt.Errorf("jit: approve select: %w", err)
	}
	if RequestState(st) != RequestPending {
		return Request{}, Grant{}, ErrRequestNotPending
	}

	// Mint the grant inline in the same transaction (instead of calling
	// Issue() which uses the pool directly) so the FK-like link is durable.
	g := Grant{
		ID:         id("grant"),
		Subject:    subject,
		TargetID:   targetID,
		ApprovedBy: "sub:" + approverSub,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO jit_grants (id, subject, target_id, approved_by, issued_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		g.ID, g.Subject, g.TargetID, g.ApprovedBy, g.IssuedAt, g.ExpiresAt); err != nil {
		return Request{}, Grant{}, fmt.Errorf("jit: approve insert grant: %w", err)
	}

	now := time.Now()
	// Phase 5e-11: also overwrite expires_at with the grant's expiry so
	// the SPA can show "approved · expires in 12m" off the request row
	// without an extra grant lookup. For pending rows, expires_at still
	// means "request auto-deny deadline"; for approved rows, it now means
	// "grant expiry" (when the operator's access ends). Both readings are
	// "the deadline that matters", which is the SPA's only use.
	if _, err := tx.Exec(ctx,
		`UPDATE jit_requests SET state=$1, decided_by=$2, decided_at=$3, grant_id=$4, expires_at=$5 WHERE id=$6`,
		string(RequestApproved), approverSub, now, g.ID, g.ExpiresAt, requestID); err != nil {
		return Request{}, Grant{}, fmt.Errorf("jit: approve update: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Request{}, Grant{}, fmt.Errorf("jit: approve commit: %w", err)
	}
	// Round-trip the request for the return value's full shape.
	r, gerr := s.GetRequest(ctx, requestID)
	if gerr != nil {
		return Request{}, g, gerr
	}
	return r, g, nil
}

// Deny transitions a pending request to denied with an approver-supplied
// reason. No grant is created. denierSub is the verified caller.
func (s *PostgresStore) Deny(ctx context.Context, requestID, denierSub, reason string) (Request, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE jit_requests SET state=$1, decided_by=$2, decided_at=$3, decided_reason=$4
		 WHERE id=$5 AND state=$6`,
		string(RequestDenied), denierSub, time.Now(), reason, requestID, string(RequestPending))
	if err != nil {
		return Request{}, fmt.Errorf("jit: deny: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Disambiguate: not-found vs not-pending.
		r, gerr := s.GetRequest(ctx, requestID)
		if errors.Is(gerr, ErrNoRequest) {
			return Request{}, ErrNoRequest
		}
		if gerr == nil && r.State != RequestPending {
			return Request{}, ErrRequestNotPending
		}
		return Request{}, fmt.Errorf("jit: deny update: 0 rows affected")
	}
	return s.GetRequest(ctx, requestID)
}

// ExpireOld bulk-transitions pending requests whose expires_at has passed
// into the expired state. Intended to be called periodically (e.g. every
// 5min from controller main) so stale rows don't accumulate. Returns the
// number of rows expired.
func (s *PostgresStore) ExpireOld(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE jit_requests SET state=$1
		 WHERE state=$2 AND expires_at <= now()`,
		string(RequestExpired), string(RequestPending))
	if err != nil {
		return 0, fmt.Errorf("jit: expire old: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
