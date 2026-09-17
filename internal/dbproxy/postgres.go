// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dbproxy brokers database access (ADR 0030 Phase 5c). For Postgres,
// the worker is a Postgres server to the operator and a Postgres client to the
// target: the operator authenticates to JESS (token + grant), NOT to Postgres,
// and the proxy connects to the target with INJECTED credentials (Vault dynamic
// DB creds in prod) so the operator never sees the database password. Every
// Query/Parse is reported for per-query audit.
package dbproxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// Config configures the Postgres broker.
type Config struct {
	// CredsFor returns the libpq connection string for the target WITH injected
	// credentials. In production this mints short-lived Vault dynamic DB creds;
	// in tests it returns a static DSN. The operator never sees the result.
	CredsFor func(ctx context.Context, target *catalog.Target) (connString string, err error)

	// Policy, if set, is the per-statement enforcement seam at the relay (ADR
	// 0049: "Per-statement policy (read-only, table allow-list) enforceable at
	// the relay"). It is consulted for every Query/Parse BEFORE the statement is
	// forwarded to the target. A nil return permits the statement; a non-nil
	// error denies it — the relay then sends the operator a Postgres
	// ErrorResponse (the statement never reaches the target) and the session
	// stays open for the next statement. nil Policy = no enforcement (audit
	// only), preserving the pre-Phase-2 pass-through behaviour.
	Policy func(sql string) error
}

// ErrStatementDenied wraps a Policy denial so callers can distinguish a
// policy-blocked statement from a relay/connection failure.
var ErrStatementDenied = errors.New("dbproxy: statement denied by policy")

// Handle proxies the Postgres wire protocol between opConn (operator) and the
// target. auditQuery (may be nil) receives every SQL statement.
func (c *Config) Handle(ctx context.Context, opConn net.Conn, target *catalog.Target, auditQuery func(sql string)) error {
	backend := pgproto3.NewBackend(opConn, opConn)

	// 1. Operator startup. We already run inside a secure brokered tunnel, so
	//    decline SSL/GSS negotiation and accept the StartupMessage.
	startup, err := backend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("dbproxy: receive startup: %w", err)
	}
	for {
		switch startup.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := opConn.Write([]byte{'N'}); err != nil {
				return err
			}
			if startup, err = backend.ReceiveStartupMessage(); err != nil {
				return fmt.Errorf("dbproxy: receive startup: %w", err)
			}
			continue
		case *pgproto3.StartupMessage:
		default:
			return fmt.Errorf("dbproxy: unexpected startup message %T", startup)
		}
		break
	}

	// 2. Connect to the target with INJECTED creds; hijack the post-auth conn.
	connString, err := c.CredsFor(ctx, target)
	if err != nil {
		return fmt.Errorf("dbproxy: creds for %s: %w", target.ID, err)
	}
	pgConn, err := pgconn.Connect(ctx, connString)
	if err != nil {
		return fmt.Errorf("dbproxy: connect target: %w", err)
	}
	hj, err := pgConn.Hijack()
	if err != nil {
		_ = pgConn.Close(ctx)
		return fmt.Errorf("dbproxy: hijack target: %w", err)
	}
	defer hj.Conn.Close()
	targetFE := hj.Frontend

	// 3. Tell the operator it is authenticated, relaying the target's parameters.
	backend.Send(&pgproto3.AuthenticationOk{})
	for k, v := range hj.ParameterStatuses {
		backend.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: hj.PID, SecretKey: hj.SecretKey})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return fmt.Errorf("dbproxy: flush startup: %w", err)
	}

	// 4. Proxy both directions; audit queries operator→target.
	errc := make(chan error, 2)
	go func() { errc <- copyOpToTarget(backend, targetFE, auditQuery, c.Policy) }()
	go func() { errc <- copyTargetToOp(targetFE, backend) }()
	<-errc
	_ = hj.Conn.Close()
	_ = opConn.Close()
	return nil
}

func copyOpToTarget(backend *pgproto3.Backend, targetFE *pgproto3.Frontend, auditQuery func(string), policy func(string) error) error {
	for {
		msg, err := backend.Receive()
		if err != nil {
			return err
		}
		// Audit + enforce per-statement policy at the relay BEFORE forwarding.
		// On a policy denial the statement never reaches the target: we tell the
		// operator (ErrorResponse + ReadyForQuery) and keep the session open.
		switch m := msg.(type) {
		case *pgproto3.Query:
			if auditQuery != nil {
				auditQuery(m.String)
			}
			if denied := denyStatement(backend, m.String, policy); denied != nil {
				if !errors.Is(denied, errStatementWasDenied) {
					return denied // flush error — session is broken
				}
				continue
			}
		case *pgproto3.Parse:
			if auditQuery != nil {
				auditQuery(m.Query)
			}
			if denied := denyStatement(backend, m.Query, policy); denied != nil {
				if !errors.Is(denied, errStatementWasDenied) {
					return denied
				}
				continue
			}
		}
		targetFE.Send(msg)
		if err := targetFE.Flush(); err != nil {
			return err
		}
	}
}

// errStatementWasDenied is an internal sentinel: the statement was rejected by
// policy and the operator has been told — the caller should skip forwarding and
// keep proxying.
var errStatementWasDenied = errors.New("dbproxy: statement was denied")

// denyStatement applies policy to sql. Returns nil if the statement is allowed,
// errStatementWasDenied if it was denied (operator already notified), or a real
// error if writing the denial to the operator failed (the session is broken).
func denyStatement(backend *pgproto3.Backend, sql string, policy func(string) error) error {
	if policy == nil {
		return nil
	}
	perr := policy(sql)
	if perr == nil {
		return nil
	}
	// Mirror a real Postgres rejection so standard clients surface it cleanly
	// and the connection stays usable for the next statement.
	backend.Send(&pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501", // insufficient_privilege
		Message:  fmt.Sprintf("%v: %v", ErrStatementDenied, perr),
	})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return err
	}
	return errStatementWasDenied
}

func copyTargetToOp(targetFE *pgproto3.Frontend, backend *pgproto3.Backend) error {
	for {
		msg, err := targetFE.Receive()
		if err != nil {
			return err
		}
		backend.Send(msg)
		if err := backend.Flush(); err != nil {
			return err
		}
	}
}
