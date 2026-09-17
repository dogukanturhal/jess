// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/mysqlproxy"
	"github.com/dogukanturhal/jess/internal/recording"
)

// mysqlBroker is the ADR 0049 Phase 4 MySQL Broker. It is the MySQL-wire sibling
// of the Postgres broker (postgres.go) and is built the same way: it speaks the
// MySQL wire protocol via the existing, security-reviewed mysqlproxy record-proxy
// (the MySQL analog of dbproxy) and mints an ephemeral DB credential from the
// Vault database secrets engine per session (CredentialBroker.IssueDBCreds,
// role-per-target, short TTL — see the lifecycle note on postgres.go). No
// standing credential reaches the operator or lives on the target. Every
// brokered SQL statement is teed into the ADR-0030 WORM chain as a query log, and
// the SAME per-statement StatementPolicy seam the Postgres broker uses
// (DefaultStatementPolicy / policyFor) is enforced at the relay before any
// statement reaches the target.
//
// It mirrors postgresBroker exactly: Mint validates the grant + mints the backend
// credential, Dial sets up the WORM recorder fail-closed and returns a
// RecordedConn whose Wait runs the mysqlproxy relay and whose Close seals the
// bundle. The only difference from postgresBroker is the wire library
// (mysqlproxy vs dbproxy) — the broker spine is identical.
type mysqlBroker struct {
	// proxy is the MySQL wire MitM config (mysqlproxy). Its CredsFor is
	// overridden per session by Dial so the injected creds are the freshly
	// minted ephemeral Vault role (see Mint) — the broker owns the credential
	// lifecycle, not the shared proxy config.
	proxy *mysqlproxy.Config
	// creds mints the per-session ephemeral DB role from Vault. Required: a MySQL
	// broker with no credential source can never connect to a target (Mint fails
	// closed, identical to the Postgres broker).
	creds CredentialBroker
	// rec captures the per-statement query log to a tamper-evident signed WORM
	// bundle, or nil for no recording (a Recorded=true target is then denied,
	// fail-closed — identical to the SSH/Postgres brokers).
	rec recording.Recorder
}

// NewMySQLBroker returns the MySQL Broker over the mysqlproxy wire-proxy, the
// Vault credential broker (for the ephemeral DB role mint), and the recorder
// (rec may be nil — recording is then unavailable and Recorded targets are
// denied fail-closed, exactly as the Postgres broker does).
func NewMySQLBroker(proxy *mysqlproxy.Config, creds CredentialBroker, rec recording.Recorder) Broker {
	return &mysqlBroker{proxy: proxy, creds: creds, rec: rec}
}

// Protocol implements Broker.
func (b *mysqlBroker) Protocol() string { return string(catalog.ProtoMySQL) }

// mysqlCredential is the MySQL broker's per-session credential: the target
// connection details with the freshly minted ephemeral Vault DB user/password.
// It never leaves the worker — the operator is already authenticated to jess and
// connects to the broker with no password.
//
// When the broker has no standalone CredentialBroker but the wrapped mysqlproxy
// config already carries a CredsFor (the worker's prod wiring,
// mysqlConfigFromVault — Vault dynamic-creds), Mint defers the credential mint to
// Wait time by stashing that CredsFor in credsFor. This reuses the existing,
// security-reviewed creds assembly verbatim, mirroring the Postgres broker.
type mysqlCredential struct {
	creds mysqlproxy.TargetCreds
	// credsFor, when non-nil, is the wrapped proxy's per-session creds minter,
	// used as the credential source instead of creds (proxy-creds mode).
	credsFor func(context.Context, *catalog.Target) (mysqlproxy.TargetCreds, error)
	grant    AccessGrant
}

func (mysqlCredential) Protocol() string { return string(catalog.ProtoMySQL) }

// Mint implements Broker. It mints the ephemeral DB role/credential from Vault
// (database secrets engine, short TTL) scoped to the target + grant and assembles
// the injected target connection details. The operator never sees these
// credentials; Dial consumes them. Fails closed if the credential broker is
// unconfigured (mirrors the Postgres broker exactly).
func (b *mysqlBroker) Mint(ctx context.Context, grant AccessGrant) (Credential, error) {
	if b.proxy == nil {
		return nil, fmt.Errorf("mysql broker: proxy not configured")
	}
	if grant.Target == nil {
		return nil, fmt.Errorf("mysql broker: grant has no target")
	}
	if grant.Client == nil {
		return nil, fmt.Errorf("mysql broker: grant has no client connection")
	}
	// Proxy-creds mode: no standalone CredentialBroker, but the wrapped proxy
	// already mints the (Vault dynamic-creds) target connection. Defer to it at
	// Wait time so the worker's existing creds assembly is reused unchanged.
	if b.creds == nil {
		if b.proxy.CredsFor == nil {
			return nil, fmt.Errorf("mysql broker: no credential broker and proxy has no CredsFor (cannot mint ephemeral DB role)")
		}
		return mysqlCredential{credsFor: b.proxy.CredsFor, grant: grant}, nil
	}

	role := vaultDBRole(grant.Target)
	user, pass, err := b.creds.IssueDBCreds(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("mysql broker: issue ephemeral DB creds (role %q): %w", role, err)
	}
	return mysqlCredential{
		creds: mysqlproxy.TargetCreds{
			Address:  mysqlAddr(grant.Target),
			User:     user,
			Password: pass,
			Database: grant.Target.Database,
		},
		grant: grant,
	}, nil
}

// Dial implements Broker. It sets up the WORM query-log recorder (identical
// fail-closed semantics to the SSH/Postgres brokers) and returns a RecordedConn
// whose Wait runs the mysqlproxy relay — teeing every statement into the bundle
// and enforcing the per-statement policy — and whose Close seals the bundle.
func (b *mysqlBroker) Dial(ctx context.Context, target *catalog.Target, cred Credential) (RecordedConn, error) {
	mc, ok := cred.(mysqlCredential)
	if !ok {
		return nil, fmt.Errorf("mysql broker: credential is not a MySQL credential (%T)", cred)
	}
	if target == nil {
		return nil, fmt.Errorf("mysql broker: nil target")
	}
	client, ok := mc.grant.Client.(net.Conn)
	if !ok {
		return nil, fmt.Errorf("mysql broker: client connection is not a net.Conn (%T)", mc.grant.Client)
	}

	conn := &mysqlRecordedConn{
		ctx:    ctx,
		proxy:  b.proxy,
		target: target,
		client: client,
		cred:   mc,
		policy: policyFor(target),
	}

	if b.rec != nil {
		meta := recordingMetaFor(mc.grant, string(catalog.ProtoMySQL), recording.FormatQueryLog)
		w, rerr := b.rec.Open(ctx, meta)
		if rerr != nil {
			if target.Recorded {
				// Fail closed: a must-record target is denied if recording fails.
				return nil, fmt.Errorf("mysql broker: recording required but unavailable (fail-closed): %w", rerr)
			}
			// Non-recorded target: proceed without a recorder.
		} else {
			conn.qlog = recording.NewQueryLogWriter(w) // Close seals the bundle
		}
	} else if target.Recorded {
		return nil, fmt.Errorf("mysql broker: recording required but no recorder configured (fail-closed)")
	}

	return conn, nil
}

// mysqlRecordedConn is an open MySQL brokered session. Wait runs the mysqlproxy
// relay (returns when the operator disconnects); Close seals the query-log
// bundle. Mirrors pgRecordedConn.
type mysqlRecordedConn struct {
	ctx    context.Context
	proxy  *mysqlproxy.Config
	target *catalog.Target
	client net.Conn
	cred   mysqlCredential
	policy StatementPolicy
	qlog   *recording.QueryLogWriter // nil = not recording
}

// Wait runs the MySQL record-proxy. For every brokered statement it records a
// query-log line into the WORM bundle (the recording is the audit trail) and
// enforces the per-statement policy at the relay — a denied statement never
// reaches the target. It returns when the operator disconnects.
func (c *mysqlRecordedConn) Wait() error {
	// The query log is written by enforce for EVERY statement (allowed + denied)
	// before any bytes reach the target, so mysqlproxy's auditQuery is left nil to
	// avoid double-recording — enforce is the single record+decide site, exactly
	// as in the Postgres broker.
	return c.waitConfig().Handle(c.ctx, c.client, c.target, nil)
}

// waitConfig builds the per-session mysqlproxy config Wait drives: a config copy
// so the injected ephemeral creds + the per-statement hooks are scoped to this
// session and never mutate the shared proxy config. Split out so the wiring
// (injected creds via CredsFor, enforce as the relay Policy) is unit-testable
// without a live MySQL.
func (c *mysqlRecordedConn) waitConfig() *mysqlproxy.Config {
	// Proxy-creds mode (credsFor set) defers to the wrapped proxy's creds minter;
	// otherwise the creds minted at Mint time are injected.
	credsFor := func(context.Context, *catalog.Target) (mysqlproxy.TargetCreds, error) {
		return c.cred.creds, nil // injected ephemeral creds; operator never sees them
	}
	if c.cred.credsFor != nil {
		credsFor = c.cred.credsFor
	}
	return &mysqlproxy.Config{
		CredsFor: credsFor,
		Policy:   c.enforce,
	}
}

// enforce is the relay's per-statement hook: it records the statement to the WORM
// query log with the policy decision, then returns the policy error (nil =
// allow). mysqlproxy turns a non-nil return into an operator-facing MySQL error
// and skips forwarding — so the recording is written for allowed AND denied
// statements before any bytes reach the target. Identical to
// pgRecordedConn.enforce.
func (c *mysqlRecordedConn) enforce(sql string) error {
	var perr error
	if c.policy != nil {
		perr = c.policy.Allow(sql)
	}
	if c.qlog != nil {
		ev := recording.QueryEvent{SQL: sql, Decision: recording.QueryAllowed}
		if perr != nil {
			ev.Decision = recording.QueryDenied
			ev.DenyReason = perr.Error()
		}
		// A recording failure on a Recorded target must fail the statement closed
		// (no un-recorded brokered statement). For a non-recorded target the
		// recorder is nil and we never reach here.
		if rerr := c.qlog.Record(ev); rerr != nil && c.target.Recorded {
			return fmt.Errorf("recording required but failed (fail-closed): %w", rerr)
		}
	}
	return perr
}

// Close seals the query-log bundle (Close error fails the session closed, ADR
// 0030 Phase 5). Safe to call when not recording.
func (c *mysqlRecordedConn) Close() error {
	if c.qlog == nil {
		return nil
	}
	return c.qlog.Close()
}

// mysqlAddr returns the target's host:port for the backend dial, defaulting the
// standard MySQL port when the catalog address omits it. (mysqlproxy dials this
// verbatim via the go-mysql client.)
func mysqlAddr(t *catalog.Target) string {
	host, port := splitHostPort(t.Address)
	if host == "" {
		host = t.Address
	}
	if port == "" {
		port = "3306"
	}
	return net.JoinHostPort(host, port)
}

// compile-time guards.
var (
	_ io.Closer = (*mysqlRecordedConn)(nil)
	_ Broker    = (*mysqlBroker)(nil)
)
