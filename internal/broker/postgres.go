// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/dbproxy"
	"github.com/dogukanturhal/jess/internal/recording"
)

// The per-session backend credential is short-lived by design (ADR 0049:
// "ephemeral DB role/credential … short TTL"): its lease only has to outlive the
// brokered session, and Vault revokes it on lease expiry regardless of how the
// session ends. The TTL is configured on the Vault database-engine role that
// CredentialBroker.IssueDBCreds mints from (role-per-target, see vaultDBRole).

// postgresBroker is the ADR 0049 Phase 2 Postgres Broker. It speaks the PG wire
// protocol via the existing, security-reviewed dbproxy record-proxy (ADR 0030
// Phase 5c) and mints an ephemeral DB credential from the Vault database secrets
// engine per session (CredentialBroker.IssueDBCreds) — no standing credential
// reaches the operator or lives on the target. Every brokered SQL statement is
// teed into the ADR-0030 WORM chain as a query log, and a per-statement policy
// is enforced at the relay (read-only flag + table allow-list seam).
//
// It mirrors sshBroker (ssh.go): Mint validates the grant + mints the backend
// credential, Dial sets up the WORM recorder fail-closed and returns a
// RecordedConn whose Wait runs the dbproxy relay and whose Close seals the
// bundle.
type postgresBroker struct {
	// proxy is the Postgres wire MitM config. Its CredsFor is overridden per
	// session by Dial so the injected creds are the freshly minted ephemeral
	// Vault role (see Mint) — the broker owns the credential lifecycle, not the
	// shared proxy config.
	proxy *dbproxy.Config
	// creds mints the per-session ephemeral DB role from Vault. Required: a
	// Postgres broker with no credential source can never connect to a target
	// (Mint fails closed).
	creds CredentialBroker
	// rec captures the per-statement query log to a tamper-evident signed WORM
	// bundle, or nil for no recording (a Recorded=true target is then denied,
	// fail-closed — identical to the SSH broker).
	rec recording.Recorder
}

// NewPostgresBroker returns the Postgres Broker over the dbproxy wire-proxy, the
// Vault credential broker (for the ephemeral DB role mint), and the recorder
// (rec may be nil — recording is then unavailable and Recorded targets are
// denied fail-closed, exactly as the SSH broker does).
func NewPostgresBroker(proxy *dbproxy.Config, creds CredentialBroker, rec recording.Recorder) Broker {
	return &postgresBroker{proxy: proxy, creds: creds, rec: rec}
}

// Protocol implements Broker.
func (b *postgresBroker) Protocol() string { return string(catalog.ProtoPostgres) }

// StatementPolicy is the per-statement enforcement seam at the Postgres relay
// (ADR 0049 Phase 2: "Per-statement policy (read-only, table allow-list)
// enforceable at the relay"). It is consulted for every brokered statement
// BEFORE it reaches the target. Allow returns nil to permit; a non-nil error
// denies the statement (the relay sends the operator a Postgres ErrorResponse
// and keeps the session open).
//
// Phase 2 ships a deliberately simple, dependency-free implementation
// (DefaultStatementPolicy) so the seam is wired end-to-end; a real SQL parser /
// Rego PDP slots in behind the same interface later without touching the relay.
type StatementPolicy interface {
	// Allow reports whether sql may run; a non-nil error is the deny reason.
	Allow(sql string) error
}

// DefaultStatementPolicy is the Phase 2 reference policy: an optional read-only
// gate plus an optional table allow-list, both string-level heuristics (no SQL
// parser yet — see the type doc on StatementPolicy). The zero value
// (ReadOnly=false, AllowedTables empty) is a pass-through seam: it allows every
// statement, which is the Phase 2 default until per-target policy columns land
// in the catalog.
type DefaultStatementPolicy struct {
	// ReadOnly, when true, denies any statement that is not a plain read
	// (SELECT/SHOW/EXPLAIN/WITH … and session no-ops). Heuristic, fail-closed:
	// anything not recognised as a read is denied.
	ReadOnly bool
	// AllowedTables, when non-empty, is the set of bare table names a statement
	// may reference (matched case-insensitively). Empty = no table restriction.
	// This is a best-effort substring guard in Phase 2 — the real allow-list
	// needs the parser, which this seam is built to receive.
	AllowedTables []string
}

// readOnlyPrefixes are the leading keywords of statements treated as reads.
var readOnlyPrefixes = []string{"select", "show", "explain", "with", "fetch", "values", "table"}

// writeKeywords are statements DefaultStatementPolicy denies in read-only mode
// even if they somehow slip past the read prefixes (defense in depth).
var writeKeywords = []string{
	"insert", "update", "delete", "drop", "alter", "create", "truncate",
	"grant", "revoke", "copy", "merge", "call", "do",
}

// Allow implements StatementPolicy.
func (p DefaultStatementPolicy) Allow(sql string) error {
	trimmed := strings.TrimSpace(strings.ToLower(sql))
	if trimmed == "" {
		return nil // empty statement — let the target decide
	}
	if p.ReadOnly {
		if err := p.allowReadOnly(trimmed); err != nil {
			return err
		}
	}
	if len(p.AllowedTables) > 0 {
		if err := p.allowTables(trimmed); err != nil {
			return err
		}
	}
	return nil
}

func (p DefaultStatementPolicy) allowReadOnly(trimmed string) error {
	for _, w := range writeKeywords {
		if strings.HasPrefix(trimmed, w) {
			return fmt.Errorf("read-only: %q statements are not permitted", w)
		}
	}
	for _, ro := range readOnlyPrefixes {
		if strings.HasPrefix(trimmed, ro) {
			return nil
		}
	}
	return fmt.Errorf("read-only: only read statements are permitted")
}

func (p DefaultStatementPolicy) allowTables(trimmed string) error {
	for _, t := range p.AllowedTables {
		if t == "" {
			continue
		}
		if strings.Contains(trimmed, strings.ToLower(t)) {
			return nil
		}
	}
	return fmt.Errorf("table allow-list: statement references no allowed table")
}

// pgCredential is the Postgres broker's per-session credential: the libpq
// connection string assembled from the freshly minted ephemeral Vault DB role.
// It never leaves the worker — the operator is already authenticated to jess and
// connects to the broker with no password.
//
// When the broker has no standalone CredentialBroker but the wrapped dbproxy
// config already carries a CredsFor (the worker's prod wiring,
// dbConfigFromVault — Vault dynamic-creds + the correct sslmode/URL-escaped DSN),
// Mint defers the credential mint to Dial/Wait time by stashing that CredsFor in
// credsFor and leaving connString empty. This reuses the existing,
// security-reviewed DSN assembly verbatim rather than re-deriving it here, so
// routing the worker through the broker is byte-for-byte the pre-broker DSN.
type pgCredential struct {
	// connString is the target DSN with the injected ephemeral creds. Empty when
	// credsFor is set (the proxy mints the DSN per session in Wait).
	connString string
	// credsFor, when non-nil, is the wrapped proxy's per-session DSN minter,
	// used as the credential source instead of connString (proxy-creds mode).
	credsFor func(context.Context, *catalog.Target) (string, error)
	grant    AccessGrant
}

func (pgCredential) Protocol() string { return string(catalog.ProtoPostgres) }

// Mint implements Broker. It mints the ephemeral DB role/credential from Vault
// (database secrets engine, short TTL) scoped to the target + grant and
// assembles the injected DSN. The operator never sees these credentials; Dial
// consumes them. Fails closed if the credential broker is unconfigured.
func (b *postgresBroker) Mint(ctx context.Context, grant AccessGrant) (Credential, error) {
	if b.proxy == nil {
		return nil, fmt.Errorf("postgres broker: proxy not configured")
	}
	if grant.Target == nil {
		return nil, fmt.Errorf("postgres broker: grant has no target")
	}
	if grant.Client == nil {
		return nil, fmt.Errorf("postgres broker: grant has no client connection")
	}
	// Proxy-creds mode: no standalone CredentialBroker, but the wrapped proxy
	// already mints the (Vault dynamic-creds) DSN. Defer to it at Wait time so the
	// worker's existing, security-reviewed DSN assembly is reused unchanged.
	if b.creds == nil {
		if b.proxy.CredsFor == nil {
			return nil, fmt.Errorf("postgres broker: no credential broker and proxy has no CredsFor (cannot mint ephemeral DB role)")
		}
		return pgCredential{credsFor: b.proxy.CredsFor, grant: grant}, nil
	}

	role := vaultDBRole(grant.Target)
	user, pass, err := b.creds.IssueDBCreds(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("postgres broker: issue ephemeral DB creds (role %q): %w", role, err)
	}
	return pgCredential{
		connString: pgConnString(grant.Target, user, pass),
		grant:      grant,
	}, nil
}

// Dial implements Broker. It sets up the WORM query-log recorder (identical
// fail-closed semantics to the SSH broker) and returns a RecordedConn whose Wait
// runs the dbproxy relay — teeing every statement into the bundle and enforcing
// the per-statement policy — and whose Close seals the bundle.
func (b *postgresBroker) Dial(ctx context.Context, target *catalog.Target, cred Credential) (RecordedConn, error) {
	pc, ok := cred.(pgCredential)
	if !ok {
		return nil, fmt.Errorf("postgres broker: credential is not a Postgres credential (%T)", cred)
	}
	if target == nil {
		return nil, fmt.Errorf("postgres broker: nil target")
	}
	client, ok := pc.grant.Client.(net.Conn)
	if !ok {
		return nil, fmt.Errorf("postgres broker: client connection is not a net.Conn (%T)", pc.grant.Client)
	}

	conn := &pgRecordedConn{
		ctx:    ctx,
		proxy:  b.proxy,
		target: target,
		client: client,
		cred:   pc,
		policy: policyFor(target),
	}

	if b.rec != nil {
		meta := recordingMetaFor(pc.grant, string(catalog.ProtoPostgres), recording.FormatQueryLog)
		w, rerr := b.rec.Open(ctx, meta)
		if rerr != nil {
			if target.Recorded {
				// Fail closed: a must-record target is denied if recording fails.
				return nil, fmt.Errorf("postgres broker: recording required but unavailable (fail-closed): %w", rerr)
			}
			// Non-recorded target: proceed without a recorder.
		} else {
			conn.qlog = recording.NewQueryLogWriter(w) // Close seals the bundle
		}
	} else if target.Recorded {
		return nil, fmt.Errorf("postgres broker: recording required but no recorder configured (fail-closed)")
	}

	return conn, nil
}

// pgRecordedConn is an open Postgres brokered session. Wait runs the dbproxy
// relay (returns when the operator disconnects); Close seals the query-log
// bundle.
type pgRecordedConn struct {
	ctx    context.Context
	proxy  *dbproxy.Config
	target *catalog.Target
	client net.Conn
	cred   pgCredential
	policy StatementPolicy
	qlog   *recording.QueryLogWriter // nil = not recording
}

// Wait runs the Postgres record-proxy. For every brokered statement it records a
// query-log line into the WORM bundle (the recording is the audit trail) and
// enforces the per-statement policy at the relay — a denied statement never
// reaches the target. It returns when the operator disconnects.
func (c *pgRecordedConn) Wait() error {
	// The query log is written by enforce for EVERY statement (allowed + denied)
	// before any bytes reach the target, so auditQuery is left nil to avoid
	// double-recording — enforce is the single record+decide site.
	return c.waitConfig().Handle(c.ctx, c.client, c.target, nil)
}

// waitConfig builds the per-session dbproxy config Wait drives: a config copy so
// the injected ephemeral creds + the per-statement hooks are scoped to this
// session and never mutate the shared proxy config. Proxy-creds mode (credsFor
// set) defers to the wrapped proxy's DSN minter; otherwise the connString minted
// at Mint time is injected. Split out so the wiring (injected creds via CredsFor,
// enforce as the relay Policy) is unit-testable without a live Postgres, mirroring
// the MySQL broker's waitConfig.
func (c *pgRecordedConn) waitConfig() *dbproxy.Config {
	credsFor := func(context.Context, *catalog.Target) (string, error) {
		return c.cred.connString, nil // injected ephemeral creds; operator never sees them
	}
	if c.cred.credsFor != nil {
		credsFor = c.cred.credsFor
	}
	return &dbproxy.Config{
		CredsFor: credsFor,
		Policy:   c.enforce,
	}
}

// enforce is the relay's per-statement hook: it records the statement to the
// WORM query log with the policy decision, then returns the policy error (nil =
// allow). dbproxy turns a non-nil return into an operator-facing ErrorResponse
// and skips forwarding — so the recording is written for allowed AND denied
// statements before any bytes reach the target.
func (c *pgRecordedConn) enforce(sql string) error {
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
func (c *pgRecordedConn) Close() error {
	if c.qlog == nil {
		return nil
	}
	return c.qlog.Close()
}

// policyFor derives the per-statement policy from the target's catalog fields.
// Phase 2 has no per-target read-only / allow-list columns yet, so this returns
// a permissive (pass-through) DefaultStatementPolicy — the seam is wired and
// enforced; tightening it is a catalog change, not a relay change. Returning a
// concrete policy (rather than nil) keeps the enforcement path always live.
func policyFor(_ *catalog.Target) StatementPolicy {
	return DefaultStatementPolicy{}
}

// vaultDBRole is the Vault database secrets-engine role the broker mints from for
// a target. Phase 2 uses the target ID as the role name (the conventional 1:1
// role-per-target mapping the Vault DB mount is configured with); a target with
// no ID falls back to a generic role so the mint still has a name to ask for
// (and fails loudly at Vault if it doesn't exist).
func vaultDBRole(t *catalog.Target) string {
	if t.ID != "" {
		return t.ID
	}
	return "postgres"
}

// pgConnString assembles the libpq connection string for the target with the
// injected ephemeral creds. Mirrors dbproxy's expected DSN; the operator never
// sees this. sslmode is left to the target Address conventions — DB targets are
// reached only worker-side over the cluster network.
func pgConnString(t *catalog.Target, user, pass string) string {
	host, port := splitHostPort(t.Address)
	var sb strings.Builder
	fmt.Fprintf(&sb, "postgres://%s:%s@%s", user, pass, host)
	if port != "" {
		fmt.Fprintf(&sb, ":%s", port)
	}
	if t.Database != "" {
		fmt.Fprintf(&sb, "/%s", t.Database)
	}
	return sb.String()
}

// splitHostPort splits host:port, tolerating a bare host (no port) and IPv6
// addresses in brackets. It does not error — a malformed address surfaces as a
// connect failure at dial time with a clear dbproxy error.
func splitHostPort(addr string) (host, port string) {
	if addr == "" {
		return "", ""
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "" // no port component
	}
	return h, p
}

// compile-time guards.
var (
	_ io.Closer       = (*pgRecordedConn)(nil)
	_ StatementPolicy = DefaultStatementPolicy{}
	_ Broker          = (*postgresBroker)(nil)
)
