// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mysqlproxy brokers MySQL/MariaDB access — sibling to dbproxy
// (Postgres). Same security model: the worker is a MySQL server to the
// operator and a MySQL client to the target. The operator authenticates
// to JESS (Falcon-ID token + grant), NOT to MySQL — the operator-facing
// auth is permissive (`--user=broker --password=`), and the proxy
// connects to the target with INJECTED credentials (Vault dynamic DB
// creds in prod) so the operator never sees the database password.
// Every COM_QUERY / COM_STMT_PREPARE is reported for per-query audit.
package mysqlproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	mclient "github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	mserver "github.com/go-mysql-org/go-mysql/server"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// ErrTargetUnavailable is returned when the target connection fails before
// any operator command runs.
var ErrTargetUnavailable = errors.New("mysqlproxy: target unavailable")

// auditTruncate matches Controller's audit ceiling for query strings —
// 8KB is enough to capture any reasonable SQL while bounding log volume
// for `INSERT INTO huge VALUES (...)` style payloads.
const auditTruncate = 8 << 10

// Config wires the operator-side auth (permissive — operator pre-authenticated
// upstream) and the target-side credentials (injected from Vault). Mirrors
// dbproxy.Config so spine.WorkerRuntime can dispatch to either.
type Config struct {
	// CredsFor returns the MySQL connection details for the target WITH
	// injected credentials. Production wires this to vaultx's
	// database/creds/<role> mount; tests can return static values.
	CredsFor func(ctx context.Context, target *catalog.Target) (TargetCreds, error)

	// Policy, if set, is the per-statement enforcement seam at the relay (ADR
	// 0049 Phase 4: "Per-statement policy (read-only, table allow-list)
	// enforceable at the relay"). It is consulted for every COM_QUERY /
	// COM_STMT_PREPARE BEFORE the statement is forwarded to the target. A nil
	// return permits the statement; a non-nil error denies it — the relay then
	// surfaces a MySQL error to the operator (the statement never reaches the
	// target) and keeps the session open for the next statement. nil Policy = no
	// enforcement (audit only), preserving the pre-Phase-4 pass-through
	// behaviour. Mirrors dbproxy.Config.Policy exactly.
	Policy func(sql string) error
}

// ErrStatementDenied wraps a Policy denial so callers can distinguish a
// policy-blocked statement from a relay/connection failure. Mirrors
// dbproxy.ErrStatementDenied.
var ErrStatementDenied = errors.New("mysqlproxy: statement denied by policy")

// TargetCreds describes how the broker should connect to the target. Mirrors
// the fields a MySQL driver DSN would carry, but split so callers don't have
// to assemble a DSN string with proper escaping.
type TargetCreds struct {
	// Address is host:port (e.g. mysql-rw.cnpg-clusters.svc.cluster.local:3306).
	Address string
	// User + Password are the Vault-issued dynamic credentials — the operator
	// never sees these (server-side only).
	User     string
	Password string
	// Database is the default schema; may be empty.
	Database string
}

// Handle proxies the MySQL wire protocol between opConn (operator) and the
// target. auditQuery (may be nil) receives every COM_QUERY / COM_STMT_PREPARE
// SQL text (truncated at 8KB for log-volume safety).
//
// Operator side: server.NewCustomizedConn with a permissive
// auth handler — the operator's connect string must use a known broker
// username + an empty password. This matches dbproxy's "Jess already
// authorized, skip the protocol-level password check" design.
//
// Target side: go-mysql-org/go-mysql client.Connect handles the full
// MySQL handshake (caching_sha2_password ⇄ mysql_native_password
// switching, TLS upgrade, capability negotiation) so we don't have to.
func (c *Config) Handle(ctx context.Context, opConn net.Conn, target *catalog.Target, auditQuery func(sql string)) error {
	if opConn == nil {
		return errors.New("mysqlproxy: opConn nil")
	}
	if c == nil || c.CredsFor == nil {
		_ = opConn.Close()
		return errors.New("mysqlproxy: Config.CredsFor nil")
	}

	creds, err := c.CredsFor(ctx, target)
	if err != nil {
		_ = opConn.Close()
		return fmt.Errorf("mysqlproxy: creds for %s: %w", target.ID, err)
	}

	targetConn, err := mclient.Connect(creds.Address, creds.User, creds.Password, creds.Database)
	if err != nil {
		_ = opConn.Close()
		return fmt.Errorf("%w: %s: %v", ErrTargetUnavailable, target.ID, err)
	}
	defer targetConn.Close()

	handler := &proxyHandler{target: targetConn, audit: auditQuery, policy: c.Policy}
	// NewCustomizedConn does the full handshake before returning, including
	// the OK packet to the operator. Once it returns, we drive the command
	// loop until HandleCommand returns an error (operator disconnected).
	srv := mserver.NewDefaultServer()
	serverConn, err := srv.NewCustomizedConn(opConn, permissiveAuth{}, handler)
	if err != nil {
		// opConn already closed by NewCustomizedConn on handshake failure.
		return fmt.Errorf("mysqlproxy: operator handshake: %w", err)
	}
	// server.Conn.Close panics if the inner packet.Conn was already
	// torn down by HandleCommand's own disconnect path (it nil-receives
	// from the embedded *packet.Conn). Guard the defer with Closed().
	defer func() {
		if !serverConn.Closed() {
			serverConn.Close()
		}
	}()

	for {
		if err := serverConn.HandleCommand(); err != nil {
			// Operator disconnected cleanly (io.EOF / connection reset) or
			// the target rejected something — both end the brokered session.
			if errors.Is(err, mysql.ErrBadConn) || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}
		if serverConn.Closed() {
			return nil
		}
	}
}

// permissiveAuth is the operator-facing auth handler: the operator is
// pre-authenticated by Jess (Falcon-ID token + grant) so we don't gate on
// a MySQL-level password. The configured "empty password" credential
// matches whatever the operator presents (no password) for the
// mysql_native_password plugin.
//
// Security note: the operator-port TLS + Jess auth in the operator handshake
// path (BEFORE this handler runs) is what protects the brokered session.
// The MySQL-level user/password is decorative for client compatibility.
type permissiveAuth struct{}

func (permissiveAuth) GetCredential(_ string) (mserver.Credential, bool, error) {
	// Empty-password credential under mysql_native_password — the operator's
	// client connects with `--user=<anything> --password=` (no password).
	return mserver.Credential{
		Passwords:      []string{""},
		AuthPluginName: mysql.AUTH_NATIVE_PASSWORD,
	}, true, nil
}

func (permissiveAuth) CheckUsername(_ string) (bool, error)   { return true, nil }
func (permissiveAuth) OnAuthSuccess(_ *mserver.Conn) error    { return nil }
func (permissiveAuth) OnAuthFailure(_ *mserver.Conn, _ error) {}

// proxyHandler forwards every command method to the target client.Conn.
// auditQuery is invoked on every COM_QUERY and COM_STMT_PREPARE SQL text.
type proxyHandler struct {
	target *mclient.Conn

	// stmts tracks ctx tokens we hand back from HandleStmtPrepare so we can
	// resolve them in HandleStmtExecute / HandleStmtClose. The go-mysql
	// library hands us back whatever `context` we returned from Prepare —
	// we use it as a key into the target-side *Stmt.
	stmtMu sync.Mutex
	stmts  map[any]*mclient.Stmt

	audit func(sql string)

	// policy, if set, is consulted for every COM_QUERY / COM_STMT_PREPARE
	// before the statement is forwarded. A non-nil return denies the statement
	// (surfaced to the operator, never reaches the target). nil = pass-through.
	policy func(sql string) error
}

// denyStatement applies policy to sql. Returns nil if allowed, or a MySQL wire
// error if denied (which HandleQuery/HandleStmtPrepare return to the operator —
// go-mysql writes it as an ErrPacket and keeps the session usable). Mirrors
// dbproxy.denyStatement's "reject cleanly, keep the connection open" contract.
func (h *proxyHandler) denyStatement(sql string) error {
	if h.policy == nil {
		return nil
	}
	perr := h.policy(sql)
	if perr == nil {
		return nil
	}
	return mysql.NewError(mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR,
		fmt.Sprintf("%v: %v", ErrStatementDenied, perr))
}

func (h *proxyHandler) emitAudit(sql string) {
	if h.audit == nil {
		return
	}
	if len(sql) > auditTruncate {
		sql = sql[:auditTruncate]
	}
	h.audit(sql)
}

// UseDB forwards COM_INIT_DB.
func (h *proxyHandler) UseDB(dbName string) error {
	return h.target.UseDB(dbName)
}

// HandleQuery forwards COM_QUERY. It audits the SQL text first (the audit hook
// is where the broker tees the statement into the WORM query log — recorded for
// BOTH allowed and denied statements), then enforces the per-statement policy
// BEFORE forwarding: a denied statement never reaches the target.
func (h *proxyHandler) HandleQuery(query string) (*mysql.Result, error) {
	h.emitAudit(query)
	if denied := h.denyStatement(query); denied != nil {
		return nil, denied
	}
	return h.target.Execute(query)
}

// HandleFieldList forwards COM_FIELD_LIST. Not commonly used but legal.
func (h *proxyHandler) HandleFieldList(table, fieldWildcard string) ([]*mysql.Field, error) {
	return h.target.FieldList(table, fieldWildcard)
}

// HandleStmtPrepare forwards COM_STMT_PREPARE, audits the SQL text, stashes
// the target-side *Stmt against a token we return as context.
func (h *proxyHandler) HandleStmtPrepare(query string) (params int, columns int, context any, err error) {
	h.emitAudit(query)
	if denied := h.denyStatement(query); denied != nil {
		return 0, 0, nil, denied
	}
	stmt, perr := h.target.Prepare(query)
	if perr != nil {
		return 0, 0, nil, perr
	}
	token := new(int)
	h.stmtMu.Lock()
	if h.stmts == nil {
		h.stmts = make(map[any]*mclient.Stmt)
	}
	h.stmts[token] = stmt
	h.stmtMu.Unlock()
	return stmt.ParamNum(), stmt.ColumnNum(), token, nil
}

// HandleStmtExecute forwards COM_STMT_EXECUTE. The SQL was audited at
// PREPARE time; binary params here are not part of the audited text.
func (h *proxyHandler) HandleStmtExecute(context any, _ string, args []any) (*mysql.Result, error) {
	h.stmtMu.Lock()
	stmt, ok := h.stmts[context]
	h.stmtMu.Unlock()
	if !ok {
		return nil, errors.New("mysqlproxy: unknown statement context")
	}
	return stmt.Execute(args...)
}

// HandleStmtClose forwards COM_STMT_CLOSE.
func (h *proxyHandler) HandleStmtClose(context any) error {
	h.stmtMu.Lock()
	stmt, ok := h.stmts[context]
	if ok {
		delete(h.stmts, context)
	}
	h.stmtMu.Unlock()
	if !ok {
		return nil
	}
	return stmt.Close()
}

// HandleOtherCommand catches everything the typed methods above don't —
// COM_PING (0x0E), COM_RESET_CONNECTION (0x1F), COM_CHANGE_USER (0x11),
// etc. Most just need the OK passthrough that the library wraps for us;
// returning ErrUnknown lets the server send a generic ER_UNKNOWN_ERROR
// which is the safe default for unfamiliar bytes.
func (h *proxyHandler) HandleOtherCommand(cmd byte, _ []byte) error {
	switch cmd {
	case mysql.COM_PING:
		return h.target.Ping()
	}
	return mysql.NewError(mysql.ER_UNKNOWN_ERROR,
		fmt.Sprintf("mysqlproxy: COM byte 0x%02x not implemented", cmd))
}
