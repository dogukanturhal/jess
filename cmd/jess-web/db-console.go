// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Browser SQL console backend (ADR 0049 Phase 2/4 surface — the user-facing
// half of the now-wired Postgres/MySQL brokering).
//
// THE LOAD-BEARING ARCHITECTURE DECISION (do not change):
//
//   Server-side query API. The browser is a dumb renderer and NEVER speaks
//   raw pgwire/MySQL. Statement policy + WORM query-log recording are enforced
//   at the worker relay (internal/dbproxy, internal/mysqlproxy); if the browser
//   spoke the wire protocol directly it would bypass BOTH. So jess-web is the
//   wire-protocol client, the browser only sends `{sql}` and gets back
//   `{columns, rows, rowsAffected}` JSON.
//
// Per-query flow (mirrors ws.go's SSH bridge dial exactly):
//
//   browser  ──POST /api/db/query {target,grant,sql}──▶  jess-web
//   jess-web ──client.Dial(controllerAddr, ctrlTLS,
//                wire.OperatorRequest{Token: op.Token,         ◀── the operator's
//                                     TargetID, GrantID})──▶  controller     real
//   controller ──(brokered)──▶ worker ──▶ DB broker relay ──▶ target          Falcon-ID
//                                                                              identity
//
// The returned net.Conn carries the raw DB wire bytes AFTER the OperatorRequest
// JSON header — i.e. it IS the operator-side `opConn` that dbproxy.Handle /
// mysqlproxy.Handle proxy. jess-web then drives a real Go DB client over that
// conn:
//
//   Postgres — github.com/jackc/pgx/v5/pgconn with a DialFunc that returns the
//              already-open relay conn (TLS disabled; the relay declines SSL with
//              'N', exactly as dbproxy.Handle expects). Auth is permissive at the
//              relay (the worker injects the real Vault creds target-side).
//   MySQL    — github.com/go-mysql-org/go-mysql/client.ConnectWithDialer over the
//              relay conn. The relay's permissiveAuth accepts any user + empty
//              password (the worker injects the real creds target-side).
//
// Because every statement traverses the relay, the worker still records it to
// the WORM query log AND enforces the per-statement policy. A policy denial
// comes back as a normal DB error (PG ErrorResponse / MySQL ErrPacket) which we
// surface as `{error: "..."}` — never a crash, never an open unmediated conn.
//
// One brokered session per query: each POST opens a fresh operator session →
// fresh worker broker session → fresh ephemeral Vault DB role + fresh WORM
// bundle, then tears it down. That keeps the surface fail-closed (an expired
// grant / dial failure / denied statement is a clean error) and matches the
// worker's mint→dial→relay→close spine, at the cost of a connect per query —
// acceptable for an interactive console (humans type one statement at a time).

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	mclient "github.com/go-mysql-org/go-mysql/client"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/dogukanturhal/jess/internal/client"
	"github.com/dogukanturhal/jess/internal/wire"
)

// dbConsoleConfig holds the per-process controller-dial config for the SQL
// console. It is the same controller operator-port dial + mTLS the SSH WS
// bridge uses (connectConfig) — reused verbatim so the console inherits the
// svc-cert mTLS posture without a second code path.
type dbConsoleConfig struct {
	controllerAddr string
	tlsCfg         *tls.Config
	sessions       *sessionStore
}

// queryTimeout bounds a single brokered query end-to-end (dial + handshake +
// execution + result read). An interactive console statement that runs longer
// than this is almost certainly a runaway scan; the operator can re-run with a
// LIMIT. Generous enough for normal analytic queries.
const queryTimeout = 60 * time.Second

// maxSQLBytes caps the submitted statement size. Matches the controller audit
// ceiling spirit (the relay truncates the audited text at 8KB) — a console is
// for interactive statements, not bulk DDL dumps.
const maxSQLBytes = 64 << 10

// maxResultRows bounds how many rows we marshal into the JSON response so a
// `SELECT *` on a huge table doesn't OOM jess-web or the browser. The relay
// still streamed + recorded the full result; we just stop materialising past
// the cap and flag it as truncated.
const maxResultRows = 5000

// dbQueryRequest is the browser → jess-web POST body.
type dbQueryRequest struct {
	Target   string `json:"target"`
	Grant    string `json:"grant"` // optional — empty = admin-direct-connect auto-mint
	Protocol string `json:"protocol"`
	SQL      string `json:"sql"`
}

// dbQueryResponse is the jess-web → browser JSON. Exactly one of (Columns/Rows/
// RowsAffected) OR Error is meaningful. Rows are [][]*string so a SQL NULL is a
// JSON null and any value is its text representation — the browser renders text,
// it does not re-type the column.
type dbQueryResponse struct {
	Columns      []string    `json:"columns"`
	Rows         [][]*string `json:"rows"`
	RowsAffected int64       `json:"rows_affected"`
	CommandTag   string      `json:"command_tag,omitempty"`
	Truncated    bool        `json:"truncated,omitempty"`
	ElapsedMS    int64       `json:"elapsed_ms"`
	Error        string      `json:"error,omitempty"`
}

// handleQuery is POST /api/db/query. It authenticates the operator from the
// cookie session, opens a brokered DB relay session to the target+grant (the
// operator's REAL Falcon-ID token flows into the OperatorRequest — never a
// service identity), runs the single statement through the relay, and returns
// the result set (or a clean error). Fail-closed: any failure is a JSON error,
// never an open unmediated connection.
func (c *dbConsoleConfig) handleQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		writeQueryError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	op, err := c.sessions.operatorFromRequest(r)
	if err != nil {
		writeQueryError(w, http.StatusUnauthorized, "not signed in")
		return
	}

	var req dbQueryRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSQLBytes+4096))
	if err := dec.Decode(&req); err != nil {
		writeQueryError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	if req.Target == "" {
		writeQueryError(w, http.StatusBadRequest, "target required")
		return
	}
	if strings.TrimSpace(req.SQL) == "" {
		writeQueryError(w, http.StatusBadRequest, "sql required")
		return
	}
	if len(req.SQL) > maxSQLBytes {
		writeQueryError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("statement too large (%d bytes; max %d)", len(req.SQL), maxSQLBytes))
		return
	}

	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	switch proto {
	case "postgres", "mysql":
	default:
		writeQueryError(w, http.StatusBadRequest,
			fmt.Sprintf("unsupported protocol %q (SQL console supports postgres, mysql)", req.Protocol))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()

	// Open the brokered relay session. This is the SAME dial the SSH WS bridge
	// uses (client.Dial → controller operator port, wire.OperatorRequest with
	// the operator's verified token + target + grant, presenting the svc-cert
	// mTLS config). The returned conn carries the raw DB wire bytes after the
	// JSON header — i.e. the operator-side opConn of dbproxy/mysqlproxy.
	relay, err := client.Dial(ctx, c.controllerAddr, c.tlsCfg, wire.OperatorRequest{
		Token: op.Token, TargetID: req.Target, GrantID: req.Grant,
	})
	if err != nil {
		// Fail-closed: a dial failure (grant expired, target offline, authz
		// denied at the controller, step-up required) is a clean error — no
		// connection was established.
		writeQueryError(w, http.StatusBadGateway, "controller dial failed: "+err.Error())
		return
	}
	defer relay.Close()

	started := time.Now()
	var resp *dbQueryResponse
	switch proto {
	case "postgres":
		resp, err = runPostgresQuery(ctx, relay, req.SQL)
	case "mysql":
		resp, err = runMySQLQuery(ctx, relay, req.Target, req.SQL)
	}
	if err != nil {
		// A transport/handshake failure (the relay closed, or the wire protocol
		// didn't match the declared protocol) — distinct from a DB-level error,
		// which runXQuery returns inside resp.Error. Surface it as a normal error
		// result, not a 5xx, so the console shows it in the status bar.
		resp = &dbQueryResponse{Error: err.Error()}
	}
	resp.ElapsedMS = time.Since(started).Milliseconds()

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// runPostgresQuery drives a pgx pgconn client over the already-open relay conn
// and marshals the result set to JSON.
//
// The DialFunc returns the pre-established relay conn so pgx's handshake (the
// StartupMessage + simple-query protocol) flows through the broker — the relay's
// dbproxy.Handle declines SSL ('N'), accepts the startup, and returns
// AuthenticationOk after injecting the real Vault creds target-side. We disable
// TLS (TLSConfig nil) because the operator↔controller leg is already mTLS and
// the relay declines in-band SSL; we use a permissive user/no-password because
// the relay does not gate on a PG-level password.
//
// A policy denial OR any target SQL error comes back as a *pgconn.PgError on
// Exec — we put it in resp.Error and keep the surface fail-closed (no result is
// returned alongside an error).
func runPostgresQuery(ctx context.Context, relay net.Conn, sql string) (*dbQueryResponse, error) {
	cfg, err := pgconn.ParseConfig("postgres://broker@db/postgres")
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	// Route the connection over the brokered relay conn. DialFunc runs before
	// TLS and is the seam pgx exposes for exactly this — hand it the relay and
	// it speaks pgwire straight through the broker. The conn is consumed once.
	used := false
	cfg.DialFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		if used {
			return nil, errors.New("postgres: relay conn already consumed")
		}
		used = true
		return relayNoClose{relay}, nil
	}
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	cfg.TLSConfig = nil // relay leg is already mTLS; relay declines in-band SSL
	cfg.RuntimeParams["application_name"] = "jess-web-sql-console"

	pgConn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		// Handshake failed — relay closed, or the target isn't actually Postgres.
		// Surface as a DB-level error result rather than a transport error so the
		// console renders it cleanly.
		return &dbQueryResponse{Error: pgErrorString(err)}, nil
	}
	defer pgConn.Close(ctx)

	// Simple-query protocol: Exec sends one Query message (the relay audits +
	// policy-checks it before forwarding). ReadAll drains every result set the
	// statement produced; we marshal the LAST one (mirrors psql, where a
	// multi-statement string shows the final result + the aggregate tags).
	results, err := pgConn.Exec(ctx, sql).ReadAll()
	if err != nil {
		// PgError here = target rejection OR relay policy denial (42501
		// insufficient_privilege from dbproxy.denyStatement). Either way it's a
		// clean DB-level error for the console.
		return &dbQueryResponse{Error: pgErrorString(err)}, nil
	}
	if len(results) == 0 {
		return &dbQueryResponse{Columns: []string{}, Rows: [][]*string{}}, nil
	}

	resp := &dbQueryResponse{Rows: [][]*string{}, Columns: []string{}}
	for i, res := range results {
		if res.Err != nil {
			return &dbQueryResponse{Error: pgErrorString(res.Err)}, nil
		}
		// Aggregate affected rows across statements; render the LAST result set's
		// columns/rows (the one an operator cares about for a SELECT).
		resp.RowsAffected += res.CommandTag.RowsAffected()
		resp.CommandTag = res.CommandTag.String()
		if i != len(results)-1 {
			continue
		}
		cols := make([]string, len(res.FieldDescriptions))
		for j, fd := range res.FieldDescriptions {
			cols[j] = fd.Name
		}
		resp.Columns = cols
		for ri, row := range res.Rows {
			if ri >= maxResultRows {
				resp.Truncated = true
				break
			}
			out := make([]*string, len(row))
			for ci, cell := range row {
				if cell == nil {
					out[ci] = nil // SQL NULL → JSON null
					continue
				}
				s := string(cell) // text-format wire value
				out[ci] = &s
			}
			resp.Rows = append(resp.Rows, out)
		}
	}
	return resp, nil
}

// runMySQLQuery drives a go-mysql client over the already-open relay conn and
// marshals the result set to JSON.
//
// ConnectWithDialer is the seam: the dialer returns the pre-established relay
// conn so the full MySQL handshake (the relay's mysqlproxy permissiveAuth
// accepts any user + empty password, then injects the real Vault creds
// target-side) runs through the broker. addr/network are placeholders — the
// dialer ignores them and returns the relay. The default database is left empty
// (the relay's target side carries the target.Database default).
//
// A policy denial (ER_SPECIFIC_ACCESS_DENIED_ERROR from mysqlproxy.denyStatement)
// or any target SQL error comes back as a *mysql.MyError on Execute — we put it
// in resp.Error and return no result set.
func runMySQLQuery(ctx context.Context, relay net.Conn, target, sql string) (*dbQueryResponse, error) {
	used := false
	dialer := func(_ context.Context, _, _ string) (net.Conn, error) {
		if used {
			return nil, errors.New("mysql: relay conn already consumed")
		}
		used = true
		return relayNoClose{relay}, nil
	}
	// network/addr are placeholders (the dialer ignores them); user="broker",
	// empty password matches the relay's permissiveAuth. dbName empty — the
	// target-side relay carries the catalog default DB.
	conn, err := mclient.ConnectWithDialer(ctx, "tcp", "broker:3306", "broker", "", "", dialer)
	if err != nil {
		return &dbQueryResponse{Error: mysqlErrorString(err)}, nil
	}
	defer conn.Close()

	res, err := conn.Execute(sql)
	if err != nil {
		return &dbQueryResponse{Error: mysqlErrorString(err)}, nil
	}
	defer res.Close()

	resp := &dbQueryResponse{
		Columns:      []string{},
		Rows:         [][]*string{},
		RowsAffected: int64(res.AffectedRows),
	}
	rs := res.Resultset
	if rs == nil || len(rs.Fields) == 0 {
		// Non-SELECT (INSERT/UPDATE/DDL): no result set, just affected rows.
		return resp, nil
	}
	cols := make([]string, len(rs.Fields))
	for i, f := range rs.Fields {
		cols[i] = string(f.Name)
	}
	resp.Columns = cols
	for ri := range rs.Values {
		if ri >= maxResultRows {
			resp.Truncated = true
			break
		}
		out := make([]*string, len(rs.Fields))
		for ci := range rs.Fields {
			isNull, nerr := rs.IsNull(ri, ci)
			if nerr == nil && isNull {
				out[ci] = nil // SQL NULL → JSON null
				continue
			}
			s, serr := rs.GetString(ri, ci)
			if serr != nil {
				// Unrenderable cell — surface a placeholder rather than failing
				// the whole result (the value reached us, the renderer just can't
				// stringify its type).
				v := fmt.Sprintf("<unrenderable: %v>", serr)
				out[ci] = &v
				continue
			}
			cell := s
			out[ci] = &cell
		}
		resp.Rows = append(resp.Rows, out)
	}
	return resp, nil
}

// relayNoClose wraps the relay conn so the DB client's Close() (which pgx /
// go-mysql call on conn teardown) does NOT close the underlying relay socket —
// the handler owns the relay lifecycle (defer relay.Close()). Without this, the
// client library would close the relay out from under us on its own Close path
// and the deferred close would double-close. All other net.Conn methods pass
// through unchanged so the wire protocol works normally.
type relayNoClose struct{ net.Conn }

func (relayNoClose) Close() error { return nil }

// pgErrorString renders a Postgres error for the browser. A *pgconn.PgError
// (target rejection or relay policy denial) gets its Severity + Code + Message;
// anything else gets the bare error text.
func pgErrorString(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code != "" {
			return fmt.Sprintf("%s: %s (SQLSTATE %s)", pgErr.Severity, pgErr.Message, pgErr.Code)
		}
		return pgErr.Message
	}
	return err.Error()
}

// mysqlErrorString renders a MySQL error for the browser. The go-mysql
// *mysql.MyError already stringifies as "ERROR <code> (<state>): <msg>" so we
// use its text directly; a transport error gets its bare text.
func mysqlErrorString(err error) string {
	return err.Error()
}

func writeQueryError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dbQueryResponse{Error: msg})
}
