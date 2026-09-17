# internal/mysqlproxy — MySQL/MariaDB broker

Sibling to `internal/dbproxy` (Postgres). Closes the last `☐` on the
protocol-parity matrix vs Boundary CE.

## Status

**Implemented (2026-05-30).** Operator → broker → target round-trips
work end-to-end for SELECT, INSERT, PREPARE/EXECUTE, and any other
COM_QUERY / COM_STMT_* the operator sends. Every COM_QUERY and
COM_STMT_PREPARE SQL text is delivered to the audit hook (truncated at
8KB). Integration test against `mysql:8` in docker passes (`go test
./internal/mysqlproxy/ -run TestMySQLBroker -v -timeout 150s`).

## Wire-protocol reference

- **Initial Handshake Packet** (server → client): MariaDB KB
  [server_handshake](https://mariadb.com/kb/en/connection/#initial-handshake-packet)
- **HandshakeResponse41** (client → server): MariaDB KB
  [client handshake response](https://mariadb.com/kb/en/connection/#client-handshake-response)
- **COM_QUERY** (0x03): [command-query](https://mariadb.com/kb/en/com_query/)
- **COM_STMT_PREPARE** (0x16) / **COM_STMT_EXECUTE** (0x17): MariaDB KB prepared statement command pages
- MySQL packet framing (3-byte length + 1-byte sequence): MariaDB KB
  [protocol packet](https://mariadb.com/kb/en/0-packet/)

## Library

**`github.com/go-mysql-org/go-mysql`** v1.15. Provides:

- `server.NewCustomizedConn` — operator-facing handshake + command loop
- `server.AuthenticationHandler` — pluggable auth (we use `permissiveAuth`
  which accepts any user with an empty password — Jess pre-authorized
  the operator upstream, so MySQL-level auth is decorative)
- `client.Connect` + `client.Conn` — target-side connection with full
  handshake (caching_sha2_password ⇄ mysql_native_password switching,
  TLS upgrade, capability negotiation)

Considered and rejected: `github.com/siddontang/go-mysql` (go-mysql-org
is the community-maintained active fork); `dolthub/go-mysql-server`
(server-side query engine, way more than we need); writing the wire
protocol from scratch (premature reinvention — MySQL has dozens of edge
cases around auth-method-switch and TLS upgrade).

## Implementation summary

1. **Operator handshake** — `mserver.NewCustomizedConn` with
   `permissiveAuth{}` and a `proxyHandler{target, audit}`. The auth
   handler accepts any operator with an empty password under
   mysql_native_password.

2. **Target connect** — `c.CredsFor` returns a `TargetCreds{Address,
   User, Password, Database}` from Vault dyn-creds; `client.Connect`
   completes the real handshake target-side.

3. **Command loop** — `serverConn.HandleCommand()` in a `for` loop.
   The library dispatches each COM byte to the right `proxyHandler`
   method (`HandleQuery`, `HandleStmtPrepare`, `HandleStmtExecute`,
   `HandleStmtClose`, `UseDB`, `HandleFieldList`, `HandleOtherCommand`).

4. **Forwarding** — every method delegates 1:1 to the target client.Conn.
   `HandleStmtPrepare` stashes the target-side `*Stmt` against an opaque
   token; `HandleStmtExecute` and `HandleStmtClose` resolve it.

5. **Auditing** — `HandleQuery` and `HandleStmtPrepare` invoke
   `audit(sql)` before forwarding. Binary EXECUTE params aren't
   re-audited (the SQL was already captured at PREPARE). SQL is
   clipped at 8KB before emit (`auditTruncate`) — matches Controller's
   PG audit ceiling.

6. **Connection lifecycle** — `defer serverConn.Close()` guarded by
   `Closed()` (library's Close path nil-dereferences when called on an
   already-torn-down connection).

## Catalog entry

```json
{
  "id": "app-mysql-01",
  "name": "app mysql (dynamic creds)",
  "protocol": "mysql",
  "address": "mysql-rw.cnpg-clusters.svc.cluster.local:3306",
  "database": "app",
  "region": "eu-tr",
  "required_roles": ["platform_admin"],
  "recorded": false
}
```

Recording defaults to `false` because MySQL responses can include large
BLOBs; a future enhancement could capture EXPLAIN-style metadata
without dumping row data.

## Operator-side connection

Operators connect to the local jessctl-forwarded port with an empty
password:

```bash
mysql -h 127.0.0.1 -P <port> -u operator
# OR (some clients require -p)
mysql -h 127.0.0.1 -P <port> -u operator -p   # press enter at the prompt
```

The MySQL-level user can be any string — Jess decided whether to allow
the brokered session upstream (token + grant). The target-side dynamic
credentials come from Vault and are never visible to the operator.

## Worker wiring (when ready)

`cmd/jess-worker/vault_wiring.go` will need a sibling to the existing
Postgres credential-broker:

```go
mysqlCfg := &mysqlproxy.Config{
    CredsFor: func(ctx context.Context, t *catalog.Target) (mysqlproxy.TargetCreds, error) {
        user, pass, _, err := vault.DBCredentials(ctx, "database", roleFor(t))
        if err != nil { return mysqlproxy.TargetCreds{}, err }
        return mysqlproxy.TargetCreds{
            Address: t.Address, User: user, Password: pass, Database: t.Database,
        }, nil
    },
}
```

Plus a `ProtoMySQL` dispatch case in the spine broker switch (currently
the catalog rejects "mysql" targets at load time when no mysql config is
wired — that guard should narrow to "if MySQL is enabled, allow").
