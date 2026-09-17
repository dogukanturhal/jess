// SPDX-License-Identifier: AGPL-3.0-or-later

// Command jessctl is the operator CLI. It authenticates to Falcon-ID (OIDC) and
// opens a local port that tunnels through the Jess broker to a target, so the
// operator points a normal client (ssh, psql, …) at the local port:
//
//	jessctl connect echo --controller internal.example.com:7101 --grant <id> --listen :2222
//	ssh -p 2222 hexxlock@127.0.0.1
//
// Auth: --token / $JESS_TOKEN if you already have a Falcon-ID token, otherwise
// `jessctl login` (or connect without a token) runs the browser OIDC flow.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dogukanturhal/jess/internal/client"
	"github.com/dogukanturhal/jess/internal/transport"
	"github.com/dogukanturhal/jess/internal/wire"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var defaultScopes = []string{"openid", "email", "profile", "roles", "offline_access"}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "connect":
		cmdConnect(os.Args[2:])
	case "login":
		cmdLogin(os.Args[2:])
	case "request":
		cmdRequest(os.Args[2:])
	case "up":
		cmdUp(os.Args[2:])
	case "admin":
		cmdAdmin(os.Args[2:])
	case "rdp-probe":
		cmdRDPProbe(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  jessctl connect <target-id> --controller <addr> --grant <id> [--listen 127.0.0.1:0] [--token T]
  jessctl connect --controller <addr> --grant <id> [--listen 127.0.0.1:0] [--token T] <target-id>
  jessctl login --issuer <url> --client-id <id>
  jessctl up --admin <https-addr> [--renew-before 30m] [--out-dir ~/.config/jess] [--force]

Phase 6 — one-shot operator bring-up: ensures a fresh operator client cert
exists at ~/.config/jess/operator.crt (mints if missing or expiring within
--renew-before). Safe to run on every shell startup; prints the export-env
block to paste into your session.

Phase 5b — JIT request workflow (any verified caller):
  jessctl request --admin <https-addr> --target <id> --reason <text> [--ttl-min N]

Admin subcommands (Falcon-ID token must carry platform_admin role):
  jessctl admin issue-grant   --admin <https-addr> --subject <sub> --target <id> --ttl <duration>
  jessctl admin list-grants   --admin <https-addr> [--target <id>]
  jessctl admin revoke        --admin <https-addr> --grant <id>
  jessctl admin list-requests --admin <https-addr> [--state pending|approved|denied|expired]
  jessctl admin approve       --admin <https-addr> --request <id> --ttl <duration>
  jessctl admin deny          --admin <https-addr> --request <id> --reason <text>
  jessctl admin operator-cert        --admin <https-addr> [--out-dir ~/.config/jess] [--ttl 8h]
  jessctl admin operator-cert-revoke --admin <https-addr> --serial <hex>
  jessctl admin lock          --admin <https-addr> --type <axis> --value <v> --reason <text> [--expires <dur>] [--replace]
  jessctl admin unlock        --admin <https-addr> --id <lock-id>
  jessctl admin list-locks    --admin <https-addr>
  jessctl admin chain-verify  --admin <https-addr> [--json]
  jessctl admin bundle-verify --admin <https-addr> --session <id> [--json]

Diagnostics:
  jessctl rdp-probe --target <host[:port]> [--request-protocols tls,credssp]
    Probe an RDP service (X.224 + RDP_NEG_REQ/RSP). Reports reachability,
    negotiated protocol (TLS / CredSSP / legacy), and NLA posture.
    Use before deploying the ironrdp broker against a new target.

The positional <target-id> may appear before or after the flags — Go's
standard flag package stops at the first non-flag arg, so jessctl
pre-extracts the positional to make either ordering work.

Pass --token or set JESS_TOKEN to skip the browser OIDC flow.`)
}

// extractPositional walks args linearly, returning the first non-flag
// argument together with the remaining args (in flag-only order). Knows
// which flags take a value via fs.Lookup; bool flags are valueless.
// Makes `jessctl connect <target> --flags ...` work as well as
// `jessctl connect --flags ... <target>`. A `--` separator stops the
// scan, the rest passes through verbatim.
func extractPositional(fs *flag.FlagSet, args []string) (rest []string, positional string) {
	rest = make([]string, 0, len(args))
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if !strings.HasPrefix(a, "-") {
			if positional == "" {
				positional = a
				i++
				continue
			}
			rest = append(rest, a)
			i++
			continue
		}
		// flag — does it take a separate value token?
		name := strings.TrimLeft(a, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			rest = append(rest, a)
			i++
			continue
		}
		rest = append(rest, a)
		i++
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i < len(args) {
			rest = append(rest, args[i])
			i++
		}
	}
	return rest, positional
}

func cmdConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	controller := fs.String("controller", env("JESS_CONTROLLER", ""), "controller operator address host:port")
	grant := fs.String("grant", env("JESS_GRANT", ""), "JIT grant id")
	listen := fs.String("listen", "127.0.0.1:0", "local listen address")
	token := fs.String("token", env("JESS_TOKEN", ""), "Falcon-ID token (else OIDC login)")
	issuer := fs.String("issuer", env("JESS_OIDC_ISSUER", "https://id.hexxlock.com"), "OIDC issuer")
	clientID := fs.String("client-id", env("JESS_OIDC_CLIENT_ID", "svc-jess"), "OIDC client id")
	redirect := fs.String("redirect", env("JESS_OIDC_REDIRECT", "127.0.0.1:8400"), "OIDC loopback redirect host:port (must match a registered redirect_uri)")
	useTLS := fs.Bool("tls", env("JESS_OPERATOR_TLS", "") != "", "dial the controller operator port over TLS")
	tlsCA := fs.String("tls-ca", env("JESS_OPERATOR_TLS_CA", ""), "CA PEM verifying the controller (operator port); empty = system roots")
	tlsServerName := fs.String("tls-server-name", env("JESS_OPERATOR_TLS_SERVER_NAME", ""), "expected controller TLS server name")
	tlsCert := fs.String("tls-cert", env("JESS_OPERATOR_TLS_CERT", ""), "operator client cert PEM (optional mTLS)")
	tlsKey := fs.String("tls-key", env("JESS_OPERATOR_TLS_KEY", ""), "operator client key PEM (optional mTLS)")
	rest, target := extractPositional(fs, args)
	_ = fs.Parse(rest)
	if target == "" {
		target = fs.Arg(0)
	}
	if target == "" || *controller == "" || *grant == "" {
		fmt.Fprintln(os.Stderr, "connect requires <target-id>, --controller, and --grant")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TLS to the operator port (any of --tls / --tls-ca / --tls-server-name /
	// --tls-cert enables it). Keeps the bearer token off the wire in clear.
	var tlsCfg *tls.Config
	if *useTLS || *tlsCA != "" || *tlsServerName != "" || *tlsCert != "" {
		c, terr := transport.LoadClientTLS(*tlsCA, *tlsServerName, *tlsCert, *tlsKey)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "operator TLS: %v\n", terr)
			os.Exit(1)
		}
		tlsCfg = c
	}

	tok := *token
	if tok == "" {
		var err error
		if tok, err = client.LoginOIDC(ctx, *issuer, *clientID, *redirect, defaultScopes); err != nil {
			fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
			os.Exit(1)
		}
	}

	addr, err := client.LocalProxy(ctx, *listen, *controller, tlsCfg,
		wire.OperatorRequest{Token: tok, TargetID: target, GrantID: *grant})
	if err != nil {
		fmt.Fprintf(os.Stderr, "local proxy: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("jessctl: %s → %s via %s\n  forwarding %s ; point your client at it. Ctrl-C to stop.\n",
		addr, target, *controller, addr)
	<-ctx.Done()
}

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	issuer := fs.String("issuer", env("JESS_OIDC_ISSUER", "https://id.hexxlock.com"), "OIDC issuer")
	clientID := fs.String("client-id", env("JESS_OIDC_CLIENT_ID", "svc-jess"), "OIDC client id")
	redirect := fs.String("redirect", env("JESS_OIDC_REDIRECT", "127.0.0.1:8400"), "OIDC loopback redirect host:port (must match a registered redirect_uri)")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tok, err := client.LoginOIDC(ctx, *issuer, *clientID, *redirect, defaultScopes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(strings.TrimSpace(tok))
}

// adminCmd is the dispatch table for jessctl admin subcommands.
type adminCmd struct {
	run func([]string)
	doc string
}

func cmdAdmin(args []string) {
	cmds := map[string]adminCmd{
		"issue-grant":          {run: cmdAdminIssue, doc: "issue a new JIT grant"},
		"list-grants":          {run: cmdAdminList, doc: "list active JIT grants (optionally per target)"},
		"revoke":               {run: cmdAdminRevoke, doc: "end an active JIT grant by id"},
		"list-requests":        {run: cmdAdminListRequests, doc: "list JIT grant requests (Phase 5b workflow)"},
		"approve":              {run: cmdAdminApprove, doc: "approve a pending JIT request → mints a grant"},
		"deny":                 {run: cmdAdminDeny, doc: "deny a pending JIT request with reason"},
		"operator-cert":        {run: cmdAdminOperatorCert, doc: "mint a short-lived operator client cert (replaces manual openssl)"},
		"operator-cert-revoke": {run: cmdAdminOperatorCertRevoke, doc: "revoke an operator client cert by serial (Phase 4 lite — Vault PKI CRL backstop)"},
		"lock":                 {run: cmdAdminLock, doc: "issue a kill primitive (Phase 5j-1) — block subject / target / cert_serial / mfa_device with ≤10s propagation"},
		"unlock":               {run: cmdAdminUnlock, doc: "remove a lock by id (Phase 5j-1)"},
		"list-locks":           {run: cmdAdminListLocks, doc: "list active locks newest-first (Phase 5j-1)"},
		"chain-verify":         {run: cmdAdminChainVerify, doc: "verify the cross-session WORM audit chain (Phase 5e-16)"},
		"bundle-verify":        {run: cmdAdminBundleVerify, doc: "verify one recording bundle's signature + content hash (Phase 5e-14)"},
		"rdp-probe":            {run: cmdAdminRDPProbe, doc: "probe one RDP target via the controller (admin-gated, SSRF-guarded; Phase 5f-2b)"},
		"rdp-sweep":            {run: cmdAdminRDPSweep, doc: "probe every catalog RDP target via the controller (Phase 5f-2d / 5f-9)"},
		"target":               {run: cmdAdminTarget, doc: "ad-hoc target CRUD on the admin-API provider (Phase 7f) — add|list|get|edit|delete"},
	}
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "admin requires a subcommand:")
		for k, c := range cmds {
			fmt.Fprintf(os.Stderr, "  jessctl admin %-12s — %s\n", k, c.doc)
		}
		os.Exit(2)
	}
	c, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown admin subcommand %q\n", args[0])
		os.Exit(2)
	}
	c.run(args[1:])
}

// adminClientFromFlags wires the admin HTTP client using the same TLS
// + OIDC-login machinery `connect` uses. Returns a ready client and a
// cancel func for the context (caller defers cancel()).
func adminClientFromFlags(args []string, extra func(fs *flag.FlagSet)) (*client.AdminClient, context.Context, context.CancelFunc) {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	addr := fs.String("admin", env("JESS_ADMIN", ""), "controller admin address https://host:7103")
	token := fs.String("token", env("JESS_TOKEN", ""), "Falcon-ID token (else OIDC login)")
	issuer := fs.String("issuer", env("JESS_OIDC_ISSUER", "https://id.hexxlock.com"), "OIDC issuer")
	clientID := fs.String("client-id", env("JESS_OIDC_CLIENT_ID", "svc-jess"), "OIDC client id")
	redirect := fs.String("redirect", env("JESS_OIDC_REDIRECT", "127.0.0.1:8400"), "OIDC loopback redirect host:port")
	tlsCA := fs.String("tls-ca", env("JESS_OPERATOR_TLS_CA", ""), "CA PEM verifying the controller; empty = system roots")
	tlsServerName := fs.String("tls-server-name", env("JESS_OPERATOR_TLS_SERVER_NAME", ""), "expected controller TLS server name")
	tlsCert := fs.String("tls-cert", env("JESS_OPERATOR_TLS_CERT", ""), "operator client cert PEM (optional mTLS)")
	tlsKey := fs.String("tls-key", env("JESS_OPERATOR_TLS_KEY", ""), "operator client key PEM (optional mTLS)")
	if extra != nil {
		extra(fs)
	}
	_ = fs.Parse(args)
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "--admin <https-addr> required (or JESS_ADMIN)")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	tok := *token
	if tok == "" {
		var err error
		if tok, err = client.LoginOIDC(ctx, *issuer, *clientID, *redirect, defaultScopes); err != nil {
			fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
			cancel()
			os.Exit(1)
		}
	}

	var tlsCfg *tls.Config
	if *tlsCA != "" || *tlsServerName != "" || *tlsCert != "" {
		c, terr := transport.LoadClientTLS(*tlsCA, *tlsServerName, *tlsCert, *tlsKey)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "admin TLS: %v\n", terr)
			cancel()
			os.Exit(1)
		}
		tlsCfg = c
	}

	// Stash the FlagSet on the context so per-subcommand flags can read it
	// in a way that doesn't require re-parsing args. Subcommands instead
	// take the fs via the extra() hook and read directly — see issue/list/revoke.
	_ = fs

	return &client.AdminClient{BaseURL: *addr, Token: tok, TLS: tlsCfg}, ctx, cancel
}

func cmdAdminIssue(args []string) {
	var subject, target string
	var ttl time.Duration
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&subject, "subject", "", "Falcon-ID sub (UUID) of the grantee")
		fs.StringVar(&target, "target", "", "target id from the catalog (e.g. node-app-01)")
		fs.DurationVar(&ttl, "ttl", 30*time.Minute, "grant validity window (e.g. 15m, 1h, max 24h)")
	})
	defer cancel()
	if subject == "" || target == "" || ttl <= 0 {
		fmt.Fprintln(os.Stderr, "--subject, --target, --ttl required")
		os.Exit(2)
	}
	g, err := c.IssueGrant(ctx, subject, target, ttl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(g, "", "  ")
	fmt.Println(string(enc))
}

func cmdAdminList(args []string) {
	var target string
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&target, "target", "", "filter by target id (optional)")
	})
	defer cancel()
	gs, err := c.ListGrants(ctx, target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(gs, "", "  ")
	fmt.Println(string(enc))
}

func cmdAdminRevoke(args []string) {
	var id string
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&id, "grant", "", "grant id to revoke")
	})
	defer cancel()
	if id == "" {
		fmt.Fprintln(os.Stderr, "--grant required")
		os.Exit(2)
	}
	if err := c.Revoke(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		os.Exit(1)
	}
	fmt.Printf("revoked %s\n", id)
}

// cmdRequest — top-level `jessctl request`. Submits a Phase 5b grant
// request without requiring an admin role. The submitter's subject is
// derived server-side from the verified Falcon-ID token.
func cmdRequest(args []string) {
	var target, reason string
	var ttlMin int
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&target, "target", "", "target id from the catalog (e.g. node-app-01)")
		fs.StringVar(&reason, "reason", "", "why you need access (SOC 2 CC6.2 evidence)")
		fs.IntVar(&ttlMin, "ttl-min", 0, "request validity window in minutes (0 = server default 240m)")
	})
	defer cancel()
	if target == "" || reason == "" {
		fmt.Fprintln(os.Stderr, "--target and --reason required")
		os.Exit(2)
	}
	r, err := c.SubmitRequest(ctx, target, reason, ttlMin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(enc))
}

func cmdAdminListRequests(args []string) {
	var state string
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&state, "state", "", "filter by state: pending|approved|denied|expired (default: all)")
	})
	defer cancel()
	rs, err := c.ListRequests(ctx, state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list-requests:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(rs, "", "  ")
	fmt.Println(string(enc))
}

func cmdAdminApprove(args []string) {
	var id string
	var ttl time.Duration
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&id, "request", "", "request id to approve")
		fs.DurationVar(&ttl, "ttl", 30*time.Minute, "lifetime of the minted grant (e.g. 15m, 1h, max 24h)")
	})
	defer cancel()
	if id == "" || ttl <= 0 {
		fmt.Fprintln(os.Stderr, "--request and --ttl required")
		os.Exit(2)
	}
	out, err := c.ApproveRequest(ctx, id, ttl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "approve:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
}

func cmdAdminDeny(args []string) {
	var id, reason string
	c, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&id, "request", "", "request id to deny")
		fs.StringVar(&reason, "reason", "", "why (auditability — required)")
	})
	defer cancel()
	if id == "" || reason == "" {
		fmt.Fprintln(os.Stderr, "--request and --reason required")
		os.Exit(2)
	}
	r, err := c.DenyRequest(ctx, id, reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deny:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(enc))
}
