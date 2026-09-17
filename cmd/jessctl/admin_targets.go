// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 7f — jessctl admin target {add,list,get,edit,delete}.
//
// Backed by the controller's /admin/targets REST surface (see
// internal/admin/targets.go). Storage is in-memory on the controller
// in v1; Phase 7f-2 will switch to Postgres-backed persistence — the
// CLI wire shape is stable across that swap.
//
// Each subcommand returns non-zero on error so shell scripts wrapping
// jessctl get reliable exit codes.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/dogukanturhal/jess/internal/client"
)

// cmdAdminTargetAdd implements `jessctl admin target add`.
//
//	--id          required: catalog id (must be unique cluster-wide)
//	--address     required: host:port the worker dials
//	--protocol    default ssh — one of ssh|rdp|postgres|mysql|tcp
//	--host-key    SSH only: pinned authorized_keys line
//	--role        repeatable: roles required by PDP (default platform_admin)
//	--criticality default medium — risk-score weighting
//	--tag         repeatable: arbitrary labels
//	--region      multi-region scope, blank = unscoped
//	--database    DB-protocol targets: default database/schema name
//	--recorded    bool: gate session-open on a working recorder (default true)
//	--json FILE   alternative: read full Target JSON from FILE ('-' = stdin)
//	              flags above are ignored when --json is present
func cmdAdminTargetAdd(args []string) {
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.String("id", "", "catalog id (required)")
		fs.String("address", "", "host:port (required)")
		fs.String("protocol", "ssh", "protocol: ssh|rdp|postgres|mysql|tcp")
		fs.String("host-key", "", "SSH host pubkey (authorized_keys line)")
		fs.Func("role", "required role (repeatable; default [platform_admin])", func(string) error { return nil })
		fs.String("criticality", "medium", "low|medium|high|critical")
		fs.Func("tag", "label (repeatable)", func(string) error { return nil })
		fs.String("region", "", "multi-region scope")
		fs.String("database", "", "default DB (postgres/mysql targets)")
		fs.Bool("recorded", true, "fail-closed if no recorder")
		fs.String("json", "", "read full Target JSON from FILE ('-' = stdin)")
	})
	defer cancel()
	body, err := buildTargetBodyFromFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin target add:", err)
		os.Exit(2)
	}
	out, err := cli.CreateTarget(ctx, body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin target add:", err)
		os.Exit(1)
	}
	printTargetView(out)
}

// cmdAdminTargetList implements `jessctl admin target list`. Prints a
// compact table; --json switches to machine-readable output.
func cmdAdminTargetList(args []string) {
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.Bool("json", false, "emit JSON instead of the table")
	})
	defer cancel()
	wantJSON := hasFlag(args, "json")
	rows, err := cli.ListTargets(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin target list:", err)
		os.Exit(1)
	}
	if wantJSON {
		_ = json.NewEncoder(os.Stdout).Encode(rows)
		return
	}
	sort.Slice(rows, func(i, j int) bool { return targetID(rows[i]) < targetID(rows[j]) })
	fmt.Printf("%-30s %-10s %-22s %-12s %-30s %s\n",
		"ID", "PROTO", "ADDRESS", "CRITICALITY", "TAGS", "ADDED BY")
	for _, r := range rows {
		fmt.Printf("%-30s %-10s %-22s %-12s %-30s %s\n",
			str(r.Target["id"]),
			str(r.Target["protocol"]),
			str(r.Target["address"]),
			str(r.Target["criticality"]),
			joinTags(r.Target["tags"]),
			r.AddedBy,
		)
	}
	if len(rows) == 0 {
		fmt.Println("(no admin-managed targets — use `jessctl admin target add`)")
	}
}

// cmdAdminTargetGet implements `jessctl admin target get <id>`.
func cmdAdminTargetGet(args []string) {
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.Bool("json", false, "emit JSON instead of the human view")
	})
	defer cancel()
	id := firstPositional(args)
	if id == "" {
		fmt.Fprintln(os.Stderr, "admin target get: <id> positional required")
		os.Exit(2)
	}
	row, err := cli.GetTarget(ctx, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin target get:", err)
		os.Exit(1)
	}
	if hasFlag(args, "json") {
		_ = json.NewEncoder(os.Stdout).Encode(row)
		return
	}
	printTargetView(row)
}

// cmdAdminTargetEdit implements `jessctl admin target edit <id> <flags>`.
// Same flag surface as Add — but only the address/protocol/* you pass
// are sent; the server REPLACES the existing entry's field set so
// callers should pass the full intended state, not a delta.
func cmdAdminTargetEdit(args []string) {
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.String("address", "", "host:port")
		fs.String("protocol", "ssh", "protocol")
		fs.String("host-key", "", "SSH host pubkey")
		fs.Func("role", "required role (repeatable)", func(string) error { return nil })
		fs.String("criticality", "medium", "low|medium|high|critical")
		fs.Func("tag", "label (repeatable)", func(string) error { return nil })
		fs.String("region", "", "multi-region scope")
		fs.String("database", "", "default DB")
		fs.Bool("recorded", true, "fail-closed if no recorder")
		fs.String("json", "", "read full Target JSON from FILE ('-' = stdin)")
	})
	defer cancel()
	id := firstPositional(args)
	if id == "" {
		fmt.Fprintln(os.Stderr, "admin target edit: <id> positional required")
		os.Exit(2)
	}
	body, err := buildTargetBodyFromFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin target edit:", err)
		os.Exit(2)
	}
	// PATCH ignores body.id (the URL parameter is pinned server-side);
	// but for parity with Add we set it.
	body["id"] = id
	out, err := cli.PatchTarget(ctx, id, body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin target edit:", err)
		os.Exit(1)
	}
	printTargetView(out)
}

// cmdAdminTargetDelete implements `jessctl admin target delete <id>`.
func cmdAdminTargetDelete(args []string) {
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {})
	defer cancel()
	id := firstPositional(args)
	if id == "" {
		fmt.Fprintln(os.Stderr, "admin target delete: <id> positional required")
		os.Exit(2)
	}
	if err := cli.DeleteTarget(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "admin target delete:", err)
		os.Exit(1)
	}
	fmt.Printf("deleted: %s\n", id)
}

// ---- internals -------------------------------------------------------

// buildTargetBodyFromFlags reads either --json FILE/stdin OR the
// flag-driven Target fields and returns a map[string]any ready to
// POST/PATCH.
func buildTargetBodyFromFlags(args []string) (map[string]any, error) {
	if path := flagStringValue(args, "json"); path != "" {
		var src io.Reader
		if path == "-" {
			src = os.Stdin
		} else {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			src = f
		}
		var body map[string]any
		if err := json.NewDecoder(src).Decode(&body); err != nil {
			return nil, fmt.Errorf("--json: %w", err)
		}
		return body, nil
	}
	body := map[string]any{}
	if v := flagStringValue(args, "id"); v != "" {
		body["id"] = v
	}
	if v := flagStringValue(args, "address"); v != "" {
		body["address"] = v
	}
	if v := flagStringValue(args, "protocol"); v != "" {
		body["protocol"] = v
	}
	if v := flagStringValue(args, "host-key"); v != "" {
		body["host_key"] = v
	}
	if roles := flagAllValues(args, "role"); len(roles) > 0 {
		body["required_roles"] = roles
	}
	if v := flagStringValue(args, "criticality"); v != "" {
		body["criticality"] = v
	}
	if tags := flagAllValues(args, "tag"); len(tags) > 0 {
		body["tags"] = tags
	}
	if v := flagStringValue(args, "region"); v != "" {
		body["region"] = v
	}
	if v := flagStringValue(args, "database"); v != "" {
		body["database"] = v
	}
	if hasFlag(args, "recorded") {
		body["recorded"] = flagBoolValue(args, "recorded")
	}
	return body, nil
}

func printTargetView(v client.AdminTarget) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func targetID(t client.AdminTarget) string { return str(t.Target["id"]) }

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func joinTags(v any) string {
	if v == nil {
		return ""
	}
	arr, ok := v.([]any)
	if !ok {
		return ""
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, str(x))
	}
	if len(out) > 3 {
		return strings.Join(out[:3], ",") + ",…"
	}
	return strings.Join(out, ",")
}

// ---- tiny flag helpers (no external dep) ----------------------------

// hasFlag returns true if --name (or --name=…) appears in args.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--"+name || strings.HasPrefix(a, "--"+name+"=") ||
			a == "-"+name || strings.HasPrefix(a, "-"+name+"=") {
			return true
		}
	}
	return false
}

// flagStringValue returns the value of --name (or --name=value), or ""
// if missing. Tolerates either --name V or --name=V syntax.
func flagStringValue(args []string, name string) string {
	dash := "--" + name
	dash1 := "-" + name
	for i, a := range args {
		if a == dash || a == dash1 {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if strings.HasPrefix(a, dash+"=") {
			return strings.TrimPrefix(a, dash+"=")
		}
		if strings.HasPrefix(a, dash1+"=") {
			return strings.TrimPrefix(a, dash1+"=")
		}
	}
	return ""
}

// flagAllValues returns every value of a repeatable --name. Tolerates
// either `--name V --name W` or `--name=V --name=W` patterns.
func flagAllValues(args []string, name string) []string {
	dash := "--" + name
	dash1 := "-" + name
	var out []string
	for i, a := range args {
		if a == dash || a == dash1 {
			if i+1 < len(args) {
				out = append(out, args[i+1])
			}
			continue
		}
		if strings.HasPrefix(a, dash+"=") {
			out = append(out, strings.TrimPrefix(a, dash+"="))
			continue
		}
		if strings.HasPrefix(a, dash1+"=") {
			out = append(out, strings.TrimPrefix(a, dash1+"="))
		}
	}
	return out
}

// flagBoolValue returns the value of --name as a bool. Accepts the
// idiomatic --name (= true) form as well as --name=true|false.
func flagBoolValue(args []string, name string) bool {
	dash := "--" + name
	dash1 := "-" + name
	for i, a := range args {
		if a == dash || a == dash1 {
			if i+1 < len(args) {
				v := args[i+1]
				if v == "false" || v == "0" {
					return false
				}
			}
			return true
		}
		if strings.HasPrefix(a, dash+"=") || strings.HasPrefix(a, dash1+"=") {
			v := strings.SplitN(a, "=", 2)[1]
			return v != "false" && v != "0"
		}
	}
	return false
}

// firstPositional returns the first non-flag argument from args. Used
// by `target get/edit/delete <id>` which take a positional id.
func firstPositional(args []string) string {
	skip := 0
	for i, a := range args {
		if skip > 0 {
			skip--
			continue
		}
		if strings.HasPrefix(a, "-") {
			// --key=value is a single arg; --key value takes the
			// next arg. We don't know which here without the
			// FlagSet — best-effort: assume --key value when no '='
			// is present AND the next token doesn't start with '-'.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				skip = 1
			}
			continue
		}
		// First non-flag wins.
		return a
	}
	return ""
}

// stash unused so the package compiles if helpers go unused in some
// build paths (every helper used by at least one subcommand in this
// file — keep this stub OUT of the public surface).
var _ = context.Background

// cmdAdminTarget is the dispatcher under `jessctl admin target`. Forks
// based on the next arg (add|list|get|edit|delete).
func cmdAdminTarget(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, `usage:
  jessctl admin target add    --id <id> --address <host:port> ...
  jessctl admin target list   [--json]
  jessctl admin target get    <id> [--json]
  jessctl admin target edit   <id> --address <host:port> ...
  jessctl admin target delete <id>`)
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		cmdAdminTargetAdd(args[1:])
	case "list":
		cmdAdminTargetList(args[1:])
	case "get":
		cmdAdminTargetGet(args[1:])
	case "edit":
		cmdAdminTargetEdit(args[1:])
	case "delete", "rm":
		cmdAdminTargetDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown admin target subcommand: %q\n", args[0])
		os.Exit(2)
	}
}
