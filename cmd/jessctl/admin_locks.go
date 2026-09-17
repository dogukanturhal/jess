// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

// cmdAdminLock implements `jessctl admin lock --type subject|target|cert_serial|mfa_device
// --value <v> --reason <r> [--expires <duration>] [--replace]`. Phase 5j-1
// admin kill primitive. Same backend the SPA admin tab will use; same
// audit + log line stamped with the verified Falcon-ID subject as
// `locked_by` per RFC 8705-style identity binding.
func cmdAdminLock(args []string) {
	var targetType, targetValue, reason, expiresStr string
	var replace bool
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&targetType, "type", "", "lock axis: subject | target | cert_serial | mfa_device")
		fs.StringVar(&targetValue, "value", "", "lock target value (Falcon-ID sub, target id, cert serial, or device id)")
		fs.StringVar(&reason, "reason", "", "human-readable cause (surfaces in audit log + kill messages)")
		fs.StringVar(&expiresStr, "expires", "", "lock validity window (e.g. 1h, 24h, 7d). Empty = indefinite.")
		fs.BoolVar(&replace, "replace", false, "upsert on duplicate (otherwise 409)")
	})
	defer cancel()
	if targetType == "" || targetValue == "" || reason == "" {
		fmt.Fprintln(os.Stderr, "usage: jessctl admin lock --type <axis> --value <v> --reason <text> [--expires <dur>] [--replace] --admin <https-addr>")
		os.Exit(2)
	}
	var expiresAt time.Time
	if expiresStr != "" {
		d, err := time.ParseDuration(expiresStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --expires %q: %v\n", expiresStr, err)
			os.Exit(2)
		}
		expiresAt = time.Now().Add(d)
	}
	l, err := cli.CreateLock(ctx, targetType, targetValue, reason, expiresAt, replace)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lock:", err)
		os.Exit(1)
	}
	enc, _ := json.MarshalIndent(l, "", "  ")
	fmt.Println(string(enc))
	// Operator-facing summary.
	exp := "indefinite"
	if l.ExpiresAt != nil {
		exp = l.ExpiresAt.Local().Format(time.RFC1123)
	}
	fmt.Printf("\nlocked %s=%s (id=%s, expires=%s)\n", l.TargetType, l.TargetVal, l.ID, exp)
	fmt.Println("Effective kill latency: ≤ grant-watch interval (default 10s, env JESS_GRANT_WATCH_INTERVAL_SECONDS).")
}

// cmdAdminUnlock implements `jessctl admin unlock --id <lock-id>`. Idempotent
// — not-found is not an error.
func cmdAdminUnlock(args []string) {
	var lockID string
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&lockID, "id", "", "lock id to remove (from `jessctl admin list-locks`)")
	})
	defer cancel()
	if lockID == "" {
		fmt.Fprintln(os.Stderr, "--id required (get the id from `jessctl admin list-locks`)")
		os.Exit(2)
	}
	if err := cli.DeleteLock(ctx, lockID); err != nil {
		fmt.Fprintln(os.Stderr, "unlock:", err)
		os.Exit(1)
	}
	fmt.Printf("removed lock id=%s\n", lockID)
}

// cmdAdminListLocks implements `jessctl admin list-locks`. Returns active
// locks ordered newest-first. Empty list = no active locks.
func cmdAdminListLocks(args []string) {
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {})
	defer cancel()
	locks, err := cli.ListLocks(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list-locks:", err)
		os.Exit(1)
	}
	if len(locks) == 0 {
		fmt.Println("(no active locks)")
		return
	}
	for _, l := range locks {
		exp := "indefinite"
		if l.ExpiresAt != nil {
			exp = l.ExpiresAt.Local().Format(time.RFC1123)
		}
		fmt.Printf("%s  %-12s %-44s  by=%-20s at=%-25s expires=%-25s  reason=%s\n",
			l.ID, l.TargetType, l.TargetVal, l.LockedBy, l.LockedAt.Local().Format(time.RFC3339), exp, l.Reason)
	}
}
