// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5e-19 — jessctl admin chain-verify + bundle-verify.
//
// CLI parity with the SPA "Verify chain" / "Verify recording" buttons
// (5e-14 + 5e-16). Useful for SRE who don't want to open the browser
// and for cron-driven compliance checks ("nightly chain-verify, page
// on non-zero exit").
//
// Exit codes:
//   0  verify ran and reported OK (chain intact / bundle valid)
//   1  verify ran and reported a tamper / break
//   2  client / network / auth error (verify could not complete)
//
// --json renders the raw verdict instead of the human-pretty form so
// SRE scripts can pipe into jq.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func cmdAdminChainVerify(args []string) {
	var asJSON bool
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.BoolVar(&asJSON, "json", false, "emit raw JSON verdict instead of pretty form")
	})
	defer cancel()
	r, err := cli.VerifyChain(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "chain-verify:", err)
		os.Exit(2)
	}
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		if !r.OK {
			os.Exit(1)
		}
		return
	}
	if r.OK {
		fmt.Printf("\033[1;32m✓ chain intact\033[0m  rows=%d  genesis=%s…  head=%s…\n",
			r.Total, sliceHash(r.GenesisHash), sliceHash(r.HeadHash))
		return
	}
	fmt.Printf("\033[1;31m⚠ CHAIN BROKEN\033[0m  %d break(s) across %d rows\n", len(r.Breaks), r.Total)
	for i, b := range r.Breaks {
		if i >= 20 {
			fmt.Printf("  … and %d more (use --json for the full list)\n", len(r.Breaks)-20)
			break
		}
		fmt.Printf("  pos=%-4d  reason=%-22s  session=%s\n", b.Position, b.Reason, b.SessionID)
		if b.Expected != "" || b.Got != "" {
			fmt.Printf("            expected=%s…  got=%s…\n", sliceHash(b.Expected), sliceHash(b.Got))
		}
	}
	os.Exit(1)
}

func cmdAdminBundleVerify(args []string) {
	var asJSON bool
	var sessionID string
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.BoolVar(&asJSON, "json", false, "emit raw JSON verdict instead of pretty form")
		fs.StringVar(&sessionID, "session", "", "session id whose recording to verify (required)")
	})
	defer cancel()
	if sessionID == "" {
		fmt.Fprintln(os.Stderr, "bundle-verify: --session <id> required")
		os.Exit(2)
	}
	r, err := cli.VerifyBundle(ctx, sessionID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle-verify:", err)
		os.Exit(2)
	}
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		if !r.OK {
			os.Exit(1)
		}
		return
	}
	if r.OK {
		sealed := ""
		if r.SealedAt != nil {
			sealed = r.SealedAt.Format("2006-01-02 15:04:05 MST")
		}
		fmt.Printf("\033[1;32m✓ bundle intact\033[0m  session=%s  key=%s  sealed=%s  bytes=%d\n",
			r.SessionID, r.KeyID, sealed, r.ContentBytes)
		return
	}
	fmt.Printf("\033[1;31m⚠ BUNDLE BROKEN\033[0m  session=%s\n", r.SessionID)
	fmt.Printf("  signature_valid=%v  hash_match=%v  chain_link_ok=%v  key=%s\n",
		r.SignatureValid, r.HashMatch, r.ChainLinkOK, r.KeyID)
	if !r.ChainLinkOK && (r.ChainLinkExpected != "" || r.ChainLinkGot != "") {
		fmt.Printf("  chain expected=%s…  got=%s…\n",
			sliceHash(r.ChainLinkExpected), sliceHash(r.ChainLinkGot))
	}
	if r.Error != "" {
		fmt.Printf("  error: %s\n", r.Error)
	}
	os.Exit(1)
}

// sliceHash returns the first 12 chars of a hex hash — enough to be
// uniquely identifying in logs / cmp output, short enough for terminal.
func sliceHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
