// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5f-2b / 5f-2d / 5f-9 — jessctl admin RDP surfaces.
//
// CLI parity with the SPA "Test reachability" + "Sweep RDP targets"
// buttons. Useful for SRE who want to script reachability checks
// from cron / shell pipes without spinning up a browser.
//
// All three call the controller admin port via AdminClient (same
// bearer + TLS plumbing as the chain/bundle verify subcommands).
// SSRF guard for the single-target probe still enforced server-side
// — operators who want to probe an arbitrary public target should
// use `jessctl rdp-probe` (the direct CLI, not the admin one).
//
// Exit codes (mirrors chain/bundle verify):
//   0  call ran and reported OK (reachable / all reachable)
//   1  call ran and reported failure (unreachable / any failed)
//   2  client/network/auth error

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdAdminRDPProbe(args []string) {
	var asJSON bool
	var target string
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.BoolVar(&asJSON, "json", false, "emit raw JSON verdict instead of pretty form")
		fs.StringVar(&target, "target", "", "RDP target host:port (must be RFC1918)")
	})
	defer cancel()
	if target == "" {
		fmt.Fprintln(os.Stderr, "admin rdp-probe: --target HOST:PORT required")
		os.Exit(2)
	}
	r, err := cli.RDPProbeOne(ctx, target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rdp-probe:", err)
		os.Exit(2)
	}
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		if !r.Reachable || r.FailureCode != 0 {
			os.Exit(1)
		}
		return
	}
	prettyRDPProbe(r)
	if !r.Reachable || r.FailureCode != 0 {
		os.Exit(1)
	}
}

func cmdAdminRDPSweep(args []string) {
	var asJSON bool
	cli, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.BoolVar(&asJSON, "json", false, "emit raw JSON sweep response instead of pretty form")
	})
	defer cancel()
	r, err := cli.RDPSweep(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rdp-sweep:", err)
		os.Exit(2)
	}
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		if r.Failed > 0 {
			os.Exit(1)
		}
		return
	}
	if r.Total == 0 {
		fmt.Println("\033[1;33mno RDP targets in catalog\033[0m")
		return
	}
	headline := "\033[1;32m✓ all reachable\033[0m"
	if r.Failed > 0 {
		headline = fmt.Sprintf("\033[1;31m⚠ %d of %d unreachable\033[0m", r.Failed, r.Total)
	}
	fmt.Printf("%s  %d/%d reachable in %dms\n", headline, r.Reachable, r.Total, r.ElapsedMs)
	for _, row := range r.Results {
		prettyRDPProbeRow(row)
	}
	if r.Failed > 0 {
		os.Exit(1)
	}
}

func prettyRDPProbe(r RDPProbeReport) {
	switch {
	case !r.Reachable:
		fmt.Printf("\033[1;31m✗ unreachable\033[0m  %s  (%s)\n", r.Target, r.Error)
	case r.FailureCode != 0:
		fmt.Printf("\033[1;33m⚠ nego-failure\033[0m  %s  code=%d (%s)  in %dms\n",
			r.Target, r.FailureCode, r.FailureReason, r.DurationMs)
	default:
		caps := []string{}
		if r.TLSSupported {
			caps = append(caps, "TLS")
		}
		if r.NLARequired {
			caps = append(caps, "NLA")
		}
		fmt.Printf("\033[1;32m✓ %s\033[0m  %s  [%s]  in %dms\n",
			r.NegotiatedProto, r.Target, strings.Join(caps, "+"), r.DurationMs)
	}
}

// RDPProbeReport / SweepResult are defined in internal/client; mirrored
// type aliases for shorter call sites here.
type RDPProbeReport = clientRDPProbeReport
type SweepResult = clientSweepResult
