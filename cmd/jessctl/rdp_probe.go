// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5f-2a — RDP reachability + capability probe (CLI driver).
//
// Wire format + Probe function live in internal/rdpprobe so the
// controller's admin endpoint (Phase 5f-2b) shares them. This file
// is now just the CLI: flag parse → call rdpprobe.Probe → render
// pretty or --json.
//
// See internal/rdpprobe/rdpprobe.go for spec references + frame
// layout. See internal/rdpprobe/ssrf.go for the controller-side
// SSRF gate (NOT applied here — the CLI runs from a workstation
// and operators can probe any RDP target they have network reach to).

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/rdpprobe"
)

func cmdRDPProbe(args []string) {
	fs := flag.NewFlagSet("rdp-probe", flag.ExitOnError)
	target := fs.String("target", "", "RDP target host:port (e.g. 10.0.20.10:3389)")
	timeout := fs.Duration("timeout", 5*time.Second, "TCP + handshake total timeout")
	asJSON := fs.Bool("json", false, "emit raw JSON report instead of pretty form")
	reqProtocolsStr := fs.String("request-protocols", "tls,credssp",
		"requested protocols (comma-separated subset of: rdp, tls, credssp, rdstls, credssp-eua)")
	cookie := fs.String("cookie", "",
		"optional X.224 routing cookie (e.g. \"mstshash=testuser\" for load-balancer routing)")
	_ = fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "rdp-probe: --target host:port required")
		os.Exit(2)
	}
	if !strings.Contains(*target, ":") {
		*target = *target + ":3389"
	}
	requestedProtos, err := rdpprobe.ParseRequestedProtocols(*reqProtocolsStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rdp-probe:", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r := rdpprobe.Probe(ctx, *target, *cookie, requestedProtos, *timeout)
	emit(r, *asJSON)

	switch {
	case !r.Reachable:
		os.Exit(2)
	case r.FailureCode != 0:
		os.Exit(1)
	}
}

func emit(r rdpprobe.Report, asJSON bool) {
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	if !r.Reachable {
		fmt.Printf("\033[1;31m✗ unreachable\033[0m  %s  (%s)\n", r.Target, r.Error)
		return
	}
	if !r.ConnectionConfirm {
		fmt.Printf("\033[1;31m✗ reachable but no X.224 CC\033[0m  %s  (%s)\n", r.Target, r.Error)
		return
	}
	if r.FailureCode != 0 {
		fmt.Printf("\033[1;33m⚠ RDP nego failure\033[0m  %s  code=%d (%s)  in %dms\n",
			r.Target, r.FailureCode, r.FailureReason, r.DurationMs)
		return
	}
	caps := []string{}
	if r.TLSSupported {
		caps = append(caps, "TLS")
	}
	if r.NLARequired {
		caps = append(caps, "NLA-required")
	}
	if len(caps) == 0 {
		caps = append(caps, "RDP-legacy")
	}
	fmt.Printf("\033[1;32m✓ RDP service responding\033[0m  %s  negotiated=%s  [%s]  in %dms\n",
		r.Target, r.NegotiatedProto, strings.Join(caps, ","), r.DurationMs)
}
