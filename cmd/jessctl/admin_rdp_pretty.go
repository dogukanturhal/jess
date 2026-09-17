// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Shared pretty-printer for one sweep row + the type aliases that
// give us short names without importing internal/client into every
// file (Go disallows re-import of the same package across files in
// the same package).

import (
	"fmt"
	"strings"

	"github.com/dogukanturhal/jess/internal/client"
)

type clientRDPProbeReport = client.RDPProbeReport
type clientSweepResult = client.SweepResult

func prettyRDPProbeRow(row SweepResult) {
	p := row.Probe
	id := row.TargetID
	if row.TargetName != "" {
		id = fmt.Sprintf("%s (%s)", row.TargetID, row.TargetName)
	}
	switch {
	case !p.Reachable:
		fmt.Printf("  \033[31m✗\033[0m  %-40s  %s  unreachable: %s\n", id, p.Target, p.Error)
	case p.FailureCode != 0:
		fmt.Printf("  \033[33m⚠\033[0m  %-40s  %s  code=%d (%s)\n",
			id, p.Target, p.FailureCode, p.FailureReason)
	default:
		caps := []string{}
		if p.TLSSupported {
			caps = append(caps, "TLS")
		}
		if p.NLARequired {
			caps = append(caps, "NLA")
		}
		fmt.Printf("  \033[32m✓\033[0m  %-40s  %s  %s [%s]  %dms\n",
			id, p.Target, p.NegotiatedProto, strings.Join(caps, "+"), p.DurationMs)
	}
}
