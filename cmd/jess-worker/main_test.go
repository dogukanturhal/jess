// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
)

// TestResolveControllerDNS_IPPassthrough — when the input is already an
// IP:port (no hostname to resolve), pass through unchanged. Defensive
// fallback that preserves the existing dial behaviour when DNS isn't
// applicable (literal IPs in dev/tests).
func TestResolveControllerDNS_IPPassthrough(t *testing.T) {
	got := resolveControllerDNS("10.0.0.1:7100")
	if len(got) != 1 || got[0] != "10.0.0.1:7100" {
		t.Errorf("IP-literal pass-through: got %v, want [10.0.0.1:7100]", got)
	}
}

// TestResolveControllerDNS_HostnameThatFailsLookup — unresolvable
// hostname must fall back to the original string (NOT crash, NOT return
// nil). The worker's Run loop will then fail to dial it and back off,
// surfacing the misconfig clearly without crashing the binary at startup.
func TestResolveControllerDNS_HostnameThatFailsLookup(t *testing.T) {
	got := resolveControllerDNS("does-not-exist.example.invalid:7100")
	if len(got) != 1 || got[0] != "does-not-exist.example.invalid:7100" {
		t.Errorf("DNS-fail fallback: got %v, want original", got)
	}
}

// TestResolveControllerDNS_MalformedAddrPassThrough — input without
// host:port shape passes through (worker.Run errors at dial; we don't
// want startup to crash on a typo).
func TestResolveControllerDNS_MalformedAddrPassThrough(t *testing.T) {
	got := resolveControllerDNS("not-a-host-port")
	if len(got) != 1 || got[0] != "not-a-host-port" {
		t.Errorf("malformed pass-through: got %v", got)
	}
}

// TestResolveControllerDNS_LocalhostExpands — localhost resolves to
// 127.0.0.1 (and on dual-stack to ::1). Asserts the resolved port is
// preserved + the result is non-empty.
func TestResolveControllerDNS_LocalhostExpands(t *testing.T) {
	got := resolveControllerDNS("localhost:7100")
	if len(got) == 0 {
		t.Fatal("localhost yielded zero results — at least 127.0.0.1 expected")
	}
	for _, addr := range got {
		// Each entry must keep the :7100 port.
		if len(addr) < len(":7100") || addr[len(addr)-5:] != ":7100" {
			t.Errorf("port not preserved in %q", addr)
		}
	}
}
