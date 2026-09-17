// SPDX-License-Identifier: AGPL-3.0-or-later

package rdpprobe

import (
	"errors"
	"fmt"
	"net"
)

// IsAllowedTarget enforces the SSRF guard the controller's admin
// endpoint uses to keep `/admin/rdp-probe` from being abused to scan
// the public internet from inside the cluster.
//
// Rules (all must hold):
//   - target parses as host:port
//   - port is in the explicit allow-list (default: just 3389 — RDP)
//   - host resolves to ONLY RFC1918 + link-local addresses (no public
//     IPs, no AAAA literal globals, no DNS rebinding window because
//     we resolve once here and the dialer re-resolves later in
//     net.Dialer.DialContext — both must pass).
//
// Rationale: the controller is in-cluster and can reach anything its
// pod network reaches, including arbitrary public IPs through the
// cluster egress. Without this gate, an admin token (or worse, a
// compromised admin SA) could probe arbitrary public services from
// the cluster's egress IP — a classic SSRF lateral move. The guard
// keeps the admin endpoint a useful pre-deploy check ONLY for
// targets the broker is plausibly going to bridge to.
//
// TOCTOU note: the dialer re-resolves the host AFTER this check
// passes, so a DNS rebind between check and dial would let a public
// IP through. Mitigation lives at the kubernetes egress policy
// (NetworkPolicy / CiliumClusterwideNetworkPolicy) which should
// already block egress to non-RFC1918 from the controller pod.
// This function is defence-in-depth.
func IsAllowedTarget(target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("expected host:port, got %q: %w", target, err)
	}
	switch portStr {
	case "3389", "13389":
		// 3389 = RDP standard; 13389 = common non-standard alt
	default:
		return fmt.Errorf("port %s not in allow-list (3389, 13389)", portStr)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return errors.New("no IPs resolved")
	}
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			return fmt.Errorf("host %s resolves to non-private IP %s (SSRF guard)", host, ip)
		}
	}
	return nil
}

// isPrivateIP returns true for RFC1918, link-local, and loopback —
// the IP ranges where probing inside the cluster is plausibly
// legitimate (workload subnets, k8s services). Public IPs (including
// IPv6 globals) are denied.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		// net.IP.IsPrivate covers RFC1918 + RFC4193 fc00::/7 +
		// RFC2544 198.18/15 + 100.64/10 CGNAT.
		return true
	}
	return false
}
