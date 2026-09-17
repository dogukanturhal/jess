// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"strings"
	"testing"
)

// Gap audit #9 — admin-API target registration SSRF guard.
// Verifies the validator blocks well-known dangerous addresses while
// allowing legitimate RFC1918 + hostname targets.
func TestValidateAddressNotSSRF(t *testing.T) {
	t.Parallel()
	type tc struct {
		name    string
		addr    string
		wantErr bool
	}
	cases := []tc{
		// Blocked — cloud metadata.
		{"aws-metadata", "169.254.169.254", true},
		{"aws-metadata-port", "169.254.169.254:80", true},
		{"aws-metadata-v6", "fd00:ec2::254", true},
		{"gce-metadata-host", "metadata.google.internal:80", true},

		// Blocked — loopback / link-local / unspecified.
		{"localhost", "localhost", true},
		{"localhost-port", "localhost:22", true},
		{"ipv4-loopback", "127.0.0.1:22", true},
		{"ipv4-loopback-other", "127.42.0.1:22", true},
		{"ipv6-loopback", "[::1]:22", true},
		{"ipv4-link-local", "169.254.0.5:22", true},
		{"ipv6-link-local", "[fe80::1]:22", true},
		{"unspecified", "0.0.0.0:22", true},

		// Allowed — RFC1918 + ULA + hostnames + k8s service DNS.
		{"rfc1918-10", "10.0.20.10:22", false},
		{"rfc1918-192", "192.168.1.100:3389", false},
		{"rfc1918-172", "172.16.5.10:5432", false},
		{"k8s-svc", "jess-pg-rw.cnpg-clusters.svc.cluster.local:5432", false},
		{"plain-host", "dc01.internal.example.com:3389", false},
		{"ipv6-private", "[fc00::1]:22", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := validateAddressNotSSRF(c.addr)
			if c.wantErr && err == nil {
				t.Fatalf("validateAddressNotSSRF(%q) = nil, want error", c.addr)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validateAddressNotSSRF(%q) = %v, want nil", c.addr, err)
			}
			if c.wantErr && err != nil && !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "loopback") && !strings.Contains(err.Error(), "link-local") {
				t.Fatalf("validateAddressNotSSRF(%q) error %q does not surface the SSRF/loopback/link-local reason", c.addr, err)
			}
		})
	}
}
