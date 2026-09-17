// SPDX-License-Identifier: AGPL-3.0-or-later

package vaultx

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSignPKICert_URISansAndAltNames asserts the wire body SignPKICert sends
// to Vault. The device-cert flow needs the SPIFFE identity in a URI-type SAN
// (uri_sans) — posture-signer's DeviceCertVerifier reads cert.URIs, so a
// SPIFFE string smuggled through alt_names (DNS SAN) would never satisfy it
// and every heartbeat would 403 (ErrSANMismatch). This locks the parameter
// mapping so the regression can't silently come back.
func TestSignPKICert_URISansAndAltNames(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/sign/device-cert") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"certificate":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----","issuing_ca":"ca","serial_number":"01:02","expiration":4102444800}}`)
	}))
	defer srv.Close()

	c, err := New(Config{Addr: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const spiffe = "spiffe://hexxlock.com/device/3f9b2c1a-0000-4abc-9def-1234567890ab"
	_, err = c.SignPKICert(context.Background(), "jess-device-ca", "device-cert", PKISignRequest{
		CSRPEM:     "-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----",
		CommonName: "04ad2960",
		URISans:    []string{spiffe},
		AltNames:   []string{"device.local"},
	})
	if err != nil {
		t.Fatalf("SignPKICert: %v", err)
	}

	if got, _ := gotBody["uri_sans"].(string); got != spiffe {
		t.Errorf("uri_sans = %q, want %q", got, spiffe)
	}
	// The SPIFFE URI must NOT end up in alt_names.
	if alt, _ := gotBody["alt_names"].(string); strings.Contains(alt, "spiffe://") {
		t.Errorf("alt_names must not carry the SPIFFE URI, got %q", alt)
	}
	if alt, _ := gotBody["alt_names"].(string); alt != "device.local" {
		t.Errorf("alt_names = %q, want %q", alt, "device.local")
	}
	if cn, _ := gotBody["common_name"].(string); cn != "04ad2960" {
		t.Errorf("common_name = %q, want server-verified sub", cn)
	}
}
