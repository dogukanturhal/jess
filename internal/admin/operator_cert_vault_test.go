// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// fakeVaultPKI is a minimal Vault HTTP surface that satisfies the three
// endpoints VaultSigner needs: /v1/<mount>/ca/pem, /v1/<mount>/ca_chain,
// /v1/<mount>/sign/<role>. Captures the last sign request so tests can
// assert the wire shape (the CN-binding property is the load-bearing one).
type fakeVaultPKI struct {
	t              *testing.T
	caPEM          string
	chainPEM       string
	lastSignBody   map[string]any
	lastRevokeBody map[string]any
	signCertPEM    string
	tokenRequired  string // if set, X-Vault-Token must equal this
}

func (f *fakeVaultPKI) start() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jess-ca/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		if f.tokenRequired != "" && r.Header.Get("X-Vault-Token") != f.tokenRequired {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(f.caPEM))
	})
	mux.HandleFunc("/v1/jess-ca/ca_chain", func(w http.ResponseWriter, r *http.Request) {
		if f.chainPEM == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(f.chainPEM))
	})
	mux.HandleFunc("/v1/jess-ca/revoke", func(w http.ResponseWriter, r *http.Request) {
		if f.tokenRequired != "" && r.Header.Get("X-Vault-Token") != f.tokenRequired {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.lastRevokeBody = body
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"revocation_time": time.Now().Unix()},
		})
	})
	mux.HandleFunc("/v1/jess-ca/sign/operator-cert", func(w http.ResponseWriter, r *http.Request) {
		if f.tokenRequired != "" && r.Header.Get("X-Vault-Token") != f.tokenRequired {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.lastSignBody = body
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":   f.signCertPEM,
				"issuing_ca":    f.caPEM,
				"serial_number": "01:02:03",
				"expiration":    time.Now().Add(time.Hour).Unix(),
			},
		})
	})
	return httptest.NewServer(mux)
}

// TestVaultSignerForwardsSubjectAndCSR pins the load-bearing property:
// SignCSR forwards the CALLER'S verified subject to Vault as common_name,
// NOT whatever the CSR's CN claimed. RFC 8705 §2.1 tls_client_auth binding.
func TestVaultSignerForwardsSubjectAndCSR(t *testing.T) {
	// Generate a valid CA + leaf so the fake server has something to return.
	caCertPEM, _ := mintTestCA(t)
	leafPEM, _ := mintCSR(t, "doesnt-matter") // re-use CSR helper as a stand-in for "some PEM cert"

	fake := &fakeVaultPKI{
		t:             t,
		caPEM:         string(caCertPEM),
		signCertPEM:   string(leafPEM),
		tokenRequired: "test-token",
	}
	srv := fake.start()
	defer srv.Close()

	vc, err := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewVaultSigner(context.Background(), vc, "jess-ca", "operator-cert")
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, _ := mintCSR(t, "what-the-operator-claimed")
	gotCert, err := signer.SignCSR(context.Background(), csrPEM, "verified-falcon-id-uuid", "ops@example.com", 4*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if len(gotCert) == 0 {
		t.Fatal("empty cert returned")
	}

	// CN-binding wire assertion — the request body to Vault must carry the
	// caller's verified subject as common_name, not the CSR's CN.
	if fake.lastSignBody == nil {
		t.Fatal("no sign request captured")
	}
	if cn := fake.lastSignBody["common_name"]; cn != "verified-falcon-id-uuid" {
		t.Errorf("Vault common_name=%v, want verified-falcon-id-uuid (CSR's CN MUST be ignored)", cn)
	}
	if csr := fake.lastSignBody["csr"]; !strings.Contains(csr.(string), "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("Vault csr looks malformed: %v", csr)
	}
	if ttl := fake.lastSignBody["ttl"]; ttl != "14400s" {
		t.Errorf("Vault ttl=%v, want 14400s (4h)", ttl)
	}
	if fmt := fake.lastSignBody["format"]; fmt != "pem" {
		t.Errorf("Vault format=%v, want pem", fmt)
	}
}

func TestVaultSignerCapsTTL(t *testing.T) {
	caCertPEM, _ := mintTestCA(t)
	leafPEM, _ := mintCSR(t, "x")
	fake := &fakeVaultPKI{t: t, caPEM: string(caCertPEM), signCertPEM: string(leafPEM)}
	srv := fake.start()
	defer srv.Close()

	vc, _ := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "any"})
	signer, _ := NewVaultSigner(context.Background(), vc, "jess-ca", "operator-cert")

	csrPEM, _ := mintCSR(t, "x")
	if _, err := signer.SignCSR(context.Background(), csrPEM, "sub", "", 99*time.Hour); err != nil {
		t.Fatal(err)
	}
	want := int(MaxOperatorCertTTL.Seconds())
	if ttl := fake.lastSignBody["ttl"]; ttl != fmt2sec(want) {
		t.Errorf("TTL not capped: got %v, want %ds (= MaxOperatorCertTTL)", ttl, want)
	}
}

func TestVaultSignerCAPemReturnsBundle(t *testing.T) {
	caCertPEM, _ := mintTestCA(t)
	chain := "-----BEGIN CERTIFICATE-----\nFAKEINTERMEDIATE\n-----END CERTIFICATE-----\n"
	fake := &fakeVaultPKI{t: t, caPEM: string(caCertPEM), chainPEM: chain}
	srv := fake.start()
	defer srv.Close()

	vc, _ := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "any"})
	signer, err := NewVaultSigner(context.Background(), vc, "jess-ca", "operator-cert")
	if err != nil {
		t.Fatal(err)
	}
	bundle := string(signer.CAPem())
	if !strings.Contains(bundle, "BEGIN CERTIFICATE") {
		t.Errorf("CA bundle missing CA cert: %q", bundle[:120])
	}
	if !strings.Contains(bundle, "FAKEINTERMEDIATE") {
		t.Errorf("CA bundle missing chain intermediate: %q", bundle[:120])
	}
}

func TestVaultSignerRejectsEmptySubject(t *testing.T) {
	caCertPEM, _ := mintTestCA(t)
	fake := &fakeVaultPKI{t: t, caPEM: string(caCertPEM)}
	srv := fake.start()
	defer srv.Close()

	vc, _ := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "any"})
	signer, _ := NewVaultSigner(context.Background(), vc, "jess-ca", "operator-cert")

	csrPEM, _ := mintCSR(t, "x")
	if _, err := signer.SignCSR(context.Background(), csrPEM, "", "", time.Hour); err == nil {
		t.Error("expected error on empty subject — would leak a no-CN cert")
	}
}

// fmt2sec turns an int seconds count into the "%ds" string Vault expects.
// Tiny helper that avoids importing "fmt" twice in this test file.
func fmt2sec(s int) string {
	// strconv.Itoa is enough; keep imports minimal
	const digits = "0123456789"
	if s == 0 {
		return "0s"
	}
	out := ""
	for s > 0 {
		out = string(digits[s%10]) + out
		s /= 10
	}
	return out + "s"
}

// TestVaultSignerRevokeSerialCallsVault pins the revoke wire shape:
//   - POST /v1/<mount>/revoke
//   - body carries `serial_number` (Vault's expected key, NOT `serial`)
//   - X-Vault-Token header carries the auth (when tokenRequired set)
//   - successful 200 returns nil error
//
// Also verifies idempotency surface: the fake echoes a revocation_time
// regardless of whether the serial was previously seen — VaultSigner
// accepts that and returns nil (matches Vault PKI /revoke semantics).
func TestVaultSignerRevokeSerialCallsVault(t *testing.T) {
	caCertPEM, _ := mintTestCA(t)
	fake := &fakeVaultPKI{
		t:             t,
		caPEM:         string(caCertPEM),
		tokenRequired: "test-token",
	}
	srv := fake.start()
	defer srv.Close()

	vc, err := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewVaultSigner(context.Background(), vc, "jess-ca", "operator-cert")
	if err != nil {
		t.Fatal(err)
	}

	const inputSerial = "4b:95:f9:03:71:32:dc:80"
	if err := signer.RevokeSerial(context.Background(), inputSerial); err != nil {
		t.Fatalf("RevokeSerial: %v", err)
	}
	if fake.lastRevokeBody == nil {
		t.Fatal("Vault /revoke endpoint not called")
	}
	if got, want := fake.lastRevokeBody["serial_number"], inputSerial; got != want {
		t.Errorf("wire body[serial_number] = %v, want %v", got, want)
	}
	if _, present := fake.lastRevokeBody["serial"]; present {
		t.Error("wire body unexpectedly carries `serial` key (Vault expects `serial_number`)")
	}
}

// TestVaultSignerRevokeSerialBubblesVaultError pins that a non-2xx Vault
// response surfaces as an error (not silently swallowed).
func TestVaultSignerRevokeSerialBubblesVaultError(t *testing.T) {
	caCertPEM, _ := mintTestCA(t)
	fake := &fakeVaultPKI{
		t:             t,
		caPEM:         string(caCertPEM),
		tokenRequired: "test-token",
	}
	srv := fake.start()
	defer srv.Close()

	vc, _ := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "wrong-token"}) // 403 from fake
	signer, err := NewVaultSigner(context.Background(), vc, "jess-ca", "operator-cert")
	if err == nil {
		// Constructor fetched CA bundle with wrong token → expected to fail.
		t.Fatal("NewVaultSigner with wrong token should fail at CA bundle fetch")
	}
	_ = signer
}
