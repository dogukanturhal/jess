// SPDX-License-Identifier: AGPL-3.0-or-later

package vaultx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestLDAPDynamicCredential_HappyPath asserts the engine path + response
// parsing: GET /v1/<mount>/creds/<role> → username/password + lease TTL.
func TestLDAPDynamicCredential_HappyPath(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"lease_id":"ldap/creds/rdp-dc/abc",
			"lease_duration":900,
			"renewable":false,
			"data":{"username":"v-ldap-jess-xyz","password":"Ephem3ral!","distinguished_name":"CN=v-ldap-jess-xyz,OU=Svc,DC=hexxlock,DC=corp"}
		}`)
	}))
	defer srv.Close()

	c, err := New(Config{Addr: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cred, err := c.LDAPDynamicCredential(context.Background(), "ldap", "rdp-dc")
	if err != nil {
		t.Fatalf("LDAPDynamicCredential: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotPath != "/v1/ldap/creds/rdp-dc" {
		t.Errorf("path = %q, want /v1/ldap/creds/rdp-dc", gotPath)
	}
	if cred.Username != "v-ldap-jess-xyz" || cred.Password != "Ephem3ral!" {
		t.Errorf("credential not parsed: user=%q pass-set=%v", cred.Username, cred.Password != "")
	}
	if cred.LeaseTTL != 900*time.Second {
		t.Errorf("lease TTL = %s, want 15m", cred.LeaseTTL)
	}
	if cred.LeaseID != "ldap/creds/rdp-dc/abc" {
		t.Errorf("lease id = %q", cred.LeaseID)
	}
	if !strings.HasPrefix(cred.DistName, "CN=v-ldap-jess-xyz") {
		t.Errorf("distinguished name = %q", cred.DistName)
	}
}

// TestLDAPDynamicCredential_EmptyCredential rejects a partial record
// (defense against a misconfigured role) rather than returning a blank cred.
func TestLDAPDynamicCredential_EmptyCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"lease_duration":60,"data":{"username":"","password":""}}`)
	}))
	defer srv.Close()

	c, _ := New(Config{Addr: srv.URL, Token: "test-token"})
	if _, err := c.LDAPDynamicCredential(context.Background(), "ldap", "rdp-dc"); err == nil {
		t.Fatal("expected error on empty username/password")
	}
}

// TestLDAPDynamicCredential_VaultError surfaces a Vault 403 as an error
// (fail-closed; no credential).
func TestLDAPDynamicCredential_VaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
	}))
	defer srv.Close()

	// Static token → no re-login loop on 403.
	c, _ := New(Config{Addr: srv.URL, Token: "test-token"})
	if _, err := c.LDAPDynamicCredential(context.Background(), "ldap", "rdp-dc"); err == nil {
		t.Fatal("expected error on Vault 403")
	}
}
