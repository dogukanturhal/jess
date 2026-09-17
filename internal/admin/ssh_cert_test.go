// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/pdp"
)

// fakeSSHSigner records the last call args + returns a canned cert.
type fakeSSHSigner struct {
	cert string
	err  error

	lastMount      string
	lastRole       string
	lastPublicKey  string
	lastPrincipals []string
	lastTTL        time.Duration
}

func (f *fakeSSHSigner) SignSSHCert(_ context.Context, mount, role, pk string, principals []string, ttl time.Duration) (string, error) {
	f.lastMount = mount
	f.lastRole = role
	f.lastPublicKey = pk
	f.lastPrincipals = principals
	f.lastTTL = ttl
	if f.err != nil {
		return "", f.err
	}
	return f.cert, nil
}

func newAdminWithSSH(_ *testing.T, signer SSHCertSigner) *Handler {
	v := &fakeAdminVerifier{identity: pdp.Identity{Subject: "alice-sub", Roles: []string{"platform_admin"}}}
	return New(nil, v, "platform_admin").WithSSHCertSigner(SSHCertConfig{
		Vault:           signer,
		Mount:           "jess-ssh-ca",
		Role:            "operator-client",
		MaxTTL:          12 * time.Hour,
		PrincipalPrefix: "git-",
	})
}

func TestSSHCert_HappyPath(t *testing.T) {
	t.Parallel()
	signer := &fakeSSHSigner{cert: "ssh-ed25519-cert-v01@openssh.com AAAA…"}
	h := newAdminWithSSH(t, signer)
	body, _ := json.Marshal(SSHCertRequest{
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7s",
		TTLSeconds: 1800,
	})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Device-UUID", "01HZZ-uuid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp SSHCertResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Cert != signer.cert {
		t.Errorf("cert mismatch")
	}
	if len(resp.Principals) != 1 || resp.Principals[0] != "git-alice-sub" {
		t.Errorf("principals: want [git-alice-sub], got %+v", resp.Principals)
	}
	if !strings.Contains(resp.KeyID, "device=01HZZ-uuid") {
		t.Errorf("key_id missing device claim: %q", resp.KeyID)
	}
	if !strings.Contains(resp.KeyID, "operator=alice-sub") {
		t.Errorf("key_id missing operator sub: %q", resp.KeyID)
	}
	if signer.lastTTL != 30*time.Minute {
		t.Errorf("TTL not propagated: want 30m, got %s", signer.lastTTL)
	}
}

func TestSSHCert_TTLClamped(t *testing.T) {
	t.Parallel()
	signer := &fakeSSHSigner{cert: "stub"}
	h := newAdminWithSSH(t, signer)
	// Ask for 48h, server should clamp to 12h.
	body, _ := json.Marshal(SSHCertRequest{
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7s",
		TTLSeconds: 48 * 3600,
	})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
	if signer.lastTTL != 12*time.Hour {
		t.Errorf("TTL clamp failed: want 12h, got %s", signer.lastTTL)
	}
}

func TestSSHCert_BadKeyAlgorithm(t *testing.T) {
	t.Parallel()
	h := newAdminWithSSH(t, &fakeSSHSigner{})
	body, _ := json.Marshal(SSHCertRequest{
		PublicKey:  "ssh-dss AAAAB3NzaC1kc3MAAACBA…",
		TTLSeconds: 60,
	})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unsupported algorithm") {
		t.Errorf("unexpected error: %s", w.Body.String())
	}
}

func TestSSHCert_EmptyKey(t *testing.T) {
	t.Parallel()
	h := newAdminWithSSH(t, &fakeSSHSigner{})
	body, _ := json.Marshal(SSHCertRequest{PublicKey: "", TTLSeconds: 60})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestSSHCert_NegativeTTL(t *testing.T) {
	t.Parallel()
	h := newAdminWithSSH(t, &fakeSSHSigner{})
	body, _ := json.Marshal(SSHCertRequest{
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7s",
		TTLSeconds: -1,
	})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestSSHCert_VaultError_BadGateway(t *testing.T) {
	t.Parallel()
	signer := &fakeSSHSigner{err: errors.New("vault down")}
	h := newAdminWithSSH(t, signer)
	body, _ := json.Marshal(SSHCertRequest{
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7s",
		TTLSeconds: 60,
	})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", w.Code)
	}
}

func TestSSHCert_NotConfigured_503(t *testing.T) {
	t.Parallel()
	v := &fakeAdminVerifier{identity: pdp.Identity{Subject: "x", Roles: []string{"platform_admin"}}}
	h := New(nil, v, "platform_admin") // no WithSSHCertSigner
	body, _ := json.Marshal(SSHCertRequest{PublicKey: "ssh-ed25519 X", TTLSeconds: 60})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
}

func TestSSHCert_WrongRole_403(t *testing.T) {
	t.Parallel()
	v := &fakeAdminVerifier{identity: pdp.Identity{Subject: "x", Roles: []string{"viewer"}}}
	h := New(nil, v, "platform_admin").WithSSHCertSigner(SSHCertConfig{
		Vault: &fakeSSHSigner{}, Mount: "x", Role: "y",
	})
	req := httptest.NewRequest(http.MethodPost, "/ssh-cert", bytes.NewReader([]byte(`{"public_key":"ssh-ed25519 X","ttl_seconds":60}`)))
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

func TestValidateOpenSSHPublicKey(t *testing.T) {
	t.Parallel()
	good := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7s",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNT",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA",
	}
	bad := []struct {
		key    string
		errSub string
	}{
		{"", "empty"},
		{"only-one-field", "format"},
		{"ssh-dss AAAA…", "unsupported"},
		{"ssh-ed25519 abc", "body too short"},
		{strings.Repeat("x ", 5000), "too large"},
	}
	for _, k := range good {
		if err := validateOpenSSHPublicKey(k); err != nil {
			t.Errorf("good key rejected: %q → %v", k, err)
		}
	}
	for _, bc := range bad {
		err := validateOpenSSHPublicKey(bc.key)
		if err == nil {
			t.Errorf("bad key %q accepted", bc.key)
			continue
		}
		if !strings.Contains(err.Error(), bc.errSub) {
			t.Errorf("bad key %q: want error containing %q, got %v", bc.key, bc.errSub, err)
		}
	}
}
