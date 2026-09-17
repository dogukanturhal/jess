// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// dummyVaultClient returns a non-nil vaultx.Client built with a static token so
// the constructor doesn't dial (vaultx.New short-circuits on a static token).
// newSSHCertConfig never calls Vault, so this is sufficient for its env-default
// branch tests.
func dummyVaultClient() *vaultx.Client {
	c, err := vaultx.New(vaultx.Config{Addr: "http://vault.test:8200", Token: "test-token"})
	if err != nil {
		panic(err)
	}
	return c
}

func TestParseResize(t *testing.T) {
	frame := func(op byte, cols, rows uint32) []byte {
		b := make([]byte, 9)
		b[0] = op
		binary.BigEndian.PutUint32(b[1:5], cols)
		binary.BigEndian.PutUint32(b[5:9], rows)
		return b
	}

	t.Run("well-formed", func(t *testing.T) {
		cols, rows, ok := parseResize(frame(resizeOpcode, 120, 40))
		if !ok || cols != 120 || rows != 40 {
			t.Fatalf("parseResize = (%d,%d,%v), want (120,40,true)", cols, rows, ok)
		}
	})

	t.Run("wrong opcode is ignored", func(t *testing.T) {
		if _, _, ok := parseResize(frame(0x02, 80, 24)); ok {
			t.Fatal("non-resize opcode must not parse as resize (would corrupt control channel)")
		}
	})

	t.Run("wrong length is ignored", func(t *testing.T) {
		if _, _, ok := parseResize([]byte{resizeOpcode, 0, 0, 80}); ok {
			t.Fatal("short frame must not parse")
		}
		if _, _, ok := parseResize(nil); ok {
			t.Fatal("nil frame must not parse")
		}
	})

	t.Run("zero / absurd dimensions are rejected", func(t *testing.T) {
		if _, _, ok := parseResize(frame(resizeOpcode, 0, 24)); ok {
			t.Fatal("zero cols must be rejected")
		}
		if _, _, ok := parseResize(frame(resizeOpcode, 80, 0)); ok {
			t.Fatal("zero rows must be rejected")
		}
		if _, _, ok := parseResize(frame(resizeOpcode, 99999, 24)); ok {
			t.Fatal("absurd cols must be rejected")
		}
	})
}

func TestAtoiDefault(t *testing.T) {
	cases := []struct {
		in   string
		def  int
		want int
	}{
		{"", 80, 80},
		{"120", 80, 120},
		{"0", 24, 24},    // non-positive falls back
		{"-5", 24, 24},   // negative falls back
		{"abc", 24, 24},  // garbage falls back
		{"  10", 24, 24}, // strconv.Atoi rejects surrounding space → fallback
	}
	for _, c := range cases {
		if got := atoiDefault(c.in, c.def); got != c.want {
			t.Errorf("atoiDefault(%q,%d) = %d, want %d", c.in, c.def, got, c.want)
		}
	}
}

func TestNewSSHCertConfigNilVaultClient(t *testing.T) {
	// No Vault client → no clientless SSH (legacy bridge). Must never panic.
	if cfg := newSSHCertConfig(nil); cfg != nil {
		t.Fatal("newSSHCertConfig(nil) must return nil (no Vault → legacy raw bridge)")
	}
}

func TestNewSSHCertConfigDefaults(t *testing.T) {
	// With a (non-nil) Vault client + JESS_VAULT_ADDR set, the config should
	// default the operator SSH CA mount/role/principal/ttl. We only exercise
	// the env-defaulting branch — a dummy non-nil client is enough since the
	// constructor never dials.
	t.Setenv("JESS_VAULT_ADDR", "http://vault.example:8200")
	t.Setenv("JESS_WEB_SSH_CA_VAULT_MOUNT", "")
	t.Setenv("JESS_WEB_SSH_CA_VAULT_ROLE", "")
	t.Setenv("JESS_WEB_SSH_OPERATOR_USER", "")
	t.Setenv("JESS_WEB_SSH_CERT_TTL", "")

	cfg := newSSHCertConfig(dummyVaultClient())
	if cfg == nil {
		t.Fatal("expected a config when Vault is configured")
	}
	if cfg.mount != "ssh-client-signer" {
		t.Errorf("default mount = %q, want ssh-client-signer", cfg.mount)
	}
	if cfg.role != "ssh-admin" {
		t.Errorf("default role = %q, want ssh-admin", cfg.role)
	}
	if cfg.principal != "hexxlock" {
		t.Errorf("default principal = %q, want hexxlock", cfg.principal)
	}
	if cfg.ttl != 5*time.Minute {
		t.Errorf("default ttl = %s, want 5m", cfg.ttl)
	}
}

func TestNewSSHCertConfigOverrides(t *testing.T) {
	t.Setenv("JESS_VAULT_ADDR", "http://vault.example:8200")
	t.Setenv("JESS_WEB_SSH_CA_VAULT_MOUNT", "custom-ssh-ca")
	t.Setenv("JESS_WEB_SSH_CA_VAULT_ROLE", "custom-role")
	t.Setenv("JESS_WEB_SSH_OPERATOR_USER", "Administrator")
	t.Setenv("JESS_WEB_SSH_CERT_TTL", "10m")

	cfg := newSSHCertConfig(dummyVaultClient())
	if cfg == nil {
		t.Fatal("expected a config")
	}
	if cfg.mount != "custom-ssh-ca" || cfg.role != "custom-role" ||
		cfg.principal != "Administrator" || cfg.ttl != 10*time.Minute {
		t.Errorf("overrides not applied: %+v", *cfg)
	}
}
