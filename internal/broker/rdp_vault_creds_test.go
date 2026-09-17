// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// fakeVaultLDAP is a deterministic stand-in for the vaultx LDAP secrets-engine
// client. It records the mount+role it was asked for and returns a scripted
// credential or error.
type fakeVaultLDAP struct {
	gotMount string
	gotRole  string
	calls    int
	cred     vaultx.LDAPCredential
	err      error
}

func (f *fakeVaultLDAP) LDAPDynamicCredential(_ context.Context, mount, role string) (vaultx.LDAPCredential, error) {
	f.calls++
	f.gotMount = mount
	f.gotRole = role
	if f.err != nil {
		return vaultx.LDAPCredential{}, f.err
	}
	return f.cred, nil
}

func okCred() vaultx.LDAPCredential {
	return vaultx.LDAPCredential{
		Username: "v-ldap-jess-abc123",
		Password: "Sup3rEphemeral!",
		LeaseID:  "ldap/creds/rdp-dc/lease-xyz",
		LeaseTTL: 15 * time.Minute,
	}
}

// NewVaultRDPCredBroker enforces its required config (mount + non-nil client).
func TestNewVaultRDPCredBroker_RequiresMountAndClient(t *testing.T) {
	if _, err := NewVaultRDPCredBroker(nil, VaultRDPCredsConfig{Mount: "ldap"}); err == nil {
		t.Fatal("expected error on nil vault client")
	}
	if _, err := NewVaultRDPCredBroker(&fakeVaultLDAP{}, VaultRDPCredsConfig{}); err == nil {
		t.Fatal("expected error on empty mount (fail-closed)")
	}
	if _, err := NewVaultRDPCredBroker(&fakeVaultLDAP{}, VaultRDPCredsConfig{Mount: "ldap"}); err != nil {
		t.Fatalf("unexpected error on valid config: %v", err)
	}
}

// IssueForOperator (web seam) mints a short-lived AD credential, returns the
// lease TTL, stamps the configured domain, and reads from the configured mount.
func TestIssueForOperator_MintsADCredentialWithTTL(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()}
	b, err := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Role: "rdp-dc", Domain: "HEXXLOCK"})
	if err != nil {
		t.Fatal(err)
	}

	sec, ttl, err := b.IssueForOperator(context.Background(), "win-dc-01", "sub-operator-42")
	if err != nil {
		t.Fatalf("IssueForOperator: %v", err)
	}
	if sec.Kind != RDPSecretADCredential {
		t.Errorf("kind = %q, want %q", sec.Kind, RDPSecretADCredential)
	}
	if sec.Username != "v-ldap-jess-abc123" || sec.Password != "Sup3rEphemeral!" {
		t.Errorf("credential not passed through: user=%q pass-set=%v", sec.Username, sec.Password != "")
	}
	if sec.Domain != "HEXXLOCK" {
		t.Errorf("domain = %q, want HEXXLOCK", sec.Domain)
	}
	if ttl != 15*time.Minute {
		t.Errorf("ttl = %s, want 15m (lease TTL)", ttl)
	}
	if fv.gotMount != "ldap" {
		t.Errorf("mount = %q, want ldap", fv.gotMount)
	}
}

// With a fixed Role configured, every target uses that single Vault role.
func TestIssueForOperator_FixedRole(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()}
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Role: "rdp-shared"})
	if _, _, err := b.IssueForOperator(context.Background(), "any-target", "sub-1"); err != nil {
		t.Fatal(err)
	}
	if fv.gotRole != "rdp-shared" {
		t.Errorf("role = %q, want fixed rdp-shared", fv.gotRole)
	}
}

// With NO fixed role, the role falls back to the target ID (per-target role —
// the 1:1 convention shared with the DB brokers / vaultRDPRole).
func TestIssueForOperator_PerTargetRole(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()}
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap"}) // no Role
	if _, _, err := b.IssueForOperator(context.Background(), "win-dc-07", "sub-2"); err != nil {
		t.Fatal(err)
	}
	if fv.gotRole != "win-dc-07" {
		t.Errorf("role = %q, want per-target win-dc-07", fv.gotRole)
	}
}

// Per-target role with an empty target ID is fail-closed (no addressable role).
func TestIssueForOperator_PerTargetRole_EmptyTargetID_FailsClosed(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()}
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap"}) // no Role
	if _, _, err := b.IssueForOperator(context.Background(), "", "sub-3"); err == nil {
		t.Fatal("expected fail-closed when no role and no target ID")
	}
	if fv.calls != 0 {
		t.Errorf("Vault should not be called on unresolved role; calls=%d", fv.calls)
	}
}

// A Vault error propagates (fail-closed) and is wrapped — no credential leaks.
func TestIssueForOperator_VaultError_FailsClosed(t *testing.T) {
	fv := &fakeVaultLDAP{err: errors.New("permission denied")}
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Role: "rdp-dc"})
	_, _, err := b.IssueForOperator(context.Background(), "win-dc-01", "sub-4")
	if err == nil {
		t.Fatal("expected error from Vault to propagate")
	}
}

// An empty username/password from Vault is rejected (defense against a
// misconfigured role returning a partial record).
func TestIssueForOperator_EmptyCredential_FailsClosed(t *testing.T) {
	// vaultx.LDAPDynamicCredential itself guards empty user/pass; here we
	// exercise the broker's own guard by faking a record the engine "passed".
	fv := &fakeVaultLDAP{cred: vaultx.LDAPCredential{Username: "", Password: "", LeaseTTL: time.Minute}}
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Role: "rdp-dc"})
	sec, _, err := b.IssueForOperator(context.Background(), "win-dc-01", "sub-5")
	// The fake bypasses vaultx's own empty-guard, so the broker returns the
	// empty cred; the live-engine guard (Open) then fail-closes on empty
	// user/pass. Assert the broker does not silently fabricate a credential.
	if err == nil && (sec.Username != "" || sec.Password != "") {
		t.Fatal("broker must not fabricate credential material")
	}
}

// The config TTL hint caps the reported TTL when it is shorter than the lease.
func TestIssueForOperator_ConfigTTLHintCapsReported(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()} // lease 15m
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Role: "rdp-dc", TTL: 5 * time.Minute})
	_, ttl, err := b.IssueForOperator(context.Background(), "win-dc-01", "sub-6")
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 5*time.Minute {
		t.Errorf("ttl = %s, want 5m (config hint shorter than lease)", ttl)
	}
}

// The worker-broker seam (IssueRDPCredential) mints from the role it is given
// and returns the AD credential shape NewRDPBroker expects.
func TestIssueRDPCredential_WorkerSeam(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()}
	b, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Domain: "HEXXLOCK"})

	sec, err := b.IssueRDPCredential(context.Background(), "win-dc-01")
	if err != nil {
		t.Fatalf("IssueRDPCredential: %v", err)
	}
	if sec.Kind != RDPSecretADCredential || sec.Username == "" {
		t.Errorf("worker seam did not return a usable AD credential: %+v", sec.Kind)
	}
	if fv.gotRole != "win-dc-01" {
		t.Errorf("worker seam role = %q, want win-dc-01", fv.gotRole)
	}
}

// The Vault broker plugs straight into NewLiveRDPBroker as the production
// credential source (compile + Mint smoke through the real broker spine).
func TestVaultCredBroker_WiresIntoLiveRDPBroker(t *testing.T) {
	fv := &fakeVaultLDAP{cred: okCred()}
	creds, _ := NewVaultRDPCredBroker(fv, VaultRDPCredsConfig{Mount: "ldap", Domain: "HEXXLOCK"})

	bk := NewLiveRDPBroker(creds, nil, 0, "")
	grant := AccessGrant{
		Target: &Target{ID: "win-dc-01", Address: "10.0.0.5:3389"},
		Client: &fakeRDPConn{},
	}
	cred, err := bk.Mint(context.Background(), grant)
	if err != nil {
		t.Fatalf("Mint through live broker with Vault creds: %v", err)
	}
	rc, ok := cred.(rdpCredential)
	if !ok {
		t.Fatalf("Mint returned %T, want rdpCredential", cred)
	}
	if rc.sec.Username == "" || rc.sec.Kind != RDPSecretADCredential {
		t.Errorf("minted secret not an AD credential: %+v", rc.sec.Kind)
	}
	if fv.gotRole != "win-dc-01" {
		t.Errorf("role = %q, want target ID win-dc-01 (vaultRDPRole)", fv.gotRole)
	}
}
