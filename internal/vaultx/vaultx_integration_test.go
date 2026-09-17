// SPDX-License-Identifier: AGPL-3.0-or-later

package vaultx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startVaultDev spins a throwaway `vault server -dev` in docker and returns its
// address + root token. SKIPS (not fails) without docker so the suite stays
// green locally and runs for real in CI's DinD (same pattern as startPostgres).
func startVaultDev(t *testing.T) (addr, token, name string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name = "jess-vault-" + hex.EncodeToString(b)
	run := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"--cap-add=IPC_LOCK",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID=root",
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"-p", "127.0.0.1::8200", "hashicorp/vault:1.17")
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("docker run failed (skipping): %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	var hostPort string
	for i := 0; i < 30; i++ {
		out, err := exec.Command("docker", "port", name, "8200/tcp").Output()
		if err == nil && len(out) > 0 {
			line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
			if idx := strings.LastIndex(line, ":"); idx >= 0 {
				hostPort = line[idx+1:]
				break
			}
		}
		time.Sleep(time.Second)
	}
	if hostPort == "" {
		t.Skip("could not determine vault host port")
	}
	addr = "http://127.0.0.1:" + hostPort
	for i := 0; i < 40; i++ {
		resp, err := http.Get(addr + "/v1/sys/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return addr, "root", name
			}
		}
		time.Sleep(time.Second)
	}
	t.Skip("vault did not become ready in time")
	return "", "", ""
}

// vaultExec runs `vault <args>` inside the dev container with root auth.
func vaultExec(t *testing.T, name string, script string) {
	t.Helper()
	cmd := exec.Command("docker", "exec",
		"-e", "VAULT_ADDR=http://127.0.0.1:8200", "-e", "VAULT_TOKEN=root",
		name, "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("vault setup failed: %v\n%s", err, out)
	}
}

func TestVaultTransitSignAndVerify(t *testing.T) {
	addr, token, name := startVaultDev(t)
	vaultExec(t, name, "vault secrets enable transit && vault write -f transit/keys/jess-recordings type=ed25519")

	c, err := New(Config{Addr: addr, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Low-level: sign + fetch public key + verify.
	data := []byte("tamper-evident-recording-manifest")
	sig, err := c.TransitSign(ctx, "transit", "jess-recordings", data)
	if err != nil {
		t.Fatalf("transit sign: %v", err)
	}
	pub, err := c.TransitPublicKey(ctx, "transit", "jess-recordings")
	if err != nil {
		t.Fatalf("transit public key: %v", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		t.Fatal("signature did not verify against the Vault-fetched public key")
	}
	if ed25519.Verify(pub, []byte("other"), sig) {
		t.Fatal("signature verified over WRONG data (must not)")
	}

	// Adapter: TransitSigner satisfies recording.Signer (KeyID/Sign/Public).
	ts, err := NewTransitSigner(ctx, c, "transit", "jess-recordings")
	if err != nil {
		t.Fatalf("new transit signer: %v", err)
	}
	if !strings.Contains(ts.KeyID(), "jess-recordings") {
		t.Errorf("KeyID = %q, want it to name the key", ts.KeyID())
	}
	sig2, err := ts.Sign(data)
	if err != nil {
		t.Fatalf("adapter sign: %v", err)
	}
	if !ed25519.Verify(ts.Public(), data, sig2) {
		t.Fatal("adapter signature did not verify against adapter Public()")
	}
}

func TestVaultSignSSHCert(t *testing.T) {
	addr, token, name := startVaultDev(t)
	vaultExec(t, name, strings.Join([]string{
		"vault secrets enable -path=ssh-client-signer ssh",
		"vault write ssh-client-signer/config/ca generate_signing_key=true",
		"vault write ssh-client-signer/roles/ssh-admin key_type=ca allow_user_certificates=true allowed_users='*' default_user=hexxlock allowed_extensions='*' ttl=10m",
	}, " && "))

	c, err := New(Config{Addr: addr, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	// Mint an ephemeral key and have Vault sign it for principal "hexxlock".
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = priv
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	authPub := string(ssh.MarshalAuthorizedKey(sshPub))

	certStr, err := c.SignSSHCert(context.Background(), "ssh-client-signer", "ssh-admin", authPub, []string{"hexxlock"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("ssh sign: %v", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("vault did not return an SSH certificate, got %T", pk)
	}
	found := false
	for _, p := range cert.ValidPrincipals {
		if p == "hexxlock" {
			found = true
		}
	}
	if !found {
		t.Errorf("cert principals = %v, want to include hexxlock", cert.ValidPrincipals)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want UserCert", cert.CertType)
	}
}
