// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5e-14 — recording bundle tamper-evidence verifier.
//
// Worker writes signed bundles via vault transit (cmd/jess-worker/
// vault_wiring.go recorderFromVault). Phase 5e-14 lets the controller
// (and through it the admin SPA) re-check those signatures + content
// hashes WITHOUT a Vault round-trip per verify — we fetch the ed25519
// public key once at startup and run verify locally.
//
// Env config (all optional — without them, the verify endpoint
// surfaces 503 and the admin SPA hides the tamper-evidence badge):
//
//	JESS_REC_VERIFY_VAULT_ADDR             https://vault.example.com
//	JESS_REC_VERIFY_VAULT_TOKEN            (or token-file via JESS_REC_VERIFY_VAULT_TOKEN_FILE)
//	JESS_REC_VERIFY_VAULT_K8S_ROLE         alt to token: k8s-sa-token auth (default jess-recordings)
//	JESS_REC_VERIFY_VAULT_TRANSIT_MOUNT    default "transit"
//	JESS_REC_VERIFY_VAULT_TRANSIT_KEY      default "jess-recordings"
//
// If both token + k8s-role are unset, we fall back to the same
// VAULT_TOKEN/VAULT_ADDR envs the rest of the stack uses (controller
// often already has Vault auth for other reasons — no need to re-wire).

import (
	"context"
	"crypto/ed25519"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// bundleVerifier satisfies internal/admin.RecordingVerifier. Holds a
// long-lived MinIO read store + the ed25519 pub key fetched from Vault
// Transit at boot.
type bundleVerifier struct {
	store *recording.S3Store
	pub   ed25519.PublicKey
}

func (v *bundleVerifier) VerifyBundle(ctx context.Context, sessionID string) (recording.VerifyResult, error) {
	return recording.VerifyDetail(ctx, v.store, sessionID, v.pub)
}

// recordingVerifierFromEnv returns a verifier when Vault + MinIO are
// both configured; nil otherwise. Errors during construction surface
// as a log line and a nil return — the admin endpoint then surfaces a
// clean 503 instead of crashing the controller (verify is a UX
// nice-to-have, not load-bearing for session brokering).
func recordingVerifierFromEnv(store *recording.S3Store) *bundleVerifier {
	if store == nil {
		return nil
	}
	vaultAddr := firstNonEmpty(os.Getenv("JESS_REC_VERIFY_VAULT_ADDR"), os.Getenv("VAULT_ADDR"))
	if vaultAddr == "" {
		return nil
	}
	mount := env("JESS_REC_VERIFY_VAULT_TRANSIT_MOUNT", "transit")
	key := env("JESS_REC_VERIFY_VAULT_TRANSIT_KEY", "jess-recordings")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	vc, err := buildVaultClientForVerify(ctx, vaultAddr)
	if err != nil {
		log.Printf("jess-controller: recording-verify init: vault client: %v (verify endpoint disabled)", err)
		return nil
	}
	pub, err := vc.TransitPublicKey(ctx, mount, key)
	if err != nil {
		log.Printf("jess-controller: recording-verify init: fetch transit pub key %s/%s: %v (verify endpoint disabled)", mount, key, err)
		return nil
	}
	log.Printf("jess-controller: recording-verify enabled (transit %s/%s, %d-byte ed25519 pub)", mount, key, len(pub))
	return &bundleVerifier{store: store, pub: pub}
}

func buildVaultClientForVerify(_ context.Context, addr string) (*vaultx.Client, error) {
	token := firstNonEmpty(os.Getenv("JESS_REC_VERIFY_VAULT_TOKEN"), os.Getenv("VAULT_TOKEN"))
	if path := os.Getenv("JESS_REC_VERIFY_VAULT_TOKEN_FILE"); path != "" && token == "" {
		if b, err := os.ReadFile(path); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	if token != "" {
		return vaultx.New(vaultx.Config{Addr: addr, Token: token})
	}
	// k8s-SA auth fallback. Same vaultx.New entry-point — internally
	// performs the projected-SA-token login during construction so
	// misconfiguration surfaces at controller startup, not on first
	// verify.
	return vaultx.New(vaultx.Config{
		Addr:     addr,
		K8sMount: env("JESS_REC_VERIFY_VAULT_K8S_AUTH_MOUNT", "kubernetes"),
		K8sRole:  env("JESS_REC_VERIFY_VAULT_K8S_ROLE", "jess-recordings"),
	})
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
