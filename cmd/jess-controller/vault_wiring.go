// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Vault client wiring for the jess-controller. Currently the ONLY thing
// the controller needs Vault for is signing operator client certs via
// the jess-ca PKI mount (PKI Phase 2 of the operator-cert auto-mint
// migration). The worker has its own, much wider, Vault wiring in
// cmd/jess-worker/vault_wiring.go — keeping the two split limits the
// controller's blast radius if its Vault token is ever exfiltrated.

import (
	"fmt"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// newControllerVaultClient builds the Vault client for the controller's
// PKI signer. Env config:
//
//	JESS_VAULT_ADDR        e.g. http://vault-ha.vault.svc.cluster.local:8200
//	JESS_VAULT_TOKEN       static token (dev only); preferred = k8s auth
//	JESS_VAULT_K8S_MOUNT   default "kubernetes"
//	JESS_VAULT_K8S_ROLE    e.g. "jess-controller" (declared in iac vault-jess-ca-pki.tf)
//
// Either JESS_VAULT_TOKEN OR JESS_VAULT_K8S_ROLE must be set (vaultx
// requires one). Production uses K8s auth; dev/tests can use a static
// token.
func newControllerVaultClient() (*vaultx.Client, error) {
	addr := env("JESS_VAULT_ADDR", "")
	if addr == "" {
		return nil, fmt.Errorf("JESS_VAULT_ADDR required for Vault PKI signer")
	}
	return vaultx.New(vaultx.Config{
		Addr:     addr,
		Token:    env("JESS_VAULT_TOKEN", ""),
		K8sMount: env("JESS_VAULT_K8S_MOUNT", "kubernetes"),
		K8sRole:  env("JESS_VAULT_K8S_ROLE", ""),
	})
}

// newDeviceAttestVaultClient builds the Vault client used to sign DEVICE
// certs against the jess-device-ca PKI mount. It logs in under a SEPARATE,
// minimal-scope k8s auth role (`jess-device-controller`, policy
// jess-device-pki → only jess-device-ca/sign/device-cert) rather than the
// operator-cert role (`jess-controller`, policy jess-controller-pki).
//
// Why a distinct role (not widening jess-controller-pki): ADR 0043 Phase 3
// least-privilege — a leak of the operator-cert token must not be able to
// mint device certs and vice-versa. The role + policy are provisioned in
// iac vault-jess-device-ca-pki.tf; this mirrors the recording-verifier's
// own-role pattern (JESS_REC_VERIFY_VAULT_K8S_ROLE). Both roles share the
// jess/jess ServiceAccount, so only the role name differs.
func newDeviceAttestVaultClient() (*vaultx.Client, error) {
	addr := env("JESS_VAULT_ADDR", "")
	if addr == "" {
		return nil, fmt.Errorf("JESS_VAULT_ADDR required for device-cert Vault PKI signer")
	}
	return vaultx.New(vaultx.Config{
		Addr:     addr,
		Token:    env("JESS_VAULT_TOKEN", ""),
		K8sMount: env("JESS_VAULT_K8S_MOUNT", "kubernetes"),
		K8sRole:  env("JESS_DEVICE_VAULT_K8S_ROLE", "jess-device-controller"),
	})
}
