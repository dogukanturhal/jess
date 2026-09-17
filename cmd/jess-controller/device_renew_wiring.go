// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// device_renew_wiring.go — constructs the device-cert RENEW handler (ADR
// 0048) and is mounted on a dedicated plain-HTTP listener (Envoy terminates
// the device-cert mTLS and forwards XFCC; Linkerd secures the Envoy→jess
// hop). This is SEPARATE from the Talon-fronted mTLS admin port that hosts
// /device-cert/attest — renewal is machine-to-machine, auth'd purely by the
// current valid device cert, so it must not sit behind the human IAP.

import (
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"github.com/dogukanturhal/jess/internal/devicecert"
	"github.com/dogukanturhal/jess/internal/devicepolicy"
)

// buildDeviceRenewHandler constructs the DeviceRenewHandler when
// JESS_DEVICE_RENEW_ENABLED=true, returning (handler, true). Returns
// (nil, false) when disabled so the caller skips the renew listener.
//
// Fatal conditions when enabled (fail loudly so the Deployment is fixed
// before any renewal reaches the handler):
//   - JESS_DEVICE_CA_PATH unreadable / no parseable cert (can't verify the
//     presented device cert against jess-device-ca).
//   - Vault device-sign client cannot be constructed.
func buildDeviceRenewHandler(next http.Handler) (http.Handler, bool) {
	if os.Getenv("JESS_DEVICE_RENEW_ENABLED") != "true" {
		return nil, false
	}

	// jess-device-ca trust anchor — the SAME bundle posture-signer mounts
	// (trust-manager Bundle `posture-signer-device-ca`, key ca.crt). Used
	// to validate the device cert the agent presents (via XFCC) for renewal.
	caPath := env("JESS_DEVICE_CA_PATH", "/etc/jess/device-ca/ca.crt")
	pool, err := loadCertPool(caPath)
	if err != nil {
		log.Fatalf("jess-controller: device-renew CA pool from %q: %v", caPath, err)
	}
	verifier, err := devicecert.NewVerifier(pool)
	if err != nil {
		log.Fatalf("jess-controller: device-renew verifier: %v", err)
	}

	// Same minimal-scope jess-device-controller role used by attest signing
	// (jess-device-pki → jess-device-ca/sign/device-cert only).
	vc, err := newDeviceAttestVaultClient()
	if err != nil {
		log.Fatalf("jess-controller: device-renew Vault client: %v", err)
	}

	// Optional revocation gate (ADR 0048 hardening). When
	// JESS_DEVICE_RENEW_REVOCATION_CHECK=true, look each device up in
	// Falcon-ID by UUID before re-minting and fail-closed on a revoked /
	// no-longer-enrolled device. Default OFF: the check is a behaviour
	// change on the live renew path, so it is rolled out explicitly once the
	// Falcon-ID by-uuid endpoint is deployed. Reuses the same Falcon-ID
	// internal URL + s2s token source as the attest wiring.
	var lookup deviceLookup
	if os.Getenv("JESS_DEVICE_RENEW_REVOCATION_CHECK") == "true" {
		falconURL := os.Getenv("JESS_FALCON_ID_INTERNAL_URL")
		if falconURL == "" {
			log.Fatal("jess-controller: JESS_DEVICE_RENEW_REVOCATION_CHECK=true requires JESS_FALCON_ID_INTERNAL_URL")
		}
		lookup = devicepolicy.NewFalconIDEnrollmentStoreWithSource(falconURL, falconIDS2STokenSource())
		log.Printf("jess-controller: device-cert renewal REVOCATION CHECK enabled (falcon-id=%s)", falconURL)
	}

	log.Printf("jess-controller: device-cert RENEW handler ENABLED (ca=%s)", caPath)
	return NewDeviceRenewHandler(next, verifier, vc, lookup), true
}

// loadCertPool reads a PEM file and returns a pool containing its certs.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errNoCertInPEM
	}
	return pool, nil
}

var errNoCertInPEM = &renewConfigError{"no PEM certificate found in device-CA file"}

type renewConfigError struct{ msg string }

func (e *renewConfigError) Error() string { return e.msg }
