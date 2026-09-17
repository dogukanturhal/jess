// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// device_attest_wiring.go — builds the deviceattest.Registry from env config
// and wires NewDeviceCertAttestHandler into the admin handler chain.
//
// Env vars (all JESS_DEVICE_ATTEST_* or JESS_FALCONID_*):
//
//	JESS_DEVICE_ATTEST_ENABLED          bool, default false
//	    Explicit gate.  When false the handler is NOT mounted; POST
//	    /device-cert/attest returns 404.  Safe default for a cluster that
//	    has not yet provisioned the jess-device-ca Vault PKI mount.
//
//	JESS_FALCONID_ISSUER                string, default "https://id.hexxlock.com"
//	    Expected iss claim in every enrollment witness JWS.  Must match
//	    the issuer used by Falcon-ID when it mints the witness JWS.
//
//	JESS_FALCONID_JWKS_URL              string, default "<issuer>/.well-known/jwks.json"
//	    Full HTTPS URL of Falcon-ID's JWKS endpoint.  Defaults to the
//	    standard OIDC JWKS path under JESS_FALCONID_ISSUER.
//	    Override only in non-standard deployments.
//
//	JESS_DEVICE_VENDOR_ROOTS_PEM        string, default "" (Path A disabled)
//	    Filesystem path inside the running container to a PEM bundle of
//	    TPM vendor root CAs (Infineon, STMicro, Nuvoton, Intel PTT, MS
//	    Pluton).  When empty, Path A chain verification is disabled for all
//	    platforms; Path B TOFU remains active.  Logs a warning at startup
//	    so the operator is aware.
//
// When JESS_DEVICE_ATTEST_ENABLED=true but required dependencies
// (JESS_FALCON_ID_INTERNAL_URL, JESS_FALCON_ID_S2S_TOKEN, Vault client) are
// not configured, buildDeviceAttestHandler logs a fatal message naming the
// missing var and refuses to start.  No silent degradation.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dogukanturhal/jess/internal/caep"
	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/devicepolicy"
	"github.com/dogukanturhal/jess/internal/falconid"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// supportedPlatforms is the list of platform names for which TOFU (Path B)
// verifiers are registered.  Path A (chain) is also registered for each when
// JESS_DEVICE_VENDOR_ROOTS_PEM is provided.
var supportedPlatforms = []string{
	"tpm2-linux",
	"tpm2-windows",
	"tpm2-macos",
	"software-bootstrap",
}

// buildDeviceAttestHandler constructs the DeviceCertAttestHandler when
// JESS_DEVICE_ATTEST_ENABLED=true and returns (handler, true).  Returns
// (nil, false) when the feature is disabled — callers skip mounting the
// handler entirely.
//
// Fatal conditions when enabled:
//   - JESS_FALCON_ID_INTERNAL_URL empty (enrollment store has no base URL)
//   - neither JESS_FALCON_ID_S2S_TOKEN_FILE nor JESS_FALCON_ID_S2S_TOKEN set
//     (enrollment store unauthenticated)
//   - Vault client cannot be constructed (JESS_VAULT_ADDR missing)
func buildDeviceAttestHandler(
	next http.Handler,
	verifier pdp.TokenVerifier,
	pending deviceattest.PendingObserver,
) (http.Handler, bool) {
	if os.Getenv("JESS_DEVICE_ATTEST_ENABLED") != "true" {
		return nil, false
	}

	// JESS_FALCONID_ISSUER — iss claim expected in witness JWSes.
	// JESS_FALCONID_JWKS_URL — where to fetch the OIDC signing key.
	issuer := env("JESS_FALCONID_ISSUER", "https://id.hexxlock.com")
	jwksURL := env("JESS_FALCONID_JWKS_URL", issuer+"/.well-known/jwks.json")

	// JESS_FALCON_ID_INTERNAL_URL + a Falcon-ID s2s token source — the
	// FalconIDEnrollmentStore requires both to be set when the feature is
	// enabled.  Fail loudly so the operator fixes the Deployment manifest
	// before any enrollment attempt reaches the handler.
	falconURL := os.Getenv("JESS_FALCON_ID_INTERNAL_URL")
	if falconURL == "" {
		log.Fatal("jess-controller: JESS_DEVICE_ATTEST_ENABLED=true requires JESS_FALCON_ID_INTERNAL_URL (Falcon-ID cluster-internal base URL for enrollment store)")
	}
	tokenSrc := falconIDS2STokenSource()

	// Vault client — required for jess-device-ca PKI signing. Uses the
	// minimal-scope jess-device-controller role (jess-device-pki policy),
	// NOT the operator-cert role — sign-only on jess-device-ca/sign/
	// device-cert. (newControllerVaultClient's jess-controller role lacks
	// jess-device-pki → 403 permission denied at mint time.)
	vc, err := newDeviceAttestVaultClient()
	if err != nil {
		log.Fatalf("jess-controller: device-attest Vault client: %v", err)
	}

	// One enrollment store, shared by the TOFU verifiers (prior-enrollment
	// lookup) and the handler's corporate-asset gate (corp-asset allowlist).
	enrollmentStore := devicepolicy.NewFalconIDEnrollmentStoreWithSource(falconURL, tokenSrc)

	reg := buildDeviceAttestRegistry(issuer, jwksURL, enrollmentStore)

	// JESS_CORP_ASSET_GATE selects the corporate-asset gate posture:
	//   "audit"   (default) — log would-be downgrades, keep CORP (soak window)
	//   "enforce"           — downgrade non-corporate-asset CORP devices to BYOD
	// Default audit so a first deploy never mass-downgrades a fleet whose EK
	// hashes are not pre-registered yet; flip to enforce after the soak confirms
	// the allowlist is populated.
	corpAssetMode := env("JESS_CORP_ASSET_GATE", "audit")
	enforce := corpAssetMode == "enforce"

	handler := NewDeviceCertAttestHandler(next, verifier, reg, vc).
		WithCorpAssetChecker(enrollmentStore, enforce).
		WithPendingObserver(pending)
	log.Printf("jess-controller: device-cert attestation handler ENABLED (issuer=%s jwks=%s platforms=%v corp_asset_gate=%s)",
		issuer, jwksURL, reg.Enabled(), corpAssetMode)
	return handler, true
}

// falconIDS2STokenSource builds the Bearer-token source for Falcon-ID s2s
// calls, preferring the live file written by the svctoken-refresher native-
// sidecar (JESS_FALCON_ID_S2S_TOKEN_FILE) so the ~hourly client_credentials
// rotation propagates without a pod restart — the canonical platform pattern
// shared with gitlab-bcl-receiver, argocd-repo-server and the CAEP
// subscriber. Falls back to the legacy read-once env token
// JESS_FALCON_ID_S2S_TOKEN for backward compatibility. Fatal when neither is
// set so misconfiguration surfaces at startup, never at the first enrollment
// request.
//
// Reading the token from the shared tmpfs file (rather than a secretKeyRef
// env) is what breaks the Reloader feedback loop: with no token Secret in the
// pod template, reloader.stakater.com/auto no longer bounces the pod on every
// token mint.
func falconIDS2STokenSource() devicepolicy.TokenSource {
	if path := os.Getenv("JESS_FALCON_ID_S2S_TOKEN_FILE"); path != "" {
		log.Printf("jess-controller: Falcon-ID s2s token sourced from file %s (live rotation, no restart)", path)
		return caep.FileTokenSource{Path: path}
	}
	if tok := os.Getenv("JESS_FALCON_ID_S2S_TOKEN"); tok != "" {
		log.Print("jess-controller: Falcon-ID s2s token sourced from read-once env JESS_FALCON_ID_S2S_TOKEN — prefer JESS_FALCON_ID_S2S_TOKEN_FILE for restart-free rotation")
		return caep.StaticTokenSource{Tok: tok}
	}
	log.Fatal("jess-controller: JESS_DEVICE_ATTEST_ENABLED=true requires JESS_FALCON_ID_S2S_TOKEN_FILE (preferred) or JESS_FALCON_ID_S2S_TOKEN (OAuth2 client_credentials token for Falcon-ID enrollment store)")
	return nil // unreachable: log.Fatal exits
}

// buildDeviceAttestRegistry constructs the deviceattest.Registry, registering
// a Path B TOFU verifier for each platform in supportedPlatforms, and
// optionally a Path A chain verifier when vendor roots are available.
//
// The registry dispatch model:
//   - EKCertPEM absent → tofuVerifier (Path B)
//   - EKCertPEM present → chainVerifier (Path A)
//
// In the current registry we register TOFU verifiers under each platform
// name.  The handler routes EKCertPEM-bearing requests to the chain verifier
// by re-mapping through registryWithPathDispatch (see comment in handler).
//
// TODO(ztna-phase3b): implement a composite Verifier per platform that
// dispatches between chain + TOFU based on req.EKCertPEM, and register
// the composite under each platform name.  For now, we register one
// TOFU verifier per platform (the common case for AMD fTPM fleets) and
// one chain verifier per platform under the "<platform>+chain" key so
// the handler can fall through to chain on EKCertPEM presence.
func buildDeviceAttestRegistry(issuer, jwksURL string, enrollmentStore *devicepolicy.FalconIDEnrollmentStore) *deviceattest.Registry {
	keyStore := falconid.NewFalconIDOperatorPublicKeyStore(jwksURL)
	witnessVerifier := devicepolicy.NewWebAuthnWitnessVerifier(issuer, keyStore)

	reg := deviceattest.NewRegistry()

	// Path B TOFU verifiers — one per platform, share the same store +
	// witness verifier (they are all thread-safe and hold no platform-
	// specific state).
	for _, platform := range supportedPlatforms {
		p := platform // capture for closure
		reg.Register(p, deviceattest.NewTOFUVerifier(p, enrollmentStore, witnessVerifier))
	}

	// Path A chain verifiers — only wired when vendor roots PEM is available.
	// JESS_DEVICE_VENDOR_ROOTS_PEM is the filesystem path (injected via
	// ConfigMap/Secret volume in the Deployment manifest).
	rootsPath := os.Getenv("JESS_DEVICE_VENDOR_ROOTS_PEM")
	if rootsPath == "" {
		log.Print("jess-controller: JESS_DEVICE_VENDOR_ROOTS_PEM unset — Path A (chain) verification disabled; only Path B (TOFU) active")
	} else {
		vendorRoots, err := loadVendorRootsPEM(rootsPath)
		if err != nil {
			log.Fatalf("jess-controller: load vendor roots PEM %s: %v", rootsPath, err)
		}
		// Register chain verifiers under the "<platform>+chain" key so the
		// handler can look up the correct verifier when EKCertPEM is present.
		for _, platform := range supportedPlatforms {
			p := platform
			reg.Register(p+"+chain", deviceattest.NewChainVerifier(p, vendorRoots))
		}
		log.Printf("jess-controller: Path A (chain) verification enabled for platforms=%v (roots=%s)", supportedPlatforms, rootsPath)
	}

	return reg
}

// loadVendorRootsPEM parses a PEM bundle file and returns an x509.CertPool
// containing every CERTIFICATE block found.  Returns an error if the file
// cannot be read or contains no valid certificate blocks.
func loadVendorRootsPEM(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	pool := x509.NewCertPool()
	rest := raw
	added := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate block: %w", err)
		}
		pool.AddCert(cert)
		added++
	}
	if added == 0 {
		return nil, fmt.Errorf("no valid CERTIFICATE blocks found in %s", path)
	}
	log.Printf("jess-controller: loaded %d vendor root CA(s) from %s", added, path)
	return pool, nil
}
