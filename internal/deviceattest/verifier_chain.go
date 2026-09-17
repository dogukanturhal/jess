// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"context"

	"github.com/google/go-attestation/attest"
)

// chainVerifier implements Verifier for Path A: EK cert chain verification
// against a pool of pinned manufacturer root CAs. Used for:
//   - Discrete TPMs (Infineon, Nuvoton, STMicro, NationZ)
//   - Intel PTT (firmware TPM with On-Die CA)
//   - AMD Ryzen Pro + Pluton (MANUFACTURER=MSFT, chains to MS Root CA 2014)
//
// Trust model: the EK certificate is signed by the TPM vendor's CA;
// verifying the chain to a pinned root proves the key resides in genuine
// vendor-manufactured hardware. This justifies TIER_CORP eligibility.
//
// Fail-closed posture: any chain error (expired cert, wrong CA, self-signed,
// key usage violation) returns ErrVerification with a specific diagnostic
// reason. There is no "soft" path A — callers wanting a softer landing
// should route to Path B after a chain failure.
type chainVerifier struct {
	vendorRoots *x509.CertPool
	platform    string
	now         func() time.Time
}

// ChainOption configures a chainVerifier.
type ChainOption func(*chainVerifier)

// WithChainClock replaces the real-time clock with fn. Used in tests
// to simulate expired or future certificates without real clock manipulation.
func WithChainClock(fn func() time.Time) ChainOption {
	return func(v *chainVerifier) { v.now = fn }
}

// NewChainVerifier constructs a production Path A verifier.
//
// platform must be one of the recognized platform strings (e.g.
// "tpm2-linux", "tpm2-windows"). vendorRoots MUST NOT be nil or empty —
// without pinned roots the verifier cannot establish manufacturer trust.
// Nil vendorRoots panics immediately so the bug surfaces at controller
// startup, not at request time.
func NewChainVerifier(platform string, vendorRoots *x509.CertPool, opts ...ChainOption) Verifier {
	if vendorRoots == nil {
		panic("deviceattest: NewChainVerifier: vendorRoots must not be nil")
	}
	v := &chainVerifier{
		vendorRoots: vendorRoots,
		platform:    platform,
		now:         time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements Verifier for Path A.
//
// Flow:
//  1. Guard: reject if EKCertPEM is empty (Path A requires the certificate).
//  2. Anti-spoof: reject Path A entirely if RequiresTOFU(manufacturer, kind)
//     is true. This closes the downgrade vector where a client claims an
//     EK-cert-bearing platform (e.g. Intel discrete) but the manufacturer+kind
//     combination is one that we KNOW does not factory-ship an EK cert
//     (AMD consumer fTPM). A forged/stolen EK cert for an AMD device must
//     not buy TIER_CORP just because the controller wired chainVerifier
//     for the platform name.
//  3. Decode PEM → DER.
//  4. Parse DER via attest.ParseEKCertificate (handles TCG-specific extensions
//     that standard x509.ParseCertificate may reject on strict EK certs).
//  5. Verify the cert chain against the injected vendor root pool using
//     x509.Certificate.Verify with the controller's current time.
//  6. Validate EK key usage: x509.KeyUsageKeyEncipherment or
//     x509.KeyUsageDataEncipherment must be set (TCG EK profile §3.2.7).
//  7. Return TIER_CORP on success.
func (v *chainVerifier) Verify(_ context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: Path A requires the EK certificate.
	if len(req.EKCertPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: Path A (chain) verifier requires EKCertPEM; "+
				"use tofuVerifier (Path B) when EK certificate is absent",
			ErrVerification,
		)
	}

	// Guard 2 (anti-spoof): manufacturer+kind matrix overrides cert
	// presence. RequiresTOFU encodes the operator-locked fact "this
	// hardware family does not factory-ship an EK cert chain we trust"
	// — usually AMD consumer fTPM (per internal engineering notes
	// path_b_2026_06_06). A client cannot bypass that ceiling by
	// presenting any cert, however well-signed. Force Path B routing
	// at the verifier layer so the safety holds independent of how
	// the controller's Registry happens to be wired.
	if RequiresTOFU(req.Manufacturer, req.Kind) {
		return VerifyResponse{}, fmt.Errorf(
			"%w: chain verifier refused: (manufacturer=%q, kind=%q) requires TOFU "+
				"(per ZTNA tier matrix). Controller MUST dispatch this request "+
				"to tofuVerifier even if an EKCertPEM is presented",
			ErrVerification, req.Manufacturer, req.Kind,
		)
	}

	// Guard 3: EK public key must also be present for audit logging.
	if len(req.EKPubKeyPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf("%w: EKPubKeyPEM is required alongside EKCertPEM for audit", ErrVerification)
	}

	// Decode PEM.
	block, rest := pem.Decode(req.EKCertPEM)
	if block == nil {
		return VerifyResponse{}, fmt.Errorf("%w: EKCertPEM is not valid PEM", ErrVerification)
	}
	if len(rest) > 0 {
		if extra, _ := pem.Decode(rest); extra != nil {
			return VerifyResponse{}, fmt.Errorf(
				"%w: EKCertPEM contains multiple PEM blocks; "+
					"expected exactly one EK certificate (no intermediate bundling)",
				ErrVerification,
			)
		}
	}
	if block.Type != "CERTIFICATE" {
		return VerifyResponse{}, fmt.Errorf(
			"%w: EKCertPEM block type %q is not CERTIFICATE",
			ErrVerification, block.Type,
		)
	}

	// Parse the DER certificate via go-attestation's ParseEKCertificate,
	// which handles the TCG-specific Subject Alternative Name (OID
	// 2.23.133.8.1 — TPM EK SAN) that standard x509.ParseCertificate
	// may reject under Go's strict extension handling.
	cert, err := attest.ParseEKCertificate(block.Bytes)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: EK certificate parse failed: %v",
			ErrVerification, err,
		)
	}

	// Verify chain against pinned vendor roots.
	// x509.VerifyOptions.CurrentTime uses v.now() so tests can inject
	// arbitrary times without OS clock manipulation.
	opts := x509.VerifyOptions{
		Roots:       v.vendorRoots,
		CurrentTime: v.now(),
		// KeyUsages: we check separately below so we get a specific error
		// message rather than the generic "certificate specifies an
		// incompatible key usage" from the verify path.
	}
	if _, err := cert.Verify(opts); err != nil {
		// Map common x509 errors to specific diagnostic reasons for the
		// audit row. The unwrapped error message is preserved in the
		// returned error for debugging; the Reason is what Grafana sees.
		reason := classifyChainError(err)
		return VerifyResponse{}, fmt.Errorf(
			"%w: EK cert chain verification failed (%s): %v",
			ErrVerification, reason, err,
		)
	}

	// Validate EK key usage per TCG EK Credential Profile v2.5 §3.2.7:
	// the EK certificate MUST assert KeyEncipherment or DataEncipherment.
	// A cert missing both would still verify against the root but is not
	// a valid EK cert — reject it to prevent non-EK vendor certs being
	// used to claim Path A.
	const ekKeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	if cert.KeyUsage&ekKeyUsage == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: EK certificate does not assert KeyEncipherment or DataEncipherment "+
				"(TCG EK Credential Profile v2.5 §3.2.7); KeyUsage=0x%x",
			ErrVerification, cert.KeyUsage,
		)
	}

	return VerifyResponse{
		Path: "A_chain",
		Tier: "TIER_CORP",
		Reasons: []string{
			"ek_chain_verified",
			"issuer_" + sanitizeLabel(cert.Issuer.CommonName),
		},
	}, nil
}

// classifyChainError maps x509 verification errors to stable diagnostic
// labels suitable for Prometheus label values and audit rows. The labels
// are lowercase_underscore to avoid cardinality issues.
func classifyChainError(err error) string {
	msg := err.Error()
	switch {
	case containsAny(msg, "certificate has expired", "certificate is not yet valid", "x509: certificate has expired"):
		return "cert_expired"
	case containsAny(msg, "certificate signed by unknown authority"):
		return "unknown_ca"
	case containsAny(msg, "certificate is not authorized to sign other certificates"):
		return "invalid_ca_constraint"
	case containsAny(msg, "cannot validate certificate"):
		return "chain_validation_error"
	default:
		return "chain_error"
	}
}

// sanitizeLabel converts an arbitrary string to a Prometheus-label-safe
// value: lowercase, non-alphanumeric runs replaced with underscore,
// leading/trailing underscores stripped.
func sanitizeLabel(s string) string {
	if s == "" {
		return "unknown"
	}
	out := make([]byte, 0, len(s))
	prevUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
			prevUnderscore = false
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c+32) // toLower
			prevUnderscore = false
		} else {
			if !prevUnderscore && len(out) > 0 {
				out = append(out, '_')
			}
			prevUnderscore = true
		}
	}
	// Strip trailing underscore.
	if len(out) > 0 && out[len(out)-1] == '_' {
		out = out[:len(out)-1]
	}
	return string(out)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
