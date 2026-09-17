// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest — tpm2_windows.go
//
// TPM 2.0 Windows quote verifier (server-side).
//
// References:
//   - TCG EK Credential Profile v2.5 §3.2 — EK certificate profile
//     https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p5_r2_pub.pdf
//   - Microsoft TPM Root CA 2014 / 2018 — Pluton and firmware TPMs (MSFT manufacturer)
//     https://www.microsoft.com/pki/certs/MicrosoftTPMRootCA2014.crt
//     https://www.microsoft.com/pki/certs/MicrosoftTPMRootCA2018.crt
//   - go-attestation AKPublic.Verify — nonce-bound quote verification
//     https://pkg.go.dev/github.com/google/go-attestation/attest#AKPublic.Verify
//   - ADR 0043 §3.c.1 — platform verifier layout
//
// Microsoft Pluton note
// =====================
// AMD Ryzen Pro + Pluton SKUs report MANUFACTURER=MSFT (not AMD). Their EK
// certificate chains to Microsoft TPM Root CA 2014 or 2018, both publicly
// available at the URLs above. The vendorRoots pool MUST contain at least
// one of these roots for Pluton devices to pass Path A verification.
//
// Unlike tpm2-linux, Windows TPM attestation goes through the Platform
// Crypto Provider (PCP) which wraps the TPM operations. The on-device
// posture-agent (hexxlock-access, Windows build) produces:
//
//   - AKPublicBlob  — TPMT_PUBLIC bytes from AttestationParameters.Public
//   - QuoteBlob     — TPMS_ATTEST bytes from TPM2_Quote
//   - QuoteSigBlob  — TPMT_SIGNATURE bytes from TPM2_Quote
//   - NonceClient   — controller-issued freshness nonce
//
// The server-side verification flow is identical to tpm2_linux.go; the
// only difference is:
//  1. The vendor root pool should include MS TPM Root CA 2014/2018.
//  2. The Platform string is "tpm2-windows".
//  3. Payload type is TPM2WindowsQuotePayload (structurally identical to
//     TPM2LinuxQuotePayload; separate type for future divergence).
//
// Platform string: "tpm2-windows"

package deviceattest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-attestation/attest"
)

// TPM2WindowsQuotePayload is the JSON structure the posture-agent on Windows
// marshals into VerifyRequest.PlatformBlob. Fields are structurally identical
// to TPM2LinuxQuotePayload; the separate type allows future Windows-specific
// fields (e.g., PCPKeyName for Windows PCP key name) without breaking Linux.
type TPM2WindowsQuotePayload struct {
	// AKPublicBlob is the TPMT_PUBLIC-encoded bytes of the Attestation Key.
	AKPublicBlob []byte `json:"ak_public"`

	// QuoteBlob is the TPMS_ATTEST structure from TPM2_Quote.
	QuoteBlob []byte `json:"quote"`

	// QuoteSigBlob is the TPMT_SIGNATURE from TPM2_Quote.
	QuoteSigBlob []byte `json:"quote_sig"`

	// PCPKeyName is the Windows Platform Crypto Provider key name used to
	// identify the AK in the Windows TPM key storage provider. Optional;
	// included for audit logging only — the server does not call the PCP API.
	PCPKeyName string `json:"pcp_key_name,omitempty"`
}

// tpm2WindowsVerifier implements Verifier for Platform="tpm2-windows".
//
// Trust ceiling: TIER_CORP (same as tpm2-linux with EK chain).
//
// For Microsoft Pluton (MANUFACTURER=MSFT), the vendorRoots pool MUST contain
// the Microsoft TPM Root CA 2014 and/or 2018 PEM-encoded certificates.
type tpm2WindowsVerifier struct {
	chain Verifier // wraps chainVerifier for EK certificate validation
	now   func() time.Time
}

// TPM2WindowsOption configures a tpm2WindowsVerifier.
type TPM2WindowsOption func(*tpm2WindowsVerifier)

// WithTPM2WindowsClock replaces the real-time clock. Used in tests.
func WithTPM2WindowsClock(fn func() time.Time) TPM2WindowsOption {
	return func(v *tpm2WindowsVerifier) { v.now = fn }
}

// NewTPM2WindowsVerifier constructs a production TPM 2.0 Windows verifier.
//
// vendorRoots MUST NOT be nil. For Microsoft Pluton support, include
// the Microsoft TPM Root CA 2014 and 2018 certificates in the pool:
//
//	pool := x509.NewCertPool()
//	pool.AppendCertsFromPEM(mstpmRootCA2014PEM)
//	pool.AppendCertsFromPEM(mstpmRootCA2018PEM)
//	v := NewTPM2WindowsVerifier(pool)
//
// Register the returned verifier with:
//
//	registry.Register("tpm2-windows", NewTPM2WindowsVerifier(pool))
func NewTPM2WindowsVerifier(vendorRoots *x509.CertPool, opts ...TPM2WindowsOption) Verifier {
	if vendorRoots == nil {
		panic("deviceattest: NewTPM2WindowsVerifier: vendorRoots must not be nil")
	}
	v := &tpm2WindowsVerifier{
		chain: NewChainVerifier("tpm2-windows", vendorRoots),
		now:   time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	// Rebuild the embedded chain verifier with the (possibly injected) clock.
	if v.now != nil {
		v.chain = NewChainVerifier("tpm2-windows", vendorRoots, WithChainClock(v.now))
	}
	return v
}

// Verify implements Verifier for Platform="tpm2-windows".
//
// Flow:
//  1. Guard: PlatformBlob must be present and parseable as TPM2WindowsQuotePayload.
//  2. Parse the AK public key via attest.ParseAKPublic.
//  3. Verify the AK quote signature + nonce binding via AKPublic.Verify.
//  4. Delegate EK chain verification to the embedded chainVerifier.
//  5. Return TIER_CORP with reasons: "tpm2_windows_quote_verified" +
//     "ek_chain_verified" + issuer label from the chain verifier.
func (v *tpm2WindowsVerifier) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: platform blob required.
	if len(req.PlatformBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: tpm2-windows verifier requires PlatformBlob (TPM2WindowsQuotePayload JSON)",
			ErrVerification,
		)
	}

	// Guard 2: nonce required.
	if len(req.NonceClient) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: tpm2-windows verifier requires NonceClient for quote freshness binding",
			ErrVerification,
		)
	}

	// Parse the platform-specific payload.
	var payload TPM2WindowsQuotePayload
	if err := json.Unmarshal(req.PlatformBlob, &payload); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: tpm2-windows PlatformBlob is not valid TPM2WindowsQuotePayload JSON: %v",
			ErrVerification, err,
		)
	}
	if len(payload.AKPublicBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf("%w: tpm2-windows: AKPublicBlob is empty in PlatformBlob", ErrVerification)
	}
	if len(payload.QuoteBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf("%w: tpm2-windows: QuoteBlob is empty in PlatformBlob", ErrVerification)
	}
	if len(payload.QuoteSigBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf("%w: tpm2-windows: QuoteSigBlob is empty in PlatformBlob", ErrVerification)
	}

	// Parse the AK public key.
	akPublic, err := attest.ParseAKPublic(payload.AKPublicBlob)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: tpm2-windows: AK public key parse failed: %v",
			ErrVerification, err,
		)
	}

	// Construct and verify the quote.
	quote := attest.Quote{
		Quote:     payload.QuoteBlob,
		Signature: payload.QuoteSigBlob,
	}
	if err := akPublic.Verify(quote, nil, req.NonceClient); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: tpm2-windows: AK quote verification failed (tampered quote or nonce mismatch): %v",
			ErrVerification, err,
		)
	}

	// Delegate EK chain verification.
	chainResp, err := v.chain.Verify(ctx, req)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: tpm2-windows: EK chain verification failed: %v",
			ErrVerification, err,
		)
	}

	reasons := make([]string, 0, 1+len(chainResp.Reasons))
	reasons = append(reasons, "tpm2_windows_quote_verified")
	if payload.PCPKeyName != "" {
		reasons = append(reasons, "pcp_key_"+sanitizeLabel(payload.PCPKeyName))
	}
	reasons = append(reasons, chainResp.Reasons...)

	return VerifyResponse{
		Path:    "A_chain",
		Tier:    "TIER_CORP",
		Reasons: reasons,
	}, nil
}
