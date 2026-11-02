// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// device_renew_handler.go — POST /device-cert/renew (ADR 0048).
//
// Silent, daemon-driven device-cert renewal. Unlike /device-cert/attest
// (Talon-fronted, OIDC Bearer + WebAuthn witness, first issuance), renewal
// is authenticated SOLELY by the device's CURRENT valid cert presented over
// Envoy device-cert mTLS and forwarded as XFCC — the SPIFFE/SVID rotation
// pattern. The posture-agent calls this at 50% TTL with its existing CSR; a
// fresh 24h cert is minted for the same device_uuid/user_sub. No re-attest,
// no human in the loop.
//
// Wire shape:
//
//	POST /device-cert/renew                (Envoy mTLS → XFCC; Linkerd mTLS hop)
//	Content-Type: application/json
//	{ "csr_pem": "<base64-of-PEM PKCS#10 CSR>" }
//
//	200 { "device_cert_pem", "serial_number", "expires_at" }
//	400 malformed body / bad CSR
//	401 no/invalid device cert (chain/EKU)
//	403 cert expired or SPIFFE SAN missing → client must re-ENROLL, not renew
//	502 Vault PKI sign failure (transient)

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/devicecert"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// deviceLookup reads a device's enrollment record by its SPIFFE-SAN UUID.
// The renewal gate (ADR 0048 hardening) uses it to refuse renewal of a
// revoked — or no-longer-enrolled — device. *devicepolicy.FalconIDEnrollmentStore
// satisfies this. A nil lookup disables the revocation check.
type deviceLookup interface {
	GetByUUID(ctx context.Context, deviceUUID string) (deviceattest.EnrolledDevice, error)
}

// DeviceRenewHandler implements POST /device-cert/renew; other requests
// forward to next.
type DeviceRenewHandler struct {
	next        http.Handler
	verifier    *devicecert.Verifier
	vaultClient *vaultx.Client
	// lookup is the optional revocation gate. nil = check disabled (the
	// renew path is then authenticated solely by the current device cert).
	lookup deviceLookup

	// browser-cert issuance (POST /device-cert/browser).
	// otpMaxAge caps how long after enrollment a device witnessed by the
	// authenticator-app OTP fallback may keep renewing (JESS_OTP_WITNESS_MAX_AGE).
	// Needs lookup; zero disables the cap.
	otpMaxAge time.Duration
	now       func() time.Time

	browserRole string // Vault PKI role on the device CA mount
	browserRL   *issueLimiter
}

// NewDeviceRenewHandler constructs the renewal handler. verifier + vaultClient
// are required; lookup is optional (nil disables the revocation check).
func NewDeviceRenewHandler(next http.Handler, v *devicecert.Verifier, vc *vaultx.Client, lookup deviceLookup) *DeviceRenewHandler {
	if v == nil {
		panic("device_renew_handler: verifier must not be nil")
	}
	if vc == nil {
		panic("device_renew_handler: vaultClient must not be nil")
	}
	return &DeviceRenewHandler{
		next: next, verifier: v, vaultClient: vc, lookup: lookup,
		otpMaxAge: defaultOTPWitnessMaxAge, now: time.Now,
		browserRole: env("JESS_BROWSER_CERT_VAULT_ROLE", browserCertVaultRole),
		browserRL:   newIssueLimiter(browserCertRateLimit, time.Hour),
	}
}

// defaultOTPWitnessMaxAge is the default JESS_OTP_WITNESS_MAX_AGE.
const defaultOTPWitnessMaxAge = 720 * time.Hour

// RenewRequest is the JSON body. csr_pem is base64-of-PEM (Go marshals
// []byte as base64), matching the agent's rotation::RenewRequest.
type RenewRequest struct {
	CSRPEM []byte `json:"csr_pem"`
}

// RenewResponse mirrors the attest response's cert fields.
type RenewResponse struct {
	DeviceCertPEM string `json:"device_cert_pem"`
	SerialNumber  string `json:"serial_number"`
	ExpiresAt     string `json:"expires_at"`
}

func (h *DeviceRenewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/device-cert/renew":
			h.handleRenew(w, r)
			return
		case "/device-cert/browser":
			h.handleBrowser(w, r)
			return
		}
	}
	h.next.ServeHTTP(w, r)
}

func (h *DeviceRenewHandler) handleRenew(w http.ResponseWriter, r *http.Request) {
	// Step 1 — authenticate by the CURRENT device cert (XFCC).
	id, err := h.verifier.VerifyRequest(r)
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, devicecert.ErrExpired), errors.Is(err, devicecert.ErrSANMissing):
			// A cert past expiry (or without a device SPIFFE SAN) cannot be
			// renewed — the device must run the full enrollment again. 403
			// so the agent escalates to re-enroll rather than retry-loop.
			status = http.StatusForbidden
		case errors.Is(err, devicecert.ErrXFCCMalformed), errors.Is(err, devicecert.ErrXFCCMissingCrt):
			status = http.StatusBadRequest
		}
		writeRenewError(w, status, err.Error())
		return
	}

	// A browser-kind cert can never renew itself or mint a device cert.
	if id.Browser {
		log.Printf("device_renew_handler: renewal DENIED device=%s — browser-kind cert", id.DeviceUUID)
		writeRenewError(w, http.StatusForbidden, "browser certificates cannot be used to renew")
		return
	}

	// Step 1.5 — revocation gate (ADR 0048 hardening). The current device
	// cert passing mTLS is necessary but not sufficient: a cert that is still
	// within its 24h validity but whose device has been REVOKED must not
	// silently renew. We look the device up by UUID and fail-CLOSED on a
	// definitively revoked or no-longer-enrolled device. A transient lookup
	// error is SOFT-failed (log + proceed): the cert is short-lived and was
	// valid at issuance, so a Falcon-ID blip must not mass-expire the fleet —
	// the agent simply retries next cycle. nil lookup = check disabled.
	if !h.checkEnrolled(r.Context(), w, id.DeviceUUID, "renewal") {
		return
	}

	// Step 2 — decode + validate the CSR (proof-of-possession of the key
	// the new cert will bind to). The CSR's claimed subject/SANs are
	// ignored; identity comes from the verified cert (id).
	var req RenewRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		writeRenewError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", derr))
		return
	}
	if len(req.CSRPEM) == 0 {
		writeRenewError(w, http.StatusBadRequest, "csr_pem is required")
		return
	}
	if verr := validateCSRSelfSigned(req.CSRPEM); verr != nil {
		writeRenewError(w, http.StatusBadRequest, verr.Error())
		return
	}

	// Step 3 — mint a fresh cert for the SAME identity. Same Vault path +
	// SPIFFE uri_sans as first issuance (mintDeviceCert).
	spiffeURI := spiffeURIPrefix + id.DeviceUUID
	signResp, serr := h.vaultClient.SignPKICert(r.Context(), deviceCertVaultMount, deviceCertVaultRole,
		vaultx.PKISignRequest{
			CSRPEM:     string(req.CSRPEM),
			CommonName: id.UserSub,
			TTL:        deviceCertTTL,
			URISans:    []string{spiffeURI},
		})
	if serr != nil {
		log.Printf("device_renew_handler: vault sign failed device=%s: %v", id.DeviceUUID, serr)
		writeRenewError(w, http.StatusBadGateway, fmt.Sprintf("device certificate renewal failed (Vault PKI): %v", serr))
		return
	}

	log.Printf("device_renew_handler: renewed device=%s user=%s serial=%s", id.DeviceUUID, id.UserSub, signResp.SerialNumber)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(RenewResponse{
		DeviceCertPEM: signResp.Certificate,
		SerialNumber:  signResp.SerialNumber,
		ExpiresAt:     signResp.Expiration.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}

// checkEnrolled applies the revocation gate (see Step 1.5 in handleRenew).
// Returns false after writing the 403 when the device is revoked / not
// enrolled; a transient lookup error is soft-failed.
func (h *DeviceRenewHandler) checkEnrolled(ctx context.Context, w http.ResponseWriter, deviceUUID, what string) bool {
	if h.lookup == nil {
		return true
	}
	dev, lerr := h.lookup.GetByUUID(ctx, deviceUUID)
	switch {
	case lerr != nil:
		log.Printf("device_renew_handler: revocation lookup failed device=%s (soft-fail, allowing %s): %v", deviceUUID, what, lerr)
	case dev.DeviceUUID == "":
		log.Printf("device_renew_handler: %s DENIED device=%s — not enrolled (re-enroll required)", what, deviceUUID)
		writeRenewError(w, http.StatusForbidden, "device is not enrolled ("+what+" denied; re-enroll required)")
		return false
	case !dev.DisabledAt.IsZero():
		log.Printf("device_renew_handler: %s DENIED device=%s — revoked at %v (re-enroll required)", what, deviceUUID, dev.DisabledAt)
		writeRenewError(w, http.StatusForbidden, "device has been revoked ("+what+" denied; re-enroll required)")
		return false
	case dev.WitnessMethod == deviceattest.WitnessMethodOTP && h.otpMaxAge > 0 &&
		!dev.EnrolledAt.IsZero() && h.now().Sub(dev.EnrolledAt) > h.otpMaxAge:
		// Authenticator-app witnessed devices are a time-boxed fallback:
		// past the cap the user must re-enroll (ideally with a passkey).
		log.Printf("device_renew_handler: %s DENIED device=%s — OTP-witnessed enrollment older than %s (re-enroll required)", what, deviceUUID, h.otpMaxAge)
		writeRenewError(w, http.StatusForbidden, "device was enrolled with an authenticator-app witness and has exceeded its maximum age ("+what+" denied; re-enroll required)")
		return false
	}
	return true
}

// validateCSRSelfSigned checks the CSR is well-formed and self-signed
// (proves the caller holds the private key for the renewed cert).
func validateCSRSelfSigned(csrPEM []byte) error {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("csr_pem is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse csr_pem: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("csr self-signature invalid (proof-of-possession failed): %w", err)
	}
	return nil
}

func writeRenewError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
