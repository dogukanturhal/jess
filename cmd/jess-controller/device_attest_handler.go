// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// device_attest_handler.go — POST /device-cert/attest endpoint.
//
// This file wires the deviceattest package's Registry.Dispatch into an HTTP
// handler, mints device certificates via the jess-device-ca Vault PKI mount,
// and is the single entry point for all ZTNA Phase 3 device enrollment and
// re-attestation traffic (ADR 0043).
//
// Wire shape:
//
//	POST /device-cert/attest
//	Authorization: Bearer <Falcon-ID id_token>
//	Content-Type: application/json
//	{...AttestRequest...}
//
// On success (200):
//
//	{...AttestResponse...}
//
// Error codes:
//
//	400  malformed request body
//	401  missing or invalid Falcon-ID id_token
//	403  verification failure (tier mismatch, witness rejected, chain invalid)
//	502  Vault PKI sign failure (transient — retry appropriate)
//
// The endpoint is layered as an http.Handler wrapper (same pattern as
// admin.NewAttest) so it can be grafted onto the existing admin port
// middleware chain.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// deviceCertVaultMount is the Vault PKI mount for device certificates
// (provisioned in iac!181 vault-jess-device-ca-pki.tf, role "device-cert").
// The mount name matches the ADR 0043 §6 commitment.
const deviceCertVaultMount = "jess-device-ca"

// deviceCertVaultRole is the Vault PKI role for device certificate signing.
// The role allows: CN = <user_sub>, URI SAN = spiffe://hexxlock.com/device/<uuid>,
// TTL up to 24h, max_ttl 30 days (renewed on re-attestation).
const deviceCertVaultRole = "device-cert"

// deviceCertTTL is the default validity period for an issued device cert.
// Matches ADR 0040 D-003: 24h certificate lifetime requires daily re-attestation,
// providing revocation granularity comparable to an OCSP staple window.
const deviceCertTTL = 24 * time.Hour

// spiffeURIPrefix is the SPIFFE trust domain SAN prefix stamped into every
// device cert per ADR 0040 D-005.
const spiffeURIPrefix = "spiffe://hexxlock.com/device/"

// DeviceCertAttestHandler implements POST /device-cert/attest. It is an
// http.Handler wrapper — non-matching requests are forwarded to next.
type DeviceCertAttestHandler struct {
	next        http.Handler
	verifier    pdp.TokenVerifier      // Falcon-ID OIDC verifier
	registry    *deviceattest.Registry // platform → Verifier dispatch
	vaultClient *vaultx.Client         // for PKI sign
	// corpAsset gates TIER_CORP on the corporate-asset allowlist (migration
	// 0007). When non-nil, a verifier result of TIER_CORP is downgraded to
	// TIER_BYOD unless the device's EK pubkey hash is a pre-registered
	// corporate asset — closing the gap where a genuine TPM (chains to a
	// trusted vendor root) buys CORP without being one of OUR devices.
	// nil = gate disabled (the verifier's tier is used verbatim).
	corpAsset CorpAssetChecker
	// corpAssetEnforce selects audit vs enforce for the gate. false (audit) =
	// the would-be downgrade is LOGGED but NOT applied (CORP is kept) — a soak
	// window to confirm the allowlist is populated before enforcing. true
	// (enforce) = the downgrade is applied. Only meaningful when corpAsset is
	// non-nil.
	corpAssetEnforce bool
	// pending, when non-nil, records genuine-TPM would-be-CORP devices that are
	// NOT corporate assets into a review queue (TOFU auto-enroll). PURELY
	// observational — recording does NOT change the tier decision below; an
	// admin must explicitly approve a pending device to promote it.
	pending deviceattest.PendingObserver
}

// CorpAssetChecker reports whether a device EK pubkey hash was pre-registered as
// a corporate asset. Satisfied by *devicepolicy.FalconIDEnrollmentStore.
type CorpAssetChecker interface {
	IsCorporateAsset(ctx context.Context, ekHash string) (bool, error)
}

// AttestRequest is the JSON body for POST /device-cert/attest.
// All binary fields (platform_blob, ek_cert_pem, ek_pubkey_pem) are
// PEM-encoded strings or base64-encoded blobs (as documented per field).
type AttestRequest struct {
	// Platform names the hardware attestation substrate.
	// One of: tpm2-linux, tpm2-windows, android-strongbox,
	// apple-app-attest, macos-mdm.
	Platform string `json:"platform"`

	// DeviceUUID is the client-asserted UUIDv4 for this device.
	// Stamped into the issued cert's SPIFFE SAN.
	DeviceUUID string `json:"device_uuid"`

	// UserSub is the Falcon-ID subject from the verified id_token.
	// This field is IGNORED from the request body — the handler
	// always uses the verified token's sub claim.
	// (Included in the struct for documentation clarity; tagged with
	// json:"-" to prevent accidental use of the client-supplied value.)
	UserSub string `json:"-"`

	// NonceClient is a freshness nonce from the controller, embedded in
	// the TPM2_MakeCredential / Certify challenge. Base64-encoded bytes.
	NonceClient []byte `json:"nonce_client"`

	// EKCertPEM is the PEM-encoded EK certificate (Path A, optional).
	// Present when the TPM has a vendor-signed EK cert chain.
	// Absent (nil/empty) when Path B (TOFU) should be used.
	EKCertPEM []byte `json:"ek_cert_pem,omitempty"`

	// EKPubKeyPEM is the PEM-encoded EK public key (required for both paths).
	EKPubKeyPEM []byte `json:"ek_pubkey_pem"`

	// CSRPEM is the PEM-encoded PKCS#10 CSR the device generated and signed
	// with its OWN private key (proof-of-possession). Vault signs THIS CSR,
	// so the issued device cert is bound to the device's key — the same key
	// the posture-agent presents for mTLS. The CSR public key MUST equal
	// EKPubKeyPEM (validated in validateAttestRequest); the device private
	// key never leaves the device. Required.
	CSRPEM []byte `json:"csr_pem"`

	// Manufacturer is the TPM2_PT_MANUFACTURER ASCII value.
	// Empty for non-TPM platforms.
	Manufacturer string `json:"manufacturer,omitempty"`

	// Kind is the TPM module classification: discrete | firmware | pluton.
	// Empty for non-TPM platforms.
	Kind string `json:"kind,omitempty"`

	// Hardware is the system/machine identity (DMI/SMBIOS) the enrollment
	// agent auto-detected — serial, model, manufacturer. Optional; omitted
	// entirely when nothing was detected. Distinct from the TPM Manufacturer
	// above (that is the TPM chip vendor; this is the laptop vendor).
	Hardware *AttestHardwareRequest `json:"hardware,omitempty"`

	// PlatformBlob is platform-specific attestation evidence.
	// JSON-encoded per each platform's payload type (see deviceattest.VerifyRequest).
	PlatformBlob []byte `json:"platform_blob,omitempty"`

	// Witness is the Path B enrollment witness (optional on re-attestation
	// once the device is enrolled; required on first Path B enrollment).
	Witness *AttestWitnessRequest `json:"witness,omitempty"`
}

// AttestWitnessRequest carries the Path B WebAuthn-signed operator witness.
type AttestWitnessRequest struct {
	// AdminSub is the Falcon-ID sub of the operator who witnessed the enrollment.
	AdminSub string `json:"admin_sub"`

	// SignedJWS is the compact JWS signed by the operator's WebAuthn credential.
	SignedJWS string `json:"signed_jws"`

	// IssuedAt is the iat from the decoded JWS header (RFC3339 UTC).
	IssuedAt string `json:"issued_at"`
}

// AttestHardwareRequest carries the system/machine hardware identity the
// enrollment agent auto-detected from DMI/SMBIOS. Field names match the
// cross-repo iam_devices contract (serial_number / model / manufacturer).
// Every field may be empty (undetected / unprivileged probe).
type AttestHardwareRequest struct {
	SerialNumber string `json:"serial_number,omitempty"`
	Model        string `json:"model,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
}

// sanitizeHWField bounds an attacker-controlled hardware-identity string from
// the (untrusted) enrollment agent before it is persisted to iam_devices and
// rendered in the admin console: trim, drop control characters (so a value
// cannot smuggle a newline into a log/CSV), and cap at 128 runes. The agent's
// own valid_eyrie_text validator already does this, but the server MUST NOT
// rely on a client-side check.
func sanitizeHWField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if rs := []rune(s); len(rs) > 128 {
		s = string(rs[:128])
	}
	return s
}

// AttestResponse is the JSON body returned on successful attestation.
type AttestResponse struct {
	// Path is the trust path used: "A_chain" or "B_tofu".
	Path string `json:"path"`

	// Tier is the access tier: "TIER_CORP", "TIER_BYOD", or "TIER_BREAKGLASS".
	Tier string `json:"tier"`

	// Reasons is the list of stable diagnostic strings from the verifier.
	Reasons []string `json:"reasons"`

	// DeviceCertPEM is the PEM-encoded device certificate minted by
	// jess-device-ca for this device. Validity: deviceCertTTL from now.
	// CN = verified user_sub; URI SAN = spiffe://hexxlock.com/device/<uuid>.
	DeviceCertPEM string `json:"device_cert_pem"`

	// SerialNumber is the Vault PKI serial number of the issued device cert.
	// Used by CRL builders and audit tools.
	SerialNumber string `json:"serial_number"`

	// ExpiresAt is the device cert expiry time (RFC3339 UTC).
	ExpiresAt string `json:"expires_at"`
}

// NewDeviceCertAttestHandler constructs the device-cert attestation handler.
//
// verifier is the existing controller Falcon-ID OIDC verifier (constructed in
// main, shared with the admin port). registry is the deviceattest.Registry
// built by buildDeviceAttestRegistry. vaultClient is the controller Vault client
// (constructed by newControllerVaultClient, which already handles K8s auth).
//
// All three MUST NOT be nil — nil values panic at construction time.
func NewDeviceCertAttestHandler(
	next http.Handler,
	verifier pdp.TokenVerifier,
	registry *deviceattest.Registry,
	vaultClient *vaultx.Client,
) *DeviceCertAttestHandler {
	if verifier == nil {
		panic("device_attest_handler: verifier must not be nil")
	}
	if registry == nil {
		panic("device_attest_handler: registry must not be nil")
	}
	if vaultClient == nil {
		panic("device_attest_handler: vaultClient must not be nil")
	}
	return &DeviceCertAttestHandler{
		next:        next,
		verifier:    verifier,
		registry:    registry,
		vaultClient: vaultClient,
	}
}

// WithCorpAssetChecker enables the corporate-asset gate (migration 0007).
// Optional builder-style setter so the constructor signature stays stable;
// when unset the gate is disabled and the verifier's tier is used verbatim.
// enforce=false runs the gate in AUDIT mode (log the would-be downgrade, keep
// CORP) — the recommended first-deploy posture for a soak; enforce=true applies
// the downgrade.
func (h *DeviceCertAttestHandler) WithCorpAssetChecker(c CorpAssetChecker, enforce bool) *DeviceCertAttestHandler {
	h.corpAsset = c
	h.corpAssetEnforce = enforce
	return h
}

// WithPendingObserver enables TOFU auto-enroll: genuine-TPM would-be-CORP
// devices that are not corporate assets are recorded for admin review. Optional;
// observational only — it never changes the attestation tier decision.
func (h *DeviceCertAttestHandler) WithPendingObserver(o deviceattest.PendingObserver) *DeviceCertAttestHandler {
	h.pending = o
	return h
}

// ServeHTTP dispatches POST /device-cert/attest to the attestation handler;
// all other requests are forwarded to next.
func (h *DeviceCertAttestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/device-cert/attest" {
		h.next.ServeHTTP(w, r)
		return
	}
	h.handleAttest(w, r)
}

// handleAttest is the core request handler. All exits that are not 200 write
// an error JSON body via writeAttestError.
func (h *DeviceCertAttestHandler) handleAttest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Step 1 — Falcon-ID token authentication.
	rawToken := extractBearerToken(r)
	if rawToken == "" {
		writeAttestError(w, http.StatusUnauthorized, "missing Authorization Bearer token")
		return
	}
	identity, err := h.verifier.Verify(ctx, rawToken)
	if err != nil {
		writeAttestError(w, http.StatusUnauthorized, fmt.Sprintf("token verification failed: %v", err))
		return
	}
	userSub := identity.Subject
	if userSub == "" {
		writeAttestError(w, http.StatusUnauthorized, "verified token has empty subject")
		return
	}

	// Step 2 — decode and validate the request body.
	var req AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAttestError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	// Overwrite user_sub from the request body with the server-verified value.
	req.UserSub = userSub

	if err := validateAttestRequest(&req); err != nil {
		writeAttestError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Step 3 — dispatch to the platform verifier.
	pv := h.registry.VerifierFor(req.Platform)
	if pv == nil {
		writeAttestError(w, http.StatusBadRequest,
			fmt.Sprintf("platform %q not supported by this controller (enabled: %v)",
				req.Platform, h.registry.Enabled()))
		return
	}

	verifyReq := deviceattest.VerifyRequest{
		Platform:     req.Platform,
		Manufacturer: req.Manufacturer,
		Kind:         req.Kind,
		EKPubKeyPEM:  req.EKPubKeyPEM,
		EKCertPEM:    req.EKCertPEM,
		UserSub:      req.UserSub,
		DeviceUUID:   req.DeviceUUID,
		NonceClient:  req.NonceClient,
		PlatformBlob: req.PlatformBlob,
	}
	// System/machine hardware identity (DMI/SMBIOS) — optional, carried in the
	// request's hardware block. Persisted to iam_devices on first-enrollment so
	// the admin onboarding view can show serial/model/manufacturer. The agent
	// is UNTRUSTED (a malicious client can bypass its own validator), so clamp
	// length + strip control chars server-side before it is stored and shown.
	if req.Hardware != nil {
		verifyReq.SerialNumber = sanitizeHWField(req.Hardware.SerialNumber)
		verifyReq.Model = sanitizeHWField(req.Hardware.Model)
		verifyReq.SystemManufacturer = sanitizeHWField(req.Hardware.Manufacturer)
	}
	if req.Witness != nil {
		iat, parseErr := time.Parse(time.RFC3339, req.Witness.IssuedAt)
		if parseErr != nil {
			writeAttestError(w, http.StatusBadRequest,
				fmt.Sprintf("witness.issued_at is not valid RFC3339: %v", parseErr))
			return
		}
		verifyReq.Witness = &deviceattest.WitnessBundle{
			AdminSub:  req.Witness.AdminSub,
			SignedJWS: []byte(req.Witness.SignedJWS),
			IssuedAt:  iat,
		}
	}

	result, err := pv.Verify(ctx, verifyReq)
	if err != nil {
		// All verifier errors wrap ErrVerification — map to 403.
		if errors.Is(err, deviceattest.ErrVerification) {
			writeAttestError(w, http.StatusForbidden,
				fmt.Sprintf("device attestation failed: %v", err))
			return
		}
		// Unexpected internal error — 500.
		log.Printf("device_attest_handler: unexpected verifier error platform=%s device=%s: %v",
			req.Platform, req.DeviceUUID, err)
		writeAttestError(w, http.StatusInternalServerError, "internal verifier error")
		return
	}

	// Step 3b — corporate-asset gate. A verifier returns TIER_CORP on
	// hardware genuineness (Path A: EK cert chains to a pinned vendor root),
	// which proves "a real TPM from a trusted vendor" — NOT "one of OUR
	// devices". Downgrade CORP -> BYOD unless the device's EK pubkey hash was
	// pre-registered as a corporate asset (migration 0007 allowlist). This is
	// the single global choke point: it covers every CORP-yielding path and
	// flows the downgraded tier into BOTH the minted cert and the response.
	// Fail closed — if the allowlist cannot be consulted we do not grant CORP.
	//
	// AUDIT mode (corpAssetEnforce=false): the would-be downgrade is LOGGED but
	// NOT applied (CORP is kept). This is the recommended first-deploy posture —
	// a soak window to confirm the allowlist is fully populated before flipping
	// to enforce, so the fail-closed gate does not mass-downgrade a fleet whose
	// EK hashes have not been pre-registered yet.
	if h.corpAsset != nil && result.Tier == "TIER_CORP" {
		sum := sha256.Sum256(req.EKPubKeyPEM)
		ekHash := hex.EncodeToString(sum[:])
		isCorp, caErr := h.corpAsset.IsCorporateAsset(ctx, ekHash)
		switch {
		case caErr != nil:
			if h.corpAssetEnforce {
				log.Printf("device_attest_handler: corp-asset check failed device=%s: %v — failing closed (TIER_BYOD)",
					req.DeviceUUID, caErr)
				result.Tier = "TIER_BYOD"
				result.Reasons = append(result.Reasons, "corp_asset_check_error_downgraded")
			} else {
				log.Printf("device_attest_handler: [AUDIT] corp-asset check failed device=%s: %v — enforce mode WOULD fail closed (TIER_BYOD); keeping TIER_CORP",
					req.DeviceUUID, caErr)
				result.Reasons = append(result.Reasons, "corp_asset_audit_check_error")
			}
		case !isCorp:
			// TOFU auto-enroll: record this genuine-TPM would-be-CORP device as a
			// promotion candidate for admin review. ADDITIVE — does not affect the
			// tier decision in the branches below.
			if h.pending != nil {
				h.pending.Observe(deviceattest.PendingDevice{
					EKHash:      ekHash,
					DeviceUUID:  req.DeviceUUID,
					Platform:    req.Platform,
					Subject:     userSub,
					WouldBeTier: "TIER_CORP",
				})
			}
			if h.corpAssetEnforce {
				result.Tier = "TIER_BYOD"
				result.Reasons = append(result.Reasons, "not_corporate_asset_downgraded")
			} else {
				log.Printf("device_attest_handler: [AUDIT] device=%s is not a corporate asset — enforce mode WOULD downgrade CORP->BYOD; keeping TIER_CORP",
					req.DeviceUUID)
				result.Reasons = append(result.Reasons, "corp_asset_audit_would_downgrade")
			}
		default:
			result.Reasons = append(result.Reasons, "corporate_asset_verified")
		}
	}

	// Step 4 — mint the device certificate via Vault PKI.
	certPEM, serial, expiresAt, err := h.mintDeviceCert(ctx, userSub, req.DeviceUUID, result.Tier, req.CSRPEM)
	if err != nil {
		log.Printf("device_attest_handler: vault pki sign failed platform=%s device=%s: %v",
			req.Platform, req.DeviceUUID, err)
		writeAttestError(w, http.StatusBadGateway,
			fmt.Sprintf("device certificate minting failed (Vault PKI unavailable): %v", err))
		return
	}

	// Step 5 — return the response.
	resp := AttestResponse{
		Path:          result.Path,
		Tier:          result.Tier,
		Reasons:       result.Reasons,
		DeviceCertPEM: certPEM,
		SerialNumber:  serial,
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// mintDeviceCert generates a fresh ECDSA P-256 CSR for the device and signs
// it via the jess-device-ca Vault PKI mount. The device's private key is
// generated server-side for this initial issuance; in production the device
// agent generates its own key pair and sends the CSR, but this server-side
// generation path covers the enrollment flow where the agent does not yet have
// a device cert.
//
// NOTE on key ownership: The current implementation mints the cert server-side
// (jess-controller generates the ephemeral private key, signs the cert, and
// returns the cert + a PKCS#8-encoded private key). The caller discards the
// private key after delivery. Future work (Phase 3b): the device agent generates
// its own keypair and sends only a CSR, removing the private-key-in-transit risk.
//
// The CN is set to userSub (verified Falcon-ID sub); the SPIFFE URI SAN is
// spiffe://hexxlock.com/device/<deviceUUID> per ADR 0040 D-005.
// csrMatchesEK verifies the client CSR is well-formed, self-signed (proof the
// caller holds the device private key), and carries the SAME public key as the
// enrolled EK. This binds the issued cert to the device's key — the key the
// posture-agent presents for mTLS — and stops a caller from getting a cert for
// any other key under this device's enrollment.
func csrMatchesEK(csrPEM, ekPubPEM []byte) error {
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
	csrSPKI, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal csr public key: %w", err)
	}
	ekBlk, _ := pem.Decode(ekPubPEM)
	if ekBlk == nil {
		return fmt.Errorf("ek_pubkey_pem is not PEM")
	}
	ekPub, err := x509.ParsePKIXPublicKey(ekBlk.Bytes)
	if err != nil {
		return fmt.Errorf("parse ek_pubkey_pem: %w", err)
	}
	ekSPKI, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		return fmt.Errorf("marshal ek public key: %w", err)
	}
	if !bytes.Equal(csrSPKI, ekSPKI) {
		return fmt.Errorf("csr public key does not match enrolled ek_pubkey_pem")
	}
	return nil
}

// mintDeviceCert signs the DEVICE's CSR (validated by csrMatchesEK to carry the
// enrolled EK public key) via Vault PKI. The cert is bound to the device's own
// key — the private key never leaves the device — so the posture-agent's mTLS
// identity (device-key.pem + this cert) validates. Vault overrides CN to the
// server-verified userSub and injects the SPIFFE SAN.
func (h *DeviceCertAttestHandler) mintDeviceCert(
	ctx context.Context,
	userSub, deviceUUID, tier string,
	csrPEM []byte,
) (certPEM, serial string, expiresAt time.Time, err error) {
	_ = tier // tier is recorded in iam_devices; cert subject is governed by the Vault role + CN.
	spiffeURI := spiffeURIPrefix + deviceUUID

	signResp, signErr := h.vaultClient.SignPKICert(ctx, deviceCertVaultMount, deviceCertVaultRole,
		vaultx.PKISignRequest{
			CSRPEM:     string(csrPEM),
			CommonName: userSub,
			TTL:        deviceCertTTL,
			// SPIFFE identity goes in a URI-type SAN (uri_sans), NOT alt_names.
			// posture-signer's DeviceCertVerifier reads cert.URIs and matches
			// spiffe://hexxlock.com/device/<uuid> against the heartbeat
			// device_uuid; an alt_names/DNS SAN would never appear there and
			// every heartbeat would 403 with ErrSANMismatch. The Vault
			// device-cert role allows_uri_sans = ["spiffe://hexxlock.com/device/*"].
			URISans: []string{spiffeURI},
		})
	if signErr != nil {
		return "", "", time.Time{}, fmt.Errorf("vault pki sign: %w", signErr)
	}

	return signResp.Certificate, signResp.SerialNumber, signResp.Expiration, nil
}

// validateAttestRequest performs field-level validation on the decoded request
// before any crypto or network calls. Returns a descriptive error on the first
// violation.
func validateAttestRequest(req *AttestRequest) error {
	if req.Platform == "" {
		return fmt.Errorf("platform is required")
	}
	if req.DeviceUUID == "" {
		return fmt.Errorf("device_uuid is required")
	}
	if len(req.EKPubKeyPEM) == 0 {
		return fmt.Errorf("ek_pubkey_pem is required")
	}
	if len(req.CSRPEM) == 0 {
		return fmt.Errorf("csr_pem is required")
	}
	if err := csrMatchesEK(req.CSRPEM, req.EKPubKeyPEM); err != nil {
		return err
	}
	if req.Witness != nil {
		if req.Witness.AdminSub == "" {
			return fmt.Errorf("witness.admin_sub is required when witness is present")
		}
		if req.Witness.SignedJWS == "" {
			return fmt.Errorf("witness.signed_jws is required when witness is present")
		}
		if req.Witness.IssuedAt == "" {
			return fmt.Errorf("witness.issued_at is required when witness is present")
		}
	}
	return nil
}

// extractBearerToken extracts the bearer token from the Authorization header.
// Returns empty string if the header is absent or malformed.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// writeAttestError writes a JSON error body to w with the given HTTP status.
func writeAttestError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
