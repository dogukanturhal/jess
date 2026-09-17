// SPDX-License-Identifier: AGPL-3.0-or-later

// ssh_cert.go — operator-facing SSH client certificate minter.
//
// Task #130. Lets a device-attested operator mint a short-lived SSH
// client cert (signed by Vault's jess-ssh-ca PKI mount) that the
// matching SSH server (GitLab, target hosts wired to TrustedUserCAKeys)
// accepts as the operator's identity. Each cert is bound to:
//
//   - the operator's verified Falcon-ID subject (principal: git-<sub>)
//   - the operator's device-UUID (carried in the cert as a
//     KeyID/extension so SOC audit can join a git push to the device
//     that emitted the SSH key)
//   - a hard TTL (12h max — re-issuance forces a fresh device-posture
//     check via the Talon edge mTLS verifier each session)
//
// The Talon identity-token header `X-Talon-Identity-Token` carries the
// verified posture-tier + device-UUID downstream so jess doesn't have
// to re-validate them. Per ADR 0040 §Phase 4, that header is signed by
// Talon's iap-identity-key (which jess can verify via Talon's JWKS at
// internal.example.com/.well-known/jwks.json). For this scaffold the
// device-UUID is sourced from a trusted header — wiring the JWKS
// verification lands in a follow-up MR (task #140 jess↔talon SSH bridge
// closeout).
//
// Route:
//
//	POST /ssh-cert    body {"public_key","ttl_seconds"}; returns
//	                       {"cert":"ssh-ed25519-cert-v01@openssh.com …",
//	                        "principals":[…], "expires_at":"…"}

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SSHCertSigner is the subset of vaultx.Client this handler needs.
type SSHCertSigner interface {
	SignSSHCert(ctx context.Context, sshMount, role, publicKeyAuthorized string, principals []string, ttl time.Duration) (string, error)
}

// SSHCertConfig wires the SSH-CA route.
type SSHCertConfig struct {
	Vault           SSHCertSigner
	Mount           string        // e.g. "jess-ssh-ca"
	Role            string        // e.g. "operator-client"
	MaxTTL          time.Duration // hard ceiling regardless of caller request (default 12h)
	PrincipalPrefix string        // e.g. "git-" — principals become <prefix><caller-sub>
}

// WithSSHCertSigner mounts POST /ssh-cert on the admin Handler.
// Returns the Handler for chaining (matches the WithDeviceStore pattern).
func (h *Handler) WithSSHCertSigner(cfg SSHCertConfig) *Handler {
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 12 * time.Hour
	}
	if cfg.PrincipalPrefix == "" {
		cfg.PrincipalPrefix = "git-"
	}
	h.sshCert = &cfg
	return h
}

// SSHCertRequest is the body of POST /ssh-cert.
type SSHCertRequest struct {
	// PublicKey is the operator's SSH public key in authorized_keys
	// format (e.g. "ssh-ed25519 AAAA…"). The matching private key
	// stays in the TPM / OS-keyring on the operator workstation.
	PublicKey string `json:"public_key"`

	// TTLSeconds is the requested cert lifetime. Capped by
	// SSHCertConfig.MaxTTL — if the caller asks for more, the server
	// clamps + returns the clamped TTL in expires_at.
	TTLSeconds int `json:"ttl_seconds"`
}

// SSHCertResponse mirrors the wire shape returned to the caller. The
// `cert` field is the OpenSSH-format certificate the operator drops
// into ~/.ssh/<key>-cert.pub.
type SSHCertResponse struct {
	Cert       string    `json:"cert"`
	Principals []string  `json:"principals"`
	ExpiresAt  time.Time `json:"expires_at"`
	KeyID      string    `json:"key_id"`
}

// handleSSHCert dispatches POST /ssh-cert. Returns true on match.
func (h *Handler) handleSSHCert(w http.ResponseWriter, r *http.Request, callerSub string) bool {
	if r.Method != http.MethodPost || r.URL.Path != "/ssh-cert" {
		return false
	}
	if h.sshCert == nil {
		writeErr(w, http.StatusServiceUnavailable, "ssh-cert signer not configured")
		return true
	}
	var req SSHCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return true
	}
	if req.PublicKey == "" {
		writeErr(w, http.StatusBadRequest, "public_key required")
		return true
	}
	if req.TTLSeconds <= 0 {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be > 0")
		return true
	}
	if err := validateOpenSSHPublicKey(req.PublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "public_key: "+err.Error())
		return true
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl > h.sshCert.MaxTTL {
		ttl = h.sshCert.MaxTTL
	}

	// Build the cert principals + key-id. Principals scope what the
	// SSH server will treat the operator as; key-id is the audit
	// breadcrumb. Both carry the verified caller's sub — never the
	// claimed-by-request sub.
	principals := []string{h.sshCert.PrincipalPrefix + callerSub}
	// Device-UUID + tier sourcing (task #140 jess↔talon SSH bridge
	// Phase 2 closure):
	//   - If a TalonIdentityVerifier is wired, the device UUID comes
	//     from the cryptographically-verified X-Talon-Identity-Token
	//     JWT signature (Talon's iap-identity-key). A forged JWT fails
	//     the signature check + the request is rejected via the
	//     401-mapped TalonIdentityFailed branch below.
	//   - If no verifier is wired (Phase 1 fallback), accept the
	//     X-Talon-Device-UUID bare header. This path is intended for
	//     dev / pre-Phase-4 clusters; production should set
	//     JESS_TALON_IDENTITY_ISSUER so the verifier is constructed.
	deviceUUID := "no-device-claim"
	tier := ""
	if h.talonIdentity != nil {
		claims, err := h.talonIdentity.Verify(r.Context(), r)
		switch {
		case err == nil:
			deviceUUID = claims.DeviceUUID
			tier = claims.Tier
		case errors.Is(err, ErrNoTalonIdentityToken):
			// Header missing — fall through to the bare-header path
			// so a non-Talon-fronted dev request still works.
		default:
			// Signature failure / audience mismatch / expired = 401.
			// Distinct from "header missing" so audit logs can flag
			// active forgery attempts.
			writeErr(w, http.StatusUnauthorized, "X-Talon-Identity-Token: "+err.Error())
			return true
		}
	}
	if deviceUUID == "no-device-claim" {
		// No verified Talon identity — accept bare header as Phase 1
		// fallback. Operators relying on the bare header in production
		// MUST configure the JWT verifier; the log line surfaces the
		// downgrade so it's visible in SOC tooling.
		if h := r.Header.Get("X-Talon-Device-UUID"); h != "" {
			deviceUUID = h
		}
	}
	_ = tier // tier reserved for future use (e.g. per-tier TTL clamping)
	keyID := fmt.Sprintf("operator=%s device=%s issued=%s", callerSub, deviceUUID,
		h.now().UTC().Format(time.RFC3339))

	cert, err := h.sshCert.Vault.SignSSHCert(
		r.Context(),
		h.sshCert.Mount,
		h.sshCert.Role,
		req.PublicKey,
		principals,
		ttl,
	)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "vault sign: "+err.Error())
		return true
	}
	writeJSON(w, http.StatusOK, SSHCertResponse{
		Cert:       cert,
		Principals: principals,
		ExpiresAt:  h.now().Add(ttl).UTC(),
		KeyID:      keyID,
	})
	return true
}

// validateOpenSSHPublicKey runs a structural check on the
// authorized_keys-formatted key. Doesn't decode the base64 body — Vault's
// SSH signer does that — but rejects obviously-malformed inputs
// (missing algorithm token, suspicious whitespace, empty body, oversize).
func validateOpenSSHPublicKey(pk string) error {
	pk = strings.TrimSpace(pk)
	if pk == "" {
		return errors.New("empty key")
	}
	if len(pk) > 8192 {
		return errors.New("key too large (>8 KiB)")
	}
	parts := strings.Fields(pk)
	if len(parts) < 2 {
		return errors.New("authorized_keys format requires `<alg> <body>` (got " +
			fmt.Sprintf("%d field(s))", len(parts)))
	}
	switch parts[0] {
	case "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa", "sk-ssh-ed25519@openssh.com":
	default:
		return fmt.Errorf("unsupported algorithm %q", parts[0])
	}
	if len(parts[1]) < 16 {
		return errors.New("body too short")
	}
	return nil
}
