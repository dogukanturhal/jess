// SPDX-License-Identifier: AGPL-3.0-or-later

// Package azure verifies Azure VM attested-data documents.
//
// Wire shape
// ==========
// An Azure VM fetches its own attested-data document from the
// instance metadata service (IMDS) — analogous to AWS's Instance
// Identity Document but encoded as a PKCS#7 token in a JWT-like
// envelope:
//
//	GET http://169.254.169.254/metadata/attested/document?api-version=2020-09-01
//	  Header: Metadata: true
//
// The response is a JSON {"encoding": "pkcs7", "signature": "<base64>"}.
// The signature is a PKCS#7 / CMS structure signed by an
// intermediate cert chained to Azure's "Microsoft Azure RSA TLS
// Issuing CA" root.
//
// This verifier is INTENTIONALLY a scaffold for the v1 release:
//
//   - The Document/Presentation shapes are defined so the controller
//     endpoint compiles + audits Azure attestation attempts.
//   - Provenance() returns ProvenanceAzure so the registry dispatch
//     works end-to-end.
//   - Verify() returns ErrVerification with reason="not_implemented"
//     until the full PKCS#7 + cert-chain validation lands in
//     Phase 7g-2.
//
// Why scaffold first
// ==================
// AWS IMDS uses raw RSA-PKCS#1 v1.5 over a JSON doc (simple). Azure
// uses CMS-wrapped X.509 cert chain with intermediate validation —
// substantially more code + careful chain pinning. Shipping the
// AWS path now + scaffolding Azure for follow-up matches the way
// Teleport rolled out their IAM-join (AWS first, Azure later).
//
// Production deployments on Azure should NOT enable this verifier
// until 7g-2 ships full validation — otherwise every Azure
// attestation attempt fails-closed with 401 (the conservative
// posture, but pointless for Azure shops until the impl is done).
package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dogukanturhal/jess/internal/attestation"
)

// Verifier validates Azure VM attested-data documents.
type Verifier struct {
	// MicrosoftRootsPEM is the PEM bundle of trusted Microsoft Azure
	// root certificates. Operator must provide; the verifier refuses
	// to start without at least one trusted root.
	MicrosoftRootsPEM []byte
}

// Presentation is the JSON envelope the controller endpoint accepts
// from the attestation client.
type Presentation struct {
	// Encoding identifies the signature format — Azure uses "pkcs7"
	// as of api-version=2020-09-01.
	Encoding string `json:"encoding"`
	// Signature is the base64-decoded PKCS#7 / CMS structure as
	// returned by IMDS. The signed payload inside is the JSON
	// attested-data document.
	Signature []byte `json:"signature"`
}

// attestedData mirrors the JSON document Azure signs. Decoded only
// after PKCS#7 verification succeeds.
type attestedData struct {
	SubscriptionID string `json:"subscriptionId"`
	VMID           string `json:"vmId"`
	LicenseType    string `json:"licenseType,omitempty"`
	Plan           any    `json:"plan,omitempty"`
	Nonce          string `json:"nonce"`
	PublisherID    string `json:"publisherId,omitempty"`
	Sku            string `json:"sku,omitempty"`
	Timestamp      struct {
		CreatedOn string `json:"createdOn"`
		ExpiresOn string `json:"expiresOn"`
	} `json:"timeStamp"`
}

// New constructs a Verifier. rootsPEM must contain at least one
// Microsoft Azure root cert — without it, the verifier can't pin
// the cert chain that Azure's CMS signature claims to derive from.
func New(rootsPEM []byte) (*Verifier, error) {
	if len(rootsPEM) == 0 {
		return nil, fmt.Errorf("azure verifier: MicrosoftRootsPEM is empty (operator must supply Azure root certs)")
	}
	return &Verifier{MicrosoftRootsPEM: rootsPEM}, nil
}

// Provenance implements attestation.Verifier.
func (*Verifier) Provenance() attestation.Provenance { return attestation.ProvenanceAzure }

// Verify implements attestation.Verifier. Phase 7g-1 scaffold: parses
// the envelope (so the controller endpoint can return shaped errors)
// but returns ErrVerification with reason="not_implemented" until
// the full PKCS#7 + cert-chain validation lands in 7g-2.
func (v *Verifier) Verify(_ context.Context, blob []byte) (attestation.Document, error) {
	var pres Presentation
	if err := json.Unmarshal(blob, &pres); err != nil {
		return attestation.Document{}, fmt.Errorf("%w: bad envelope JSON: %v", attestation.ErrVerification, err)
	}
	if pres.Encoding != "pkcs7" {
		return attestation.Document{}, fmt.Errorf("%w: unsupported encoding %q (expected pkcs7)", attestation.ErrVerification, pres.Encoding)
	}
	if len(pres.Signature) == 0 {
		return attestation.Document{}, fmt.Errorf("%w: missing signature", attestation.ErrVerification)
	}
	// 7g-1 scaffold: refuse all Azure attestations until 7g-2 ships
	// real PKCS#7 + chain validation. Surface the gap loudly via
	// ErrVerification so the controller audits the attempt.
	return attestation.Document{}, fmt.Errorf("%w: azure verifier not yet implemented (Phase 7g-2)", attestation.ErrVerification)
}
