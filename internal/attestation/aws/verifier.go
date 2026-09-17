// SPDX-License-Identifier: AGPL-3.0-or-later

// Package aws verifies AWS EC2 Instance Identity Documents.
//
// Wire shape
// ==========
// Every EC2 instance fetches its own signed identity document from
// IMDSv2:
//
//	curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
//	curl -s http://169.254.169.254/latest/dynamic/instance-identity/signature
//
// The /document endpoint returns JSON with accountId, instanceId,
// region, etc. The /signature endpoint returns the base64-encoded
// RSA-SHA256 signature of that JSON, signed by an AWS-region-specific
// RSA-2048 key. AWS publishes the regional public keys at
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
//
// We deliberately use /signature (raw RSA-PKCS#1-v1.5) rather than the
// PKCS#7-wrapped /pkcs7 endpoint — same cryptographic guarantee with
// none of the ASN.1 framing dependency.
//
// Operator workflow (the eventual `jess-attest` binary will do this
// automatically; Phase 7g-3):
//
//  1. On a fresh EC2 instance, fetch /document + /signature
//  2. POST {document, signature} to controller /admin/attest with
//     provenance=aws
//  3. Controller verifies the RSA signature against the embedded AWS
//     region key, decodes the document, audits, returns 200.
//
// Security model
// ==============
//   - The public key set is COMPILED INTO the binary, sourced from
//     AWS public docs. No internet fetch at verify-time → cannot be
//     MITM'd. Keys rotate rarely; when they do, this file updates in
//     lockstep with a deliberate code review.
//   - Documents older than MaxDocumentAge (default 10min) are rejected
//     so a leaked-then-replayed document has a small replay window.
//   - No "skip-verify" knob. Period. Operators wanting to disable
//     attestation should not enable this verifier in the registry.
package aws

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/dogukanturhal/jess/internal/attestation"
)

// DefaultMaxDocumentAge bounds how long after AWS signed a document
// we still accept it. 10 minutes matches Teleport's default + is
// short enough that a leaked document has a small replay window.
const DefaultMaxDocumentAge = 10 * time.Minute

// Verifier verifies AWS Instance Identity Documents.
type Verifier struct {
	// PubKeys is the set of region → RSA public key pairs we accept.
	// Map of region code (e.g. "us-east-1") to *rsa.PublicKey. Built
	// at construction from the embedded PEM block.
	PubKeys map[string]*rsa.PublicKey

	// MaxDocumentAge defaults to DefaultMaxDocumentAge when zero.
	MaxDocumentAge time.Duration

	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// Presentation is the JSON envelope the controller endpoint accepts
// from the attestation client. DocumentJSON is the literal bytes
// returned by IMDS /document; Signature is the raw bytes (decoded
// from the IMDS base64) of /signature.
type Presentation struct {
	// DocumentJSON is the raw bytes of
	// /latest/dynamic/instance-identity/document (compact JSON).
	DocumentJSON []byte `json:"document"`
	// Signature is the base64-decoded bytes of
	// /latest/dynamic/instance-identity/signature.
	Signature []byte `json:"signature"`
}

// identityDocument mirrors the IMDS /document JSON. Only the fields
// we attest on are decoded.
type identityDocument struct {
	AccountID        string    `json:"accountId"`
	InstanceID       string    `json:"instanceId"`
	Region           string    `json:"region"`
	Architecture     string    `json:"architecture"`
	ImageID          string    `json:"imageId"`
	PendingTime      time.Time `json:"pendingTime"`
	PrivateIP        string    `json:"privateIp"`
	AvailabilityZone string    `json:"availabilityZone"`
	InstanceType     string    `json:"instanceType"`
}

// New constructs a Verifier preloaded with AWS regional public keys.
// MaxDocumentAge defaults to 10 minutes; pass non-zero to override.
func New(maxDocumentAge time.Duration) (*Verifier, error) {
	keys, err := parseEmbeddedPubKeys()
	if err != nil {
		return nil, fmt.Errorf("aws verifier: parse embedded keys: %w", err)
	}
	if maxDocumentAge == 0 {
		maxDocumentAge = DefaultMaxDocumentAge
	}
	return &Verifier{
		PubKeys:        keys,
		MaxDocumentAge: maxDocumentAge,
		Now:            time.Now,
	}, nil
}

// NewWithKeys lets tests inject a custom key set without going
// through the embedded PEM. Production callers should use New().
func NewWithKeys(keys map[string]*rsa.PublicKey, maxAge time.Duration) *Verifier {
	if maxAge == 0 {
		maxAge = DefaultMaxDocumentAge
	}
	return &Verifier{PubKeys: keys, MaxDocumentAge: maxAge, Now: time.Now}
}

// Provenance implements attestation.Verifier.
func (*Verifier) Provenance() attestation.Provenance { return attestation.ProvenanceAWS }

// Verify implements attestation.Verifier. blob is a JSON envelope
// matching Presentation.
func (v *Verifier) Verify(_ context.Context, blob []byte) (attestation.Document, error) {
	var pres Presentation
	if err := json.Unmarshal(blob, &pres); err != nil {
		return attestation.Document{}, fmt.Errorf("%w: bad envelope JSON: %v", attestation.ErrVerification, err)
	}
	if len(pres.DocumentJSON) == 0 || len(pres.Signature) == 0 {
		return attestation.Document{}, fmt.Errorf("%w: missing document or signature", attestation.ErrVerification)
	}

	// Parse document to discover its region (chicken-and-egg — but
	// the region claim is benign info, and the signature check below
	// is what protects against forgery).
	var doc identityDocument
	if err := json.Unmarshal(pres.DocumentJSON, &doc); err != nil {
		return attestation.Document{}, fmt.Errorf("%w: bad document JSON: %v", attestation.ErrVerification, err)
	}
	if doc.Region == "" {
		return attestation.Document{}, fmt.Errorf("%w: document.region empty", attestation.ErrVerification)
	}

	pubKey, found := v.PubKeys[doc.Region]
	if !found {
		return attestation.Document{}, fmt.Errorf("%w: no public key for region %q", attestation.ErrVerification, doc.Region)
	}

	// AWS signs SHA-256(document) with RSA-PKCS#1 v1.5 padding.
	hash := sha256.Sum256(pres.DocumentJSON)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], pres.Signature); err != nil {
		return attestation.Document{}, fmt.Errorf("%w: rsa verify: %v", attestation.ErrVerification, err)
	}

	// Time bounds: reject documents older than MaxDocumentAge.
	// PendingTime is the document's birth time (when AWS first
	// signed for this instance).
	now := v.Now()
	if !doc.PendingTime.IsZero() && now.Sub(doc.PendingTime) > v.MaxDocumentAge {
		return attestation.Document{}, fmt.Errorf("%w: document is %v old (max %v)",
			attestation.ErrVerification, now.Sub(doc.PendingTime).Round(time.Second), v.MaxDocumentAge)
	}

	return attestation.Document{
		Provenance: attestation.ProvenanceAWS,
		AccountID:  doc.AccountID,
		InstanceID: doc.InstanceID,
		Region:     doc.Region,
		IssuedAt:   doc.PendingTime,
		ExpiresAt:  doc.PendingTime.Add(v.MaxDocumentAge),
		Extras: map[string]string{
			"architecture":      doc.Architecture,
			"image_id":          doc.ImageID,
			"private_ip":        doc.PrivateIP,
			"availability_zone": doc.AvailabilityZone,
			"instance_type":     doc.InstanceType,
		},
	}, nil
}

// parseEmbeddedPubKeys decodes the package-embedded PEM block listing
// AWS regional public keys. The block is intentionally inlined as a
// const so binary builds are reproducible without any internet fetch.
func parseEmbeddedPubKeys() (map[string]*rsa.PublicKey, error) {
	out := make(map[string]*rsa.PublicKey, len(embeddedKeys))
	for region, pemBytes := range embeddedKeys {
		block, _ := pem.Decode([]byte(pemBytes))
		if block == nil {
			return nil, fmt.Errorf("region %q: pem.Decode returned nil", region)
		}
		// Try PKIX SubjectPublicKeyInfo first (modern AWS format),
		// fall back to PKCS#1 RSAPublicKey (legacy).
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			rsaKey, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("region %q: PKIX key is not RSA", region)
			}
			out[region] = rsaKey
			continue
		}
		rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("region %q: parse RSA key: %w", region, err)
		}
		out[region] = rsaKey
	}
	return out, nil
}
