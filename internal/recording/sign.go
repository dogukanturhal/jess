// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Signer produces a detached signature over a recording manifest. The dev/test
// implementation is Ed25519Signer (in-process key). PRODUCTION uses a Vault
// Transit-backed signer (same interface; the private key never leaves Vault) —
// wired in a later step.
type Signer interface {
	KeyID() string
	Sign(data []byte) (sig []byte, err error)
	// Public returns the verification key (dev path; in prod a verifier fetches
	// the public key from Vault Transit by KeyID).
	Public() ed25519.PublicKey
}

// Ed25519Signer is an in-process signer for dev/tests.
type Ed25519Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewEd25519Signer mints a fresh ed25519 key labeled keyID.
func NewEd25519Signer(keyID string) (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("recording: generate signing key: %w", err)
	}
	return &Ed25519Signer{keyID: keyID, priv: priv}, nil
}

func (s *Ed25519Signer) KeyID() string { return s.keyID }

func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

func (s *Ed25519Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}
