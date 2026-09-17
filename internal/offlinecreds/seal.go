// SPDX-License-Identifier: AGPL-3.0-or-later

package offlinecreds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Sealer protects pre-positioned credential material at rest with authenticated
// encryption (AES-256-GCM). A pre-positioned credential is a small bounded
// standing secret; sealing it means the plaintext never lives in a plain struct
// field, never lands in a heap dump verbatim, and — if a durable-store backend
// is later added — is never written to disk in the clear ("do NOT write a
// long-lived plaintext secret"). AES-256-GCM is the same AEAD the platform uses
// for its opaque session cookies.
//
// Key provenance:
//   - Production may pass a 32-byte key from a scoped/HW-backed source
//     (JESS_OFFLINE_CREDS_SEAL_KEY, base64) so sealed blobs are portable /
//     durable.
//   - The secure default is an EPHEMERAL per-process key (NewEphemeralSealer):
//     the sealed cache lives only in this process's memory and cannot be
//     unsealed by any other process or after a restart. A restart is itself a
//     reconnect opportunity (Vault is normally reachable again), so the smaller
//     blast radius of an ephemeral key is the more-secure default.
type Sealer struct {
	aead cipher.AEAD
}

// KeySize is the required key length for the AES-256-GCM sealer.
const KeySize = 32

// NewSealer wraps a 32-byte key in an AES-256-GCM AEAD.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("offlinecreds: seal key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("offlinecreds: aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("offlinecreds: gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// NewEphemeralSealer generates a fresh random 32-byte key held only in process
// memory. This is the secure default for the in-memory pre-position cache.
func NewEphemeralSealer() (*Sealer, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("offlinecreds: generate ephemeral seal key: %w", err)
	}
	return NewSealer(key)
}

// Seal encrypts plaintext, returning nonce||ciphertext||tag. A fresh random
// nonce is prepended per call (GCM requires a unique nonce per key).
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("offlinecreds: seal nonce: %w", err)
	}
	// Seal appends the ciphertext to the nonce so the nonce travels with the blob.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. A truncated blob or a failed authentication tag (tamper /
// wrong key) is an error — the caller MUST fail closed rather than trust
// unverified plaintext.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("offlinecreds: sealed blob too short")
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	pt, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("offlinecreds: open sealed credential: %w", err)
	}
	return pt, nil
}
