// SPDX-License-Identifier: AGPL-3.0-or-later

package vaultx

import (
	"context"
	"crypto/ed25519"
	"fmt"
)

// TransitSigner adapts a Vault Transit ed25519 key to the recording.Signer
// shape (KeyID/Sign/Public) used by recording.BundleRecorder. It is satisfied
// structurally — vaultx does NOT import the recording package. The private key
// never leaves Vault; Public() is fetched once at construction for fast offline
// verification of sealed bundles.
type TransitSigner struct {
	c      *Client
	mount  string
	key    string
	pub    ed25519.PublicKey
	signFn func(data []byte) ([]byte, error) // bound to a background ctx for the Signer interface
}

// NewTransitSigner constructs a signer over transit/<key>, eagerly reading the
// public key so a misconfigured key fails at worker startup.
func NewTransitSigner(ctx context.Context, c *Client, transitMount, key string) (*TransitSigner, error) {
	pub, err := c.TransitPublicKey(ctx, transitMount, key)
	if err != nil {
		return nil, err
	}
	ts := &TransitSigner{c: c, mount: transitMount, key: key, pub: pub}
	ts.signFn = func(data []byte) ([]byte, error) {
		return c.TransitSign(context.Background(), transitMount, key, data)
	}
	return ts, nil
}

// KeyID returns the Transit key name (recorded in the bundle manifest).
func (s *TransitSigner) KeyID() string { return "vault-transit:" + s.key }

// Sign signs data via Vault Transit. The recording.Signer interface has no
// context arg, so this uses a background context (signing is a fast control op).
func (s *TransitSigner) Sign(data []byte) ([]byte, error) {
	if s.signFn == nil {
		return nil, fmt.Errorf("vaultx: TransitSigner not initialised")
	}
	return s.signFn(data)
}

// Public returns the ed25519 verification key fetched from Vault at construction.
func (s *TransitSigner) Public() ed25519.PublicKey { return s.pub }
