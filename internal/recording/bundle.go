// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Manifest is the self-describing, signed metadata for a recording bundle
// (Boundary-BSR style). The detached signature is over the manifest JSON, and
// the manifest carries the content's SHA-256 — so tampering with EITHER the
// recording or the manifest is detectable.
type Manifest struct {
	SessionID     string    `json:"session_id"`
	GrantID       string    `json:"grant_id,omitempty"`
	Subject       string    `json:"subject"`
	TargetID      string    `json:"target_id"`
	Protocol      string    `json:"protocol"`
	Format        Format    `json:"format"`
	StartedAt     time.Time `json:"started_at"`
	SealedAt      time.Time `json:"sealed_at"`
	Bytes         int64     `json:"bytes"`
	ContentKey    string    `json:"content_key"`
	ContentSHA256 string    `json:"content_sha256"`
	KeyID         string    `json:"key_id"`

	// Phase 5e-20: cross-link to the cross-session WORM audit chain.
	// Populated from Meta.SessionRowHash at seal-time. Empty when the
	// session store doesn't implement the chain (dev brokers). The
	// manifest signature covers this field, so tampering with the
	// linkage breaks signature verify (5e-14).
	//
	// Verifier semantics: when non-empty, this MUST equal the
	// row_hash currently stored on jit_sessions.id for the bundle's
	// SessionID. If it doesn't, either the chain row was tampered
	// after the bundle was sealed, OR the bundle was swapped onto a
	// different session id. Both are tampering signals — admin
	// /sessions/{id}/recording/verify reports the mismatch alongside
	// signature_valid/hash_match.
	SessionRowHash string `json:"session_row_hash,omitempty"`
}

func ext(f Format) string {
	switch f {
	case FormatAsciicastV2:
		return "cast"
	case FormatDrawing:
		return "guac"
	case FormatHTTPNDJSON:
		return "ndjson"
	case FormatQueryLog:
		return "ndjson"
	case FormatRawStream:
		return "ndjson"
	case FormatRDPStreamV2:
		return "ndjson"
	default:
		return "bin"
	}
}

func contentKey(m Meta) string     { return m.SessionID + "/recording." + ext(m.Format) }
func manifestKey(id string) string { return id + "/manifest.json" }
func sigKey(id string) string      { return id + "/manifest.sig" }

// BundleRecorder writes tamper-evident, signed recordings to a WORM ObjectStore.
type BundleRecorder struct {
	store  ObjectStore
	signer Signer
}

// NewBundleRecorder builds a recorder over the given store + signer.
func NewBundleRecorder(store ObjectStore, signer Signer) *BundleRecorder {
	return &BundleRecorder{store: store, signer: signer}
}

// Store exposes the underlying object store so verify / list / download paths
// (ADR 0051 P4 RDP replay) can read sealed bundles back without a second store
// handle. Read-only use is intended; Put goes through the recorder's seal path.
func (r *BundleRecorder) Store() ObjectStore { return r.store }

// Signer exposes the signer so verify paths can fetch the public key (KeyID +
// Public) without a second signer handle.
func (r *BundleRecorder) Signer() Signer { return r.signer }

// Open returns a WriteCloser; Close seals the bundle (see Recorder).
func (r *BundleRecorder) Open(ctx context.Context, meta Meta) (io.WriteCloser, error) {
	if meta.SessionID == "" {
		return nil, errors.New("recording: meta.SessionID required")
	}
	return &bundleWriter{r: r, ctx: ctx, meta: meta, h: sha256.New()}, nil
}

type bundleWriter struct {
	r    *BundleRecorder
	ctx  context.Context
	meta Meta
	h    interface {
		io.Writer
		Sum([]byte) []byte
	}
	buf    bytes.Buffer
	n      int64
	closed bool
}

func (w *bundleWriter) Write(p []byte) (int, error) {
	_, _ = w.h.Write(p)
	w.n += int64(len(p))
	return w.buf.Write(p)
}

// Close seals: store the content, then a manifest (with the content hash) and a
// detached signature over the manifest. Any failure returns an error so the
// caller fails the session closed.
func (w *bundleWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	ck := contentKey(w.meta)
	if err := w.r.store.Put(w.ctx, ck, w.buf.Bytes()); err != nil {
		return fmt.Errorf("recording: store content: %w", err)
	}

	man := Manifest{
		SessionID:      w.meta.SessionID,
		GrantID:        w.meta.GrantID,
		Subject:        w.meta.Subject,
		TargetID:       w.meta.TargetID,
		Protocol:       w.meta.Protocol,
		Format:         w.meta.Format,
		StartedAt:      w.meta.StartedAt,
		SealedAt:       time.Now(),
		Bytes:          w.n,
		ContentKey:     ck,
		ContentSHA256:  hex.EncodeToString(w.h.Sum(nil)),
		KeyID:          w.r.signer.KeyID(),
		SessionRowHash: w.meta.SessionRowHash,
	}
	manBytes, err := json.Marshal(man)
	if err != nil {
		return fmt.Errorf("recording: marshal manifest: %w", err)
	}
	sig, err := w.r.signer.Sign(manBytes)
	if err != nil {
		return fmt.Errorf("recording: sign manifest: %w", err)
	}
	if err := w.r.store.Put(w.ctx, manifestKey(w.meta.SessionID), manBytes); err != nil {
		return fmt.Errorf("recording: store manifest: %w", err)
	}
	if err := w.r.store.Put(w.ctx, sigKey(w.meta.SessionID), sig); err != nil {
		return fmt.Errorf("recording: store signature: %w", err)
	}
	return nil
}

// Verify re-checks a sealed bundle: the manifest signature must be valid for
// pub, and the stored content's SHA-256 must match the manifest.
func Verify(ctx context.Context, store ObjectStore, sessionID string, pub ed25519.PublicKey) error {
	res, err := VerifyDetail(ctx, store, sessionID, pub)
	if err != nil {
		return err
	}
	if !res.SignatureValid {
		return errors.New("recording: manifest signature INVALID (tampered or wrong key)")
	}
	if !res.HashMatch {
		return errors.New("recording: content hash MISMATCH (recording tampered)")
	}
	return nil
}

// VerifyResult is the structured form of Verify — exposes the
// individual check outcomes plus the manifest so admins can see WHICH
// part failed and what the bundle claims about itself. Used by the
// admin /sessions/{id}/recording/verify endpoint to drive the SPA
// tamper-evidence badge (green = both true; red = any false).
//
// Both flags can be true (sealed bundle is intact), both false (we
// couldn't even reach the storage and the read errors propagate via
// the returned error), or only one false (sig OK but content swapped,
// or sig FAILS but content matches manifest — either way the bundle
// is no longer trustworthy).
type VerifyResult struct {
	SignatureValid bool     `json:"signature_valid"`
	HashMatch      bool     `json:"hash_match"`
	Manifest       Manifest `json:"manifest"`
}

// VerifyDetail is the structured form of Verify. Distinct from Verify
// so the existing Verify call sites + tests aren't churned, and so the
// admin endpoint can show "sig OK but content mismatch" vs "sig FAILS"
// instead of a single opaque error.
func VerifyDetail(ctx context.Context, store ObjectStore, sessionID string, pub ed25519.PublicKey) (VerifyResult, error) {
	manBytes, err := store.Get(ctx, manifestKey(sessionID))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("recording: read manifest: %w", err)
	}
	sig, err := store.Get(ctx, sigKey(sessionID))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("recording: read signature: %w", err)
	}
	sigValid := ed25519.Verify(pub, manBytes, sig)
	var man Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return VerifyResult{}, fmt.Errorf("recording: parse manifest: %w", err)
	}
	content, err := store.Get(ctx, man.ContentKey)
	if err != nil {
		// Manifest parsed and sig possibly verified, but content gone — still
		// useful to report the signature verdict so the SPA can distinguish
		// "manifest preserved but content lost" from "everything fine".
		return VerifyResult{SignatureValid: sigValid, Manifest: man}, fmt.Errorf("recording: read content: %w", err)
	}
	sum := sha256.Sum256(content)
	hashMatch := hex.EncodeToString(sum[:]) == man.ContentSHA256
	return VerifyResult{
		SignatureValid: sigValid,
		HashMatch:      hashMatch,
		Manifest:       man,
	}, nil
}

// RecordSession composes a tamper-evident bundle with the asciicast formatter:
// raw terminal output → asciicast v2 → signed WORM bundle. The returned
// WriteCloser is what the SSH proxy / worker tees output to; Close seals.
func RecordSession(ctx context.Context, rec Recorder, meta Meta, cols, rows int) (io.WriteCloser, error) {
	w, err := rec.Open(ctx, meta)
	if err != nil {
		return nil, err
	}
	return NewAsciicastWriter(w, cols, rows), nil // AsciicastWriter.Close closes w (seals)
}
