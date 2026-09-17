// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func readManifest(t *testing.T, store *FSStore, id string) Manifest {
	t.Helper()
	b, err := store.Get(context.Background(), id+"/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBundleSealVerifyTamper(t *testing.T) {
	ctx := context.Background()
	store := NewFSStore(t.TempDir())
	signer, err := NewEd25519Signer("jess-rec-1")
	if err != nil {
		t.Fatal(err)
	}
	rec := NewBundleRecorder(store, signer)

	w, err := rec.Open(ctx, Meta{
		SessionID: "s1", Subject: "op@hexxlock", TargetID: "echo",
		Protocol: "ssh", Format: FormatAsciicastV2, StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "secret session output"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// 1. Untampered bundle verifies.
	if err := Verify(ctx, store, "s1", signer.Public()); err != nil {
		t.Fatalf("verify untampered: %v", err)
	}

	// 2. Wrong key fails.
	other, _ := NewEd25519Signer("other")
	if err := Verify(ctx, store, "s1", other.Public()); err == nil {
		t.Fatal("verify with the wrong key must fail")
	}

	// 3. Tampering the content breaks the hash.
	man := readManifest(t, store, "s1")
	if err := store.Put(ctx, man.ContentKey, []byte("tampered")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, store, "s1", signer.Public()); err == nil {
		t.Fatal("content tampering must be detected")
	}

	// 4. Tampering the manifest breaks the signature.
	if err := store.Put(ctx, "s1/manifest.json", []byte(`{"session_id":"s1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, store, "s1", signer.Public()); err == nil {
		t.Fatal("manifest tampering must be detected")
	}
}

func TestRecordSessionAsciicast(t *testing.T) {
	ctx := context.Background()
	store := NewFSStore(t.TempDir())
	signer, _ := NewEd25519Signer("k")
	rec := NewBundleRecorder(store, signer)

	w, err := RecordSession(ctx, rec, Meta{
		SessionID: "s2", Subject: "op", TargetID: "t",
		Protocol: "ssh", Format: FormatAsciicastV2, StartedAt: time.Now(),
	}, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "hello-output"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Verify(ctx, store, "s2", signer.Public()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	man := readManifest(t, store, "s2")
	content, err := store.Get(ctx, man.ContentKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"version":2`) || !strings.Contains(string(content), "hello-output") {
		t.Fatalf("recording is not asciicast carrying the output:\n%s", content)
	}
}
