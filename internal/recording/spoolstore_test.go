// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

// fakeWORM is a togglable in-memory ObjectStore standing in for MinIO. While
// "down" every Put returns downErr (a sink-unreachable / rejection error);
// while "up" it records objects and the order they were written.
type fakeWORM struct {
	down     bool
	downErr  error
	objects  map[string][]byte
	putOrder []string
	putCount int
}

func newFakeWORM() *fakeWORM { return &fakeWORM{objects: map[string][]byte{}} }

func (f *fakeWORM) setDown(down bool, err error) { f.down, f.downErr = down, err }

func (f *fakeWORM) Put(_ context.Context, key string, data []byte) error {
	f.putCount++
	if f.down {
		return f.downErr
	}
	cp := append([]byte(nil), data...)
	f.objects[key] = cp
	f.putOrder = append(f.putOrder, key)
	return nil
}

func (f *fakeWORM) Get(_ context.Context, key string) ([]byte, error) {
	d, ok := f.objects[key]
	if !ok {
		return nil, fmt.Errorf("fakeWORM: not found: %s", key)
	}
	return append([]byte(nil), d...), nil
}

func newSpoolStoreT(t *testing.T, worm ObjectStore) *SpoolStore {
	t.Helper()
	ss, err := NewSpoolStore(worm, SpoolConfig{Dir: t.TempDir(), ReconcileEvery: time.Hour})
	if err != nil {
		t.Fatalf("NewSpoolStore: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	return ss
}

// down503 is a realistic retryable sink error (S3/MinIO signals throttling as
// 503, not 429), wrapped like S3Store wraps it, to exercise errors.As unwrap.
func down503() error {
	return fmt.Errorf("recording: s3 put obj: %w", minio.ErrorResponse{StatusCode: 503, Code: "SlowDown"})
}

const (
	contentKeyS1  = "sess-1/recording.ndjson"
	manifestKeyS1 = "sess-1/manifest.json"
	sigKeyS1      = "sess-1/manifest.sig"
)

// TestSpoolStore_SinkDownBuffersAndReconciles is the core DDIL P3.6 case: with
// the WORM sink down, a must-record seal SUCCEEDS by buffering locally (the
// session proceeds, not denied); on reconnect the buffered bundle is reconciled
// into WORM in order with its hash-chain / signature / SessionRowHash intact.
func TestSpoolStore_SinkDownBuffersAndReconciles(t *testing.T) {
	ctx := context.Background()
	worm := newFakeWORM()
	ss := newSpoolStoreT(t, worm)
	signer, err := NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	rec := NewBundleRecorder(ss, signer)

	// --- sink DOWN ---
	worm.setDown(true, down503())

	const rowHash = "0badc0ffee11223344556677889900aabbccddeeff00112233445566778899aa"
	meta := Meta{
		SessionID:      "sess-1",
		Subject:        "operator@corp",
		TargetID:       "dc-01",
		Protocol:       "rdp",
		Format:         FormatRDPStreamV2,
		StartedAt:      time.Now(),
		SessionRowHash: rowHash, // the jit_sessions cross-session chain link
	}
	w, err := rec.Open(ctx, meta)
	if err != nil {
		t.Fatalf("recorder.Open: %v", err)
	}
	payload := []byte(`{"event":"session_start"}` + "\n" + `{"event":"frame","seq":1}` + "\n")
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	// SEAL while the sink is down: must SUCCEED (buffered), not fail-closed.
	if err := w.Close(); err != nil {
		t.Fatalf("seal while sink down must SUCCEED (buffered locally), got error: %v", err)
	}

	if len(worm.objects) != 0 {
		t.Fatalf("no object should have reached WORM while down, got %d", len(worm.objects))
	}
	if p := ss.Pending(); p != 3 {
		t.Fatalf("expected 3 buffered objects (content+manifest+sig), got %d", p)
	}

	// --- sink RECOVERS ---
	worm.setDown(false, nil)
	n, err := ss.Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 objects reconciled, got %d", n)
	}
	if p := ss.Pending(); p != 0 {
		t.Fatalf("expected 0 pending after reconcile, got %d", p)
	}

	// Ordering: content BEFORE manifest BEFORE sig (a verifier never sees a
	// manifest referencing absent content).
	assertOrder(t, worm.putOrder, contentKeyS1, manifestKeyS1, sigKeyS1)

	// Chain / tamper-evidence intact after the offline round-trip.
	if err := Verify(ctx, worm, "sess-1", signer.Public()); err != nil {
		t.Fatalf("bundle verify after reconcile: %v", err)
	}
	res, err := VerifyDetail(ctx, worm, "sess-1", signer.Public())
	if err != nil {
		t.Fatalf("verify detail: %v", err)
	}
	if !res.SignatureValid || !res.HashMatch {
		t.Fatalf("bundle not intact after reconcile: sigValid=%v hashMatch=%v", res.SignatureValid, res.HashMatch)
	}
	if res.Manifest.SessionRowHash != rowHash {
		t.Fatalf("SessionRowHash (cross-session chain link) not preserved: got %q want %q", res.Manifest.SessionRowHash, rowHash)
	}
	// Content is byte-for-byte identical (replay, not re-encode).
	content, err := worm.Get(ctx, res.Manifest.ContentKey)
	if err != nil {
		t.Fatalf("get content: %v", err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("content not byte-exact after reconcile:\n got=%q\nwant=%q", content, payload)
	}
}

// TestSpoolStore_ReconcileAfterRestart proves durability across a process
// restart: buffer while down in one SpoolStore, reopen a fresh SpoolStore over
// the same dir (simulating a pod restart mid-outage), then reconcile — the
// bundle still reaches WORM with its chain intact.
func TestSpoolStore_ReconcileAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	worm := newFakeWORM()
	signer, err := NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// Process 1: sink down, seal buffers, then "crash" (Close).
	ss1, err := NewSpoolStore(worm, SpoolConfig{Dir: dir, ReconcileEvery: time.Hour})
	if err != nil {
		t.Fatalf("NewSpoolStore #1: %v", err)
	}
	worm.setDown(true, down503())
	rec := NewBundleRecorder(ss1, signer)
	w, err := rec.Open(ctx, Meta{SessionID: "sess-r", Format: FormatRDPStreamV2, StartedAt: time.Now(), SessionRowHash: "rowhash-r"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = w.Write([]byte("recorded-frames-across-restart"))
	if err := w.Close(); err != nil {
		t.Fatalf("seal buffered: %v", err)
	}
	if ss1.Pending() != 3 {
		t.Fatalf("expected 3 buffered, got %d", ss1.Pending())
	}
	_ = ss1.Close() // shutdown

	// Process 2: reopen the same spool dir, sink recovered, reconcile.
	worm.setDown(false, nil)
	ss2, err := NewSpoolStore(worm, SpoolConfig{Dir: dir, ReconcileEvery: time.Hour})
	if err != nil {
		t.Fatalf("NewSpoolStore #2 (restart): %v", err)
	}
	defer func() { _ = ss2.Close() }()
	n, err := ss2.Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconcile after restart: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 reconciled after restart, got %d", n)
	}
	if err := Verify(ctx, worm, "sess-r", signer.Public()); err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
	res, _ := VerifyDetail(ctx, worm, "sess-r", signer.Public())
	if res.Manifest.SessionRowHash != "rowhash-r" {
		t.Fatalf("SessionRowHash lost across restart: %q", res.Manifest.SessionRowHash)
	}
}

// TestSpoolStore_LocalCaptureFailureFailsClosed is the preserved fail-closed
// invariant: when the sink is unreachable AND the local buffer itself cannot
// accept the object, the seal FAILS (the session is denied) — a must-record
// session never completes with its recording neither in WORM nor on disk.
func TestSpoolStore_LocalCaptureFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	worm := newFakeWORM()
	ss, err := NewSpoolStore(worm, SpoolConfig{Dir: t.TempDir(), ReconcileEvery: time.Hour})
	if err != nil {
		t.Fatalf("NewSpoolStore: %v", err)
	}
	// Break the durable local buffer: closing the spool makes Enqueue fail.
	if err := ss.Close(); err != nil {
		t.Fatalf("close spool: %v", err)
	}
	worm.setDown(true, down503()) // sink also unreachable

	signer, _ := NewEd25519Signer("k")
	rec := NewBundleRecorder(ss, signer)
	w, err := rec.Open(ctx, Meta{SessionID: "sess-2", Format: FormatRDPStreamV2, StartedAt: time.Now()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = w.Write([]byte("frame"))
	if err := w.Close(); err == nil {
		t.Fatal("seal must FAIL CLOSED when sink is down AND the local buffer is unavailable")
	}
	if len(worm.objects) != 0 {
		t.Fatalf("nothing should have reached WORM, got %d objects", len(worm.objects))
	}
}

// TestSpoolStore_NonRetryableFailsClosedNoBuffer proves a genuine sink
// REJECTION (4xx auth/permission) is surfaced (fail-closed) and NOT masked by
// buffering — otherwise a real audit-integrity problem would be hidden.
func TestSpoolStore_NonRetryableFailsClosedNoBuffer(t *testing.T) {
	ctx := context.Background()
	worm := newFakeWORM()
	ss := newSpoolStoreT(t, worm)
	worm.setDown(true, fmt.Errorf("recording: s3 put x: %w", minio.ErrorResponse{StatusCode: 403, Code: "AccessDenied"}))

	if err := ss.Put(ctx, "sess-x/manifest.json", []byte("{}")); err == nil {
		t.Fatal("a non-retryable (403) sink error must fail closed")
	}
	if p := ss.Pending(); p != 0 {
		t.Fatalf("a non-retryable error must NOT buffer; pending=%d", p)
	}
}

// TestSpoolStore_HealthySinkNoBuffer: the normal path is unchanged — a healthy
// sink writes straight through, nothing is buffered.
func TestSpoolStore_HealthySinkNoBuffer(t *testing.T) {
	ctx := context.Background()
	worm := newFakeWORM()
	ss := newSpoolStoreT(t, worm)

	if err := ss.Put(ctx, "a/b.json", []byte("hello")); err != nil {
		t.Fatalf("healthy put: %v", err)
	}
	if p := ss.Pending(); p != 0 {
		t.Fatalf("healthy put must not buffer; pending=%d", p)
	}
	got, err := ss.Get(ctx, "a/b.json")
	if err != nil || string(got) != "hello" {
		t.Fatalf("get: %q err=%v", got, err)
	}
}

func TestRetryableSinkErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"500 internal", minio.ErrorResponse{StatusCode: 500, Code: "InternalError"}, true},
		{"503 slowdown (throttle)", minio.ErrorResponse{StatusCode: 503, Code: "SlowDown"}, true},
		{"504 gateway timeout", minio.ErrorResponse{StatusCode: 504}, true},
		{"408 request timeout", minio.ErrorResponse{StatusCode: 408}, true},
		{"403 access denied", minio.ErrorResponse{StatusCode: 403, Code: "AccessDenied"}, false},
		{"404 no such bucket", minio.ErrorResponse{StatusCode: 404, Code: "NoSuchBucket"}, false},
		{"400 bad request", minio.ErrorResponse{StatusCode: 400, Code: "BadRequest"}, false},
		{"wrapped 503", fmt.Errorf("recording: s3 put k: %w", minio.ErrorResponse{StatusCode: 503}), true},
		{"wrapped 403", fmt.Errorf("recording: s3 put k: %w", minio.ErrorResponse{StatusCode: 403}), false},
		{"net dial refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"unknown transport", errors.New("some odd transport error"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := retryableSinkErr(c.err); got != c.want {
				t.Fatalf("retryableSinkErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestIsAlreadyStored(t *testing.T) {
	if !isAlreadyStored(nil) {
		t.Fatal("nil should be already-stored (idempotent success)")
	}
	if !isAlreadyStored(minio.ErrorResponse{StatusCode: 409, Code: "Conflict"}) {
		t.Fatal("409 conflict should be treated as already-stored")
	}
	if !isAlreadyStored(minio.ErrorResponse{StatusCode: 412, Code: "PreconditionFailed"}) {
		t.Fatal("412 precondition should be treated as already-stored")
	}
	if isAlreadyStored(minio.ErrorResponse{StatusCode: 403, Code: "AccessDenied"}) {
		t.Fatal("403 must NOT be swallowed as already-stored")
	}
}

func assertOrder(t *testing.T, got []string, want ...string) {
	t.Helper()
	pos := func(key string) int {
		for i, k := range got {
			if k == key {
				return i
			}
		}
		return -1
	}
	for i := 1; i < len(want); i++ {
		a, b := pos(want[i-1]), pos(want[i])
		if a < 0 || b < 0 {
			t.Fatalf("expected keys %q and %q present in put order %v", want[i-1], want[i], got)
		}
		if a >= b {
			t.Fatalf("expected %q (pos %d) before %q (pos %d) in put order %v", want[i-1], a, want[i], b, got)
		}
	}
}
