// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// ADR 0051 P4 — tests for the owner-scoped RDP recordings list/verify/download.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/recording"
)

// sealOneRDPRecording writes + seals a v2 bundle for subject/target and returns
// its session id.
func sealOneRDPRecording(t *testing.T, rec *recording.BundleRecorder, subject, target string) string {
	t.Helper()
	id := "rdp-" + sanitizeKeySeg(subject) + "-" + sanitizeKeySeg(target) + "-" + sanitizeKeySeg(time.Now().Format("150405.000000"))
	bw, err := rec.Open(t.Context(), recording.Meta{
		SessionID: id, Subject: subject, TargetID: target, Protocol: "rdp", Format: recording.FormatRDPStreamV2,
	})
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	sw := recording.NewRDPStreamWriter(bw, recording.RDPStreamMeta{Subject: subject, Target: target, SessionID: id})
	_ = sw.Resize(1280, 1024)
	_ = sw.Frame(0, 0, 1280, 1024, []byte{1, 2, 3})
	_ = sw.Mouse(10, 20, 1, 0)
	_ = sw.CloseEvent()
	if err := sw.Close(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return id
}

func newTestRecordingsServer(t *testing.T) (*rdpRecordingsConfig, *recording.BundleRecorder, *http.Cookie, *sessionStore) {
	t.Helper()
	store := recording.NewFSStore(t.TempDir())
	signer, err := recording.NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	rec := recording.NewBundleRecorder(store, signer)
	sessions := newSessionStore()
	sid, _ := newSessionID()
	sessions.put(sid, &Operator{Token: "tok", Subject: "alice", Expires: time.Now().Add(time.Hour)})
	cfg := newRDPRecordingsConfig(sessions, rec)
	return cfg, rec, &http.Cookie{Name: sessionCookie, Value: sid}, sessions
}

func doRecordingsGet(t *testing.T, cfg *rdpRecordingsConfig, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	cfg.handleRecordings(w, r)
	return w
}

// TestRDPRecordingsListOwnerScoped proves the list returns only the operator's
// own v2 recordings (not another subject's).
func TestRDPRecordingsListOwnerScoped(t *testing.T) {
	cfg, rec, cookie, _ := newTestRecordingsServer(t)
	mine := sealOneRDPRecording(t, rec, "alice", "win-dc-01")
	_ = sealOneRDPRecording(t, rec, "bob", "win-dc-02") // someone else's

	w := doRecordingsGet(t, cfg, cookie, "/api/rdp/recordings")
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", w.Code)
	}
	var resp struct {
		Recordings []struct {
			SessionID string `json:"session_id"`
			TargetID  string `json:"target_id"`
			Format    string `json:"format"`
		} `json:"recordings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Recordings) != 1 {
		t.Fatalf("listed %d recordings, want 1 (owner-scoped to alice)", len(resp.Recordings))
	}
	if resp.Recordings[0].SessionID != mine || resp.Recordings[0].TargetID != "win-dc-01" {
		t.Errorf("listed wrong recording: %+v", resp.Recordings[0])
	}
	if resp.Recordings[0].Format != string(recording.FormatRDPStreamV2) {
		t.Errorf("format = %q, want rdp-stream-v2", resp.Recordings[0].Format)
	}
}

// TestRDPRecordingsVerifyAndDownload proves verify reports a valid bundle and
// download streams the v2 NDJSON content — both owner-scoped.
func TestRDPRecordingsVerifyAndDownload(t *testing.T) {
	cfg, rec, cookie, _ := newTestRecordingsServer(t)
	id := sealOneRDPRecording(t, rec, "alice", "win-dc-01")

	// verify
	w := doRecordingsGet(t, cfg, cookie, "/api/rdp/recordings/"+id+"/verify")
	if w.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200", w.Code)
	}
	var v struct {
		OK             bool `json:"ok"`
		SignatureValid bool `json:"signature_valid"`
		HashMatch      bool `json:"hash_match"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if !v.OK || !v.SignatureValid || !v.HashMatch {
		t.Fatalf("verify verdict = %+v, want all true", v)
	}

	// download
	w = doRecordingsGet(t, cfg, cookie, "/api/rdp/recordings/"+id)
	if w.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("download content-type = %q, want application/x-ndjson", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"kind":"meta"`) || !strings.Contains(body, `"kind":"frame"`) {
		t.Errorf("download body missing v2 stream lines:\n%s", body)
	}
}

// TestRDPRecordingsDeniesCrossOwner proves an operator can't verify/download
// another subject's recording even with the exact id.
func TestRDPRecordingsDeniesCrossOwner(t *testing.T) {
	cfg, rec, cookie, _ := newTestRecordingsServer(t)
	bobsID := sealOneRDPRecording(t, rec, "bob", "win-dc-02")

	for _, path := range []string{
		"/api/rdp/recordings/" + bobsID + "/verify",
		"/api/rdp/recordings/" + bobsID,
	} {
		w := doRecordingsGet(t, cfg, cookie, path)
		if w.Code != http.StatusNotFound {
			t.Errorf("cross-owner GET %s status = %d, want 404", path, w.Code)
		}
	}
}

// TestRDPRecordingsRequiresAuth proves an anon request is rejected.
func TestRDPRecordingsRequiresAuth(t *testing.T) {
	cfg, _, _, _ := newTestRecordingsServer(t)
	w := doRecordingsGet(t, cfg, nil, "/api/rdp/recordings")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("anon status = %d, want 401", w.Code)
	}
}

// TestRDPRecordingsNoRecorder503 proves the handler 503s gracefully when no
// recorder/store is configured.
func TestRDPRecordingsNoRecorder503(t *testing.T) {
	sessions := newSessionStore()
	sid, _ := newSessionID()
	sessions.put(sid, &Operator{Token: "tok", Subject: "alice", Expires: time.Now().Add(time.Hour)})
	cfg := newRDPRecordingsConfig(sessions, nil)
	w := doRecordingsGet(t, cfg, &http.Cookie{Name: sessionCookie, Value: sid}, "/api/rdp/recordings")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no-recorder status = %d, want 503", w.Code)
	}
}
