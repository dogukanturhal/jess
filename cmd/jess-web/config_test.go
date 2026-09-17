// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigHandlerReturnsConfigJSON(t *testing.T) {
	cfg := WebConfig{
		RecordingConsoleURL: "https://internal.example.com/browser/audit-archive",
		AppEnv:              "prod",
	}
	h := configHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}
	if c := rec.Header().Get("Cache-Control"); !strings.Contains(c, "max-age=300") {
		t.Errorf("Cache-Control=%q must allow 5min cache", c)
	}
	var got WebConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if got.RecordingConsoleURL != cfg.RecordingConsoleURL {
		t.Errorf("RecordingConsoleURL roundtrip mismatch: %q vs %q", got.RecordingConsoleURL, cfg.RecordingConsoleURL)
	}
}

func TestConfigHandlerOmitsEmptyFields(t *testing.T) {
	// Empty fields should be omitempty so the SPA sees a tiny payload
	// when no env is set — no need to send `"recording_console_url": ""`
	// across the wire to every page load.
	h := configHandler(WebConfig{})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	body := rec.Body.String()
	if strings.Contains(body, "recording_console_url") {
		t.Errorf("empty RecordingConsoleURL must be omitted via omitempty, got body=%s", body)
	}
}

func TestLoadWebConfigTrimsTrailingSlash(t *testing.T) {
	// The SPA appends "/<encoded-key>" to the base URL. A trailing
	// slash in the env would cause "//<key>" which some MinIO Console
	// versions normalise + others don't — strip at load time.
	t.Setenv("JESS_WEB_RECORDING_CONSOLE_URL", "https://internal.example.com/browser/audit-archive/")
	cfg := loadWebConfig()
	if strings.HasSuffix(cfg.RecordingConsoleURL, "/") {
		t.Errorf("trailing slash should be trimmed, got %q", cfg.RecordingConsoleURL)
	}
}
