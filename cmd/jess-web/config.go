// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// SPA runtime config endpoint — Phase 5e-9.
//
// The SPA needs a small set of env-time constants the Go server knows but
// the Vite-built static bundle doesn't. Most prominent today: the
// MinIO Console deep-link base for recording bundles. Rather than
// templating index.html at request time (Vite's static output can't be
// rewritten without a custom asset pipeline), we expose a tiny JSON
// endpoint the SPA fetches once on mount and caches in a React context.
//
// Future config to land here (no schema break — just additive fields):
//
//   - brand: product name + logo URL (multi-tenant SaaS path)
//   - features: feature flags (recordings-player-enabled, etc.)
//   - support: contact link / status page URL
//
// Endpoint: GET /api/config  →  {"recording_console_url": "https://..."}
//
// Auth: NONE. This endpoint only returns site-wide non-secret config;
// the recording_console_url is itself a public URL (MinIO Console's
// browser path requires its own auth at the destination).

import (
	"encoding/json"
	"net/http"
	"strings"
)

// WebConfig is the JSON payload sent to the SPA.
type WebConfig struct {
	// RecordingConsoleURL is the base for the MinIO Console object
	// browser, including the bucket path. The SPA appends the URL-
	// encoded object key to form a deep link to the recording bundle.
	//
	// Example: "https://internal.example.com/browser/audit-archive"
	// Empty string disables the deep-link feature — the SPA shows the
	// recording_path chip as copy-only (Phase 5e-8 behaviour).
	RecordingConsoleURL string `json:"recording_console_url,omitempty"`

	// AppEnv is exposed so the SPA can surface a "dev" / "staging"
	// banner. Empty in production. Future use; not surfaced today.
	AppEnv string `json:"app_env,omitempty"`
}

// configHandler returns the SPA runtime config. Cached by the browser
// for 5min — config is essentially static (env-time constants) so
// avoiding a per-page-load round-trip is the right tradeoff. A
// jess-web pod restart still triggers a 304 vs new ETag dance on
// next refresh.
func configHandler(cfg WebConfig) http.HandlerFunc {
	body, _ := json.Marshal(cfg)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, max-age=300")
		_, _ = w.Write(body)
	}
}

// loadWebConfig reads the WebConfig from env. Centralised here so
// adding new fields is one place: env + struct field + SPA consumer.
func loadWebConfig() WebConfig {
	return WebConfig{
		RecordingConsoleURL: strings.TrimRight(env("JESS_WEB_RECORDING_CONSOLE_URL", ""), "/"),
		AppEnv:              env("ENVIRONMENT", ""),
	}
}
