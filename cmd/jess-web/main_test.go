// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// The real SPA bundle lives at web/dist/*. CI runs `pnpm build` before
// `go test`, but unit tests must work even when the dist tree is the
// .gitkeep-only placeholder. We swap in an in-memory fstest.MapFS that
// mimics what Vite produces.
func fakeDist() fs.FS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte(`<!doctype html><html><body><div id="root" data-jw-italic-word="open"></div><script type="module" src="/assets/main-abc123.js"></script></body></html>`),
		},
		"assets/main-abc123.js": &fstest.MapFile{
			Data: []byte(`/* fingerprinted SPA bundle */`),
		},
		"assets/main-abc123.css": &fstest.MapFile{
			Data: []byte(`.jw-italic-word{color:var(--hxm-blue);font-style:italic}`),
		},
		// Un-hashed top-level static files (favicon / icon set / manifest)
		// — these have stable names and must be served as the real file with
		// a revalidating cache, NOT the SPA shell.
		"favicon.ico":       &fstest.MapFile{Data: []byte("ico")},
		"favicon.svg":       &fstest.MapFile{Data: []byte("<svg/>")},
		"favicon-32x32.png": &fstest.MapFile{Data: []byte("png")},
		"site.webmanifest":  &fstest.MapFile{Data: []byte("{}")},
	}
}

// TestSPAShellServesIndex — root path returns the SPA shell with
// no-cache + security headers. The body must carry the hxm marker so
// design-system regressions surface in unit tests.
func TestSPAShellServesIndex(t *testing.T) {
	h := spaHandler(fakeDist())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q, want text/html", ct)
	}
	if c := rec.Header().Get("Cache-Control"); !strings.Contains(c, "no-cache") {
		t.Errorf("Cache-Control=%q, want no-cache (so a new bundle deploy isn't masked by a stale shell)", c)
	}
	if c := rec.Header().Get("Content-Security-Policy"); !strings.Contains(c, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none' (clickjacking): %q", c)
	}
	if c := rec.Header().Get("X-Content-Type-Options"); c != "nosniff" {
		t.Errorf("X-Content-Type-Options=%q, want nosniff", c)
	}
	if !strings.Contains(rec.Body.String(), `data-jw-italic-word="open"`) {
		t.Error("SPA shell missing hxm italic-word marker (design system not applied)")
	}
}

// TestSPAFallbackForUnknownRoute — /session, /grants/foo, anything not
// /assets/* MUST resolve to the SPA shell so client-side routing works
// on hard refresh. This is the OPPOSITE of the Phase 5e-1 behaviour
// (which 404'd unknown paths because there was no SPA router yet).
func TestSPAFallbackForUnknownRoute(t *testing.T) {
	h := spaHandler(fakeDist())

	for _, p := range []string{"/session", "/grants/abc", "/totally/made/up"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status=%d, want 200 (SPA fallback)", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s: Content-Type=%q, want text/html", p, ct)
		}
		if !strings.Contains(rec.Body.String(), `id="root"`) {
			t.Errorf("%s: response missing #root mount point", p)
		}
	}
}

// TestAssetsAreImmutable — fingerprinted /assets/* MUST set the
// 1-year immutable Cache-Control header so the operator's browser
// doesn't refetch every navigation.
func TestAssetsAreImmutable(t *testing.T) {
	h := spaHandler(fakeDist())

	req := httptest.NewRequest(http.MethodGet, "/assets/main-abc123.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	c := rec.Header().Get("Cache-Control")
	if !strings.Contains(c, "max-age=31536000") || !strings.Contains(c, "immutable") {
		t.Errorf("Cache-Control=%q, want max-age=31536000+immutable for fingerprinted asset", c)
	}
}

// TestOIDCDisabledReturns503 — when JESS_OIDC_CLIENT_ID isn't set,
// /auth/login and /api/me MUST return a structured 503 (not generic
// 404) so the operator sees what's missing.
func TestOIDCDisabledReturns503(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	oidcDisabled(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "JESS_OIDC_CLIENT_ID") {
		t.Errorf("503 body should name the missing env var; got %q", rec.Body.String())
	}
}

// TestEmbeddedDistTreePresent — sanity that the embed directive picked
// up something at web/dist (even if it's just the .gitkeep placeholder
// before a real `pnpm build`). Without this assertion an empty embed
// would silently 503 every request in production.
func TestEmbeddedDistTreePresent(t *testing.T) {
	sub, err := fs.Sub(staticFS, "web/dist")
	if err != nil {
		t.Fatalf("fs.Sub web/dist: %v", err)
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		t.Fatalf("ReadDir web/dist: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("web/dist embed is empty — committed .gitkeep should make this at least 1")
	}
}

// TestStaticFilesServedWithRevalidatingCache — un-hashed top-level static
// files (favicon, icon set, webmanifest) must be served as the REAL file
// (not the SPA shell) and with a revalidating `no-cache` so a re-branded
// favicon/icon lands on the next load instead of being pinned to a cached
// copy. Serving the SPA shell here would (a) hand an HTML body to an <img>/
// <link rel=icon> and (b) break the favicon entirely.
func TestStaticFilesServedWithRevalidatingCache(t *testing.T) {
	h := spaHandler(fakeDist())

	for _, p := range []string{"/favicon.ico", "/favicon.svg", "/favicon-32x32.png", "/site.webmanifest"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status=%d, want 200", p, rec.Code)
		}
		// Must NOT be the SPA shell.
		if strings.Contains(rec.Body.String(), `id="root"`) {
			t.Errorf("%s: served the SPA shell instead of the real static file", p)
		}
		c := rec.Header().Get("Cache-Control")
		if !strings.Contains(c, "no-cache") {
			t.Errorf("%s: Cache-Control=%q, want no-cache (revalidate so re-branding lands)", p, c)
		}
		if strings.Contains(c, "immutable") {
			t.Errorf("%s: Cache-Control=%q must NOT be immutable (un-hashed name)", p, c)
		}
	}
}

// TestExistsInFS pins the static-file vs SPA-route discriminator. A real
// embedded file → serve it; anything else → SPA fallback. Mis-classifying
// here either bypasses the SPA fallback for routes or hands the HTML shell
// to a static asset.
func TestExistsInFS(t *testing.T) {
	dist := fakeDist()
	for _, tc := range []struct {
		path   string
		exists bool
	}{
		{"/index.html", true},
		{"/favicon.ico", true},
		{"/favicon-32x32.png", true},
		{"/assets/main-abc123.js", true},
		{"/", false},
		{"/session", false},
		{"/api/me", false},
		{"/grants/abc", false},
		{"/assets", false}, // directory, not a file
	} {
		if got := existsInFS(dist, tc.path); got != tc.exists {
			t.Errorf("existsInFS(%q) = %v, want %v", tc.path, got, tc.exists)
		}
	}
}
