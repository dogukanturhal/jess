// SPDX-License-Identifier: AGPL-3.0-or-later

package diag

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/jess/internal/metrics"
)

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestDiagHandlers(t *testing.T) {
	m := metrics.New()
	m.Allow()
	m.Deny()
	m.Deny()

	h := Handler(m.Handler(), func(ctx context.Context) error { return nil })

	if code, body := get(t, h, "/healthz"); code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("/healthz = %d %q", code, body)
	}
	if code, _ := get(t, h, "/readyz"); code != 200 {
		t.Errorf("/readyz ready = %d, want 200", code)
	}
	if code, body := get(t, h, "/metrics"); code != 200 || !strings.Contains(body, "jess_authz_decisions_total") {
		t.Errorf("/metrics missing counter: %d\n%s", code, body)
	} else {
		if !strings.Contains(body, `jess_authz_decisions_total{result="deny"} 2`) {
			t.Errorf("/metrics deny count wrong:\n%s", body)
		}
	}

	// Not-ready path returns 503.
	hbad := Handler(m.Handler(), func(ctx context.Context) error { return errors.New("db down") })
	if code, _ := get(t, hbad, "/readyz"); code != 503 {
		t.Errorf("/readyz not-ready = %d, want 503", code)
	}
}
