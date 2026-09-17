// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// stubCatalog implements catalog.Catalog for the handler tests.
// Returns the staged targets verbatim from List(); Lookup is unused
// here but stubbed to satisfy the interface.
type stubCatalog struct {
	targets []*catalog.Target
	err     error
}

func (s *stubCatalog) List(_ context.Context, region string) ([]*catalog.Target, error) {
	if s.err != nil {
		return nil, s.err
	}
	if region == "" {
		return s.targets, nil
	}
	var out []*catalog.Target
	for _, t := range s.targets {
		if t.Region == region {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *stubCatalog) Lookup(_ context.Context, id string) (*catalog.Target, error) {
	for _, t := range s.targets {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, catalog.ErrTargetNotFound
}

func mkCatalogHandler(t *testing.T, id pdp.Identity, cat catalog.Catalog) *CatalogHandler {
	t.Helper()
	base := New(&fakeStore{}, &fakeVerifier{id: id}, "platform_admin")
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return NewCatalog(notFound, base, cat)
}

func TestCatalogHandler_ListReturnsAllTargets(t *testing.T) {
	cat := &stubCatalog{targets: []*catalog.Target{
		{ID: "b", Protocol: catalog.ProtoSSH, Address: "10.0.0.2:22", Source: "k8s-nodes", LastSeen: time.Now()},
		{ID: "a", Protocol: catalog.ProtoSSH, Address: "10.0.0.1:22", Source: "static"},
	}}
	h := mkCatalogHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, cat)

	r := bearerReq(http.MethodGet, "/admin/catalog", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var rows []*catalog.Target
	if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "a" || rows[1].ID != "b" {
		t.Errorf("expected sorted [a,b]; got %+v", rows)
	}
	if rows[0].Source != "static" || rows[1].Source != "k8s-nodes" {
		t.Errorf("source attribution lost: %+v", rows)
	}
}

func TestCatalogHandler_RegionFilter(t *testing.T) {
	cat := &stubCatalog{targets: []*catalog.Target{
		{ID: "eu-a", Protocol: catalog.ProtoSSH, Address: "x", Region: "eu-tr"},
		{ID: "us-a", Protocol: catalog.ProtoSSH, Address: "y", Region: "us-east"},
	}}
	h := mkCatalogHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, cat)

	r := bearerReq(http.MethodGet, "/admin/catalog?region=eu-tr", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var rows []*catalog.Target
	_ = json.NewDecoder(w.Body).Decode(&rows)
	if len(rows) != 1 || rows[0].ID != "eu-a" {
		t.Errorf("region filter broke: %+v", rows)
	}
}

func TestCatalogHandler_RejectsNonAdmin(t *testing.T) {
	cat := &stubCatalog{}
	h := mkCatalogHandler(t, pdp.Identity{Subject: "bob", Roles: []string{"viewer"}}, cat)
	r := bearerReq(http.MethodGet, "/admin/catalog", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestCatalogHandler_RejectsPOST(t *testing.T) {
	cat := &stubCatalog{}
	h := mkCatalogHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, cat)
	r := bearerReq(http.MethodPost, "/admin/catalog", `{}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestCatalogHandler_FallsThroughForOtherPaths(t *testing.T) {
	cat := &stubCatalog{}
	h := mkCatalogHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, cat)
	r := bearerReq(http.MethodGet, "/grants", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("fall-through 404 expected; got %d", w.Code)
	}
}

func TestCatalogHandler_503WhenCatalogNil(t *testing.T) {
	h := mkCatalogHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, nil)
	r := bearerReq(http.MethodGet, "/admin/catalog", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}
