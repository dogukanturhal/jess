// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
)

func mkRecordingHandler(t *testing.T, id pdp.Identity, store jit.RecordingOverrideStore, cat catalog.Catalog) *RecordingHandler {
	t.Helper()
	base := New(&fakeStore{}, &fakeVerifier{id: id}, "platform_admin")
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return NewRecording(notFound, base, store, cat, nil)
}

func twoTargetCatalog() *stubCatalog {
	return &stubCatalog{targets: []*catalog.Target{
		// "a" defaults to recorded=true (GitOps), "b" defaults to false.
		{ID: "a", Name: "alpha", Protocol: catalog.ProtoSSH, Address: "10.0.0.1:22", Recorded: true},
		{ID: "b", Name: "bravo", Protocol: catalog.ProtoRDP, Address: "10.0.0.2:3389", Recorded: false},
	}}
}

const admID = "alice"

func adminIdentity() pdp.Identity {
	return pdp.Identity{Subject: admID, Roles: []string{"platform_admin"}}
}

// The core of the feature: the EFFECTIVE recorded value = override if
// present, else the catalog default. An override flips it BOTH directions.
func TestEffectiveRecorded_OverrideBeatsCatalogDefault(t *testing.T) {
	cases := []struct {
		name           string
		catalogDefault bool
		haveOverride   bool
		overrideValue  bool
		want           bool
	}{
		{"no-override-default-true", true, false, false, true},
		{"no-override-default-false", false, false, false, false},
		{"override-on-over-default-off", false, true, true, true},  // turn ON a catalog-off target
		{"override-off-over-default-on", true, true, false, false}, // turn OFF a catalog-on target
		{"override-agrees-with-default", true, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ov := jit.RecordingOverride{Recorded: c.overrideValue}
			got := jit.EffectiveRecorded(c.catalogDefault, ov, c.haveOverride)
			if got != c.want {
				t.Fatalf("EffectiveRecorded(default=%v, override=%v, have=%v) = %v, want %v",
					c.catalogDefault, c.overrideValue, c.haveOverride, got, c.want)
			}
		})
	}
}

// PUT an override, then GET — the effective value must reflect the override
// (not the catalog default) and report source=override + updated_by stamped
// from the verified caller.
func TestRecordingHandler_SetThenListReflectsOverride(t *testing.T) {
	store := jit.NewMemoryBroker()
	cat := twoTargetCatalog()
	h := mkRecordingHandler(t, adminIdentity(), store, cat)

	// Turn OFF recording on "a" (catalog default true).
	r := bearerReq(http.MethodPut, "/recording-settings/a", `{"recorded":false}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", w.Code, w.Body.String())
	}
	var set RecordingSetting
	if err := json.NewDecoder(w.Body).Decode(&set); err != nil {
		t.Fatalf("decode PUT: %v", err)
	}
	if set.Recorded != false || set.Source != "override" {
		t.Fatalf("PUT result: recorded=%v source=%q, want recorded=false source=override", set.Recorded, set.Source)
	}
	if set.CatalogDefault != true {
		t.Errorf("catalog_default lost: got %v want true", set.CatalogDefault)
	}
	if set.UpdatedBy != admID {
		t.Errorf("updated_by = %q, want %q (verified caller)", set.UpdatedBy, admID)
	}

	// GET the list — "a" must now show effective=false via override; "b"
	// stays at its catalog default (false, source=catalog).
	r = bearerReq(http.MethodGet, "/recording-settings", "")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", w.Code, w.Body.String())
	}
	var rows []RecordingSetting
	if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", len(rows), rows)
	}
	byID := map[string]RecordingSetting{rows[0].TargetID: rows[0], rows[1].TargetID: rows[1]}
	if a := byID["a"]; a.Recorded != false || a.Source != "override" || a.CatalogDefault != true {
		t.Errorf("a: %+v — want effective=false source=override catalog_default=true", a)
	}
	if b := byID["b"]; b.Recorded != false || b.Source != "catalog" {
		t.Errorf("b: %+v — want effective=false source=catalog", b)
	}
}

// DELETE clears the override → target reverts to its catalog default.
func TestRecordingHandler_ClearRevertsToCatalogDefault(t *testing.T) {
	store := jit.NewMemoryBroker()
	cat := twoTargetCatalog()
	// Pre-seed: override "a" to false (catalog default true).
	if _, err := store.SetRecordingOverride(context.Background(), "a", false, "seed"); err != nil {
		t.Fatal(err)
	}
	h := mkRecordingHandler(t, adminIdentity(), store, cat)

	r := bearerReq(http.MethodDelete, "/recording-settings/a", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", w.Code, w.Body.String())
	}
	var set RecordingSetting
	_ = json.NewDecoder(w.Body).Decode(&set)
	if set.Recorded != true || set.Source != "catalog" {
		t.Fatalf("after clear: recorded=%v source=%q, want recorded=true source=catalog (catalog default)", set.Recorded, set.Source)
	}
	// Override is gone from the store.
	if _, found, _ := store.GetRecordingOverride(context.Background(), "a"); found {
		t.Error("override still present after DELETE")
	}
}

func TestRecordingHandler_RejectsNonAdmin(t *testing.T) {
	store := jit.NewMemoryBroker()
	h := mkRecordingHandler(t, pdp.Identity{Subject: "bob", Roles: []string{"viewer"}}, store, twoTargetCatalog())
	r := bearerReq(http.MethodGet, "/recording-settings", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", w.Code)
	}
}

func TestRecordingHandler_SetUnknownTarget404(t *testing.T) {
	store := jit.NewMemoryBroker()
	h := mkRecordingHandler(t, adminIdentity(), store, twoTargetCatalog())
	r := bearerReq(http.MethodPut, "/recording-settings/ghost", `{"recorded":true}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404 for non-catalog target", w.Code)
	}
}

func TestRecordingHandler_FallsThroughForOtherPaths(t *testing.T) {
	store := jit.NewMemoryBroker()
	h := mkRecordingHandler(t, adminIdentity(), store, twoTargetCatalog())
	r := bearerReq(http.MethodGet, "/grants", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("fall-through 404 expected; got %d", w.Code)
	}
}

func TestRecordingHandler_503WhenStoreNil(t *testing.T) {
	h := mkRecordingHandler(t, adminIdentity(), nil, twoTargetCatalog())
	r := bearerReq(http.MethodGet, "/recording-settings", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", w.Code)
	}
}
