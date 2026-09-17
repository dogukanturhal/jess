// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/catalog/providers/adminapi"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// mkTargetsHandler wires the standard test base + the targets layer.
func mkTargetsHandler(t *testing.T, id pdp.Identity) (*TargetsHandler, *adminapi.Provider) {
	t.Helper()
	store := adminapi.New(nil) // nil sink — handler tests don't care about Aggregator notify
	base := New(&fakeStore{}, &fakeVerifier{id: id}, "platform_admin")
	// next handler must not match /admin/targets/*; a 404-fallback works.
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return NewTargets(notFound, base, store), store
}

func TestTargetsHandler_CreateRoundTrip(t *testing.T) {
	h, store := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})

	body := `{"id":"dev-vm-1","protocol":"ssh","address":"10.0.0.1:22","host_key":"ssh-ed25519 AAAA root@dev"}`
	r := bearerReq(http.MethodPost, "/admin/targets", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var view TargetView
	if err := json.NewDecoder(w.Body).Decode(&view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Target.ID != "dev-vm-1" || view.AddedBy != "sub:alice" {
		t.Errorf("view = %+v, want id=dev-vm-1 added_by=sub:alice", view)
	}
	if _, _, _, ok := store.Get("dev-vm-1"); !ok {
		t.Error("store missing entry after POST")
	}
}

func TestTargetsHandler_RejectsNonAdmin(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "bob", Roles: []string{"viewer"}})
	r := bearerReq(http.MethodPost, "/admin/targets", `{"id":"x","address":"10.0.0.1:22"}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestTargetsHandler_RejectsBadJSON(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	r := bearerReq(http.MethodPost, "/admin/targets", `not json`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTargetsHandler_RequiresIDAndAddress(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	r := bearerReq(http.MethodPost, "/admin/targets", `{"protocol":"ssh"}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "id and address") {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTargetsHandler_CreateDuplicate409(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	body := `{"id":"x","address":"10.0.0.1:22"}`
	r1 := bearerReq(http.MethodPost, "/admin/targets", body)
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first POST status = %d", w1.Code)
	}
	r2 := bearerReq(http.MethodPost, "/admin/targets", body)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate POST = %d, want 409", w2.Code)
	}
}

func TestTargetsHandler_ListReturnsSortedByID(t *testing.T) {
	h, store := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	_ = store.Create(t.Context(), catalog.Target{ID: "z", Protocol: catalog.ProtoSSH, Address: "x"}, "sys")
	_ = store.Create(t.Context(), catalog.Target{ID: "a", Protocol: catalog.ProtoSSH, Address: "y"}, "sys")
	_ = store.Create(t.Context(), catalog.Target{ID: "m", Protocol: catalog.ProtoSSH, Address: "z"}, "sys")
	r := bearerReq(http.MethodGet, "/admin/targets", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var rows []TargetView
	_ = json.NewDecoder(w.Body).Decode(&rows)
	if len(rows) != 3 || rows[0].Target.ID != "a" || rows[1].Target.ID != "m" || rows[2].Target.ID != "z" {
		t.Errorf("rows not sorted: %+v", rows)
	}
}

func TestTargetsHandler_GetOne(t *testing.T) {
	h, store := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	_ = store.Create(t.Context(), catalog.Target{ID: "x", Protocol: catalog.ProtoSSH, Address: "10.0.0.1:22"}, "sys")
	r := bearerReq(http.MethodGet, "/admin/targets/x", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var view TargetView
	_ = json.NewDecoder(w.Body).Decode(&view)
	if view.Target.ID != "x" {
		t.Errorf("got = %+v, want id=x", view)
	}
}

func TestTargetsHandler_GetMissing404(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	r := bearerReq(http.MethodGet, "/admin/targets/nope", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestTargetsHandler_Update(t *testing.T) {
	h, store := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	_ = store.Create(t.Context(), catalog.Target{ID: "x", Protocol: catalog.ProtoSSH, Address: "10.0.0.1:22"}, "sys")

	r := bearerReq(http.MethodPatch, "/admin/targets/x", `{"address":"10.0.0.99:22","protocol":"ssh"}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	got, _, _, _ := store.Get("x")
	if got.Address != "10.0.0.99:22" {
		t.Errorf("post-PATCH address = %q, want 10.0.0.99:22", got.Address)
	}
}

func TestTargetsHandler_Delete(t *testing.T) {
	h, store := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	_ = store.Create(t.Context(), catalog.Target{ID: "x", Protocol: catalog.ProtoSSH, Address: "10.0.0.1:22"}, "sys")

	r := bearerReq(http.MethodDelete, "/admin/targets/x", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204, body=%s", w.Code, w.Body.String())
	}
	if _, _, _, ok := store.Get("x"); ok {
		t.Error("entry survived DELETE")
	}
}

func TestTargetsHandler_DeleteMissing404(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	r := bearerReq(http.MethodDelete, "/admin/targets/nope", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestTargetsHandler_FallsThroughForNonTargetPath(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	// /grants is the base handler's domain; our targets layer should not
	// intercept it. Falls through to the next handler which we wired as
	// http.NotFound for the test fixture.
	r := bearerReq(http.MethodGet, "/grants", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected fall-through 404 from next handler; got %d", w.Code)
	}
}

func TestTargetsHandler_MethodNotAllowedOnRoot(t *testing.T) {
	h, _ := mkTargetsHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}})
	r := bearerReq(http.MethodPut, "/admin/targets", `{}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
