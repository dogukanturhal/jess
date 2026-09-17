// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// fakeDeviceStore is an in-memory DeviceStore for tests. Mirrors the
// shape of the production FalconIDEnrollmentStore + the fakeEnrollmentStore
// in internal/deviceattest/verifier_tofu_test.go, but exposes ONLY the
// DeviceStore subset the admin tests need.
type fakeDeviceStore struct {
	mu        sync.Mutex
	devices   []deviceattest.EnrolledDevice
	disableOK func(string) bool // gate Disable() — nil = always succeed
}

func (f *fakeDeviceStore) List(_ context.Context, filter deviceattest.EnrollmentFilter) ([]deviceattest.EnrolledDevice, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]deviceattest.EnrolledDevice, 0, len(f.devices))
	for _, d := range f.devices {
		if filter.UserSub != "" && d.UserSub != filter.UserSub {
			continue
		}
		if filter.Tier != "" && d.Tier != filter.Tier {
			continue
		}
		if filter.Platform != "" && d.Platform != filter.Platform {
			continue
		}
		if !filter.IncludeDisabled && !d.DisabledAt.IsZero() {
			continue
		}
		out = append(out, d)
	}
	if filter.Offset > 0 && filter.Offset < len(out) {
		out = out[filter.Offset:]
	} else if filter.Offset >= len(out) {
		return []deviceattest.EnrolledDevice{}, nil
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 200
	}
	if limit < len(out) {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeDeviceStore) Disable(_ context.Context, deviceUUID, _ string) error {
	if f.disableOK != nil && !f.disableOK(deviceUUID) {
		return errDeviceNotFound
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.devices {
		if f.devices[i].DeviceUUID == deviceUUID {
			if f.devices[i].DisabledAt.IsZero() {
				f.devices[i].DisabledAt = time.Now().UTC()
			}
			return nil
		}
	}
	return errDeviceNotFound
}

// fakeAdminVerifier returns a successful Identity carrying the requested
// role / subject. Mirrors the pattern in admin_test.go.
type fakeAdminVerifier struct {
	identity pdp.Identity
	err      error
}

func (f *fakeAdminVerifier) Verify(_ context.Context, _ string) (pdp.Identity, error) {
	if f.err != nil {
		return pdp.Identity{}, f.err
	}
	return f.identity, nil
}

func newAdminWithDevices(t *testing.T, devices DeviceStore) *Handler {
	t.Helper()
	v := &fakeAdminVerifier{identity: pdp.Identity{Subject: "test-admin", Roles: []string{"platform_admin"}}}
	return New(nil, v, "platform_admin").WithDeviceStore(devices)
}

func authReq(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer test-token")
	return r
}

func TestListDevices_BareList(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{devices: []deviceattest.EnrolledDevice{
		{
			DeviceUUID: "uuid-1", UserSub: "alice", Platform: "tpm2-linux",
			Tier: "TIER_CORP", AttestationPath: "A_chain", EKPubkeyHash: "abc",
			EnrolledAt: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			DeviceUUID: "uuid-2", UserSub: "bob", Platform: "apple-app-attest",
			Tier: "TIER_BYOD", AttestationPath: "B_tofu", EKPubkeyHash: "def",
			EnrolledAt: time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
		},
	}}
	h := newAdminWithDevices(t, store)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp ListDevicesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("want 2 devices, got %d: %+v", len(resp.Devices), resp.Devices)
	}
}

func TestListDevices_FilterByTier(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{devices: []deviceattest.EnrolledDevice{
		{DeviceUUID: "1", UserSub: "a", Tier: "TIER_CORP", EnrolledAt: time.Now()},
		{DeviceUUID: "2", UserSub: "b", Tier: "TIER_BYOD", EnrolledAt: time.Now()},
		{DeviceUUID: "3", UserSub: "c", Tier: "TIER_CORP", EnrolledAt: time.Now()},
	}}
	h := newAdminWithDevices(t, store)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices?tier=TIER_CORP", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp ListDevicesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("want 2 CORP devices, got %d", len(resp.Devices))
	}
	for _, d := range resp.Devices {
		if d.Tier != "TIER_CORP" {
			t.Errorf("filter leaked %q", d.Tier)
		}
	}
}

func TestListDevices_FilterByUserSub(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{devices: []deviceattest.EnrolledDevice{
		{DeviceUUID: "1", UserSub: "alice", Tier: "TIER_CORP", EnrolledAt: time.Now()},
		{DeviceUUID: "2", UserSub: "bob", Tier: "TIER_CORP", EnrolledAt: time.Now()},
	}}
	h := newAdminWithDevices(t, store)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices?user_sub=alice", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
	var resp ListDevicesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].UserSub != "alice" {
		t.Fatalf("want alice's 1 device, got %+v", resp.Devices)
	}
}

func TestListDevices_IncludeDisabled(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{devices: []deviceattest.EnrolledDevice{
		{DeviceUUID: "1", UserSub: "a", Tier: "TIER_CORP", EnrolledAt: time.Now()},
		{DeviceUUID: "2", UserSub: "b", Tier: "TIER_CORP", EnrolledAt: time.Now(),
			DisabledAt: time.Now()},
	}}
	h := newAdminWithDevices(t, store)

	// Default: disabled hidden.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices", nil))
	var resp ListDevicesResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Devices) != 1 {
		t.Fatalf("default should hide disabled — got %d devices", len(resp.Devices))
	}

	// include_disabled=true: both visible.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices?include_disabled=true", nil))
	resp = ListDevicesResponse{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Devices) != 2 {
		t.Fatalf("include_disabled=true should show both — got %d", len(resp.Devices))
	}
}

func TestListDevices_BadLimit(t *testing.T) {
	t.Parallel()
	h := newAdminWithDevices(t, &fakeDeviceStore{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices?limit=-3", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestListDevices_NotConfigured_503(t *testing.T) {
	t.Parallel()
	v := &fakeAdminVerifier{identity: pdp.Identity{Subject: "x", Roles: []string{"platform_admin"}}}
	h := New(nil, v, "platform_admin") // no WithDeviceStore
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestDisableDevice_Success(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{devices: []deviceattest.EnrolledDevice{
		{DeviceUUID: "uuid-1", UserSub: "alice", Tier: "TIER_CORP", EnrolledAt: time.Now()},
	}}
	h := newAdminWithDevices(t, store)
	body := []byte(`{"reason":"laptop compromised"}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodPost, "/devices/uuid-1/disable", body))
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", w.Code, w.Body.String())
	}
	if store.devices[0].DisabledAt.IsZero() {
		t.Fatal("Disable() didn't stamp DisabledAt on the row")
	}
}

func TestDisableDevice_MissingReason_400(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{devices: []deviceattest.EnrolledDevice{
		{DeviceUUID: "uuid-1", UserSub: "a", Tier: "TIER_CORP", EnrolledAt: time.Now()},
	}}
	h := newAdminWithDevices(t, store)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodPost, "/devices/uuid-1/disable", []byte(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "reason required") {
		t.Errorf("error message missing 'reason required': %s", w.Body.String())
	}
}

func TestDisableDevice_NotFound_404(t *testing.T) {
	t.Parallel()
	store := &fakeDeviceStore{} // empty
	h := newAdminWithDevices(t, store)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodPost, "/devices/uuid-missing/disable",
		[]byte(`{"reason":"x"}`)))
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestDevices_WrongRole_403(t *testing.T) {
	t.Parallel()
	v := &fakeAdminVerifier{identity: pdp.Identity{Subject: "x", Roles: []string{"viewer"}}}
	h := New(nil, v, "platform_admin").WithDeviceStore(&fakeDeviceStore{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authReq(http.MethodGet, "/devices", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}
