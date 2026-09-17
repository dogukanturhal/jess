// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"sort"
	"sync"
	"time"
)

// pending.go — TOFU device auto-enroll review queue.
//
// The corporate-asset gate (cmd/jess-controller/device_attest_handler.go,
// Step 3b) downgrades a genuine-TPM TIER_CORP attestation to TIER_BYOD unless
// the device's EK pubkey hash was pre-registered as a corporate asset. Hand-
// collecting every device's EK hash is operationally painful. Instead, when the
// gate sees such a device (genuine TPM, would-be TIER_CORP, NOT a corporate
// asset), it ADDITIVELY records the EK here — a review queue an admin can
// approve, promoting the device to the corporate-asset allowlist (the same
// BulkPreRegister the manual CSV import uses). The device then earns TIER_CORP
// on its next attestation.
//
// IMPORTANT — this NEVER changes the attestation decision. Recording is purely
// observational; the tier downgrade/keep logic in the handler is untouched. A
// device stays BYOD/posture-only until an admin explicitly approves it. So
// there is no auto-escalation: TOFU here means "trust the EK on first SIGHT for
// the purpose of REVIEW", not "auto-grant CORP".

// PendingDevice is one genuine-TPM device observed attesting that is not (yet) a
// pre-registered corporate asset — a candidate for admin promotion.
type PendingDevice struct {
	EKHash      string    `json:"ek_hash"`
	DeviceUUID  string    `json:"device_uuid"`
	Platform    string    `json:"platform"`
	Subject     string    `json:"subject"`       // the operator sub that attested it
	WouldBeTier string    `json:"would_be_tier"` // the tier it'd earn if promoted (TIER_CORP)
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"` // attestations observed since first seen
}

// PendingObserver is the write side the attest handler holds. Kept tiny so the
// handler depends only on what it uses.
type PendingObserver interface {
	Observe(d PendingDevice)
}

// PendingDeviceStore is an in-memory, concurrent-safe review queue keyed by EK
// hash. Single jess-controller pod today (ADR 0030 Phase 5e, same as the rest
// of the controller's in-process state); a restart clears it and devices
// re-populate it on their next (daily, 24h-cert) attestation, so durability is
// not required for correctness — approving a row writes durably to Falcon-ID.
type PendingDeviceStore struct {
	mu  sync.Mutex
	by  map[string]PendingDevice
	now func() time.Time
}

// NewPendingDeviceStore builds an empty store.
func NewPendingDeviceStore() *PendingDeviceStore {
	return &PendingDeviceStore{by: map[string]PendingDevice{}, now: time.Now}
}

// Observe records (or refreshes) a pending device. Idempotent on EK hash: a
// repeat sighting bumps LastSeen/Count rather than duplicating. Empty EK hashes
// are ignored (the gate always has one here).
func (s *PendingDeviceStore) Observe(d PendingDevice) {
	if d.EKHash == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.now()
	if cur, ok := s.by[d.EKHash]; ok {
		cur.LastSeen = t
		cur.Count++
		if d.DeviceUUID != "" {
			cur.DeviceUUID = d.DeviceUUID
		}
		if d.Subject != "" {
			cur.Subject = d.Subject
		}
		s.by[d.EKHash] = cur
		return
	}
	d.FirstSeen = t
	d.LastSeen = t
	d.Count = 1
	s.by[d.EKHash] = d
}

// List returns the pending devices, newest-first by first sighting.
func (s *PendingDeviceStore) List() []PendingDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingDevice, 0, len(s.by))
	for _, d := range s.by {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.After(out[j].FirstSeen) })
	return out
}

// Take removes and returns a pending device by EK hash (used by approve, so the
// promote+remove is one logical step). ok=false if absent.
func (s *PendingDeviceStore) Take(ekHash string) (PendingDevice, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.by[ekHash]
	if ok {
		delete(s.by, ekHash)
	}
	return d, ok
}

// Delete drops a pending device without promoting it (reject). Returns whether
// a row was present.
func (s *PendingDeviceStore) Delete(ekHash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.by[ekHash]
	delete(s.by, ekHash)
	return ok
}
