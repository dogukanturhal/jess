// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"testing"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// Phase 5e-7 helper coverage — computeRecordingPath must stay in sync
// with internal/recording/bundle.go contentKey(). A drift here means
// the SPA-surfaced recording_path would not match the actual worker-
// side bundle storage key, and operator/SOC follow-ups land at a 404
// instead of the recording.

func TestComputeRecordingPathSSH(t *testing.T) {
	got := computeRecordingPath("sess-abc123", catalog.ProtoSSH)
	want := "sess-abc123/recording.cast"
	if got != want {
		t.Errorf("SSH path = %q, want %q (must match recording.contentKey())", got, want)
	}
}

func TestComputeRecordingPathTCPIsEmpty(t *testing.T) {
	if got := computeRecordingPath("sess-abc123", catalog.ProtoTCP); got != "" {
		t.Errorf("TCP path must be empty (not recorded today), got %q", got)
	}
}

func TestComputeRecordingPathPostgresIsEmpty(t *testing.T) {
	if got := computeRecordingPath("sess-abc123", catalog.ProtoPostgres); got != "" {
		t.Errorf("Postgres path must be empty, got %q", got)
	}
}

func TestComputeRecordingPathMySQLIsEmpty(t *testing.T) {
	if got := computeRecordingPath("sess-abc123", catalog.ProtoMySQL); got != "" {
		t.Errorf("MySQL path must be empty, got %q", got)
	}
}
