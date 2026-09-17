// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Optional MinIO read client for the controller's recording-stream
// endpoint (admin GET /sessions/{id}/recording, served by
// internal/admin.SessionsHandler).
//
// The worker is the canonical writer of recording bundles via
// cmd/jess-worker/vault_wiring.go recorderFromVault. The controller
// only needs READ access — and only when the operator UI surface
// (SPA in-browser asciinema-player) wants to stream the bundle.
// Without this, the SPA falls back to the MinIO Console deep link
// from Phase 5e-9 (operator's SSO carries auth at Console-side).
//
// Env config (mirrors the worker's JESS_REC_S3_* set so a single
// MinIO credential pair can serve both pods):
//
//	JESS_REC_S3_ENDPOINT       host:port (no scheme)
//	JESS_REC_S3_ACCESS_KEY     IAM access key
//	JESS_REC_S3_SECRET_KEY     IAM secret key
//	JESS_REC_S3_BUCKET         default "audit-archive"
//	JESS_REC_S3_USE_SSL        default "true"
//	JESS_REC_S3_REGION         optional
//
// Returns nil (silently) when JESS_REC_S3_ENDPOINT is unset —
// admin.NewSessions().WithRecordings(nil) leaves the endpoint
// unconfigured and it surfaces 503.

import (
	"log"

	"github.com/dogukanturhal/jess/internal/recording"
)

func recordingReaderFromEnv() *recording.S3Store {
	endpoint := env("JESS_REC_S3_ENDPOINT", "")
	if endpoint == "" {
		return nil
	}
	store, err := recording.NewS3Store(recording.S3Config{
		Endpoint:  endpoint,
		AccessKey: env("JESS_REC_S3_ACCESS_KEY", ""),
		SecretKey: env("JESS_REC_S3_SECRET_KEY", ""),
		Bucket:    env("JESS_REC_S3_BUCKET", "audit-archive"),
		UseSSL:    env("JESS_REC_S3_USE_SSL", "true") != "false",
		Region:    env("JESS_REC_S3_REGION", ""),
		// Retention + Mode are write-side concerns; default-zero is
		// fine since we never call Put on this store.
	})
	if err != nil {
		log.Printf("jess-controller: recording-reader init failed: %v (SPA player will fall back to MinIO Console deep link)", err)
		return nil
	}
	return store
}
