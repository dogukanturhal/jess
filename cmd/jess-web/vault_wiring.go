// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Vault client wiring for jess-web. Used by svc_cert.go to mint a
// short-lived service cert from the jess-ca PKI mount, presented on
// the outbound mTLS dial to the controller's operator port. Mirrors
// cmd/jess-controller/vault_wiring.go — different SA + Vault role,
// same Vault address + auth shape.

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// newWebVaultClient builds the Vault client for jess-web. Env config:
//
//	JESS_VAULT_ADDR        e.g. http://vault-ha.vault.svc.cluster.local:8200
//	JESS_VAULT_TOKEN       static token (dev only)
//	JESS_VAULT_K8S_MOUNT   default "kubernetes"
//	JESS_VAULT_K8S_ROLE    e.g. "jess-web" (declared in iac vault-jess-ca-pki.tf —
//	                       new role separate from "jess-controller" because the
//	                       PKI policy is scoped to a different sign endpoint)
//
// Caller checks whether Vault is enabled via the env presence — this
// function returns an error if neither token nor role is configured.
func newWebVaultClient() (*vaultx.Client, error) {
	addr := env("JESS_VAULT_ADDR", "")
	if addr == "" {
		return nil, fmt.Errorf("JESS_VAULT_ADDR required for Vault PKI svc-cert")
	}
	return vaultx.New(vaultx.Config{
		Addr:     addr,
		Token:    env("JESS_VAULT_TOKEN", ""),
		K8sMount: env("JESS_VAULT_K8S_MOUNT", "kubernetes"),
		K8sRole:  env("JESS_VAULT_K8S_ROLE", ""),
	})
}

// recorderFromVault builds a signed WORM recorder (MinIO Object-Lock store
// + Vault Transit signer), or nil if JESS_REC_S3_ENDPOINT is unset.
// Mirrors cmd/jess-worker/vault_wiring.go::recorderFromVault — same env
// names so a single Helm values block can wire both pods.
//
// jess-web only needs this for the Phase 5h-3b HTTP proxy: browser
// admin sessions go through the proxy and the resulting NDJSON stream
// goes into the same audit-archive bucket as terminal recordings, so
// SOC2 evidence pulls one bucket not two.
//
// The second return is the DDIL P3.6 store-and-forward handle (non-nil when
// buffering is enabled). The caller starts its background reconciler with
// `go spool.Run(ctx)` bound to the process lifetime.
func recorderFromVault(ctx context.Context, vc *vaultx.Client) (recording.Recorder, *recording.SpoolStore, error) {
	endpoint := env("JESS_REC_S3_ENDPOINT", "")
	if endpoint == "" || vc == nil {
		return nil, nil, nil
	}
	store, err := recording.NewS3Store(recording.S3Config{
		Endpoint:  endpoint,
		AccessKey: env("JESS_REC_S3_ACCESS_KEY", ""),
		SecretKey: env("JESS_REC_S3_SECRET_KEY", ""),
		Bucket:    env("JESS_REC_S3_BUCKET", "audit-archive"),
		UseSSL:    env("JESS_REC_S3_USE_SSL", "true") != "false",
		Mode:      env("JESS_REC_S3_MODE", "COMPLIANCE"),
		Retention: durationEnv("JESS_REC_RETENTION", 7*365*24*time.Hour),
		Region:    env("JESS_REC_S3_REGION", ""),
	})
	if err != nil {
		return nil, nil, err
	}

	// DDIL P3.6: wrap the WORM store with a durable local store-and-forward spool
	// (default ON). A recording that cannot reach MinIO is buffered locally and
	// reconciled on reconnect instead of denying/losing the session; if the local
	// buffer itself fails, Put fails closed. Set JESS_REC_SPOOL_ENABLED=false to
	// restore the legacy fail-at-seal behaviour.
	var objStore recording.ObjectStore = store
	var spoolStore *recording.SpoolStore
	if env("JESS_REC_SPOOL_ENABLED", "true") != "false" {
		ss, serr := recording.NewSpoolStore(store, recording.SpoolConfig{
			Dir:            env("JESS_REC_SPOOL_DIR", defaultRecSpoolDir),
			MaxAge:         durationEnv("JESS_REC_SPOOL_MAX_AGE", 30*24*time.Hour),
			MaxBytes:       int64Env("JESS_REC_SPOOL_MAX_BYTES", 0),
			MaxRecords:     intEnv("JESS_REC_SPOOL_MAX_RECORDS", 0),
			ReconcileEvery: durationEnv("JESS_REC_SPOOL_RECONCILE_INTERVAL", 30*time.Second),
		})
		if serr != nil {
			return nil, nil, fmt.Errorf("recording store-and-forward spool: %w", serr)
		}
		objStore, spoolStore = ss, ss
	}

	signer, err := vaultx.NewTransitSigner(ctx, vc,
		env("JESS_REC_TRANSIT_MOUNT", "transit"),
		env("JESS_REC_TRANSIT_KEY", "jess-recordings"))
	if err != nil {
		return nil, nil, err
	}
	return recording.NewBundleRecorder(objStore, signer), spoolStore, nil
}

// defaultRecSpoolDir is the on-disk location of the WORM store-and-forward spool
// when JESS_REC_SPOOL_DIR is unset. A dedicated per-pod path (mount a volume in
// prod so buffered recordings survive a pod restart during a MinIO outage).
const defaultRecSpoolDir = "/var/lib/jess/recording-spool"

// intEnv parses an int env var, falling back to def on unset/parse-failure.
func intEnv(k string, def int) int {
	if v := env(k, ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// int64Env parses an int64 env var, falling back to def on unset/parse-failure.
func int64Env(k string, def int64) int64 {
	if v := env(k, ""); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func durationEnv(k string, def time.Duration) time.Duration {
	if v := env(k, ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return def
}
