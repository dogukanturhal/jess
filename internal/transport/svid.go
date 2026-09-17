// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIRE SVID mTLS defaults for the jess controller↔worker link. These match the
// 2026-07-19 SPIFFE/SPIRE identity foundation design: a per-environment trust
// domain (prod.hexxlock) with per-component workload IDs differentiated by pod
// label. Override each via its JESS_SPIRE_* env var.
const (
	// DefaultSpireSocket is the SPIRE Agent Workload API address (the standard
	// spiffe-csi-driver mount path used by the platform SPIRE deployment).
	// Override with JESS_SPIRE_SOCKET.
	DefaultSpireSocket = "unix:///spiffe-workload-api/spire-agent.sock"
	// DefaultSpireTrustDomain is the production SPIFFE trust domain. Override
	// with JESS_SPIRE_TRUST_DOMAIN.
	DefaultSpireTrustDomain = "prod.hexxlock"
	// DefaultControllerSPIFFEID is the controller's registered SPIFFE ID; the
	// worker pins it. Override with JESS_SPIRE_CONTROLLER_ID.
	DefaultControllerSPIFFEID = "spiffe://prod.hexxlock/ns/jess/sa/jess/controller"
	// DefaultWorkerSPIFFEID is the worker's registered SPIFFE ID; the
	// controller pins it. Override with JESS_SPIRE_WORKER_ID.
	DefaultWorkerSPIFFEID = "spiffe://prod.hexxlock/ns/jess/sa/jess/worker"
)

// DefaultSVIDDialTimeout bounds the initial Workload API fetch so a present-but-
// not-ready SPIRE Agent can't wedge process startup — it falls back to file-PEM
// instead.
const DefaultSVIDDialTimeout = 5 * time.Second

// AcquireSVIDSource acquires an auto-rotating Workload-API X.509-SVID source for
// SVID mTLS, gated so it stays INERT until SPIRE is actually deployed AND the
// dual-auth feature flag is switched on. It NEVER hard-fails on SPIRE being
// down — SPIRE unavailability degrades to the legacy file-PEM mTLS path:
//
//   - enabled == false (JESS_SPIRE_SVID off, the default): returns
//     (nil, false, nil) immediately — the caller stays on file-PEM mTLS.
//   - enabled == true but the Workload API socket is absent (SPIRE not deployed
//     on this node): logs and returns (nil, false, nil) — file-PEM fallback.
//   - enabled == true but the agent yields no SVID within timeout (SPIRE present
//     but not ready): logs and returns (nil, false, nil) — file-PEM fallback.
//   - enabled == true and a source is obtained: returns (src, true, nil). The
//     caller builds SVIDServerConfig / SVIDClientConfig and MUST Close src on
//     shutdown.
//
// An error is returned ONLY for a genuinely malformed socket address — a config
// typo the operator should see, not a transient SPIRE outage.
func AcquireSVIDSource(ctx context.Context, enabled bool, socket string, timeout time.Duration) (*workloadapi.X509Source, bool, error) {
	if !enabled {
		return nil, false, nil
	}
	if socket == "" {
		return nil, false, fmt.Errorf("transport: JESS_SPIRE_SVID enabled but socket address is empty")
	}
	// Fast, non-blocking probe for the common "SPIRE not deployed yet" case: a
	// unix:// socket whose file doesn't exist. Avoids a timeout-length stall on
	// every boot while SPIRE is absent. Non-unix schemes (e.g. tcp://) skip the
	// probe and rely on the bounded dial below.
	if path, ok := unixSocketPath(socket); ok {
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Printf("transport: JESS_SPIRE_SVID on but SPIRE Workload API socket %s is absent — staying on file-PEM mTLS (SPIRE not deployed)", socket)
			} else {
				log.Printf("transport: JESS_SPIRE_SVID on but SPIRE Workload API socket %s is unreachable (%v) — staying on file-PEM mTLS", socket, err)
			}
			return nil, false, nil
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	src, err := NewSPIFFESource(dialCtx, socket)
	if err != nil {
		// Socket present but no SVID in time (agent starting, entry not yet
		// registered, ...). Degrade to file-PEM rather than crash-loop.
		log.Printf("transport: JESS_SPIRE_SVID on but SPIRE Workload API at %s yielded no SVID within %s (%v) — staying on file-PEM mTLS", socket, timeout, err)
		return nil, false, nil
	}
	return src, true, nil
}

// unixSocketPath extracts the filesystem path from a unix:// Workload API
// address, reporting ok=false for non-unix schemes where a filesystem
// existence probe does not apply.
func unixSocketPath(addr string) (path string, ok bool) {
	const scheme = "unix://"
	if !strings.HasPrefix(addr, scheme) {
		return "", false
	}
	return strings.TrimPrefix(addr, scheme), true
}
