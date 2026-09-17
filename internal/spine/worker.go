// SPDX-License-Identifier: AGPL-3.0-or-later

package spine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/broker"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/dbproxy"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/mysqlproxy"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/sshproxy"
	"github.com/dogukanturhal/jess/internal/tunnel"
)

func sessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "s-" + hex.EncodeToString(b)
}

// WorkerRuntime is the data-plane worker: it dials the controller outbound and
// brokers each authorized session to its target. 5a handles raw TCP; 5b adds
// the SSH record-proxy. DB (5c) and rendering (5e, jess-web) add more handlers.
type WorkerRuntime struct {
	ID    string
	Cat   catalog.Catalog
	JIT   jit.GrantStore
	Audit audit.Sink

	// SSH, if set, enables the SSH record-proxy for ProtoSSH targets (5b).
	SSH *sshproxy.Config
	// DB, if set, enables the Postgres broker for ProtoPostgres targets (5c).
	DB *dbproxy.Config
	// MySQL, if set, enables the MySQL/MariaDB broker for ProtoMySQL targets (5c).
	MySQL *mysqlproxy.Config
	// CredBroker, if set, is the Vault credential broker the DB brokers mint
	// ephemeral per-session roles from (ADR 0049 Phase 2/4). When nil, the DB
	// brokers fall back to the proxy config's own CredsFor (the worker's existing
	// dbConfigFromVault / mysqlConfigFromVault Vault dynamic-creds wiring) — so a
	// worker configured the pre-broker way keeps minting creds exactly as before.
	CredBroker broker.CredentialBroker
	// Recorder, if set, captures sessions to tamper-evident signed WORM bundles
	// (e.g. recording.NewBundleRecorder over MinIO Object-Lock + Vault Transit).
	// nil = no recording; a target with Recorded=true is denied if it is nil.
	Recorder recording.Recorder
}

// Run maintains an outbound connection to EVERY controller address (each with
// its own reconnect loop), serving the sessions any controller opens. Dialing
// all controllers is what lets ≥2 stateless controllers behind a load balancer
// each route sessions to this worker (HA); the shared Postgres grant store keeps
// their authorization decisions consistent. Blocks until ctx is cancelled.
func (w *WorkerRuntime) Run(ctx context.Context, controllerAddrs []string, tlsCfg *tls.Config) error {
	if len(controllerAddrs) == 0 {
		return fmt.Errorf("jess-worker: no controller addresses configured")
	}
	var wg sync.WaitGroup
	for _, addr := range controllerAddrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			yw := tunnel.NewYamuxWorker(tlsCfg)
			for {
				_ = yw.Dial(ctx, addr, w.handle) // returns when the conn drops
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(3 * time.Second): // reconnect backoff
				}
			}
		}(addr)
	}
	wg.Wait()
	return ctx.Err()
}

func (w *WorkerRuntime) handle(s tunnel.SessionStream) {
	defer s.Close()
	ctx := context.Background()
	h := s.Header()

	// Defense in depth: the worker re-checks the grant carried in the header,
	// independent of the controller's check.
	if _, err := w.JIT.AssertActiveID(ctx, h.GrantID, h.TargetID); err != nil {
		w.emit(ctx, audit.Event{Action: "deny", TargetID: h.TargetID, Protocol: h.Protocol, Err: err.Error()})
		return
	}

	target, err := w.Cat.Lookup(ctx, h.TargetID)
	if err != nil {
		w.emit(ctx, audit.Event{Action: "deny", TargetID: h.TargetID, Protocol: h.Protocol, Err: err.Error()})
		return
	}

	// Honour the controller-resolved EFFECTIVE recording decision (the
	// per-target admin recording override resolved against the catalog
	// default). When the controller propagated it (h.Recorded != nil),
	// it overrides this worker's own static catalog `recorded` flag so an
	// admin's runtime toggle is authoritative — the broker's fail-closed
	// recording semantics then key off the effective value. nil (old
	// controller / no override store) leaves target.Recorded untouched, so
	// the worker behaves exactly as before. We shallow-COPY the target so
	// we never mutate the shared in-memory catalog entry (the next session
	// to the same target must re-derive its own effective value).
	if h.Recorded != nil && *h.Recorded != target.Recorded {
		t := *target
		t.Recorded = *h.Recorded
		target = &t
	}

	switch target.Protocol {
	case catalog.ProtoTCP:
		w.emit(ctx, audit.Event{Action: "open", TargetID: target.ID, Protocol: string(target.Protocol), Region: target.Region})
		up, down, perr := broker.ProxyTCP(ctx, target.Address, s)
		ev := audit.Event{Action: "close", TargetID: target.ID, Protocol: string(target.Protocol), Region: target.Region, Bytes: up + down}
		if perr != nil {
			ev.Err = perr.Error()
		}
		w.emit(ctx, ev)

	case catalog.ProtoSSH:
		if w.SSH == nil {
			w.emit(ctx, audit.Event{Action: "deny", TargetID: target.ID, Protocol: string(target.Protocol), Err: "ssh proxy not configured on this worker"})
			return
		}
		// ADR 0049 Phase 0: the SSH path now runs behind the broker.Broker seam
		// (the reference protocol implementation), with no behaviour change. The
		// broker wraps this worker's existing sshproxy.Config + Recorder; mint +
		// dial + WORM teeing + fail-closed semantics are identical to the
		// pre-refactor path — only re-expressed through the interface.
		w.handleBroker(ctx, broker.NewSSHBroker(w.SSH, w.Recorder), s, target, h)

	case catalog.ProtoPostgres:
		if w.DB == nil {
			w.emit(ctx, audit.Event{Action: "deny", TargetID: target.ID, Protocol: string(target.Protocol), Err: "db broker not configured on this worker"})
			return
		}
		// ADR 0049 Phase 2: the Postgres path now runs behind the broker.Broker
		// seam (like SSH), so DB sessions get the Vault-ephemeral per-session role,
		// the per-statement WORM query log, and the per-statement policy seam —
		// fail-closed on a Recorded=true target that can't record, identical to the
		// SSH broker. The broker reuses w.DB's existing CredsFor (proxy-creds mode)
		// when w.CredBroker is nil, so the prod DSN/role wiring is unchanged.
		w.handleBroker(ctx, broker.NewPostgresBroker(w.DB, w.CredBroker, w.Recorder), s, target, h)

	case catalog.ProtoMySQL:
		if w.MySQL == nil {
			w.emit(ctx, audit.Event{Action: "deny", TargetID: target.ID, Protocol: string(target.Protocol), Err: "mysql broker not configured on this worker"})
			return
		}
		// ADR 0049 Phase 4: the MySQL path runs behind the broker.Broker seam too
		// (the MySQL twin of the Postgres arm above) — same ephemeral-cred + WORM
		// query-log + policy seam + fail-closed recording semantics.
		w.handleBroker(ctx, broker.NewMySQLBroker(w.MySQL, w.CredBroker, w.Recorder), s, target, h)

	default:
		// RDP/web-SSH (5e) handled here later.
		w.emit(ctx, audit.Event{Action: "deny", TargetID: target.ID, Protocol: string(target.Protocol), Err: "protocol not supported yet"})
	}
}

// handleBroker runs one authorized session through a broker.Broker end-to-end —
// the shared Mint→Dial→Wait→Close spine every protocol uses (ADR 0049). It
// builds the protocol-agnostic AccessGrant from the controller header (5e-7
// session id + 5e-20 chain link, same as the SSH path), mints the per-session
// backend credential, dials the target (fail-closed when a Recorded=true target
// can't record), runs the recorded relay, and seals the bundle on Close. A Mint
// or Dial failure denies the session; the session's terminal error is audited on
// close. Used by the SSH, Postgres and MySQL arms.
func (w *WorkerRuntime) handleBroker(ctx context.Context, b broker.Broker, s tunnel.SessionStream, target *catalog.Target, h tunnel.SessionHeader) {
	grant := broker.AccessGrant{
		Target: target, GrantID: h.GrantID, Subject: h.Subject,
		// Phase 5e-7: prefer the controller-supplied session id so the bundle
		// storage key matches jit_sessions.id (the broker falls back to a local id
		// when empty, as the worker did).
		SessionID: h.SessionID,
		// Phase 5e-20: pin the chain link into the manifest so bundle-verify can
		// cross-check vs the live row_hash.
		SessionRowHash: h.SessionRowHash,
		Client:         s,
	}
	cred, merr := b.Mint(ctx, grant)
	if merr != nil {
		w.emit(ctx, audit.Event{Action: "deny", TargetID: target.ID, Protocol: string(target.Protocol), Err: merr.Error()})
		return
	}
	rc, derr := b.Dial(ctx, target, cred)
	if derr != nil {
		// Dial denies fail-closed when a Recorded=true target can't record
		// (recorder errored, or none configured).
		w.emit(ctx, audit.Event{Action: "deny", TargetID: target.ID, Protocol: string(target.Protocol), Err: derr.Error()})
		return
	}
	defer rc.Close() // Close seals the signed bundle to WORM
	w.emit(ctx, audit.Event{Action: "open", Subject: h.Subject, TargetID: target.ID, Protocol: string(target.Protocol), Region: target.Region})
	serr := rc.Wait()
	ev := audit.Event{Action: "close", TargetID: target.ID, Protocol: string(target.Protocol), Region: target.Region}
	if serr != nil {
		ev.Err = serr.Error()
	}
	w.emit(ctx, ev)
}

func (w *WorkerRuntime) emit(ctx context.Context, ev audit.Event) {
	if w.Audit != nil {
		_ = w.Audit.Emit(ctx, ev)
	}
}
