// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// DDIL Phase-3 (P3.6): durable store-and-forward for session recordings.
//
// Before this, a must-record session whose WORM sink (MinIO Object-Lock) was
// unreachable at seal time lost its recording (the seal Put failed) — a
// compliance-gated target's availability was hostage to the audit bucket's
// availability. This wraps the production WORM ObjectStore with
// hexx-pep-core/pkg/spool so a recording bundle that cannot reach WORM is
// buffered locally (fsync'd, atomic write-then-rename, bounded retention,
// per-record hash-chained, never silently dropped) and reconciled into the WORM
// bucket on reconnect. The session is thus ALLOWED to proceed while the sink is
// down — the recording is still captured durably and guaranteed to reach WORM —
// instead of being denied/lost.
//
// Fail-closed is preserved for the case that matters: if the primary sink is
// unreachable AND the local buffer itself cannot durably accept the object, Put
// returns an error, so the bundle seal fails and the session is denied/failed.
// A must-record session never completes with its recording neither in WORM nor
// on durable local disk. Genuine sink REJECTIONS (auth/permission/no-bucket/bad
// request — 4xx) are surfaced too, not masked as a partition.
//
// Chain preservation (the DDIL requirement): the bundle's manifest — which
// carries the jit_sessions cross-session chain link (Meta.SessionRowHash, see
// jit.ComputeRowHash) — and its detached Ed25519 signature are computed at seal
// time, BEFORE buffering. This store buffers and later replays the manifest,
// signature and content BYTE-FOR-BYTE. Reconciliation is an exact replay, never
// a re-seal/re-sign, so the content SHA-256, the signature over the manifest,
// and the SessionRowHash linkage all survive the offline window intact. The
// spool additionally chains every buffered object (seq/prev_hash, compatible
// with pkg/chain) so any gap or mutation in the local buffer is detectable on
// drain. Ordering is preserved (content → manifest → sig) because seal emits
// them in that order on one goroutine and the spool forwards in sequence order.
//
// Compliance: NIST SP 800-53 CP-7 (equivalent security at the alternate
// site / degraded-mode operation), AU-4 (audit storage capacity, no loss) and
// AU-9 (protection of audit information) under a WORM-sink partition.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/dogukanturhal/hexx-pep-core/pkg/spool"
)

// spoolSource is the logical stream identity stamped into every buffered record
// (drives the spool's per-source monotonic seq / prev_hash chain).
const spoolSource = "jess-recording-worm"

// defaultReconcileEvery is the background drain cadence when a caller does not
// configure one. Short enough that a recovered sink drains promptly; the loop
// also drains immediately whenever a Put buffers (signalled), so this is only
// the fallback poll for a sink that recovers silently.
const defaultReconcileEvery = 30 * time.Second

// SpoolConfig configures a SpoolStore's local buffer.
type SpoolConfig struct {
	// Dir is the local spool directory (single-writer). Required.
	Dir string
	// MaxAge is the local retention window; 0 => the spool default (30 days),
	// which satisfies the DDIL spec's ">=30 days local" requirement.
	MaxAge time.Duration
	// MaxBytes caps on-disk pending bytes; 0 => unlimited (bounded by MaxAge and
	// the disk). On overflow the store applies BACKPRESSURE (never silent drop):
	// Enqueue fails, so Put fails closed and the must-record session is denied.
	MaxBytes int64
	// MaxRecords caps pending record count; 0 => unlimited. Same backpressure
	// semantics as MaxBytes.
	MaxRecords int
	// ReconcileEvery is the background drain cadence; 0 => defaultReconcileEvery.
	ReconcileEvery time.Duration
	// Logger receives buffer/reconcile/drop lines; nil => the standard logger.
	Logger *log.Logger
}

// SpoolStore is a durable store-and-forward ObjectStore wrapping a primary WORM
// store (S3Store/MinIO). It implements ObjectStore and ObjectLister so it is a
// drop-in behind BundleRecorder.
type SpoolStore struct {
	primary        ObjectStore
	sp             *spool.FileSpool
	reconcileEvery time.Duration
	log            *log.Logger

	// wake is a size-1 signal so a Put that buffers nudges the reconcile loop
	// without blocking or coalescing more than one pending wake.
	wake chan struct{}

	// reconcileMu serialises Reconcile callers (the loop + any manual call).
	reconcileMu sync.Mutex
}

// spoolPayload is the durable envelope for one WORM object: its store key and
// the exact bytes to Put. Replayed verbatim on reconcile (byte-for-byte), which
// is what preserves the manifest signature / content hash / chain linkage.
type spoolPayload struct {
	Key  string `json:"key"`
	Data []byte `json:"data"`
}

// NewSpoolStore wraps primary with a durable local spool rooted at cfg.Dir.
// Opening the spool validates the directory is usable NOW (startup fail-closed:
// a node that cannot durably buffer must not silently run must-record brokering
// without the guarantee). The caller starts the background reconciler with Run.
func NewSpoolStore(primary ObjectStore, cfg SpoolConfig) (*SpoolStore, error) {
	if primary == nil {
		return nil, errors.New("recording: SpoolStore requires a primary ObjectStore")
	}
	if cfg.Dir == "" {
		return nil, errors.New("recording: SpoolStore requires a spool Dir")
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.Default()
	}
	sp, err := spool.Open(spool.Config{
		Dir:        cfg.Dir,
		Source:     spoolSource,
		MaxAge:     cfg.MaxAge, // 0 => spool default (30d)
		MaxBytes:   cfg.MaxBytes,
		MaxRecords: cfg.MaxRecords,
		// Backpressure (not DropOldest): audit recordings must never be silently
		// dropped to make room. On overflow Enqueue fails => Put fails closed =>
		// the must-record session is denied, which is the correct degraded
		// behaviour when the local buffer is exhausted.
		Overflow: spool.Backpressure,
		DropLogger: spool.DropLoggerFunc(func(rec spool.Record, reason string) {
			// Only reached for age-based eviction (>=30d unreconciled). Loud, never
			// silent — a standing program rule.
			lg.Printf("recording: SPOOL DROP seq=%d reason=%s enqueued=%s — an audit recording aged out of the local buffer before reaching WORM",
				rec.Seq, reason, rec.EnqueuedAt.UTC().Format(time.RFC3339))
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("recording: open store-and-forward spool at %s: %w", cfg.Dir, err)
	}
	every := cfg.ReconcileEvery
	if every <= 0 {
		every = defaultReconcileEvery
	}
	return &SpoolStore{
		primary:        primary,
		sp:             sp,
		reconcileEvery: every,
		log:            lg,
		wake:           make(chan struct{}, 1),
	}, nil
}

// Put stores an object to WORM, degrading to the durable local spool when the
// sink is unreachable. See the package-level doc for the full contract.
func (s *SpoolStore) Put(ctx context.Context, key string, data []byte) error {
	// Strict FIFO under backlog: once anything is buffered, route new objects
	// through the spool too, so no object lands in WORM ahead of an older
	// buffered object (preserves content->manifest->sig ordering the verifier
	// relies on). The reconciler is then the single writer, draining in order.
	if s.pending() > 0 {
		if err := s.buffer(ctx, key, data, "backlog"); err != nil {
			return err
		}
		s.signalWake()
		return nil
	}

	err := s.primary.Put(ctx, key, data)
	if err == nil {
		return nil
	}
	if !retryableSinkErr(err) {
		// Genuine rejection (auth/permission/no-bucket/bad-request). Do NOT mask a
		// real audit-integrity problem as a partition — fail closed and surface it.
		return fmt.Errorf("recording: WORM put %q failed (non-retryable, fail-closed): %w", key, err)
	}
	// Sink unreachable / throttling / 5xx: buffer durably so the session proceeds.
	if berr := s.buffer(ctx, key, data, "sink-unreachable"); berr != nil {
		// Local capture failed too — fail closed (deny the session): a must-record
		// recording that can reach neither WORM nor durable local disk is an audit
		// gap we refuse to run into.
		return fmt.Errorf("recording: WORM sink unreachable for %q (%v) AND durable local buffer failed — fail closed: %w", key, err, berr)
	}
	s.signalWake()
	return nil
}

// buffer durably enqueues one object. A non-nil return means the local buffer
// could not accept it (backpressure / disk / closed) — the caller fails closed.
func (s *SpoolStore) buffer(ctx context.Context, key string, data []byte, reason string) error {
	payload, err := json.Marshal(spoolPayload{Key: key, Data: data})
	if err != nil {
		return fmt.Errorf("marshal spool payload for %q: %w", key, err)
	}
	rec, err := s.sp.Enqueue(ctx, payload)
	if err != nil {
		return fmt.Errorf("enqueue %q to durable spool: %w", key, err)
	}
	s.log.Printf("recording: WORM sink %s — buffered %q durably (spool seq=%d pending=%d)", reason, key, rec.Seq, s.pending())
	return nil
}

// Get reads an object back from the primary WORM store. Objects still buffered
// locally (not yet reconciled) are NOT served here — read paths (verify/replay)
// inherently need the sink up, and returning a partition-window object would
// blur "durably captured, en route to WORM" with "in WORM". Once reconciled,
// Get behaves normally.
func (s *SpoolStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.primary.Get(ctx, key)
}

// List enumerates sealed bundles from the primary store (buffered-but-not-yet-
// reconciled bundles do not list until drained). Returns nil if the primary is
// not an ObjectLister.
func (s *SpoolStore) List(ctx context.Context, prefix string) ([]string, error) {
	if l, ok := s.primary.(ObjectLister); ok {
		return l.List(ctx, prefix)
	}
	return nil, nil
}

// Reconcile drains buffered objects into the primary WORM store in sequence
// order, deleting each after a successful Put. Idempotent: a re-presented record
// (crash between forward and delete) is a harmless re-PUT to the same
// deterministic WORM key. It stops at the first still-unreachable-sink error
// (retried next tick) or a genuine rejection (surfaced loudly; the queue HOLDS
// — never a gap, never a silent drop). Returns the number forwarded.
func (s *SpoolStore) Reconcile(ctx context.Context) (int, error) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	sink := spool.SinkFunc(func(ctx context.Context, rec spool.Record) error {
		var p spoolPayload
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			// The spool verifies each record's hash before handing it over, so a
			// decode failure here is an integrity event, not a transient one. Return
			// the error to HOLD the queue (never skip => never a gap) and surface it.
			s.log.Printf("recording: SPOOL PAYLOAD DECODE FAILED seq=%d: %v — holding queue (audit integrity)", rec.Seq, err)
			return fmt.Errorf("decode spool payload seq=%d: %w", rec.Seq, err)
		}
		if err := s.primary.Put(ctx, p.Key, p.Data); err != nil {
			if isAlreadyStored(err) {
				return nil // already durable in WORM — idempotent success
			}
			return err
		}
		return nil
	})

	n, err := s.sp.Reconcile(ctx, sink)
	if n > 0 {
		s.log.Printf("recording: reconciled %d buffered WORM object(s) to the sink (pending=%d)", n, s.pending())
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Printf("recording: WORM reconcile halted with %d pending (retrying): %v", s.pending(), err)
	}
	return n, err
}

// Run is the background reconcile loop: it drains once on start (to flush
// anything a previous crash/restart left buffered), then on every tick and
// whenever a Put buffers, until ctx is cancelled.
func (s *SpoolStore) Run(ctx context.Context) {
	if _, err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
		s.log.Printf("recording: initial WORM reconcile: %v", err)
	}
	t := time.NewTicker(s.reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
		if ctx.Err() != nil {
			return
		}
		_, _ = s.Reconcile(ctx) // Reconcile already logs; errors are retried next cycle
	}
}

// Pending reports how many objects are buffered awaiting WORM (metrics / alerts:
// a persistently growing backlog means the sink is down or a record is wedged).
func (s *SpoolStore) Pending() int { return s.pending() }

// Stats exposes the underlying spool snapshot for metrics.
func (s *SpoolStore) Stats() spool.Stats { return s.sp.Stats() }

// Close releases the spool (durable; buffered records persist for a later run).
func (s *SpoolStore) Close() error { return s.sp.Close() }

func (s *SpoolStore) pending() int { return s.sp.Stats().Pending }

func (s *SpoolStore) signalWake() {
	select {
	case s.wake <- struct{}{}:
	default: // a wake is already pending; coalesce
	}
}

// retryableSinkErr classifies a primary-Put error as a transient
// availability/partition failure (=> buffer durably and degrade) versus a
// genuine rejection (=> fail closed, do not mask). Best-practice (AWS S3 retry
// guidance): retry 500 and 503 — S3/MinIO signals throttling as 503, not 429 —
// and surface 4xx (AccessDenied/NoSuchBucket/bad-request), which retrying can't
// fix. Transport failures with no HTTP response (DNS, refused, reset, TLS,
// timeout) are the DDIL partition case and are retryable.
func retryableSinkErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	// MinIO server-side verdict (unwrapped from S3Store's %w wrapping via As).
	var mErr minio.ErrorResponse
	if errors.As(err, &mErr) && mErr.StatusCode != 0 {
		switch {
		case mErr.StatusCode >= 500: // 500 InternalError, 503 SlowDown/ServiceUnavailable, 502, 504
			return true
		case mErr.StatusCode == 408 || mErr.StatusCode == 429: // RequestTimeout / throttle
			return true
		default: // 4xx client/auth/config error => genuine rejection
			return false
		}
	}
	// No HTTP response => transport/connectivity failure => partition => buffer.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// Unknown, non-HTTP error with no server verdict: favour availability. The
	// buffer is durable, bounded, hash-chained and every drop is logged, and the
	// reconciler keeps retrying — so a mis-classified transient is safely queued,
	// while a mis-classified permanent error surfaces as a growing, alertable
	// backlog rather than a silently-lost recording.
	return true
}

// isAlreadyStored reports whether a reconcile-time Put "failed" only because the
// object is already durable in WORM (the narrow at-least-once re-present case).
// PUT to a deterministic key is normally an idempotent upsert; under
// Object-Lock some configs answer a re-PUT with a conflict/precondition — treat
// that as success so the drain makes progress. Auth/permission errors are NOT
// swallowed here (they must halt the queue for an operator to see).
func isAlreadyStored(err error) bool {
	if err == nil {
		return true
	}
	var mErr minio.ErrorResponse
	if errors.As(err, &mErr) {
		switch mErr.StatusCode {
		case 409, 412: // Conflict / PreconditionFailed
			return true
		}
		switch mErr.Code {
		case "PreconditionFailed", "MethodNotAllowed":
			return true
		}
	}
	return false
}

// Compile-time guards: SpoolStore is a drop-in ObjectStore + ObjectLister.
var (
	_ ObjectStore  = (*SpoolStore)(nil)
	_ ObjectLister = (*SpoolStore)(nil)
)
