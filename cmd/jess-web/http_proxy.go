// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5h-3b — jess-web HTTP proxy handler.
//
// Browser-recorded admin access to in-cluster HTTP services. Today
// covers ONE upstream (the JESS_HTTP_PROXY_TARGETS config map drives
// which); the URL/cookie rewriting that's needed for SPA upstreams
// like ArgoCD lands in 5h-3c.
//
// Wire shape:
//
//   operator browser
//     ↓  https://internal.example.com/proxy/<service>/<path>
//     ↓  (cookie session — operator already signed into jess-web)
//     ↓
//   jess-web /proxy handler
//     ↓  authentication (cookie → Operator)
//     ↓  service lookup (JESS_HTTP_PROXY_TARGETS)
//     ↓  per-session recording.HTTPWriter (committed to MinIO WORM
//        + chained to the 5e-16 cross-session WORM chain on close)
//     ↓
//   upstream Service (e.g. grafana.monitoring.svc:80)
//
// What this commit ships:
//   * Proxy reverse-dialing one configured upstream (Grafana
//     suggested — flat URL structure, no SPA-rewrite gotchas)
//   * Per-operator session recording: one HTTPWriter per
//     (operator_sub, service) pair, sealed on idle-out (30 min)
//     OR explicit close (5h-3d SPA disconnect button)
//   * Body capture under the 5h-3a 64KiB-per-direction cap
//   * Sensitive-header redaction (Authorization/Cookie/Set-Cookie)
//     by default; opt-in via JESS_HTTP_PROXY_CAPTURE_SENSITIVE=true
//     for forensic mode (must be paired with audit policy for
//     who can read the resulting bundle)
//
// What 5h-3c will add:
//   * Subpath URL rewriting (so https://jess.ops/proxy/argocd/foo
//     correctly routes when ArgoCD emits absolute /foo links in its
//     SPA bundle)
//   * Cookie scope rewriting (upstream cookies set on
//     grafana.monitoring.svc; need rewrite to jess.ops scope)
//   * WebSocket pass-through for ArgoCD pod-log streams, kind:"ws"
//     frames in the recording
//
// What 5h-3d will add:
//   * SPA UI: "Open Grafana" button per available service
//   * Recording-replay player extension for HTTP timeline

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/recording"
)

// httpProxyConfig holds per-process configuration. Built once at
// jess-web startup from env, then passed to every proxy handler.
type httpProxyConfig struct {
	// targets maps service name → upstream URL (host[:port] only,
	// scheme defaulted to http). One entry per allowable service.
	// Parsed from JESS_HTTP_PROXY_TARGETS=name1=svc1.ns.svc:80,name2=svc2.ns.svc:443.
	// Empty map = proxy disabled (404 on every /proxy/* hit).
	targets map[string]*url.URL

	// recorder is the WORM-backed recorder shared with the SSH/RDP
	// session brokers. nil = proxy disabled — recording is a hard
	// requirement, not a nice-to-have (zero-trust posture: every
	// admin action recorded, no opt-out).
	recorder recording.Recorder

	// captureSensitive flips header redaction off. Default false.
	captureSensitive bool

	// Per-(operator,service) recording sessions. A session is one
	// HTTPWriter held open until the idle timeout or explicit close.
	// Keyed by operator-sub + "::" + service-name.
	mu       sync.Mutex
	sessions map[string]*proxySession
}

// proxySession is one operator's recording stream for one service.
type proxySession struct {
	writer    *recording.HTTPWriter
	startedAt time.Time
	lastSeen  time.Time
}

// proxySessionIdleTTL is how long a recording stream stays open after
// the operator's last request. 30min picked to match the typical SPA
// admin session — short enough to surface "did the operator finish?"
// closure events, long enough to avoid sealing on a coffee break.
const proxySessionIdleTTL = 30 * time.Minute

func newHTTPProxyConfig(rec recording.Recorder) *httpProxyConfig {
	c := &httpProxyConfig{
		targets:          map[string]*url.URL{},
		recorder:         rec,
		captureSensitive: os.Getenv("JESS_HTTP_PROXY_CAPTURE_SENSITIVE") == "true",
		sessions:         map[string]*proxySession{},
	}
	raw := os.Getenv("JESS_HTTP_PROXY_TARGETS")
	if raw == "" {
		return c
	}
	for _, entry := range strings.Split(raw, ",") {
		name, addr, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || name == "" || addr == "" {
			log.Printf("jess-web http-proxy: skipping malformed JESS_HTTP_PROXY_TARGETS entry %q (expected name=host:port)", entry)
			continue
		}
		// Default to http; operators can prefix `https://` to override.
		if !strings.Contains(addr, "://") {
			addr = "http://" + addr
		}
		u, err := url.Parse(addr)
		if err != nil {
			log.Printf("jess-web http-proxy: bad upstream URL %q for service %q: %v", addr, name, err)
			continue
		}
		c.targets[name] = u
		log.Printf("jess-web http-proxy: service %q → %s", name, u.String())
	}
	return c
}

// handleProxy is the entry point for /proxy/<service>/<path>.
// Authenticates the operator via cookie session, looks up the
// upstream, opens-or-reuses a recording stream, and reverse-proxies.
func (c *httpProxyConfig) handleProxy(sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op, err := sessions.operatorFromRequest(r)
		if err != nil {
			writeJSONErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		// Recording is non-negotiable. If the controller didn't wire
		// a recorder at startup, refuse — better an explicit 503
		// than silent loss of audit evidence.
		if c.recorder == nil {
			writeJSONErr(w, http.StatusServiceUnavailable, "http proxy recording not configured on this controller")
			return
		}
		// Parse the service name + remainder path.
		rest := strings.TrimPrefix(r.URL.Path, "/proxy/")
		service, subpath, _ := strings.Cut(rest, "/")
		if service == "" {
			writeJSONErr(w, http.StatusNotFound, "expected /proxy/<service>/<path>")
			return
		}
		upstream, found := c.targets[service]
		if !found {
			writeJSONErr(w, http.StatusNotFound, "unknown service "+service+" (set JESS_HTTP_PROXY_TARGETS to enable)")
			return
		}
		// Open or reuse the recording stream for this (operator, service).
		ps, err := c.acquireSession(r.Context(), op, service)
		if err != nil {
			log.Printf("jess-web http-proxy: acquire session op=%s service=%s err=%v", op.Subject, service, err)
			writeJSONErr(w, http.StatusInternalServerError, "recorder unavailable")
			return
		}

		// Build a reverse proxy targeting the upstream. The Director
		// strips the /proxy/<service> prefix so the upstream sees the
		// "real" path. URL rewriting on response bodies is 5h-3c.
		started := time.Now()
		captured := &captureResponseWriter{ResponseWriter: w, status: http.StatusOK}
		var reqBody bytes.Buffer
		if r.Body != nil && r.ContentLength > 0 && r.ContentLength <= int64(ps.writer.MaxBodyBytes()) {
			// Tee request body for recording without consuming it for the upstream.
			r.Body = io.NopCloser(io.TeeReader(r.Body, &reqBody))
		} else if r.ContentLength > int64(ps.writer.MaxBodyBytes()) {
			// Too large — leave body untouched for upstream, mark
			// truncated in the record.
			r.Body = io.NopCloser(io.MultiReader(&bytes.Buffer{}, r.Body))
		}
		captured.captureUpTo = ps.writer.MaxBodyBytes()

		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = upstream.Scheme
				req.URL.Host = upstream.Host
				req.URL.Path = "/" + subpath
				req.Host = upstream.Host
				// Stamp the operator identity so upstreams that
				// support it can attribute (Grafana auth proxy
				// reads X-WEBAUTH-USER).
				req.Header.Set("X-Forwarded-User", op.Subject)
				req.Header.Set("X-Forwarded-By", "jess-web-http-proxy")
			},
			Transport: http.DefaultTransport,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				writeJSONErr(w, http.StatusBadGateway, "upstream "+service+" unreachable: "+err.Error())
			},
		}
		proxy.ServeHTTP(captured, r)

		// Record AFTER serving — the operator's response is already
		// flushed; recording lag doesn't affect user latency.
		// Encoding body as base64 keeps non-UTF-8 payloads safe in
		// the JSON line.
		tx := recording.HTTPTransaction{
			StartedAt:   started,
			DurationMs:  time.Since(started).Milliseconds(),
			Method:      r.Method,
			URL:         r.URL.RequestURI(),
			Status:      captured.status,
			RemoteIP:    clientIP(r),
			OperatorSub: op.Subject,
			Request: recording.HTTPMessage{
				Headers:   r.Header,
				BodyBytes: int64(reqBody.Len()),
				Truncated: r.ContentLength > int64(ps.writer.MaxBodyBytes()),
			},
			Response: recording.HTTPMessage{
				Headers:   captured.Header().Clone(),
				BodyBytes: captured.bodyBytesTotal,
				Truncated: captured.bodyTruncated,
			},
		}
		if reqBody.Len() > 0 {
			tx.Request.BodyB64 = base64.StdEncoding.EncodeToString(reqBody.Bytes())
		}
		if captured.capturedBody.Len() > 0 {
			tx.Response.BodyB64 = base64.StdEncoding.EncodeToString(captured.capturedBody.Bytes())
		}
		if err := ps.writer.Record(tx); err != nil {
			log.Printf("jess-web http-proxy: record err op=%s service=%s: %v", op.Subject, service, err)
		}
		ps.lastSeen = time.Now()
	}
}

// captureResponseWriter is an http.ResponseWriter that records the
// status + a bounded prefix of the response body for the recording
// layer. The full body still flows to the operator's browser — the
// Write call writes BOTH to the wrapped writer AND to the capture
// buffer, up to captureUpTo bytes.
type captureResponseWriter struct {
	http.ResponseWriter
	status         int
	captureUpTo    int64
	capturedBody   bytes.Buffer
	bodyBytesTotal int64
	bodyTruncated  bool
}

func (c *captureResponseWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureResponseWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.bodyBytesTotal += int64(n)
	if c.capturedBody.Len() < int(c.captureUpTo) {
		remaining := c.captureUpTo - int64(c.capturedBody.Len())
		if int64(n) <= remaining {
			c.capturedBody.Write(p[:n])
		} else {
			c.capturedBody.Write(p[:remaining])
			c.bodyTruncated = true
		}
	} else if n > 0 {
		c.bodyTruncated = true
	}
	return n, err
}

// acquireSession returns the existing recording stream for the
// (operator, service) pair, or opens a new one. Idle streams older
// than proxySessionIdleTTL are sealed + replaced. Closing a session
// is fire-and-forget (recording finalization is best-effort; the
// audit chain catches failed seals via the existing 5e-14 verify).
func (c *httpProxyConfig) acquireSession(ctx context.Context, op *Operator, service string) (*proxySession, error) {
	key := op.Subject + "::" + service
	c.mu.Lock()
	defer c.mu.Unlock()
	if ps, found := c.sessions[key]; found {
		if time.Since(ps.lastSeen) < proxySessionIdleTTL {
			return ps, nil
		}
		// Idle out: seal + replace.
		_ = ps.writer.Close()
		delete(c.sessions, key)
	}
	// Open a fresh stream. SessionID is a synthetic combining operator
	// + service + UTC-ms so the bundle key in MinIO is unique and
	// human-debuggable.
	sessionID := fmt.Sprintf("http-%s-%s-%d", op.Subject, service, time.Now().UnixMilli())
	wc, err := c.recorder.Open(ctx, recording.Meta{
		SessionID: sessionID,
		Subject:   op.Subject,
		TargetID:  service,
		Protocol:  "http",
		Format:    recording.FormatHTTPNDJSON,
		StartedAt: time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("open recording: %w", err)
	}
	writer := recording.NewHTTPWriter(wc, 0, c.captureSensitive)
	ps := &proxySession{
		writer:    writer,
		startedAt: time.Now(),
		lastSeen:  time.Now(),
	}
	c.sessions[key] = ps
	return ps, nil
}

// clientIP returns a best-effort source IP for the operator request.
// Walks X-Forwarded-For first (we sit behind Talon → traefik → DMZ);
// falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	if i := strings.IndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
