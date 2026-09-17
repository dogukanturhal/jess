// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// In-memory operator-session store. Maps a random session-id cookie value
// to the operator's verified Falcon-ID OIDC token + email + expiry. Single
// jess-web pod for now (per ADR 0030 Phase 5e); when we scale to ≥2 a
// shared store (Redis or PG) replaces this — same Mearax pattern.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

const sessionCookie = "jess_session"

// Operator is the verified identity attached to a cookie session.
type Operator struct {
	Token   string    // verified Falcon-ID OIDC id_token (presented to controller)
	Subject string    // sub claim
	Email   string    // email claim if present
	Roles   []string  // roles claim (informational; controller still PDP-checks)
	AMR     []string  // OIDC amr (RFC 8176) — strong-auth methods used at sign-in
	Expires time.Time // session expiry (8h ceiling) — re-login required after
	// Silent-refresh state (jess-web's Go equivalent of @hexxlock/falcon-id-client's
	// auto-refresh, which jess-web can't import — that lib is TS/Next.js). The
	// id_token (`Token`) carries Falcon-ID's short (~1h) TTL; once it lapses the
	// controller's PDP rejects it ("oidc: token is expired") even though the 8h
	// cookie session is still valid. `RefreshToken` (rotated, granted by the
	// svc-jess-web client's offline_access) mints a fresh id_token; `IDTokenExpiry`
	// is the id_token's real exp, watched so we refresh BEFORE the PDP sees a dead
	// token. Zero RefreshToken ⇒ no refresh (pre-refresh sessions / tests).
	RefreshToken  string
	IDTokenExpiry time.Time
}

// refreshFunc rotates an operator's id_token via its refresh_token when it's
// near expiry. Returns the (possibly new) operator to use, or nil if no refresh
// was needed, or an error if the refresh failed (⇒ treat the session as expired).
// Injected by authConfig so the store stays free of the oauth2/oidc deps.
type refreshFunc func(ctx context.Context, sid string, op *Operator) (*Operator, error)

// sessionStore is concurrent-safe; tests can swap in a mock.
type sessionStore struct {
	mu sync.RWMutex
	by map[string]*Operator
	// refresh, when set (by authConfig), is invoked by operatorFromRequest to
	// silently rotate a near-expiry id_token. nil in tests / dev-no-auth.
	refresh refreshFunc
}

func newSessionStore() *sessionStore {
	return &sessionStore{by: map[string]*Operator{}}
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *sessionStore) put(id string, op *Operator) {
	s.mu.Lock()
	s.by[id] = op
	s.mu.Unlock()
}

func (s *sessionStore) get(id string) (*Operator, bool) {
	s.mu.RLock()
	op, ok := s.by[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(op.Expires) {
		s.delete(id)
		return nil, false
	}
	return op, true
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	delete(s.by, id)
	s.mu.Unlock()
}

// gc evicts expired entries; call periodically from main.
func (s *sessionStore) gc() {
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.by {
		if now.After(v.Expires) {
			delete(s.by, k)
		}
	}
	s.mu.Unlock()
}

// operatorFromCookie reads + validates the session cookie. Returns
// errNotSignedIn if no/invalid cookie, errSessionExpired if the entry
// existed but the operator's TTL elapsed (handled identically by the
// caller — both prompt sign-in).
var (
	errNotSignedIn    = errors.New("not signed in")
	errSessionExpired = errors.New("session expired")
)

func (s *sessionStore) operatorFromRequest(r *http.Request) (*Operator, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, errNotSignedIn
	}
	op, ok := s.get(c.Value)
	if !ok {
		return nil, errSessionExpired
	}
	// Silently rotate the id_token if it's near expiry, BEFORE any PDP-facing
	// handler presents it. A refresh failure (refresh_token expired/revoked)
	// invalidates the session so the SPA prompts a clean re-login instead of
	// surfacing the PDP's raw "token is expired" error.
	if s.refresh != nil {
		fresh, rerr := s.refresh(r.Context(), c.Value, op)
		if rerr != nil {
			s.delete(c.Value)
			return nil, errSessionExpired
		}
		if fresh != nil {
			op = fresh
		}
	}
	return op, nil
}

// operatorByID resolves + silently-refreshes an operator by session id, for
// callers that outlive a single HTTP request and must keep presenting a
// NON-expired id_token — e.g. the RDP-live grant-watch, which re-checks the
// grant against the controller on a ticker for the whole session. Same
// refresh + expiry semantics as operatorFromRequest (which takes the cookie
// off the request); this variant takes the session id directly. Returns
// errSessionExpired when the session lapsed (8h ceiling) or a refresh failed
// (refresh_token revoked/expired) — either of which is a legitimate reason for
// the caller to end a live session (continuous authentication).
func (s *sessionStore) operatorByID(ctx context.Context, sid string) (*Operator, error) {
	if sid == "" {
		return nil, errNotSignedIn
	}
	op, ok := s.get(sid)
	if !ok {
		return nil, errSessionExpired
	}
	if s.refresh != nil {
		fresh, rerr := s.refresh(ctx, sid, op)
		if rerr != nil {
			s.delete(sid)
			return nil, errSessionExpired
		}
		if fresh != nil {
			op = fresh
		}
	}
	return op, nil
}

// setSessionCookie writes the cookie with secure defaults. Marks Secure
// only when the inbound request was TLS — local dev over http:// still
// works without violating the secure-on-tls contract.
func setSessionCookie(w http.ResponseWriter, r *http.Request, id string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}
