// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Falcon-ID OIDC authorization-code flow for jess-web.
//
// Operator clicks Sign in → /auth/login → 302 to Falcon-ID with PKCE +
// state. Falcon-ID redirects back to /auth/callback?code=...&state=... →
// jess-web exchanges code for id_token → verifies the id_token →
// persists the operator in the session store → sets the session cookie
// → 302 to the original landing page (or / by default).
//
// Operator sign-out: POST /auth/logout deletes the session entry +
// clears the cookie. ID-token Falcon-ID front-channel logout is not
// wired (would need /auth/end_session_endpoint discovery + redirect).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// authConfig is the per-process OIDC config. Built once in main(),
// passed into the handlers.
type authConfig struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth        *oauth2.Config
	sessionStore *sessionStore

	// pendingState protects against CSRF on the OIDC callback. Random
	// state cookie is set on /auth/login + matched on /auth/callback.
	// Cleared after use (single-use). pendingVerifier holds the PKCE
	// code_verifier indexed by the same state value.
	mu              sync.Mutex
	pendingVerifier map[string]pendingAuth

	// refreshMu serialises silent token refreshes (refresh_token rotation is
	// single-use, so two concurrent requests must not both rotate the same
	// session). Coarse but correct for a single pod / few operators; refresh is
	// double-checked under it (re-read the session) to skip redundant rotations.
	refreshMu sync.Mutex
}

// refreshSkew — refresh the id_token once it's within this window of expiry, so
// a fresh token reaches the controller's PDP before the live one lapses.
const refreshSkew = 2 * time.Minute

type pendingAuth struct {
	codeVerifier string
	redirectTo   string
	createdAt    time.Time
}

func newAuthConfig(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, store *sessionStore) (*authConfig, error) {
	prov, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery (%s): %w", issuer, err)
	}
	a := &authConfig{
		provider: prov,
		verifier: prov.Verifier(&oidc.Config{ClientID: clientID}),
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret, // may be "" for public clients
			Endpoint:     prov.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles", "offline_access"},
		},
		sessionStore:    store,
		pendingVerifier: map[string]pendingAuth{},
	}
	// Wire silent refresh into the session store so every PDP-facing handler
	// (operatorFromRequest) gets a fresh id_token transparently.
	store.refresh = a.refreshOperator
	return a, nil
}

// refreshOperator rotates a session's id_token via its refresh_token when the
// id_token is within refreshSkew of expiry. Returns the new operator, nil if no
// refresh was needed, or an error if the rotation failed. jess-web's Go stand-in
// for @hexxlock/falcon-id-client's auto-refresh (that lib is TS/Next.js; jess-web
// is Go, so it can't import it — see session.go).
func (a *authConfig) refreshOperator(ctx context.Context, sid string, op *Operator) (*Operator, error) {
	if op.RefreshToken == "" || time.Until(op.IDTokenExpiry) > refreshSkew {
		return nil, nil // no refresh token, or still fresh enough
	}
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	// Re-read under the lock: another request may have just rotated this session.
	if cur, ok := a.sessionStore.get(sid); ok {
		op = cur
		if op.RefreshToken == "" || time.Until(op.IDTokenExpiry) > refreshSkew {
			return op, nil
		}
	}
	// Force the oauth2 TokenSource to refresh by handing it an already-expired
	// access token + the refresh token; it calls the token endpoint with the
	// refresh_token grant (client_secret_basic).
	src := a.oauth.TokenSource(ctx, &oauth2.Token{
		RefreshToken: op.RefreshToken,
		Expiry:       time.Now().Add(-time.Minute),
	})
	newTok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	idRaw, _ := newTok.Extra("id_token").(string)
	if idRaw == "" {
		return nil, errors.New("refresh: no id_token in token response")
	}
	verified, err := a.verifier.Verify(ctx, idRaw)
	if err != nil {
		return nil, fmt.Errorf("refresh: verify id_token: %w", err)
	}
	rt := op.RefreshToken
	if newTok.RefreshToken != "" {
		rt = newTok.RefreshToken // honour rotation
	}
	// Copy-on-refresh: never mutate the shared *Operator other goroutines may be
	// reading — publish a fresh snapshot atomically into the store.
	fresh := &Operator{
		Token:         idRaw,
		Subject:       op.Subject,
		Email:         op.Email,
		Roles:         op.Roles,
		AMR:           op.AMR,
		Expires:       op.Expires, // keep the 8h session ceiling
		RefreshToken:  rt,
		IDTokenExpiry: verified.Expiry,
	}
	a.sessionStore.put(sid, fresh)
	return fresh, nil
}

// loginHandler generates state + PKCE verifier, stashes them, redirects to
// the IdP. Accepts ?return=<path> so the post-callback landing matches
// what the operator was trying to reach.
func (a *authConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(24)
	if err != nil {
		http.Error(w, "state alloc: "+err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randomString(48)
	if err != nil {
		http.Error(w, "verifier alloc: "+err.Error(), http.StatusInternalServerError)
		return
	}
	returnTo := safeRedirect(r.URL.Query().Get("return"))

	a.mu.Lock()
	a.pendingVerifier[state] = pendingAuth{codeVerifier: verifier, redirectTo: returnTo, createdAt: time.Now()}
	a.gcPending()
	a.mu.Unlock()

	challenge := pkceS256(verifier)
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	// Step-up: ?acr_values=mfa propagates to the IdP authorize request
	// (OIDC core §3.1.2.1 acr_values). Falcon-ID interprets `mfa` as
	// "require a second-factor proof in this dance"; the resulting
	// id_token's amr claim then carries the method actually used
	// (otp / totp / hwk / webauthn). The controller's admin-direct-
	// connect gate inspects amr to decide whether to honour the
	// no-grant connect.
	if acr := r.URL.Query().Get("acr_values"); acr != "" {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", acr))
	}
	url := a.oauth.AuthCodeURL(state, opts...)
	http.Redirect(w, r, url, http.StatusFound)
}

// callbackHandler exchanges the code, verifies the id_token, persists
// the operator session, sets the cookie, redirects.
func (a *authConfig) callbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	p, ok := a.pendingVerifier[state]
	if ok {
		delete(a.pendingVerifier, state)
	}
	a.mu.Unlock()
	if !ok {
		// Unknown state — CSRF guard. Could also be a slow callback after
		// the GC window (10min); rare, operator just clicks Sign in again.
		http.Error(w, "unknown state (csrf guard); restart sign-in", http.StatusForbidden)
		return
	}
	if time.Since(p.createdAt) > 10*time.Minute {
		http.Error(w, "state expired; restart sign-in", http.StatusForbidden)
		return
	}

	tok, err := a.oauth.Exchange(r.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", p.codeVerifier),
	)
	if err != nil {
		http.Error(w, "code exchange: "+err.Error(), http.StatusBadGateway)
		return
	}
	idTokenRaw, ok := tok.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		http.Error(w, "id_token absent from token response", http.StatusBadGateway)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), idTokenRaw)
	if err != nil {
		http.Error(w, "id_token verify: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email string   `json:"email"`
		Sub   string   `json:"sub"`
		Roles []string `json:"roles"`
		AMR   []string `json:"amr"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "id_token claims: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sid, err := newSessionID()
	if err != nil {
		http.Error(w, "session id: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// 8h ceiling — matches the operator-cert MaxOperatorCertTTL. After
	// expiry the operator re-signs-in (same human-day shape). The id_token's own
	// (~1h) expiry is shorter, so we also keep the refresh_token + the id_token's
	// real exp for the silent-refresh path (refreshOperator) that rotates the
	// id_token under the 8h session without a re-login.
	a.sessionStore.put(sid, &Operator{
		Token:         idTokenRaw,
		Subject:       claims.Sub,
		Email:         claims.Email,
		Roles:         claims.Roles,
		AMR:           claims.AMR,
		Expires:       time.Now().Add(8 * time.Hour),
		RefreshToken:  tok.RefreshToken,
		IDTokenExpiry: idToken.Expiry,
	})
	setSessionCookie(w, r, sid, 8*time.Hour)
	http.Redirect(w, r, p.redirectTo, http.StatusFound)
}

// logoutHandler clears the cookie + deletes the server-side session,
// then redirects back to the landing page for BOTH GET and POST.
//
// Pre-fix behaviour: POST returned raw `{"ok":true}` JSON. The
// AuthBadge component's <form action="/auth/logout" method="POST">
// submits a full-navigation POST, so the browser rendered the JSON
// body in the address bar (operator on iOS Safari saw a blank dark
// page with `{"ok":true}` literal). Operator-confusing — surfaced
// as a UX bug 2026-05-31.
//
// Post-fix: 303 See Other → "/". RFC 7231 §6.4.4 mandates the
// follow-up be a GET, regardless of the original method, which is
// what a browser form submission needs to land on the landing page
// cleanly. Same posture every OIDC RP uses (Talon, Vault, Argo all
// 303 from /auth/logout).
//
// `return_to` query parameter (optional) lets the SPA redirect back
// to a specific path post-logout — same allow-list pattern as
// loginHandler's `return` param (safeRedirect strips anything that
// isn't a single-path string, defending against open-redirect).
func (a *authConfig) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		a.sessionStore.delete(c.Value)
	}
	clearSessionCookie(w, r)
	dest := safeRedirect(r.URL.Query().Get("return_to"))
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// meHandler returns the verified operator identity for the SPA.
func (a *authConfig) meHandler(w http.ResponseWriter, r *http.Request) {
	op, err := a.sessionStore.operatorFromRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"not signed in"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":    op.Subject,
		"email":      op.Email,
		"roles":      op.Roles,
		"amr":        op.AMR,
		"expires_at": op.Expires.Format(time.RFC3339),
	})
}

// gcPending evicts stale state/verifier entries. Called under mu.
func (a *authConfig) gcPending() {
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, v := range a.pendingVerifier {
		if v.createdAt.Before(cutoff) {
			delete(a.pendingVerifier, k)
		}
	}
}

// safeRedirect prevents open-redirects: only allow paths that look like
// our SPA routes (starts with / and no scheme://). Defaults to /.
func safeRedirect(in string) string {
	if in == "" {
		return "/"
	}
	if u, err := url.Parse(in); err == nil && u.Scheme == "" && u.Host == "" && len(in) > 0 && in[0] == '/' {
		return in
	}
	return "/"
}

func randomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
