// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// LoginOIDC performs an authorization-code + PKCE login against Falcon-ID using
// a loopback redirect (RFC 8252), opens the browser, and returns the raw OIDC
// ID token. redirectAddr is a FIXED loopback host:port (e.g. 127.0.0.1:8400)
// that MUST match a redirect_uri registered for clientID (Falcon-ID matches
// exact URIs; see the svc-jess Keystone bundle). clientID is a public+PKCE
// client in the dev-sandbox tenant.
func LoginOIDC(ctx context.Context, issuer, clientID, redirectAddr string, scopes []string) (idToken string, err error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}

	ln, err := net.Listen("tcp", redirectAddr)
	if err != nil {
		return "", fmt.Errorf("oidc: bind redirect %s (in use? set --redirect): %w", redirectAddr, err)
	}
	defer ln.Close()
	redirectURL := fmt.Sprintf("http://%s/callback", redirectAddr)

	conf := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
	verifier := oauth2.GenerateVerifier()
	stateB := make([]byte, 16)
	_, _ = rand.Read(stateB)
	state := hex.EncodeToString(stateB)

	type result struct {
		token string
		err   error
	}
	resCh := make(chan result, 1)
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("oidc: state mismatch")}
			return
		}
		code := r.URL.Query().Get("code")
		tok, exErr := conf.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
		if exErr != nil {
			http.Error(w, "exchange failed", http.StatusBadGateway)
			resCh <- result{err: exErr}
			return
		}
		raw, _ := tok.Extra("id_token").(string)
		if raw == "" {
			http.Error(w, "no id_token", http.StatusBadGateway)
			resCh <- result{err: fmt.Errorf("oidc: no id_token in response")}
			return
		}
		_, _ = w.Write([]byte("Login complete — you can close this tab and return to the terminal.\n"))
		resCh <- result{token: raw}
	})
	srv.Handler = mux
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	fmt.Printf("Open this URL to sign in:\n  %s\n", authURL)
	_ = openBrowser(authURL)

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(3 * time.Minute):
		return "", fmt.Errorf("oidc: login timed out")
	case res := <-resCh:
		return res.token, res.err
	}
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "cmd", []string{"/c", "start"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}
