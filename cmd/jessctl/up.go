// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dogukanturhal/jess/internal/client"
)

// cmdUp is the one-shot operator bring-up command (ADR 0030 Phase 6).
// Replaces the three-step "login + admin operator-cert + connect" run by
// folding the cert-lifecycle work into one command:
//
//	jessctl up --admin <https-addr>
//
// Default flow:
//  1. Check ~/.config/jess/operator.{crt,key} — if both exist AND the
//     cert's NotAfter is more than --renew-before from now, skip the
//     mint (fast path; most invocations are no-ops).
//  2. Otherwise: OIDC login if no token cached/env, generate key+CSR,
//     POST /operator-cert, write key (0600) + cert + jess-ca.crt.
//  3. Print the export-env block the operator pastes to their shell.
//
// Designed to be safe to run on every shell startup — adds < 50ms when
// the cert is fresh, ~5s when re-minting (one Vault round-trip via the
// controller's PKI signer). Pairs cleanly with `jessctl connect` once
// the operator has a JIT grant ID; this command intentionally does NOT
// open a tunnel (separation of concerns: mint cert vs. open session).
func cmdUp(args []string) {
	var renewBefore time.Duration
	var outDir string
	var force bool
	a, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.DurationVar(&renewBefore, "renew-before", 30*time.Minute, "re-mint if cert's NotAfter is within this window")
		fs.StringVar(&outDir, "out-dir", defaultOperatorOutDir(), "where operator.key + operator.crt + jess-ca.crt live")
		fs.BoolVar(&force, "force", false, "re-mint even if the cert is still fresh")
	})
	defer cancel()

	keyPath := filepath.Join(outDir, "operator.key")
	certPath := filepath.Join(outDir, "operator.crt")
	caPath := filepath.Join(outDir, "jess-ca.crt")

	if !force {
		if ok, expires, err := certIsFresh(certPath, renewBefore); err == nil && ok {
			fmt.Printf("operator cert at %s is still fresh (expires %s; --renew-before=%s)\n",
				certPath, expires.Local().Format(time.RFC1123), renewBefore)
			printExportEnv(certPath, keyPath, caPath)
			return
		}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "out-dir: %v\n", err)
		os.Exit(1)
	}

	csrPEM, keyPEM, err := generateKeyAndCSR()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate csr: %v\n", err)
		os.Exit(1)
	}

	// 8h is the server-side ceiling (MaxOperatorCertTTL on the controller);
	// passing 0 lets the server cap.
	resp, err := a.SignOperatorCert(ctx, csrPEM, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign operator-cert: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(certPath, []byte(resp.CertPEM), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write cert: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(caPath, []byte(resp.CAPEM), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write ca: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("minted operator cert (expires %s)\n", resp.NotAfter.Local().Format(time.RFC1123))
	fmt.Printf("  key:  %s (0600)\n", keyPath)
	fmt.Printf("  cert: %s\n", certPath)
	fmt.Printf("  ca:   %s\n", caPath)
	fmt.Println()
	printExportEnv(certPath, keyPath, caPath)

	// Quiet hint, not an action — keeps `up` purely about cert lifecycle.
	// Operators with a JIT grant just run `jessctl connect <target> --grant <id>`.
	fmt.Println()
	fmt.Println("Next: jessctl connect <target> --controller <addr>:7101 --grant <grant-id>")
	fmt.Println("If you don't have a grant yet: jessctl request --admin", flagValueOf(a), "--target <target> --reason '<why>'")
}

// certIsFresh returns (true, NotAfter, nil) if certPath exists and parses
// and has more than renewBefore left. Any error (missing, corrupt, expired
// soon) returns false — caller re-mints.
func certIsFresh(certPath string, renewBefore time.Duration) (bool, time.Time, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return false, time.Time{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return false, time.Time{}, errors.New("cert PEM empty")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, time.Time{}, err
	}
	if time.Until(cert.NotAfter) <= renewBefore {
		return false, cert.NotAfter, nil
	}
	return true, cert.NotAfter, nil
}

// generateKeyAndCSR mints a fresh EC P-256 keypair + CSR, returning both
// in PEM form. The CSR's CN is a placeholder hostname — the server
// overrides it with the verified Falcon-ID subject (CSR's claim is
// ignored, RFC 8705 §2.1 binding).
func generateKeyAndCSR() (csrPEM, keyPEM []byte, _ error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	whoami, _ := os.Hostname()
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: whoami, Organization: []string{"HexxLock-Operator"}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, err
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, keyPEM, nil
}

func printExportEnv(certPath, keyPath, caPath string) {
	fmt.Println("Export to use with jessctl connect:")
	fmt.Printf("  export JESS_OPERATOR_TLS_CERT=%s\n", certPath)
	fmt.Printf("  export JESS_OPERATOR_TLS_KEY=%s\n", keyPath)
	fmt.Printf("  export JESS_OPERATOR_TLS_CA=%s\n", caPath)
}

// flagValueOf renders the admin client's base URL for use in a hint
// message. Avoids a context plumb — the AdminClient already knows where
// it was pointing.
func flagValueOf(a *client.AdminClient) string {
	if a == nil || a.BaseURL == "" {
		return "<admin-https-addr>"
	}
	return a.BaseURL
}

// ensure context import isn't dropped by tooling if generateKeyAndCSR
// signature changes in a future refactor.
var _ = context.Background
