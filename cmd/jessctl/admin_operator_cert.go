// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// cmdAdminOperatorCert is the client side of the operator-cert auto-mint flow.
// Generates an EC P-256 key + CSR locally, calls the controller's
// POST /operator-cert endpoint, then writes operator.key (0600), operator.crt,
// and the issuer chain (jess-ca.crt) into the out-dir.
//
// Replaces the 6-step manual openssl + Vault-root-token flow documented in
// docs/sessions/2026-05-29-jess-operator-e2e.md §A. The operator no longer
// needs the Vault root token — the controller does the signing server-side
// against the CA stored in Vault, bound to the verified Falcon-ID identity.
func cmdAdminOperatorCert(args []string) {
	var ttl time.Duration
	var outDir string
	a, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.DurationVar(&ttl, "ttl", 8*time.Hour, "cert TTL (server ceiling is 8h)")
		fs.StringVar(&outDir, "out-dir", defaultOperatorOutDir(), "where to write operator.key + operator.crt + jess-ca.crt")
	})
	defer cancel()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "out-dir: %v\n", err)
		os.Exit(1)
	}

	// Generate a fresh EC P-256 keypair — matches the openssl flow's
	// `prime256v1`. The private key NEVER leaves this process / out-dir.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal key: %v\n", err)
		os.Exit(1)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Build a CSR with a placeholder subject — the server ignores the CSR's
	// CN and stamps the verified Falcon-ID subject instead. Send our local
	// username as a hint (for log correlation only).
	whoami, _ := os.Hostname()
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: whoami, Organization: []string{"HexxLock-Operator"}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create csr: %v\n", err)
		os.Exit(1)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	resp, err := a.SignOperatorCert(ctx, csrPEM, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign cert: %v\n", err)
		os.Exit(1)
	}

	keyPath := filepath.Join(outDir, "operator.key")
	certPath := filepath.Join(outDir, "operator.crt")
	caPath := filepath.Join(outDir, "jess-ca.crt")

	// Write key 0600 — owner-only, never readable by other users.
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

	fmt.Printf("operator cert minted, expires %s\n", resp.NotAfter.Local().Format(time.RFC1123))
	fmt.Printf("  key:  %s (0600)\n", keyPath)
	fmt.Printf("  cert: %s\n", certPath)
	fmt.Printf("  ca:   %s\n", caPath)
	fmt.Println()
	fmt.Println("Export to use with jessctl connect:")
	fmt.Printf("  export JESS_OPERATOR_TLS_CERT=%s\n", certPath)
	fmt.Printf("  export JESS_OPERATOR_TLS_KEY=%s\n", keyPath)
	fmt.Printf("  export JESS_OPERATOR_TLS_CA=%s\n", caPath)
}

// cmdAdminOperatorCertRevoke is the CLI side of POST /operator-cert/revoke.
// Phase 4 lite — flips an operator cert serial into the jess-ca CRL. The
// controller authenticates the caller (Falcon-ID + admin role) before
// passing the call to Vault; Vault audits the revoke against the
// controller's K8s-auth identity and the controller logs the calling
// operator's verified subject for the operator audit trail.
//
// Effective revocation latency is the operator cert's TTL (≤ 8h via
// MaxOperatorCertTTL) — the controller does NOT poll the CRL during mTLS
// handshake; short cert TTL is the primary revocation mechanism, the CRL
// is the audit + 3rd-party-validator backstop. This matches Teleport,
// HashiCorp Boundary, AWS IAM Roles Anywhere.
func cmdAdminOperatorCertRevoke(args []string) {
	var serial string
	a, ctx, cancel := adminClientFromFlags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&serial, "serial", "", "cert serial to revoke (hex, openssl-style colons optional)")
	})
	defer cancel()
	if serial == "" {
		fmt.Fprintln(os.Stderr, "--serial <hex> required (obtain via `openssl x509 -in operator.crt -noout -serial`)")
		os.Exit(2)
	}
	resp, err := a.RevokeOperatorCert(ctx, serial)
	if err != nil {
		fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("revoked serial=%s at=%s\n", resp.Serial, resp.RevokedAt.Local().Format(time.RFC1123))
	fmt.Println("Effective revocation: cert continues to be accepted by the controller until its TTL expires")
	fmt.Println("(≤8h ceiling). The serial is in the next signed CRL refresh for any 3rd-party validator.")
}

// defaultOperatorOutDir returns ~/.config/jess (honoring $XDG_CONFIG_HOME
// when set). Falls back to ./jess if HOME is unset — keeps the command
// usable from CI / containers without a home directory.
func defaultOperatorOutDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "jess")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "jess")
	}
	return "jess"
}
