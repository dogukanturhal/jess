// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Service certificate management for jess-web. Phase 5e-3 closes the
// mTLS gap left in 5e-2: instead of dialing the controller operator
// port with a plain bearer-only TLS connection, jess-web mints a
// short-lived (<=8h) X.509 client cert from the jess-ca Vault PKI
// mount and presents it on every dial.
//
// Why this matters
//
//   - The controller's operator-port trust bundle (PKI Phase 3, jess !12)
//     already trusts certs from jess-ca. Any client whose cert chains to
//     jess-ca is admitted; the Falcon-ID Bearer token still gates the
//     identity within that channel.
//   - Until this change, jess-web's WS bridge dial was bearer-only —
//     useful for dev (where the operator port is in-cluster and the
//     bearer is the operator's Falcon-ID JWT) but NOT defence-in-depth.
//     A leaked Bearer alone could open a bridge from any pod that can
//     reach the operator port; with mTLS the attacker also needs a
//     jess-ca-signed cert.
//
// Lifecycle
//
//   - newSvcCertManager mints the first cert at startup and starts a
//     goroutine that renews at ~70% of cert lifetime (single replacement
//     point so the in-flight TLS handshake never observes a torn pair).
//   - certForClient is wired into the controller-dial tls.Config as
//     GetClientCertificate — every new outbound TLS handshake reads the
//     CURRENT cert atomically.
//   - Shutdown cancels the renew loop via the supplied context.
//
// The CN is "jess-web" (a service identity, not a Falcon-ID subject).
// The iac Vault role declares this is the only CN this role can issue;
// see iac/datacenters/eu-west-1/vault/vault-jess-ca-pki.tf (Phase 5e-3
// follow-up MR will add role + policy + k8s auth role for jess-web).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// svcCertManager holds the current jess-web service cert + its renewal
// loop. Reads on certForClient are lock-free (atomic.Pointer); the
// renew goroutine swaps the whole pair atomically.
type svcCertManager struct {
	vc      *vaultx.Client
	mount   string // e.g. "jess-ca"
	role    string // e.g. "jess-web-svc" — declared in iac
	cn      string // common name baked into cert subject
	current atomic.Pointer[tls.Certificate]
}

// newSvcCertManager mints the first cert synchronously, starts the
// renewal loop on a background goroutine bound to ctx, and returns
// the manager ready to serve GetClientCertificate.
func newSvcCertManager(ctx context.Context, vc *vaultx.Client, mount, role, cn string) (*svcCertManager, error) {
	if vc == nil {
		return nil, errors.New("svcCertManager: vault client nil")
	}
	if mount == "" || role == "" || cn == "" {
		return nil, errors.New("svcCertManager: mount, role, cn all required")
	}
	m := &svcCertManager{vc: vc, mount: mount, role: role, cn: cn}
	cert, err := m.mint(ctx)
	if err != nil {
		return nil, fmt.Errorf("initial mint: %w", err)
	}
	m.current.Store(cert)
	go m.renewLoop(ctx)
	return m, nil
}

// certForClient is the GetClientCertificate hook for the controller-dial
// tls.Config. Returns the current atomic snapshot — never blocks.
func (m *svcCertManager) certForClient(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := m.current.Load()
	if c == nil {
		return nil, errors.New("jess-web svc cert not yet minted")
	}
	return c, nil
}

// mint generates a fresh EC P-256 key, builds a CSR with CN = m.cn,
// asks Vault PKI to sign it, then assembles the tls.Certificate so it
// can be presented on the next outbound dial. The private key NEVER
// leaves jess-web's address space (Vault only sees the CSR's public
// half).
func (m *svcCertManager) mint(ctx context.Context) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: m.cn}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	resp, err := m.vc.SignPKICert(ctx, m.mount, m.role, vaultx.PKISignRequest{
		CSRPEM:     string(csrPEM),
		CommonName: m.cn,
	})
	if err != nil {
		return nil, fmt.Errorf("vault sign: %w", err)
	}
	leafBlock, _ := pem.Decode([]byte(resp.Certificate))
	if leafBlock == nil {
		return nil, errors.New("vault returned non-PEM certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{leafBlock.Bytes},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// renewLoop wakes at ~70% of remaining cert lifetime and re-mints. On
// renewal failure it retries with exponential backoff capped at 5 min
// — the OLD cert keeps working (atomic load is unchanged) until it
// expires; the controller will refuse the dial at that point but the
// loop is still trying. A cluster-wide alert on jess_web_svc_cert_age
// (Phase 5e-4 telemetry) covers the case where renewal stays broken.
func (m *svcCertManager) renewLoop(ctx context.Context) {
	backoff := 30 * time.Second
	for {
		cur := m.current.Load()
		if cur == nil {
			// Should not happen — newSvcCertManager seeded it before
			// starting this loop. Guard against logic bugs anyway.
			time.Sleep(backoff)
			continue
		}
		notAfter := cur.Leaf.NotAfter
		validFor := time.Until(notAfter)
		// Renew at 70% of remaining lifetime; never wait > 6h even on
		// a long-lived cert (the role caps at 8h anyway).
		wait := validFor * 7 / 10
		if wait > 6*time.Hour {
			wait = 6 * time.Hour
		}
		if wait < 30*time.Second {
			// Cert is already <30s from expiry — re-mint immediately.
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		next, err := m.mint(ctx)
		if err != nil {
			log.Printf("jess-web: svc-cert renewal failed (retry in %s): %v", backoff, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			// Cap at 5min so we don't drift into hours of silent failure.
			backoff *= 2
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
			continue
		}
		backoff = 30 * time.Second
		m.current.Store(next)
		log.Printf("jess-web: svc-cert renewed; expires %s", next.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}
