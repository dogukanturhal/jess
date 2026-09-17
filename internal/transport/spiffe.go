// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// PRODUCTION identity for the worker↔controller link: auto-rotating SPIFFE
// X.509-SVIDs from a SPIRE Agent (replaces the long-lived file-mounted PEM
// certs). Short-lived (SPIRE default ~1h SVID, refreshed at 50% lifetime) and
// re-fetched in-process over the Workload API socket — no pod restart on
// rotation. Inert until SPIRE is deployed AND JESS_SPIRE_SVID is enabled; see
// AcquireSVIDSource for the gate, and the 2026-07-19 SPIFFE/SPIRE identity
// foundation design (retires ADR-0038's deferred plan).

// X509SVIDSource is the read side of a SPIFFE X.509-SVID provider: the union of
// the SVID source and the trust-bundle source that tlsconfig.MTLS*Config
// consume. *workloadapi.X509Source satisfies it in production; declaring it as
// an interface (rather than the concrete workloadapi type) lets unit tests
// inject an in-memory fake and exercise the mTLS handshake with no live SPIRE.
type X509SVIDSource interface {
	x509svid.Source
	x509bundle.Source
}

// NewSPIFFESource connects to the SPIRE Agent Workload API at socketAddr (e.g.
// "unix:///spiffe-workload-api/spire-agent.sock") and returns an auto-rotating
// X.509-SVID source. The go-spiffe client re-fetches + rotates the SVID and the
// trust bundle in-process. Close it on shutdown. NewX509Source blocks until the
// first SVID arrives or ctx is done — callers that must not block on SPIRE being
// down should use AcquireSVIDSource, which bounds the wait and falls back.
func NewSPIFFESource(ctx context.Context, socketAddr string) (*workloadapi.X509Source, error) {
	src, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)))
	if err != nil {
		return nil, fmt.Errorf("transport: spiffe source: %w", err)
	}
	return src, nil
}

// SVIDServerConfig builds an mTLS server config (worker-facing controller side)
// that presents this workload's SVID and authorizes the peer per authorizer
// (use AuthorizeSPIFFEID to pin the worker's exact SPIFFE ID). The SVID + trust
// bundle are read live from src on every handshake, so rotation is transparent.
func SVIDServerConfig(src X509SVIDSource, authorizer tlsconfig.Authorizer) *tls.Config {
	return tlsconfig.MTLSServerConfig(src, src, authorizer)
}

// SVIDClientConfig builds an mTLS client config (worker / operator side) that
// presents this workload's SVID and authorizes the peer per authorizer (use
// AuthorizeSPIFFEID to pin the controller's exact SPIFFE ID).
func SVIDClientConfig(src X509SVIDSource, authorizer tlsconfig.Authorizer) *tls.Config {
	return tlsconfig.MTLSClientConfig(src, src, authorizer)
}

// AuthorizeSPIFFEID authorizes exactly one SPIFFE ID — the peer's — pinning the
// controller↔worker link to a single identity via tlsconfig.AuthorizeID (not
// trust-domain-wide membership). Workers pin the controller ID; the controller
// pins the worker ID. Returns an error if id is not a well-formed SPIFFE ID (a
// config typo, surfaced at startup rather than at the first failed handshake).
func AuthorizeSPIFFEID(id string) (tlsconfig.Authorizer, error) {
	sid, err := spiffeid.FromString(id)
	if err != nil {
		return nil, fmt.Errorf("transport: parse SPIFFE ID %q: %w", id, err)
	}
	return tlsconfig.AuthorizeID(sid), nil
}

// PeerSPIFFEID extracts the peer's SPIFFE ID (URI SAN) from a completed mTLS
// handshake — the worker identity in the SPIFFE model (replaces the file-cert
// CommonName). Used as the controller's worker-identity derivation (idFn).
func PeerSPIFFEID(conn *tls.Conn) (string, error) {
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 || len(st.PeerCertificates[0].URIs) == 0 {
		return "", fmt.Errorf("transport: no SPIFFE ID in peer certificate")
	}
	return st.PeerCertificates[0].URIs[0].String(), nil
}
