// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// These tests exercise the SVID mTLS path with an in-memory fake X509 source —
// no live SPIRE agent. They cover the four behaviours the feature promises:
// the handshake authorizes the correct peer SPIFFE ID, rejects a wrong one,
// socket-absent falls back to file-PEM, and the flag-off gate is a no-op.

const (
	tdControllerID = "spiffe://prod.hexxlock/ns/jess/sa/jess/controller"
	tdWorkerID     = "spiffe://prod.hexxlock/ns/jess/sa/jess/worker"
	tdImpostorID   = "spiffe://prod.hexxlock/ns/jess/sa/jess/impostor"
)

// fakeX509Source is an in-memory X509SVIDSource: a fixed SVID plus a fixed trust
// bundle. It satisfies both x509svid.Source and x509bundle.Source, i.e. the
// transport.X509SVIDSource interface the mTLS config builders consume.
type fakeX509Source struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (f *fakeX509Source) GetX509SVID() (*x509svid.SVID, error) { return f.svid, nil }

func (f *fakeX509Source) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return f.bundle.GetX509BundleForTrustDomain(td)
}

// compile-time assertion that the fake satisfies the production interface.
var _ X509SVIDSource = (*fakeX509Source)(nil)

// testCA is a throwaway self-signed CA used to mint SPIFFE leaf SVIDs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-spire-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// mintSource issues a SPIFFE X.509-SVID (leaf with a single URI SAN = id, signed
// by the CA) and wraps it with the CA trust bundle in a fake source.
func (ca *testCA) mintSource(t *testing.T, id string) *fakeX509Source {
	t.Helper()
	sid, err := spiffeid.FromString(id)
	if err != nil {
		t.Fatalf("spiffe id %q: %v", id, err)
	}
	uri, err := url.Parse(id)
	if err != nil {
		t.Fatalf("parse uri %q: %v", id, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return &fakeX509Source{
		svid:   &x509svid.SVID{ID: sid, Certificates: []*x509.Certificate{leaf}, PrivateKey: key},
		bundle: x509bundle.FromX509Authorities(sid.TrustDomain(), []*x509.Certificate{ca.cert}),
	}
}

// handshake drives an mTLS handshake between a server config and a client config
// over a real TCP loopback, returning the first error seen (nil on mutual
// success). Loopback (rather than net.Pipe) is used so a one-sided rejection
// closes cleanly instead of blocking the peer's read. A bounded context guards
// against a stuck handshake hanging the test.
func handshake(serverCfg, clientCfg *tls.Config) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errc := make(chan error, 2)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			errc <- aerr
			return
		}
		s := tls.Server(conn, serverCfg)
		herr := s.HandshakeContext(ctx)
		errc <- herr
		_ = s.Close()
	}()
	go func() {
		d := &tls.Dialer{Config: clientCfg}
		conn, derr := d.DialContext(ctx, "tcp", ln.Addr().String())
		errc <- derr
		if conn != nil {
			_ = conn.Close()
		}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if e := <-errc; e != nil && firstErr == nil {
			firstErr = e
		}
	}
	return firstErr
}

func TestSVIDConfig_HandshakeAuthorizesCorrectPeer(t *testing.T) {
	ca := newTestCA(t)
	serverSrc := ca.mintSource(t, tdControllerID) // controller presents its SVID
	clientSrc := ca.mintSource(t, tdWorkerID)     // worker presents its SVID

	serverAuthz, err := AuthorizeSPIFFEID(tdWorkerID) // controller pins the worker
	if err != nil {
		t.Fatalf("server authorizer: %v", err)
	}
	clientAuthz, err := AuthorizeSPIFFEID(tdControllerID) // worker pins the controller
	if err != nil {
		t.Fatalf("client authorizer: %v", err)
	}

	if herr := handshake(SVIDServerConfig(serverSrc, serverAuthz), SVIDClientConfig(clientSrc, clientAuthz)); herr != nil {
		t.Fatalf("expected mutual handshake to succeed, got: %v", herr)
	}
}

func TestSVIDConfig_HandshakeRejectsWrongPeer(t *testing.T) {
	ca := newTestCA(t)
	serverSrc := ca.mintSource(t, tdControllerID)
	clientSrc := ca.mintSource(t, tdWorkerID)

	// The controller pins a DIFFERENT worker ID than the one the client presents;
	// AuthorizeID must reject it even though the leaf is validly CA-signed.
	serverAuthz, err := AuthorizeSPIFFEID(tdImpostorID)
	if err != nil {
		t.Fatalf("server authorizer: %v", err)
	}
	clientAuthz, err := AuthorizeSPIFFEID(tdControllerID)
	if err != nil {
		t.Fatalf("client authorizer: %v", err)
	}

	if herr := handshake(SVIDServerConfig(serverSrc, serverAuthz), SVIDClientConfig(clientSrc, clientAuthz)); herr == nil {
		t.Fatal("expected handshake to fail (server pins a different worker SPIFFE ID), got success")
	}
}

func TestSVIDConfig_HandshakeRejectsUntrustedCA(t *testing.T) {
	// Server and client SVIDs are minted by DIFFERENT CAs — the peer cert is
	// well-formed but does not chain to the verifier's trust bundle.
	serverSrc := newTestCA(t).mintSource(t, tdControllerID)
	clientSrc := newTestCA(t).mintSource(t, tdWorkerID)

	serverAuthz, err := AuthorizeSPIFFEID(tdWorkerID)
	if err != nil {
		t.Fatalf("server authorizer: %v", err)
	}
	clientAuthz, err := AuthorizeSPIFFEID(tdControllerID)
	if err != nil {
		t.Fatalf("client authorizer: %v", err)
	}

	if herr := handshake(SVIDServerConfig(serverSrc, serverAuthz), SVIDClientConfig(clientSrc, clientAuthz)); herr == nil {
		t.Fatal("expected handshake to fail (peer SVID from an untrusted CA), got success")
	}
}

func TestAcquireSVIDSource_FlagOffIsNoOp(t *testing.T) {
	// Flag off: the socket must never be touched and no source acquired, even
	// though a valid default socket path is supplied.
	src, active, err := AcquireSVIDSource(context.Background(), false, DefaultSpireSocket, time.Second)
	if err != nil {
		t.Fatalf("flag-off must not error: %v", err)
	}
	if active || src != nil {
		t.Fatalf("flag off must be inert: active=%v src=%v", active, src)
	}
}

func TestAcquireSVIDSource_SocketAbsentFallsBack(t *testing.T) {
	// Flag on but SPIRE not deployed (socket file absent): must degrade to
	// file-PEM (active=false) WITHOUT erroring — SPIRE-down is never fatal.
	absent := "unix://" + filepath.Join(t.TempDir(), "missing", "spire-agent.sock")
	src, active, err := AcquireSVIDSource(context.Background(), true, absent, time.Second)
	if err != nil {
		t.Fatalf("socket-absent must not hard-fail: %v", err)
	}
	if active || src != nil {
		t.Fatalf("socket absent must fall back to file-PEM: active=%v src=%v", active, src)
	}
}

func TestAcquireSVIDSource_EmptySocketErrors(t *testing.T) {
	// Flag on with an empty socket address is a config error the operator must
	// see (distinct from SPIRE simply being down).
	if _, _, err := AcquireSVIDSource(context.Background(), true, "", time.Second); err == nil {
		t.Fatal("expected an error for an empty socket address with the flag on")
	}
}
