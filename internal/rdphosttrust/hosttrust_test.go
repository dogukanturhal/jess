// SPDX-License-Identifier: AGPL-3.0-or-later

package rdphosttrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/rdpprobe"
)

// --- test PKI helpers -------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issueLeaf signs a server-auth leaf for the given SANs and validity window.
func (ca *testCA) issueLeaf(t *testing.T, serial int64, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// stash the key for the TLS-server test path
	cert.PublicKey = &key.PublicKey
	leafKeys[string(cert.Raw)] = key
	return cert
}

var leafKeys = map[string]*ecdsa.PrivateKey{}

// --- verifyChain: the security core ----------------------------------------

func TestVerifyChain_CAValidAccepted(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	leaf := ca.issueLeaf(t, 100, []string{"rdp.corp.local"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	h := New(Config{Anchors: ca.pool})

	res, err := h.verifyChain([]*x509.Certificate{leaf}, "rdp.corp.local")
	if err != nil {
		t.Fatalf("expected valid chain accepted, got error: %v", err)
	}
	if res.SerialHex != "64" { // 100 == 0x64
		t.Errorf("serial hex = %q, want 64", res.SerialHex)
	}
	if res.CAFingerprint == "" {
		t.Error("expected a CA fingerprint on the result")
	}
}

func TestVerifyChain_WrongCARejected(t *testing.T) {
	realCA := newTestCA(t, "AD-CS Root")
	leaf := realCA.issueLeaf(t, 101, []string{"rdp.corp.local"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	// Anchors are a DIFFERENT CA — the leaf must not validate.
	otherCA := newTestCA(t, "Rogue Root")
	h := New(Config{Anchors: otherCA.pool})

	if _, err := h.verifyChain([]*x509.Certificate{leaf}, "rdp.corp.local"); err == nil {
		t.Fatal("expected wrong-CA chain to be REJECTED, got nil error")
	}
}

func TestVerifyChain_RevokedBySerialRejected(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	leaf := ca.issueLeaf(t, 0xABCD, []string{"rdp.corp.local"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	h := New(Config{Anchors: ca.pool, RevokedSerials: []string{"abcd"}})

	if _, err := h.verifyChain([]*x509.Certificate{leaf}, "rdp.corp.local"); err == nil {
		t.Fatal("expected CRL-revoked (by serial) cert to be REJECTED, got nil error")
	}
}

func TestVerifyChain_RevokedByFingerprintRejected(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	leaf := ca.issueLeaf(t, 200, []string{"rdp.corp.local"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	sum := sha256.Sum256(leaf.Raw)
	h := New(Config{Anchors: ca.pool, RevokedFingerprints: []string{hex.EncodeToString(sum[:])}})

	if _, err := h.verifyChain([]*x509.Certificate{leaf}, "rdp.corp.local"); err == nil {
		t.Fatal("expected fingerprint-deny-listed cert to be REJECTED, got nil error")
	}
}

func TestVerifyChain_SANMismatchRejected(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	leaf := ca.issueLeaf(t, 201, []string{"rdp.corp.local"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	h := New(Config{Anchors: ca.pool})

	if _, err := h.verifyChain([]*x509.Certificate{leaf}, "attacker.corp.local"); err == nil {
		t.Fatal("expected SAN mismatch to be REJECTED, got nil error")
	}
}

func TestVerifyChain_ExpiredRejected(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	leaf := ca.issueLeaf(t, 202, []string{"rdp.corp.local"}, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	h := New(Config{Anchors: ca.pool})

	if _, err := h.verifyChain([]*x509.Certificate{leaf}, "rdp.corp.local"); err == nil {
		t.Fatal("expected expired cert to be REJECTED, got nil error")
	}
}

// --- Preflight decision logic ----------------------------------------------

func TestPreflight_NotRequiredIsNoop(t *testing.T) {
	// No global enforce, target not opted in, no anchors → Preflight is a no-op
	// (legacy TOFU preserved for un-enrolled targets).
	h := New(Config{})
	tgt := &catalog.Target{ID: "t1", Protocol: catalog.ProtoRDP, Address: "10.0.0.9:3389"}
	if err := h.Preflight(context.Background(), tgt); err != nil {
		t.Fatalf("non-required target should pass without validation, got: %v", err)
	}
}

func TestPreflight_RequiredButNoAnchorsFailsClosed(t *testing.T) {
	// Target opts in but no anchors configured → FAIL CLOSED.
	h := New(Config{})
	tgt := &catalog.Target{ID: "t1", Protocol: catalog.ProtoRDP, Address: "10.0.0.9:3389", RDPTLSCASigned: true}
	if err := h.Preflight(context.Background(), tgt); err == nil {
		t.Fatal("required target with no anchors must FAIL CLOSED, got nil error")
	}
}

func TestPreflight_TOFUEscapeHatchSkips(t *testing.T) {
	// Escape hatch armed → skip validation even for an enforced target with no
	// reachable host (proves no dial happens).
	h := New(Config{Enforce: true, AllowTOFU: true})
	tgt := &catalog.Target{ID: "t1", Protocol: catalog.ProtoRDP, Address: "203.0.113.1:3389"}
	if err := h.Preflight(context.Background(), tgt); err != nil {
		t.Fatalf("TOFU escape hatch should skip validation, got: %v", err)
	}
}

func TestRequired(t *testing.T) {
	enforced := New(Config{Enforce: true})
	perTargetOnly := New(Config{})
	rdp := &catalog.Target{ID: "r", Protocol: catalog.ProtoRDP}
	rdpOptIn := &catalog.Target{ID: "r2", Protocol: catalog.ProtoRDP, RDPTLSCASigned: true}

	if !enforced.Required(rdp) {
		t.Error("global enforce should make every RDP target required")
	}
	if perTargetOnly.Required(rdp) {
		t.Error("without enforce, a non-opted-in target must not be required")
	}
	if !perTargetOnly.Required(rdpOptIn) {
		t.Error("per-target opt-in must make the target required")
	}
}

// --- verifyHost: full wire path against a local X.224+TLS listener ----------

// rdpTLSListener speaks the minimal MS-RDPBCGR outer handshake (X.224 CC with
// an RDP_NEG_RSP selecting TLS) then upgrades to a TLS server presenting cert,
// so verifyHost's dial→negotiate→handshake→validate path is exercised end-to-end.
func rdpTLSListener(t *testing.T, cert *x509.Certificate, srvCfg *tls.Config) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				// Read (and discard) the client's X.224 Connection Request.
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if _, err := c.Write(x224ConfirmTLS()); err != nil {
					return
				}
				// Upgrade to TLS server on the same socket.
				tc := tls.Server(c, srvCfg)
				_ = tc.Handshake() // client validates the cert; errors are fine here
			}(conn)
		}
	}()
	return l
}

// x224ConfirmTLS builds a TPKT + X.224 Connection Confirm + RDP_NEG_RSP trailer
// selecting PROTOCOL_SSL (0x1), the shape rdpprobe.ReadX224ConnectionConfirm parses.
func x224ConfirmTLS() []byte {
	neg := make([]byte, 8)
	neg[0] = 0x02 // TYPE_RDP_NEG_RSP
	neg[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], rdpprobe.ProtoTLS)
	x224 := []byte{0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00} // LI, CC code, refs, class
	rest := append(x224, neg...)
	total := 4 + len(rest)
	tpkt := []byte{0x03, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	return append(tpkt, rest...)
}

func serverTLSConfig(t *testing.T, cert *x509.Certificate) *tls.Config {
	t.Helper()
	key := leafKeys[string(cert.Raw)]
	if key == nil {
		t.Fatal("no private key stashed for leaf")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
			Leaf:        cert,
		}},
		MinVersion: tls.VersionTLS12,
	}
}

func TestPreflight_EndToEnd_ValidAcceptedWrongCARejected(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	leaf := ca.issueLeaf(t, 300, []string{"rdp.corp.local"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	l := rdpTLSListener(t, leaf, serverTLSConfig(t, leaf))
	defer l.Close()

	tgt := &catalog.Target{ID: "dc-rdp", Protocol: catalog.ProtoRDP, Address: l.Addr().String(), RDPTLSCASigned: true}

	// Correct anchors + matching server-name → accepted.
	good := New(Config{Anchors: ca.pool, ServerName: "rdp.corp.local", DialTimeout: 3 * time.Second})
	if err := good.Preflight(context.Background(), tgt); err != nil {
		t.Fatalf("valid host cert should be accepted end-to-end, got: %v", err)
	}

	// Wrong anchors → fail closed even though the target is reachable + speaks TLS.
	rogue := New(Config{Anchors: newTestCA(t, "Rogue").pool, ServerName: "rdp.corp.local", DialTimeout: 3 * time.Second})
	if err := rogue.Preflight(context.Background(), tgt); err == nil {
		t.Fatal("wrong-CA host cert must FAIL CLOSED end-to-end, got nil error")
	}
}

// --- config parsing ---------------------------------------------------------

func TestLoadFromEnv_BadPEMIsError(t *testing.T) {
	t.Setenv(EnvCAPEM, "not a pem")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("a malformed CA PEM must be a loud config error, not a silent accept-all")
	}
}

func TestLoadFromEnv_AnchorsEnableEnforceByDefault(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	t.Setenv(EnvCAPEM, string(caPEM))
	h, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !h.Configured() {
		t.Error("anchors should be configured")
	}
	if !h.Enforced() {
		t.Error("configuring anchors should enable global enforce by default")
	}
}

func TestLoadFromEnv_EnforceCanBeDisabled(t *testing.T) {
	ca := newTestCA(t, "AD-CS Root")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	t.Setenv(EnvCAPEM, string(caPEM))
	t.Setenv(EnvEnforce, "false")
	h, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if h.Enforced() {
		t.Error("JESS_RDP_TLS_ENFORCE=false must disable global enforce (per-target only)")
	}
	if !h.Configured() {
		t.Error("anchors should still be configured")
	}
}
