// SPDX-License-Identifier: AGPL-3.0-or-later

package devicecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const testUUID = "3f9b2c1a-0000-4abc-9def-1234567890ab"

func genCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jess-device-ca"},
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
	c, _ := x509.ParseCertificate(der)
	return c, key
}

type leafOpts struct {
	uuid       string
	cn         string
	notBefore  time.Time
	notAfter   time.Time
	withSPIFFE bool
	withEKU    bool
}

func genLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, o leafOpts) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: o.cn},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
	}
	if o.withEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.withSPIFFE {
		u, _ := url.Parse(SPIFFEPrefix + o.uuid)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// xfccHeader builds an Envoy-style XFCC header carrying the leaf in Cert=.
func xfccHeader(c *x509.Certificate) string {
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	return `Hash=deadbeef;Cert="` + url.QueryEscape(p) + `"`
}

func reqWithXFCC(c *x509.Certificate) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/device-cert/renew", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccHeader(c))
	return r
}

func validLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	return genLeaf(t, ca, caKey, leafOpts{
		uuid: testUUID, cn: "04ad2960",
		notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(12 * time.Hour),
		withSPIFFE: true, withEKU: true,
	})
}

func TestVerify_HappyPath(t *testing.T) {
	ca, caKey := genCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v, err := NewVerifier(pool)
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.VerifyRequest(reqWithXFCC(validLeaf(t, ca, caKey)))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.DeviceUUID != testUUID {
		t.Errorf("device_uuid=%q want %q", id.DeviceUUID, testUUID)
	}
	if id.UserSub != "04ad2960" {
		t.Errorf("user_sub=%q want 04ad2960", id.UserSub)
	}
	if id.SPIFFE != SPIFFEPrefix+testUUID {
		t.Errorf("spiffe=%q", id.SPIFFE)
	}
}

func TestVerify_Failures(t *testing.T) {
	ca, caKey := genCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v, _ := NewVerifier(pool)

	cases := []struct {
		name string
		req  *http.Request
		want error
	}{
		{"no xfcc no tls", func() *http.Request { r, _ := http.NewRequest("POST", "/device-cert/renew", nil); return r }(), ErrNoCert},
		{"expired", reqWithXFCC(genLeaf(t, ca, caKey, leafOpts{uuid: testUUID, cn: "u", notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour), withSPIFFE: true, withEKU: true})), ErrExpired},
		{"no spiffe", reqWithXFCC(genLeaf(t, ca, caKey, leafOpts{uuid: testUUID, cn: "u", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour), withSPIFFE: false, withEKU: true})), ErrSANMissing},
		{"no clientauth eku", reqWithXFCC(genLeaf(t, ca, caKey, leafOpts{uuid: testUUID, cn: "u", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour), withSPIFFE: true, withEKU: false})), ErrMissingEKU},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.VerifyRequest(tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerify_WrongCAFails(t *testing.T) {
	ca, caKey := genCA(t)
	other, _ := genCA(t) // trust pool has a DIFFERENT CA
	pool := x509.NewCertPool()
	pool.AddCert(other)
	v, _ := NewVerifier(pool)
	_, err := v.VerifyRequest(reqWithXFCC(validLeaf(t, ca, caKey)))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("got %v, want ErrChainInvalid", err)
	}
}

func TestParseXFCC_Malformed(t *testing.T) {
	ca, caKey := genCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v, _ := NewVerifier(pool)
	_ = validLeaf(t, ca, caKey)

	r, _ := http.NewRequest("POST", "/device-cert/renew", nil)
	r.Header.Set("X-Forwarded-Client-Cert", `Hash=abc;Subject="CN=x"`) // no Cert=
	if _, err := v.VerifyRequest(r); !errors.Is(err, ErrXFCCMissingCrt) {
		t.Fatalf("got %v, want ErrXFCCMissingCrt", err)
	}
}
