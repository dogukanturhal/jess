// SPDX-License-Identifier: AGPL-3.0-or-later

package sshproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// hostCert mints an SSH HOST cert for hostSigner.PublicKey() signed by ca, with
// the given valid_principals. cert_type=host is the difference between this and
// userCert in sshproxy_test.go — same Sign primitive, different CertType.
func hostCert(t *testing.T, ca ssh.Signer, hostSigner ssh.Signer, principals ...string) ssh.PublicKey {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             hostSigner.PublicKey(),
		Serial:          1,
		CertType:        ssh.HostCert,
		KeyId:           "host@test",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCAHostKey_AcceptsValidCert(t *testing.T) {
	ca := newSigner(t)
	host := newSigner(t)
	cert := hostCert(t, ca, host, "node-cp-01.internal.hexxlock.com", "node-cp-01", "10.0.70.100")

	algos, cb, err := CAHostKey(ca.PublicKey())
	if err != nil {
		t.Fatalf("CAHostKey: %v", err)
	}
	if len(algos) == 0 {
		t.Fatal("CAHostKey returned empty algorithm list")
	}
	// All algos must be cert-form (ssh.CertAlgoED25519v01 etc.) — otherwise we'd
	// silently accept bare host keys on KEX.
	for _, a := range algos {
		if !strings.Contains(a, "-cert-v01@openssh.com") {
			t.Fatalf("algo %q is not a cert form — would allow bare host key acceptance", a)
		}
	}

	// Each principal should validate.
	for _, host := range []string{
		"node-cp-01.internal.hexxlock.com:22",
		"node-cp-01:22",
		"10.0.70.100:22",
	} {
		if err := cb(host, nil, cert); err != nil {
			t.Errorf("expected accept for %s, got %v", host, err)
		}
	}
}

func TestCAHostKey_RejectsPrincipalMismatch(t *testing.T) {
	ca := newSigner(t)
	host := newSigner(t)
	cert := hostCert(t, ca, host, "node-cp-01")

	_, cb, err := CAHostKey(ca.PublicKey())
	if err != nil {
		t.Fatalf("CAHostKey: %v", err)
	}
	if err := cb("dc01:22", nil, cert); err == nil {
		t.Fatal("expected rejection — host cert's ValidPrincipals does NOT include dc01 but cb accepted")
	}
}

func TestCAHostKey_RejectsBareHostKey(t *testing.T) {
	// Server presents a bare host key (no cert) when CA mode is configured —
	// must reject (no TOFU fallback in CA mode).
	ca := newSigner(t)
	bareHost := newSigner(t)

	_, cb, err := CAHostKey(ca.PublicKey())
	if err != nil {
		t.Fatalf("CAHostKey: %v", err)
	}
	if err := cb("anything:22", nil, bareHost.PublicKey()); err == nil {
		t.Fatal("expected rejection — bare host key MUST not be accepted in CA mode")
	}
}

func TestCAHostKey_RejectsCertFromDifferentCA(t *testing.T) {
	// MITM-style attack: attacker has their OWN SSH-CA and signs a host cert
	// with the legitimate principal. Worker must reject because cert.SignatureKey
	// != configured trust anchor.
	legitCA := newSigner(t)
	rogueCA := newSigner(t)
	host := newSigner(t)
	rogueCert := hostCert(t, rogueCA, host, "node-cp-01")

	_, cb, err := CAHostKey(legitCA.PublicKey())
	if err != nil {
		t.Fatalf("CAHostKey: %v", err)
	}
	if err := cb("node-cp-01:22", nil, rogueCert); err == nil {
		t.Fatal("expected rejection — cert signed by rogue CA must NOT be accepted")
	}
}

func TestCAHostKey_RejectsUserCert(t *testing.T) {
	// cert_type=user (not host) presented in the host KEX position. Server-side
	// misconfig or rogue server — must reject.
	ca := newSigner(t)
	op := newSigner(t)
	userCertObj := &ssh.Certificate{
		Key:             op.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert, // ← user, not host
		KeyId:           "op@test",
		ValidPrincipals: []string{"node-cp-01"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := userCertObj.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	_, cb, err := CAHostKey(ca.PublicKey())
	if err != nil {
		t.Fatalf("CAHostKey: %v", err)
	}
	if err := cb("node-cp-01:22", nil, userCertObj); err == nil {
		t.Fatal("expected rejection — user cert must NOT validate as host key in CA mode")
	}
}

func TestCAHostKey_NilCARejected(t *testing.T) {
	_, _, err := CAHostKey(nil)
	if err == nil {
		t.Fatal("expected error for nil CA pubkey")
	}
}
