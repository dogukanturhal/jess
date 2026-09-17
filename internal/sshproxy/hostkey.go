// SPDX-License-Identifier: AGPL-3.0-or-later

package sshproxy

import (
	"crypto/subtle"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

// PinnedHostKey returns the algorithm name AND the HostKeyCallback derived
// from a single authorized_keys-format pinned target host key. Set the
// returned algorithm in ssh.ClientConfig.HostKeyAlgorithms so SSH negotiation
// demands THIS host-key type — without that pin, x/crypto/ssh accepts whatever
// host key the server prefers (often ecdsa-sha2-nistp256 ahead of ssh-ed25519
// on OpenSSH 9.x), and the pinned-bytes comparison spuriously fails for
// servers that have multiple host keys.
func PinnedHostKey(authorizedKey string) (string, ssh.HostKeyCallback, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", nil, fmt.Errorf("sshproxy: parse pinned host key: %w", err)
	}
	want := pub.Marshal()
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if subtle.ConstantTimeCompare(key.Marshal(), want) == 1 {
			return nil
		}
		return fmt.Errorf("sshproxy: target host key mismatch for %q — refusing (possible MITM)", hostname)
	}
	return pub.Type(), cb, nil
}

// PinnedHostKeyCallback returns just the HostKeyCallback for callers that
// don't (yet) wire HostKeyAlgorithms. Prefer PinnedHostKey for new code.
func PinnedHostKeyCallback(authorizedKey string) (ssh.HostKeyCallback, error) {
	_, cb, err := PinnedHostKey(authorizedKey)
	return cb, err
}

// CAHostKey returns the cert-algorithm list AND a HostKeyCallback that accepts
// the target's host key iff it is an OpenSSH *host certificate* signed by the
// supplied CA whose ValidPrincipals contains the dialed hostname (ADR 0044 —
// SSH-CA host certificates kill per-host TOFU).
//
// Wire alongside PinnedHostKey, not instead of: per-target, choose CAHostKey
// when target.HostKeyCASigned == true (the target has been enrolled in the
// host-CA via scripts/configure-node-ssh-host-cert.sh) else fall back to
// PinnedHostKey(target.HostKey).
//
// Algorithm pinning: SSH negotiation will only accept a cert-form algorithm so
// the server is FORCED to present its host certificate (not the bare host key).
// If the server has no signed host cert, the handshake fails closed — exactly
// what we want when the target was enrolled in the CA but later regressed.
func CAHostKey(ca ssh.PublicKey) ([]string, ssh.HostKeyCallback, error) {
	if ca == nil {
		return nil, nil, fmt.Errorf("sshproxy: CAHostKey: nil CA public key")
	}
	caMarshaled := ca.Marshal()
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			// Constant-time CA-key comparison. address is "host:port"; we don't
			// scope the authority by address since one CA is trusted for ALL
			// hosts the worker dials.
			return subtle.ConstantTimeCompare(auth.Marshal(), caMarshaled) == 1
		},
		HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Reached when the server presented a bare host key (not a
			// certificate) — in CA mode we treat that as a regression of the
			// target's host-cert deployment, NOT as TOFU acceptance.
			return fmt.Errorf("sshproxy: target %q presented a bare host key in CA mode; expected a host certificate signed by the configured SSH host CA", hostname)
		},
	}
	// Pinning to cert algorithms only: server MUST advertise a cert-form host
	// key during KEX. Ed25519 is our primary host key type; legacy ECDSA/RSA
	// listed in case of mixed-OS estate (Windows OpenSSH historically defaulted
	// to ECDSA P-256). RSA is included for the same reason but is the last
	// resort.
	algos := []string{
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoRSAv01,
	}
	return algos, checker.CheckHostKey, nil
}
