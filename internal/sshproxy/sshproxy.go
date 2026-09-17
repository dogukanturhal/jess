// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sshproxy is the worker's SSH record-proxy (ADR 0030 Phase 5b): the
// worker is an SSH SERVER to the operator (authenticating the operator's
// Vault-SSH-CA-signed certificate) and an SSH CLIENT to the target, piping the
// session channels while teeing terminal output to a recorder. The operator's
// key never touches the target — the worker dials the target with a separate,
// Vault-brokered credential (DialTarget).
package sshproxy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// Config configures the SSH record-proxy.
type Config struct {
	// OperatorCA is the Vault SSH CA public key; operator certs must be signed
	// by it (and carry a valid principal for the requested login user).
	OperatorCA ssh.PublicKey
	// HostKey is the worker's SSH host key, presented to the operator.
	HostKey ssh.Signer
	// DialTarget dials the target as an SSH client. In production it fetches a
	// fresh, short-lived cert from Vault (ssh/sign) so the operator never holds
	// target credentials.
	DialTarget func(ctx context.Context, target *catalog.Target) (*ssh.Client, error)
}

func (c *Config) checkOperatorCert(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// CertChecker.Authenticate performs the FULL check: rejects non-certificate
	// keys, verifies the cert signature against IsUserAuthority (the Vault SSH
	// CA), and validates principals + validity window via CheckCert. NOTE:
	// calling CheckCert alone does NOT verify the signing authority — that is a
	// trap; Authenticate is the correct entry point.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(a ssh.PublicKey) bool {
			// Constant-time compare; NEVER add a "can't happen → return true"
			// shortcut here — that exact simplification was Teleport's
			// CVE-2025-49825 (CVSS 9.8) auth bypass.
			return subtle.ConstantTimeCompare(a.Marshal(), c.OperatorCA.Marshal()) == 1
		},
	}
	perms, err := checker.Authenticate(conn, key)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: operator cert rejected: %w", err)
	}
	return perms, nil
}

// Handle runs the SSH MitM over conn (operator side; the post-header session
// stream from the tunnel), dialing target and teeing terminal output to rec
// (nil = no recording). Returns when the operator disconnects.
func (c *Config) Handle(ctx context.Context, conn net.Conn, target *catalog.Target, rec io.Writer) error {
	srvCfg := &ssh.ServerConfig{PublicKeyCallback: c.checkOperatorCert}
	// Pin modern algorithms (Go's defaults include weaker options).
	srvCfg.KeyExchanges = []string{"curve25519-sha256", "curve25519-sha256@libssh.org"}
	srvCfg.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}
	srvCfg.MACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"}
	srvCfg.AddHostKey(c.HostKey)

	// Bound the handshake so a stalled/hostile peer can't pin a goroutine forever.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	sconn, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
	if err != nil {
		return fmt.Errorf("sshproxy: operator handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{}) // clear; the session runs without the handshake deadline
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	tclient, err := c.DialTarget(ctx, target)
	if err != nil {
		go rejectChannels(chans)
		return fmt.Errorf("sshproxy: dial target %s: %w", target.Address, err)
	}
	defer tclient.Close()

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels are brokered")
			continue
		}
		opCh, opReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		tgtCh, tgtReqs, err := tclient.OpenChannel("session", nil)
		if err != nil {
			_ = opCh.Close()
			continue
		}
		go proxyChannel(opCh, opReqs, tgtCh, tgtReqs, rec)
	}
	return nil
}

func rejectChannels(chans <-chan ssh.NewChannel) {
	for nc := range chans {
		_ = nc.Reject(ssh.ConnectionFailed, "target unavailable")
	}
}

// proxyChannel pipes one session channel both ways, forwarding all channel
// requests (pty-req, env, shell, exec, window-change, signal, exit-status) and
// teeing target→operator output to rec.
func proxyChannel(opCh ssh.Channel, opReqs <-chan *ssh.Request, tgtCh ssh.Channel, tgtReqs <-chan *ssh.Request, rec io.Writer) {
	go forwardRequestsFiltered(opReqs, tgtCh, allowedOperatorRequests) // operator -> target (deny-by-default)
	reqDone := make(chan struct{})
	go func() { forwardRequests(tgtReqs, opCh); close(reqDone) }() // target -> operator (incl. exit-status)

	go func() { _, _ = io.Copy(tgtCh, opCh); _ = tgtCh.CloseWrite() }() // operator input -> target
	go func() { _, _ = io.Copy(opCh.Stderr(), tgtCh.Stderr()) }()       // target stderr -> operator

	out := io.Writer(opCh)
	if rec != nil {
		out = io.MultiWriter(opCh, rec) // record terminal output (what the operator sees)
	}
	_, _ = io.Copy(out, tgtCh) // target output -> operator (+ recorder); returns when target closes

	// Let exit-status/exit-signal finish forwarding before we tear the channel down.
	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
	}
	_ = opCh.Close()
	_ = tgtCh.Close()
}

func forwardRequests(in <-chan *ssh.Request, ch ssh.Channel) {
	for req := range in {
		ok, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok && err == nil, nil)
		}
	}
}

// allowedOperatorRequests is the deny-by-default allow-list of channel requests
// an operator may send to the target. It deliberately EXCLUDES agent forwarding
// (auth-agent-req@openssh.com), X11, and any port-forwarding — credential-leak
// and lateral-movement vectors. SSH global forwarding requests are dropped
// separately (DiscardRequests on the connection-level requests).
var allowedOperatorRequests = map[string]bool{
	"pty-req":       true,
	"shell":         true,
	"exec":          true,
	"window-change": true,
	"signal":        true,
	"env":           true,
	"subsystem":     true, // sftp/scp — gate per-target in a later phase
}

func forwardRequestsFiltered(in <-chan *ssh.Request, ch ssh.Channel, allow map[string]bool) {
	for req := range in {
		if allow != nil && !allow[req.Type] {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue // deny-by-default (agent forwarding, x11, etc.)
		}
		ok, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok && err == nil, nil)
		}
	}
}
