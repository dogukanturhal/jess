// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/sshproxy"
)

// sshBroker is the reference Broker implementation (ADR 0049 Phase 0). It wraps
// the existing, security-reviewed sshproxy record-proxy (ADR 0030 Phase 5b) and
// recorder so the SSH path is unchanged — same operator-cert authority check,
// same per-channel target dial, same WORM teeing — only re-expressed behind the
// Broker seam. Behaviour MUST stay identical to the worker's pre-refactor SSH
// switch arm.
type sshBroker struct {
	// proxy is the SSH MitM config: operator-cert authority + worker host key +
	// DialTarget (the per-session Vault SSH-CA cert mint + target dial). The
	// SSH backend credential is minted lazily inside DialTarget at dial time —
	// this is the existing design (the operator's key never touches the target,
	// and the cert TTL starts at dial, not at grant approval). See Mint.
	proxy *sshproxy.Config
	// rec captures the session to a tamper-evident signed WORM bundle, or nil
	// for no recording (a Recorded=true target is then denied, fail-closed).
	rec recording.Recorder
}

// NewSSHBroker returns the reference SSH Broker over the existing sshproxy config
// and recorder (rec may be nil — recording is then unavailable and Recorded
// targets are denied fail-closed, exactly as the worker does today).
func NewSSHBroker(proxy *sshproxy.Config, rec recording.Recorder) Broker {
	return &sshBroker{proxy: proxy, rec: rec}
}

// Protocol implements Broker.
func (b *sshBroker) Protocol() string { return string(catalog.ProtoSSH) }

// sshCredential is the SSH broker's per-session credential marker. The actual
// short-lived Vault SSH-CA cert for the target is minted lazily inside the
// proxy's DialTarget at Dial time (the operator's key never reaches the target;
// the cert TTL must start at the hop, not at approval) — so at this seam Mint
// records that the grant is authorized and carries the recording metadata Dial
// needs. This is faithful to the existing SSH design, not a stub of the mint:
// the cert mint genuinely happens in the proxy, and hoisting it here would
// change the cert's validity window (a behaviour change Phase 0 forbids).
type sshCredential struct {
	grant AccessGrant
}

func (sshCredential) Protocol() string { return string(catalog.ProtoSSH) }

// Mint implements Broker. For SSH the backend cert is minted per-target-channel
// inside the proxy's DialTarget; Mint validates the grant carries a target and
// captures the recording metadata for Dial. See sshCredential.
func (b *sshBroker) Mint(_ context.Context, grant AccessGrant) (Credential, error) {
	if b.proxy == nil {
		return nil, fmt.Errorf("ssh broker: proxy not configured")
	}
	if grant.Target == nil {
		return nil, fmt.Errorf("ssh broker: grant has no target")
	}
	if grant.Client == nil {
		return nil, fmt.Errorf("ssh broker: grant has no client connection")
	}
	return sshCredential{grant: grant}, nil
}

// Dial implements Broker. It sets up the WORM recorder (identical fail-closed
// semantics to the worker) and returns a RecordedConn whose Wait runs the
// sshproxy MitM, teeing terminal output to the bundle, and whose Close seals it.
func (b *sshBroker) Dial(ctx context.Context, target *catalog.Target, cred Credential) (RecordedConn, error) {
	sc, ok := cred.(sshCredential)
	if !ok {
		return nil, fmt.Errorf("ssh broker: credential is not an SSH credential (%T)", cred)
	}
	if target == nil {
		return nil, fmt.Errorf("ssh broker: nil target")
	}

	conn := &sshRecordedConn{ctx: ctx, proxy: b.proxy, target: target, client: sc.grant.Client}

	if b.rec != nil {
		meta := recordingMetaFor(sc.grant, string(catalog.ProtoSSH), recording.FormatAsciicastV2)
		rc, rerr := recording.RecordSession(ctx, b.rec, meta, 80, 24)
		if rerr != nil {
			if target.Recorded {
				// Fail closed: a must-record target is denied if recording fails.
				return nil, fmt.Errorf("ssh broker: recording required but unavailable (fail-closed): %w", rerr)
			}
			// Non-recorded target: proceed without a recorder, as the worker does.
		} else {
			conn.rec = rc // Close seals the signed bundle to WORM
		}
	} else if target.Recorded {
		return nil, fmt.Errorf("ssh broker: recording required but no recorder configured (fail-closed)")
	}

	return conn, nil
}

// sshRecordedConn is an open SSH brokered session. Wait runs the MitM (returns
// when the operator disconnects); Close seals the recording bundle.
type sshRecordedConn struct {
	ctx    context.Context
	proxy  *sshproxy.Config
	target *catalog.Target
	client io.ReadWriteCloser
	rec    io.WriteCloser // nil = not recording
}

// Wait runs the SSH record-proxy over the operator connection, teeing terminal
// output to the recorder. It returns when the operator disconnects.
func (c *sshRecordedConn) Wait() error {
	// sshproxy.Handle wants a net.Conn; the tunnel session stream is one in
	// production. Tests pass a net.Conn too. Guard the conversion so a non-conn
	// caller gets a clear error rather than a panic.
	nc, ok := c.client.(interface {
		io.ReadWriteCloser
		net.Conn
	})
	if !ok {
		return fmt.Errorf("ssh broker: client connection is not a net.Conn (%T)", c.client)
	}
	var rec io.Writer
	if c.rec != nil {
		rec = c.rec
	}
	return c.proxy.Handle(c.ctx, nc, c.target, rec)
}

// Close seals the recording bundle (Close error fails the session closed, ADR
// 0030 Phase 5). It is safe to call when not recording.
func (c *sshRecordedConn) Close() error {
	if c.rec == nil {
		return nil
	}
	return c.rec.Close()
}
