// SPDX-License-Identifier: AGPL-3.0-or-later

// Package broker is the data plane: it brokers an authorized session to a
// target, minting an ephemeral credential from Vault and proxying bytes.
package broker

import (
	"context"
	"net"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// Session is an open brokered connection (audited start→close).
type Session struct {
	ID         string
	TargetID   string
	Subject    string
	DecisionID string
	StartedAt  time.Time
}

// CredentialBroker mints short-lived, per-session credentials from Vault —
// zero standing credentials reach the operator or live on the target.
// (Implemented in Phase 5b/5c against hashicorp/vault/api.)
type CredentialBroker interface {
	// SignSSH returns a Vault-signed SSH user cert (ssh-client-signer/sign/ssh-admin).
	SignSSH(ctx context.Context, publicKey []byte, principals []string, ttl time.Duration) (cert []byte, err error)
	// IssueDBCreds returns dynamic Postgres creds for a Vault database role.
	IssueDBCreds(ctx context.Context, role string) (username, password string, err error)
}

// SessionBroker opens and proxies a session for an ALREADY-authorized request.
type SessionBroker interface {
	Open(ctx context.Context, target *catalog.Target, client net.Conn) (*Session, error)
}

// TCPBroker is the v1 raw-TCP broker (runs on the outbound-only worker). SSH/DB
// brokers (with Vault credential injection) arrive in 5b/5c.
type TCPBroker struct {
	Creds CredentialBroker // unused for raw TCP; required for SSH/DB brokers
}

// Open proxies the session to the target over raw TCP and returns when it ends.
func (b *TCPBroker) Open(ctx context.Context, target *catalog.Target, client net.Conn) (*Session, error) {
	s := &Session{ID: newSessionID(), TargetID: target.ID, StartedAt: time.Now()}
	_, _, err := ProxyTCP(ctx, target.Address, client)
	return s, err
}
