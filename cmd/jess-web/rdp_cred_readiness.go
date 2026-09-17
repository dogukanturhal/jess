// SPDX-License-Identifier: AGPL-3.0-or-later

// rdp_cred_readiness — wait for a freshly-minted Vault LDAP dynamic credential
// to become authenticatable BEFORE it's handed to session_live for the RDP
// logon.
//
// WHY: the production RDP credential is a per-session ephemeral AD account that
// Vault's LDAP secrets engine creates on demand (see internal/broker/
// rdp_vault_creds.go). Active Directory is eventually consistent — HashiCorp's
// own AD/LDAP secrets-engine docs note a newly-set password can take "over 10
// seconds to propagate fully" and the remedy is to "simply wait and retry using
// the new password". jess opens the RDP NLA/logon within milliseconds of the
// mint, so it intermittently races the propagation and the Windows logon rejects
// the brand-new account with STATUS_LOGON_FAILURE ("The user name or password is
// incorrect"). This gate performs HashiCorp's prescribed wait: it binds to the
// DC as the new account with capped exponential backoff until the credential
// authenticates, THEN lets the session proceed.
//
// FAIL-OPEN by design: this is a latency optimisation, not a security control.
// If the readiness LDAP endpoint is unreachable, or the credential never
// propagates within the budget, the session proceeds anyway (no worse than
// today) — it NEVER denies a session the credential broker already authorised.
//
// Config (all on jess-web; the whole gate is OFF unless the URL is set):
//
//	JESS_RDP_CRED_READINESS_LDAP_URL    DC LDAP(S) URL, e.g. ldaps://dc.hexxlock.corp:636
//	                                    or ldap://10.0.20.10:389. Unset → gate disabled.
//	JESS_RDP_CRED_READINESS_TIMEOUT     total wait budget (default 20s)
//	JESS_RDP_CRED_READINESS_INSECURE_TLS=1  skip cert verify for ldaps (internal CA)
package main

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/dogukanturhal/jess/internal/broker"
)

type credReadiness struct {
	ldapURL     string
	timeout     time.Duration
	insecureTLS bool
}

// newCredReadiness builds the verifier from the environment, or returns nil
// (gate disabled) when JESS_RDP_CRED_READINESS_LDAP_URL is unset.
func newCredReadiness() *credReadiness {
	url := os.Getenv("JESS_RDP_CRED_READINESS_LDAP_URL")
	if url == "" {
		return nil
	}
	return &credReadiness{
		ldapURL:     url,
		timeout:     durationEnv("JESS_RDP_CRED_READINESS_TIMEOUT", 20*time.Second),
		insecureTLS: os.Getenv("JESS_RDP_CRED_READINESS_INSECURE_TLS") == "1",
	}
}

// wait blocks until the credential authenticates against the DC (LDAP simple
// bind) or the budget expires / the LDAP endpoint is unreachable. It returns
// whether the credential became ready (purely advisory — the caller proceeds
// regardless). It re-tries the SAME credential (HashiCorp: "wait and retry using
// the new password"); it never re-mints.
func (r *credReadiness) wait(ctx context.Context, sec broker.RDPSecret) bool {
	if sec.Username == "" || sec.Password == "" {
		return false
	}
	// Down-level logon name (NetBIOS\sam) — AD accepts this for a simple bind,
	// and it mirrors what the RDP NLA credential carries (Domain + Username).
	bindUser := sec.Username
	if sec.Domain != "" {
		bindUser = sec.Domain + `\` + sec.Username
	}

	start := time.Now()
	deadline := start.Add(r.timeout)
	backoff := 250 * time.Millisecond
	attempt := 0
	for {
		attempt++
		dialed, authed := r.probe(bindUser, sec.Password)
		if authed {
			if attempt > 1 {
				log.Printf("jess-web RDP live: credential propagated, ready after %s (%d attempt(s))",
					time.Since(start).Round(time.Millisecond), attempt)
			}
			return true
		}
		if !dialed {
			// Infra issue, not propagation — don't burn the whole budget spinning.
			log.Printf("jess-web RDP live: cred-readiness LDAP %s unreachable — skipping wait, proceeding best-effort", r.ldapURL)
			return false
		}
		// Dialed but the DC rejected the brand-new account → still propagating.
		if time.Now().Add(backoff).After(deadline) {
			log.Printf("jess-web RDP live: credential NOT ready after %s (%d attempts) — proceeding best-effort; the Windows logon may reject until AD finishes propagating",
				time.Since(start).Round(time.Millisecond), attempt)
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

// probe performs one LDAP simple bind as the credential. dialed reports whether
// the LDAP endpoint was reachable at all (false → infra problem, not a
// propagation signal); authed reports whether the DC accepted the credential.
func (r *credReadiness) probe(user, pass string) (dialed, authed bool) {
	var (
		l   *ldap.Conn
		err error
	)
	if r.insecureTLS {
		l, err = ldap.DialURL(r.ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		l, err = ldap.DialURL(r.ldapURL)
	}
	if err != nil {
		return false, false
	}
	defer l.Close()
	if err := l.Bind(user, pass); err != nil {
		// Almost always LDAPResultInvalidCredentials while AD propagates the new
		// account; treat any bind error as "reachable but not yet authenticatable".
		return true, false
	}
	return true, true
}
