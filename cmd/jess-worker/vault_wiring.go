// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Production credential brokering wiring (ADR 0030 Phase 5b/5c/5d). Everything
// here is OPTIONAL and env-gated: if JESS_VAULT_ADDR is unset the worker stays
// exactly as it deploys today (raw-TCP brokering, no SSH cert injection, no DB
// dynamic creds, no recording). Each capability turns on only when its env is
// present, so enabling SSH does not force DB/recording and vice-versa.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/dbproxy"
	"github.com/dogukanturhal/jess/internal/mysqlproxy"
	"github.com/dogukanturhal/jess/internal/recording"
	"github.com/dogukanturhal/jess/internal/sshproxy"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// newVaultClient builds the Vault client from env, or returns (nil,nil) if Vault
// brokering is not configured (JESS_VAULT_ADDR unset).
func newVaultClient() (*vaultx.Client, error) {
	addr := env("JESS_VAULT_ADDR", "")
	if addr == "" {
		return nil, nil
	}
	return vaultx.New(vaultx.Config{
		Addr:     addr,
		Token:    env("JESS_VAULT_TOKEN", ""), // dev/static; prefer k8s auth in prod
		K8sMount: env("JESS_VAULT_K8S_MOUNT", "kubernetes"),
		K8sRole:  env("JESS_VAULT_K8S_ROLE", ""), // e.g. "jess-worker"
	})
}

// sshConfigFromVault builds the SSH record-proxy config (OperatorCA + HostKey +
// Vault-SSH-CA DialTarget), or nil if JESS_SSH_OPERATOR_CA is unset.
func sshConfigFromVault(vc *vaultx.Client) (*sshproxy.Config, error) {
	caLine := env("JESS_SSH_OPERATOR_CA", "")
	if caLine == "" || vc == nil {
		return nil, nil
	}
	operatorCA, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caLine))
	if err != nil {
		return nil, fmt.Errorf("JESS_SSH_OPERATOR_CA: %w", err)
	}
	hostKey, err := workerHostKey()
	if err != nil {
		return nil, err
	}
	sshMount := env("JESS_SSH_VAULT_MOUNT", "ssh-client-signer")
	role := env("JESS_SSH_VAULT_ROLE", "ssh-admin")
	loginUser := env("JESS_SSH_LOGIN_USER", "hexxlock")
	ttl := durationEnv("JESS_SSH_CERT_TTL", 5*time.Minute)
	// Optional: SSH HOST-cert CA trust anchor (ADR 0044). Read once at startup
	// from jess-ssh-host-ca/public_key — used for any catalog target with
	// host_key_ca_signed=true. If the mount is unset or unreachable, the
	// worker stays exactly as it deploys today (per-host pinning).
	hostCAPub, err := loadSSHHostCAPublicKey(vc)
	if err != nil {
		// Fail-open: log + continue with pinning-only. The mount can be added
		// later without a worker rebuild; per-target CA-signed=true entries
		// will then fail at session-open with a clear "no host CA trust
		// anchor configured" error.
		log.Printf("jess-worker: SSH host-CA trust anchor unavailable (%v); CA-mode disabled, per-host pinning remains active", err)
	}
	return &sshproxy.Config{
		OperatorCA: operatorCA,
		HostKey:    hostKey,
		DialTarget: sshDialTarget(vc, sshMount, role, loginUser, ttl, hostCAPub),
	}, nil
}

// loadSSHHostCAPublicKey reads the SSH host-cert CA's public key from Vault,
// or returns (nil, nil) if no mount is configured. Mount path defaults to
// "jess-ssh-host-ca" — overridable via JESS_SSH_HOST_CA_VAULT_MOUNT. The
// response from /v1/<mount>/public_key is the raw OpenSSH authorized_keys
// line of the CA's signing public key.
func loadSSHHostCAPublicKey(vc *vaultx.Client) (ssh.PublicKey, error) {
	mount := env("JESS_SSH_HOST_CA_VAULT_MOUNT", "")
	if mount == "" || vc == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := vc.ReadRawPEM(ctx, "/v1/"+mount+"/public_key")
	if err != nil {
		return nil, fmt.Errorf("read %s/public_key: %w", mount, err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%s/public_key returned empty body", mount)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		return nil, fmt.Errorf("parse %s/public_key as authorized_keys: %w", mount, err)
	}
	log.Printf("jess-worker: SSH host-CA trust anchor loaded from Vault mount %q (type=%s)", mount, pub.Type())
	return pub, nil
}

// workerHostKey loads the worker's SSH host key from JESS_SSH_HOST_KEY (PEM), or
// generates an ephemeral ed25519 key (dev — operators see a host-key change on
// restart; mount a persistent key in prod).
func workerHostKey() (ssh.Signer, error) {
	if pemKey := env("JESS_SSH_HOST_KEY", ""); pemKey != "" {
		s, err := ssh.ParsePrivateKey([]byte(pemKey))
		if err != nil {
			return nil, fmt.Errorf("JESS_SSH_HOST_KEY: %w", err)
		}
		return s, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	log.Print("warning: JESS_SSH_HOST_KEY unset — using an EPHEMERAL worker host key (operators see a host-key change on restart; mount a persistent key in prod)")
	return ssh.NewSignerFromKey(priv)
}

// sshDialTarget returns a DialTarget that, per session, mints a fresh ephemeral
// keypair, has Vault sign it (ssh-client-signer/sign/<role>) for loginUser, and
// dials the target with that short-lived cert — the operator never holds target
// credentials. Host-key validation is target-driven:
//
//   - target.HostKeyCASigned=true → CA-mode (ADR 0044): worker accepts iff
//     target presents an OpenSSH host certificate signed by the configured
//     jess-ssh-host-ca trust anchor (caPub). No per-host pinning needed.
//   - target.HostKeyCASigned=false → pinning mode: byte-exact constant-time
//     comparison against target.HostKey (the pre-2026-06-06 behavior).
func sshDialTarget(vc *vaultx.Client, sshMount, role, defaultLoginUser string, ttl time.Duration, caPub ssh.PublicKey) func(context.Context, *catalog.Target) (*ssh.Client, error) {
	return func(ctx context.Context, t *catalog.Target) (*ssh.Client, error) {
		// Per-target SSHLoginUser overrides the worker default — needed for
		// Windows AD DCs (login as Administrator) vs Linux (login as
		// hexxlock). The cert's valid_principal AND the SSH User: header
		// both follow this. Vault SSH role's allowed_users must include
		// the value (default ssh-admin role allows hexxlock,Administrator).
		loginUser := t.SSHLoginUser
		if loginUser == "" {
			loginUser = defaultLoginUser
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, err
		}
		authPub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		certStr, err := vc.SignSSHCert(ctx, sshMount, role, authPub, []string{loginUser}, ttl)
		if err != nil {
			return nil, err
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
		if err != nil {
			return nil, fmt.Errorf("parse vault-signed cert: %w", err)
		}
		cert, ok := pk.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("vault ssh/sign did not return a certificate")
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			return nil, fmt.Errorf("cert signer: %w", err)
		}
		// Per-target host-key validation strategy.
		var hkcb ssh.HostKeyCallback
		var hkAlgos []string
		if t.HostKeyCASigned {
			if caPub == nil {
				return nil, fmt.Errorf("target %s host_key_ca_signed=true but worker has no SSH host-CA trust anchor configured (set JESS_SSH_HOST_CA_VAULT_MOUNT)", t.ID)
			}
			hkAlgos, hkcb, err = sshproxy.CAHostKey(caPub)
			if err != nil {
				return nil, fmt.Errorf("target %s host-CA validator: %w", t.ID, err)
			}
		} else {
			var hkAlgo string
			hkAlgo, hkcb, err = sshproxy.PinnedHostKey(t.HostKey)
			if err != nil {
				return nil, fmt.Errorf("target %s host-key pin: %w", t.ID, err)
			}
			hkAlgos = []string{hkAlgo}
		}
		return ssh.Dial("tcp", t.Address, &ssh.ClientConfig{
			User:              loginUser,
			Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback:   hkcb,
			HostKeyAlgorithms: hkAlgos,
			Timeout:           10 * time.Second,
		})
	}
}

// dbConfigFromVault builds the Postgres broker config (Vault dynamic-creds
// CredsFor), or nil if JESS_DB_VAULT_MOUNT is unset.
func dbConfigFromVault(vc *vaultx.Client) *dbproxy.Config {
	dbMount := env("JESS_DB_VAULT_MOUNT", "")
	if dbMount == "" || vc == nil {
		return nil
	}
	// Vault DB role per target: JESS_DB_VAULT_ROLE (single role for all DB
	// targets) or, if empty, the target ID (one Vault role per target).
	fixedRole := env("JESS_DB_VAULT_ROLE", "")
	return &dbproxy.Config{
		CredsFor: func(ctx context.Context, t *catalog.Target) (string, error) {
			role := fixedRole
			if role == "" {
				role = t.ID
			}
			user, pass, _, err := vc.DBCredentials(ctx, dbMount, role)
			if err != nil {
				return "", err
			}
			host, port, err := net.SplitHostPort(t.Address)
			if err != nil {
				return "", fmt.Errorf("target %s address %q: %w", t.ID, t.Address, err)
			}
			// The dynamic Vault user has no matching default db, so connect to the
			// target's declared database (catalog Database field).
			return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=require",
				url.QueryEscape(user), url.QueryEscape(pass), host, port, url.PathEscape(t.Database)), nil
		},
	}
}

// mysqlConfigFromVault builds the MySQL broker config (Vault dynamic-creds
// CredsFor), or nil if JESS_MYSQL_VAULT_MOUNT is unset. Independent of
// dbConfigFromVault so an operator can enable Postgres-only, MySQL-only, or
// both with no overlap — each protocol has its own Vault role.
func mysqlConfigFromVault(vc *vaultx.Client) *mysqlproxy.Config {
	dbMount := env("JESS_MYSQL_VAULT_MOUNT", "")
	if dbMount == "" || vc == nil {
		return nil
	}
	// Per-target role: JESS_MYSQL_VAULT_ROLE for a single shared role, else
	// fall back to the target ID (one Vault role per MySQL target).
	fixedRole := env("JESS_MYSQL_VAULT_ROLE", "")
	return &mysqlproxy.Config{
		CredsFor: func(ctx context.Context, t *catalog.Target) (mysqlproxy.TargetCreds, error) {
			role := fixedRole
			if role == "" {
				role = t.ID
			}
			user, pass, _, err := vc.DBCredentials(ctx, dbMount, role)
			if err != nil {
				return mysqlproxy.TargetCreds{}, err
			}
			return mysqlproxy.TargetCreds{
				Address:  t.Address,
				User:     user,
				Password: pass,
				Database: t.Database, // optional default schema (catalog field)
			}, nil
		},
	}
}

// recorderFromVault builds a signed WORM recorder (MinIO Object-Lock store +
// Vault Transit signer), or nil if JESS_REC_S3_ENDPOINT is unset.
//
// The second return is the DDIL P3.6 store-and-forward handle (non-nil when
// buffering is enabled). The caller starts its background reconciler with
// `go spool.Run(ctx)` bound to the process lifetime.
func recorderFromVault(ctx context.Context, vc *vaultx.Client) (recording.Recorder, *recording.SpoolStore, error) {
	endpoint := env("JESS_REC_S3_ENDPOINT", "")
	if endpoint == "" || vc == nil {
		return nil, nil, nil
	}
	store, err := recording.NewS3Store(recording.S3Config{
		Endpoint:  endpoint,
		AccessKey: env("JESS_REC_S3_ACCESS_KEY", ""),
		SecretKey: env("JESS_REC_S3_SECRET_KEY", ""),
		Bucket:    env("JESS_REC_S3_BUCKET", "audit-archive"),
		UseSSL:    env("JESS_REC_S3_USE_SSL", "true") != "false",
		Mode:      env("JESS_REC_S3_MODE", "COMPLIANCE"),
		Retention: durationEnv("JESS_REC_RETENTION", 7*365*24*time.Hour),
		Region:    env("JESS_REC_S3_REGION", ""),
	})
	if err != nil {
		return nil, nil, err
	}

	// DDIL P3.6: wrap the WORM store with a durable local store-and-forward spool
	// (default ON). A recording that cannot reach MinIO is buffered locally and
	// reconciled on reconnect instead of denying/losing the session; if the local
	// buffer itself fails, Put fails closed. Set JESS_REC_SPOOL_ENABLED=false to
	// restore the legacy fail-at-seal behaviour.
	var objStore recording.ObjectStore = store
	var spoolStore *recording.SpoolStore
	if env("JESS_REC_SPOOL_ENABLED", "true") != "false" {
		ss, serr := recording.NewSpoolStore(store, recording.SpoolConfig{
			Dir:            env("JESS_REC_SPOOL_DIR", defaultRecSpoolDir),
			MaxAge:         durationEnv("JESS_REC_SPOOL_MAX_AGE", 30*24*time.Hour),
			MaxBytes:       int64Env("JESS_REC_SPOOL_MAX_BYTES", 0),
			MaxRecords:     intEnv("JESS_REC_SPOOL_MAX_RECORDS", 0),
			ReconcileEvery: durationEnv("JESS_REC_SPOOL_RECONCILE_INTERVAL", 30*time.Second),
		})
		if serr != nil {
			return nil, nil, fmt.Errorf("recording store-and-forward spool: %w", serr)
		}
		objStore, spoolStore = ss, ss
	}

	signer, err := vaultx.NewTransitSigner(ctx, vc,
		env("JESS_REC_TRANSIT_MOUNT", "transit"),
		env("JESS_REC_TRANSIT_KEY", "jess-recordings"))
	if err != nil {
		return nil, nil, err
	}
	return recording.NewBundleRecorder(objStore, signer), spoolStore, nil
}

// defaultRecSpoolDir is the on-disk location of the WORM store-and-forward spool
// when JESS_REC_SPOOL_DIR is unset. A dedicated per-pod path (mount a volume in
// prod so buffered recordings survive a pod restart during a MinIO outage).
const defaultRecSpoolDir = "/var/lib/jess/recording-spool"

// intEnv parses an int env var, falling back to def on unset/parse-failure.
func intEnv(k string, def int) int {
	if v := env(k, ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// int64Env parses an int64 env var, falling back to def on unset/parse-failure.
func int64Env(k string, def int64) int64 {
	if v := env(k, ""); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func durationEnv(k string, def time.Duration) time.Duration {
	if v := env(k, ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
		log.Printf("warning: %s=%q not a duration; using default %s", k, v, def)
	}
	return def
}
