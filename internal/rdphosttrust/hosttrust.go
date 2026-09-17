// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rdphosttrust implements AD-CS-anchored TLS host-trust validation for
// RDP targets — the P2.4 retirement of trust-on-first-use (TOFU) host trust for
// the RDP broker (ADR 0047 "Future work — RDP TLS-CA validation", ADR 0062).
//
// Where SSH host trust is a Vault-signed OpenSSH host certificate validated by
// internal/sshproxy.CAHostKey (ADR 0044), RDP exposes an x.509 TLS certificate
// at the RDS host's TLS layer — typically auto-enrolled from a Windows Active
// Directory Certificate Services (AD CS) Enterprise CA via Group Policy. This
// package validates that presented certificate against the operator-configured
// AD-CS trust anchors (root + any intermediates), the dialed server name, cert
// validity window, and a revocation posture (CRL + a RevokedKeys-style
// fingerprint deny-list) — replacing accept-any/TOFU with real chain trust.
//
// The RDP wire TLS handshake to the target is terminated inside the Rust
// session_live subprocess (services/ironrdp-broker); the Go broker cannot see
// that certificate directly. So this package runs a PRE-FLIGHT validation: it
// performs the outer MS-RDPBCGR X.224 negotiation (reusing internal/rdpprobe),
// upgrades the same socket to TLS, captures the presented chain, and validates
// it BEFORE the subprocess is spawned. On failure the broker fails closed and
// never opens the session. The same anchor PEM path is forwarded to the
// subprocess env so the Rust side can (when it grows chain validation) enforce
// the equivalent, closing the small pre-flight TOCTOU window as defense in
// depth. The target's address is operator-fixed, bounding that window today.
package rdphosttrust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/rdpprobe"
)

// Environment keys — the trust-anchor + revocation + mode configuration.
const (
	// EnvCAPEM is the file path (or inline PEM) of the AD-CS trust anchors:
	// the issuing CA root and any intermediates the RDS host certs chain
	// through. Mounted into the worker / jess-web pod from a configmap whose
	// source is `certutil.exe -ca.cert` off the AD CS Enterprise CA (ADR 0047).
	EnvCAPEM = "JESS_RDP_TLS_CA_PEM"
	// EnvEnforce toggles global enforcement: when the anchors are configured,
	// enforcement defaults ON (every RDP target is CA-validated). Set to
	// "false" to validate ONLY targets that opt in via Target.RDPTLSCASigned.
	EnvEnforce = "JESS_RDP_TLS_ENFORCE"
	// EnvTOFU is the off-by-default migration escape hatch. "1"/"true" skips
	// CA validation entirely (logged loudly) so a fleet can be enrolled into
	// AD-CS trust before the gate is armed. NEVER set in steady-state.
	EnvTOFU = "JESS_RDP_TLS_TOFU"
	// EnvCRLPEM is the file path (or inline PEM) of a CRL covering the AD-CS
	// issuing CA — host certs whose serial is listed are rejected.
	EnvCRLPEM = "JESS_RDP_TLS_CRL_PEM"
	// EnvRevokedFingerprints is a comma-separated list of lower-hex SHA-256
	// fingerprints of host LEAF certificates to deny (an OpenSSH RevokedKeys
	// analog — an out-of-band, CRL-independent hard deny).
	EnvRevokedFingerprints = "JESS_RDP_TLS_REVOKED_FINGERPRINTS"
	// EnvServerName overrides the expected TLS server name. Empty = derive it
	// from the target address host. Set when targets are dialed by IP but the
	// AD-CS cert SANs carry the machine FQDN.
	EnvServerName = "JESS_RDP_TLS_SERVER_NAME"
	// EnvDialTimeout bounds the pre-flight dial+handshake (Go duration string).
	EnvDialTimeout = "JESS_RDP_TLS_DIAL_TIMEOUT"
)

// defaultDialTimeout bounds the pre-flight TCP dial + X.224 negotiation + TLS
// handshake. Generous enough for a cross-VLAN Windows host, short enough that a
// dead target fails the session-open promptly.
const defaultDialTimeout = 8 * time.Second

// HostTrust validates an RDP target's TLS server certificate against configured
// AD-CS trust anchors. The zero value is not usable; build one with New or
// LoadFromEnv.
type HostTrust struct {
	anchors     *x509.CertPool // AD-CS root + intermediates; nil = none configured
	anchorPath  string         // source path of the anchor PEM (for subprocess forward + logs)
	enforce     bool           // validate ALL rdp targets; false = only Target.RDPTLSCASigned opt-ins
	allowTOFU   bool           // migration escape hatch (off by default)
	serverName  string         // expected TLS server-name override; "" = derive from address
	rev         *revocation    // revocation posture (CRL serials + fingerprint deny-list)
	dialTimeout time.Duration
}

// Result is the validated-cert summary logged on a successful pre-flight (audit
// parity with the SSH-CA path: SAN + serial + AD-CA fingerprint).
type Result struct {
	Subject       string
	SerialHex     string
	NotAfter      time.Time
	SANs          []string
	CAFingerprint string // sha256 hex of the chain's trust anchor
}

// Config is the explicit (non-env) constructor input, for tests + callers that
// assemble trust anchors themselves.
type Config struct {
	Anchors             *x509.CertPool
	AnchorPath          string
	Enforce             bool
	AllowTOFU           bool
	ServerName          string
	RevokedSerials      []string // lower-hex CA serial numbers
	RevokedFingerprints []string // lower-hex SHA-256 leaf fingerprints
	DialTimeout         time.Duration
}

// New builds a HostTrust from an explicit Config.
func New(cfg Config) *HostTrust {
	dt := cfg.DialTimeout
	if dt <= 0 {
		dt = defaultDialTimeout
	}
	return &HostTrust{
		anchors:     cfg.Anchors,
		anchorPath:  cfg.AnchorPath,
		enforce:     cfg.Enforce,
		allowTOFU:   cfg.AllowTOFU,
		serverName:  cfg.ServerName,
		rev:         newRevocation(cfg.RevokedSerials, cfg.RevokedFingerprints),
		dialTimeout: dt,
	}
}

// LoadFromEnv builds the HostTrust from the JESS_RDP_TLS_* environment. It never
// returns a nil *HostTrust on success: a deployment with NOTHING configured
// yields an inert trust that lets non-opt-in RDP targets through (legacy TOFU,
// preserved for migration) while still failing closed for any target that sets
// RDPTLSCASigned=true (which requires anchors). Returns an error only when a
// configured input is malformed (bad PEM / unreadable file / bad duration) — a
// misconfigured trust anchor must be a loud startup failure, not a silent
// accept-all.
func LoadFromEnv() (*HostTrust, error) {
	cfg := Config{
		AllowTOFU:  envTruthy(os.Getenv(EnvTOFU)),
		ServerName: strings.TrimSpace(os.Getenv(EnvServerName)),
	}

	if raw := strings.TrimSpace(os.Getenv(EnvCAPEM)); raw != "" {
		pemBytes, path, err := readPEMSource(raw)
		if err != nil {
			return nil, fmt.Errorf("rdphosttrust: load %s: %w", EnvCAPEM, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("rdphosttrust: %s (%s) contained no valid PEM certificates", EnvCAPEM, path)
		}
		cfg.Anchors = pool
		cfg.AnchorPath = path
		// Anchors configured ⇒ enforce ON by default; explicit "false" opts out
		// to per-target-only enforcement.
		cfg.Enforce = !strings.EqualFold(strings.TrimSpace(os.Getenv(EnvEnforce)), "false")
	} else if envTruthy(os.Getenv(EnvEnforce)) {
		// Enforce requested with no anchors: honour it (fail-closed at Preflight)
		// rather than silently disabling — surfaces the misconfig loudly.
		cfg.Enforce = true
	}

	if raw := strings.TrimSpace(os.Getenv(EnvCRLPEM)); raw != "" {
		pemBytes, path, err := readPEMSource(raw)
		if err != nil {
			return nil, fmt.Errorf("rdphosttrust: load %s: %w", EnvCRLPEM, err)
		}
		serials, err := parseCRLSerials(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("rdphosttrust: parse %s (%s): %w", EnvCRLPEM, path, err)
		}
		cfg.RevokedSerials = serials
	}

	if raw := strings.TrimSpace(os.Getenv(EnvRevokedFingerprints)); raw != "" {
		for _, fp := range strings.Split(raw, ",") {
			if fp = normaliseFingerprint(fp); fp != "" {
				cfg.RevokedFingerprints = append(cfg.RevokedFingerprints, fp)
			}
		}
	}

	if raw := strings.TrimSpace(os.Getenv(EnvDialTimeout)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("rdphosttrust: invalid %s=%q: %v", EnvDialTimeout, raw, err)
		}
		cfg.DialTimeout = d
	}

	return New(cfg), nil
}

// Configured reports whether any AD-CS anchors are loaded. Callers use it for
// boot-log clarity ("host-trust ENFORCED" vs "no anchors — legacy TOFU").
func (h *HostTrust) Configured() bool { return h != nil && h.anchors != nil }

// Enforced reports whether global enforcement is on (all RDP targets validated).
func (h *HostTrust) Enforced() bool { return h != nil && h.enforce }

// AllowTOFU reports whether the migration escape hatch is armed.
func (h *HostTrust) AllowTOFU() bool { return h != nil && h.allowTOFU }

// AnchorPath returns the source path of the loaded anchor PEM (for forwarding
// to the Rust subprocess env). Empty when anchors were supplied inline / absent.
func (h *HostTrust) AnchorPath() string {
	if h == nil {
		return ""
	}
	return h.anchorPath
}

// Required reports whether a given target must be CA-validated: global enforce
// OR the target's per-target opt-in (Target.RDPTLSCASigned).
func (h *HostTrust) Required(target *catalog.Target) bool {
	if h == nil || target == nil {
		return false
	}
	return h.enforce || target.RDPTLSCASigned
}

// Preflight validates the target's RDP TLS host certificate against the AD-CS
// anchors BEFORE a session is opened. Contract:
//
//   - target not required (neither global enforce nor RDPTLSCASigned) → nil
//     (legacy TOFU preserved for un-enrolled targets during migration);
//   - TOFU escape hatch armed → nil, logged loudly (migration only);
//   - required but no anchors configured → error (FAIL-CLOSED);
//   - required + anchors → dial, negotiate, TLS-handshake, chain+revocation
//     validate; any failure → error (FAIL-CLOSED). On success, nil + an audit
//     log line carrying the validated SAN / serial / CA fingerprint.
func (h *HostTrust) Preflight(ctx context.Context, target *catalog.Target) error {
	if h == nil || target == nil {
		return nil
	}
	if !h.Required(target) {
		return nil
	}
	if h.allowTOFU {
		log.Printf("rdphosttrust: TOFU escape hatch ENABLED (%s) — SKIPPING CA validation for target %s (%s); migration only, NOT for steady-state",
			EnvTOFU, target.ID, target.Address)
		return nil
	}
	if h.anchors == nil {
		return fmt.Errorf("rdphosttrust: target %s requires CA-validated host trust but no AD-CS anchors configured (set %s) — fail-closed", target.ID, EnvCAPEM)
	}
	serverName := h.serverName
	if serverName == "" {
		serverName = hostFromAddress(target.Address)
	}
	if serverName == "" {
		return fmt.Errorf("rdphosttrust: target %s has no resolvable server name from address %q (set %s) — fail-closed", target.ID, target.Address, EnvServerName)
	}
	res, err := h.verifyHost(ctx, target.Address, serverName)
	if err != nil {
		return fmt.Errorf("rdphosttrust: CA validation FAILED for target %s (%s, expected server-name %q): %w", target.ID, target.Address, serverName, err)
	}
	log.Printf("rdphosttrust: target %s (%s) host cert VALIDATED against AD-CS anchor — subject=%q serial=%s not_after=%s ca_fp=%s san=%v",
		target.ID, target.Address, res.Subject, res.SerialHex, res.NotAfter.UTC().Format(time.RFC3339), res.CAFingerprint, res.SANs)
	return nil
}

// verifyHost dials the target, runs the outer MS-RDPBCGR X.224 negotiation
// (requesting TLS/CredSSP so the server switches to TLS), upgrades the socket
// to TLS capturing the presented chain, and validates it. Our own chain check
// runs (InsecureSkipVerify + manual Verify) so we control the roots, the
// expected server name, and the revocation posture precisely.
func (h *HostTrust) verifyHost(ctx context.Context, address, serverName string) (*Result, error) {
	d := net.Dialer{Timeout: h.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(h.dialTimeout))

	// Outer RDP negotiation: ask for TLS|CredSSP so the server agrees to the
	// TLS upgrade (a server that requires NLA still does the TLS handshake
	// first — CredSSP runs inside the TLS tunnel).
	if err := rdpprobe.WriteX224ConnectionRequest(conn, "", rdpprobe.ProtoTLS|rdpprobe.ProtoCredSSP); err != nil {
		return nil, fmt.Errorf("x224 connection request: %w", err)
	}
	_, nego, err := rdpprobe.ReadX224ConnectionConfirm(conn)
	if err != nil {
		return nil, fmt.Errorf("x224 connection confirm: %w", err)
	}
	switch nego.Kind {
	case rdpprobe.NegFailure:
		reason := rdpprobe.FailureReasons[nego.FailureCode]
		if reason == "" {
			reason = fmt.Sprintf("code %d", nego.FailureCode)
		}
		return nil, fmt.Errorf("server refused TLS negotiation: %s", reason)
	case rdpprobe.NegOK:
		if nego.Selected&(rdpprobe.ProtoTLS|rdpprobe.ProtoCredSSP) == 0 {
			return nil, fmt.Errorf("server selected plain RDP (no TLS) — cannot validate a host certificate")
		}
	default:
		// NegAbsent: a legacy server with no negotiation extension speaks plain
		// RDP with no TLS layer — there is no host certificate to validate.
		return nil, errors.New("server did not offer TLS (legacy RDP, no negotiation response)")
	}

	// Upgrade to TLS. InsecureSkipVerify defers ALL trust decisions to
	// verifyChain below (roots, server-name, validity, revocation) — this is a
	// manual-validation handshake, not an unverified one.
	tconn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // chain validated manually in verifyChain
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return h.verifyChain(tconn.ConnectionState().PeerCertificates, serverName)
}

// verifyChain validates a presented certificate chain against the AD-CS
// anchors: builds the trust path (rejecting a wrong/absent CA), enforces the
// server-name SAN + the cert validity window, then applies revocation to the
// leaf. It is a pure function of (peer, serverName, config) so the security
// core is unit-tested without a live RDP server.
func (h *HostTrust) verifyChain(peer []*x509.Certificate, serverName string) (*Result, error) {
	if len(peer) == 0 {
		return nil, errors.New("server presented no certificates")
	}
	if h.anchors == nil {
		return nil, errors.New("no AD-CS trust anchors configured")
	}
	leaf := peer[0]
	inter := x509.NewCertPool()
	for _, c := range peer[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         h.anchors,
		Intermediates: inter,
		DNSName:       serverName, // SAN / hostname match (also handles IP SANs)
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return nil, fmt.Errorf("chain/hostname validation: %w", err)
	}
	// Revocation on the validated leaf (CRL serial + fingerprint deny-list).
	if revoked, why := h.rev.check(leaf); revoked {
		return nil, fmt.Errorf("host certificate revoked (%s)", why)
	}
	// The trust anchor is the last cert in the first verified chain.
	anchor := chains[0][len(chains[0])-1]
	sum := sha256.Sum256(anchor.Raw)
	return &Result{
		Subject:       leaf.Subject.String(),
		SerialHex:     leaf.SerialNumber.Text(16),
		NotAfter:      leaf.NotAfter,
		SANs:          leaf.DNSNames,
		CAFingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// --- revocation -------------------------------------------------------------

// revocation is the host-cert revocation posture: CA-issued serial revocation
// (CRL) plus an out-of-band leaf-fingerprint deny-list (RevokedKeys analog).
// Nil-safe: a zero revocation revokes nothing.
type revocation struct {
	serials      map[string]struct{} // lower-hex CA serial
	fingerprints map[string]struct{} // lower-hex SHA-256 of leaf.Raw
}

func newRevocation(serials, fingerprints []string) *revocation {
	r := &revocation{
		serials:      make(map[string]struct{}, len(serials)),
		fingerprints: make(map[string]struct{}, len(fingerprints)),
	}
	for _, s := range serials {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			r.serials[s] = struct{}{}
		}
	}
	for _, f := range fingerprints {
		if f = normaliseFingerprint(f); f != "" {
			r.fingerprints[f] = struct{}{}
		}
	}
	return r
}

// check reports whether the leaf is revoked and why. Serial normalisation
// mirrors internal/admin/crl.go (lower-hex, no separators).
func (r *revocation) check(leaf *x509.Certificate) (bool, string) {
	if r == nil || leaf == nil {
		return false, ""
	}
	if leaf.SerialNumber != nil {
		if _, ok := r.serials[strings.ToLower(leaf.SerialNumber.Text(16))]; ok {
			return true, "serial " + leaf.SerialNumber.Text(16) + " on CRL"
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	fp := hex.EncodeToString(sum[:])
	if _, ok := r.fingerprints[fp]; ok {
		return true, "leaf fingerprint " + fp + " on deny-list"
	}
	return false, ""
}

// parseCRLSerials extracts the lower-hex revoked serials from a PEM CRL,
// mirroring internal/admin/crl.go's normalisation so the two revocation
// surfaces agree on serial form.
func parseCRLSerials(pemBytes []byte) ([]string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("PEM decode produced no block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse revocation list: %w", err)
	}
	out := make([]string, 0, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, strings.ToLower(e.SerialNumber.Text(16)))
	}
	return out, nil
}

// --- helpers ----------------------------------------------------------------

// readPEMSource resolves a JESS_RDP_TLS_*_PEM value: an inline PEM blob (when it
// contains a BEGIN marker) or a filesystem path. Returns the bytes + a label
// for logging/forwarding.
func readPEMSource(raw string) ([]byte, string, error) {
	if strings.Contains(raw, "-----BEGIN") {
		return []byte(raw), "<inline>", nil
	}
	b, err := os.ReadFile(raw)
	if err != nil {
		return nil, raw, err
	}
	return b, raw, nil
}

// hostFromAddress returns the host portion of a host:port address (or the whole
// string when it has no port).
func hostFromAddress(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.TrimSpace(addr)
}

// normaliseFingerprint lower-cases a SHA-256 fingerprint and strips common
// separators (colons/spaces) so "AA:BB:.." and "aabb.." compare equal.
func normaliseFingerprint(fp string) string {
	fp = strings.ToLower(strings.TrimSpace(fp))
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return fp
}

// envTruthy reports whether v is a truthy flag value.
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
