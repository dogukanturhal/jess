// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vaultx is a thin HashiCorp Vault client for the Jess worker's
// production credential brokering (ADR 0030 Phase 5b/5c/5d). It deliberately
// speaks Vault's HTTP API directly rather than pulling github.com/hashicorp/
// vault/api (a large dependency tree) — the worker needs only four operations:
//
//   - ssh-client-signer/sign/<role>  → short-lived SSH cert for worker→target
//   - database/creds/<role>          → dynamic, leased Postgres credentials
//   - transit/sign/<key>             → detached recording-manifest signature
//   - transit/keys/<key>             → the ed25519 verification key
//
// Auth is Kubernetes (the worker's ServiceAccount JWT → a short-lived Vault
// token), with transparent re-login on 403. A static VAULT_TOKEN short-circuits
// that for local/dev.
package vaultx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// k8sTokenPath is the projected ServiceAccount token mount (standard location).
const k8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Client is a minimal Vault API client with Kubernetes-auth token management.
type Client struct {
	addr   string // e.g. http://vault-ha.vault.svc.cluster.local:8200
	mount  string // k8s auth mount path (default "kubernetes")
	role   string // k8s auth role
	hc     *http.Client
	static bool // token came from VAULT_TOKEN (no re-login)

	mu    sync.Mutex
	token string
}

// Config configures a Client. Either Token (static) or K8sRole (login) is required.
type Config struct {
	Addr      string
	Token     string        // static token; if set, K8s auth is skipped
	K8sMount  string        // default "kubernetes"
	K8sRole   string        // Vault role bound to the worker SA
	Timeout   time.Duration // per-request timeout (default 15s)
	tokenPath string        // override for tests
}

// New builds a Client. It does not contact Vault until the first operation.
func New(cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vaultx: Addr required")
	}
	if cfg.Token == "" && cfg.K8sRole == "" {
		return nil, fmt.Errorf("vaultx: set Token or K8sRole")
	}
	to := cfg.Timeout
	if to == 0 {
		to = 15 * time.Second
	}
	mount := cfg.K8sMount
	if mount == "" {
		mount = "kubernetes"
	}
	c := &Client{
		addr:   strings.TrimRight(cfg.Addr, "/"),
		mount:  mount,
		role:   cfg.K8sRole,
		hc:     &http.Client{Timeout: to},
		static: cfg.Token != "",
		token:  cfg.Token,
	}
	if c.static {
		return c, nil
	}
	// Eagerly login so misconfiguration surfaces at worker startup, not first session.
	if err := c.login(context.Background(), pathOr(cfg.tokenPath, k8sTokenPath)); err != nil {
		return nil, err
	}
	return c, nil
}

func pathOr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// login exchanges the SA JWT for a Vault token via the kubernetes auth method.
func (c *Client) login(ctx context.Context, tokenPath string) error {
	jwt, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("vaultx: read SA token: %w", err)
	}
	body := map[string]string{"role": c.role, "jwt": strings.TrimSpace(string(jwt))}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	// raw request (no token yet)
	if err := c.req(ctx, http.MethodPost, "/v1/auth/"+c.mount+"/login", "", body, &out); err != nil {
		return fmt.Errorf("vaultx: kubernetes login (role=%s): %w", c.role, err)
	}
	if out.Auth.ClientToken == "" {
		return fmt.Errorf("vaultx: login returned no token")
	}
	c.mu.Lock()
	c.token = out.Auth.ClientToken
	c.mu.Unlock()
	return nil
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// call issues an authenticated request, re-logging in once on 403 (token expiry).
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	err := c.req(ctx, method, path, c.currentToken(), body, out)
	if err != nil && isPermDenied(err) && !c.static {
		if lerr := c.login(ctx, k8sTokenPath); lerr != nil {
			return lerr
		}
		return c.req(ctx, method, path, c.currentToken(), body, out)
	}
	return err
}

type vaultError struct {
	status int
	msg    string
}

func (e *vaultError) Error() string { return fmt.Sprintf("vault %d: %s", e.status, e.msg) }
func isPermDenied(err error) bool {
	ve, ok := err.(*vaultError)
	return ok && (ve.status == http.StatusForbidden || ve.status == http.StatusUnauthorized)
}

// StatusCode reports the HTTP status Vault returned when err originated from a
// Vault HTTP response (as opposed to a transport/timeout error). errors.As
// unwraps the %w-wrapped *vaultError the operation helpers return.
func StatusCode(err error) (int, bool) {
	var ve *vaultError
	if errors.As(err, &ve) {
		return ve.status, true
	}
	return 0, false
}

// IsUnreachable reports whether err represents a Vault PARTITION / availability
// failure — a transport error, timeout, DNS failure, or a 5xx / 429 response —
// as opposed to a genuine rejection (a 4xx: bad request, auth/permission
// denied, unknown role/lease). This is the DDIL fail-direction gate: an
// unreachable Vault may fall back to a pre-positioned offline credential
// (P3.8), whereas a 4xx MUST fail closed and never be masked as a partition
// (a real "you are not allowed" must not silently degrade to cached creds).
//
// The classification mirrors the recording store-and-forward (P3.6) treatment
// of S3 errors and AWS retry guidance: retry/treat-as-transient on 5xx + 429,
// surface 4xx. A nil error is not unreachable.
func IsUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := StatusCode(err); ok {
		return st >= 500 || st == http.StatusTooManyRequests
	}
	// No HTTP status ⇒ the request never got a Vault response (dial/TLS/timeout
	// /context) ⇒ Vault is unreachable.
	return true
}

// RevokeLease force-revokes a Vault lease by ID via /v1/sys/leases/revoke. Used
// by the offline-credentials manager to emergency-rotate pre-positioned
// dynamic credentials the moment Vault reachability is restored (P3.8 item 7).
// Idempotent from the caller's perspective: revoking an already-expired or
// unknown lease is treated as success so reconnect reconciliation never wedges
// on a lease Vault already cleaned up.
func (c *Client) RevokeLease(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}
	body := map[string]any{"lease_id": leaseID}
	if err := c.call(ctx, http.MethodPost, "/v1/sys/leases/revoke", body, nil); err != nil {
		// A 400 "invalid lease" / 404 means the lease is already gone — the
		// desired end state. Only surface real failures (5xx/transport).
		if st, ok := StatusCode(err); ok && st >= 400 && st < 500 {
			return nil
		}
		return fmt.Errorf("vaultx: revoke lease: %w", err)
	}
	return nil
}

// req performs one HTTP round-trip and decodes JSON into out (may be nil).
func (c *Client) req(ctx context.Context, method, path, token string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.addr+path, rdr)
	if err != nil {
		return err
	}
	if token != "" {
		httpReq.Header.Set("X-Vault-Token", token)
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return &vaultError{status: resp.StatusCode, msg: strings.TrimSpace(string(raw))}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("vaultx: decode %s: %w", path, err)
		}
	}
	return nil
}

// SignSSHCert signs publicKeyAuthorized (an authorized_keys line) with the SSH
// CA role and returns the signed certificate (OpenSSH cert authorized_keys form).
func (c *Client) SignSSHCert(ctx context.Context, sshMount, role, publicKeyAuthorized string, principals []string, ttl time.Duration) (string, error) {
	body := map[string]any{
		"public_key":       publicKeyAuthorized,
		"valid_principals": strings.Join(principals, ","),
		"cert_type":        "user",
		"ttl":              fmt.Sprintf("%ds", int(ttl.Seconds())),
	}
	var out struct {
		Data struct {
			SignedKey string `json:"signed_key"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/"+sshMount+"/sign/"+role, body, &out); err != nil {
		return "", fmt.Errorf("vaultx: ssh sign (role=%s): %w", role, err)
	}
	if out.Data.SignedKey == "" {
		return "", fmt.Errorf("vaultx: ssh sign returned empty cert")
	}
	return out.Data.SignedKey, nil
}

// OCSPPost POSTs a binary OCSP request body to Vault's PKI OCSP endpoint.
// Used by internal/devicecrl/Responder to proxy operator-issued OCSP
// queries through jess rather than exposing Vault directly. Returns the
// HTTP status, the raw response body, the Content-Type the upstream
// chose (typically "application/ocsp-response"), and any transport
// error.
func (c *Client) OCSPPost(ctx context.Context, path, contentType string, body []byte) (int, []byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("Content-Type", contentType)
	if tok := c.currentToken(); tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, respBody, resp.Header.Get("Content-Type"), nil
}

// ReadRawPEM fetches a raw (non-JSON) PEM-encoded resource from Vault, such
// as /v1/<pki-mount>/ca/pem or /v1/<pki-mount>/ca_chain. Returns empty bytes
// (no error) on 404 — useful for ca_chain which is missing for single-root
// mounts. Used by the operator-cert handler to build the trust bundle.
func (c *Client) ReadRawPEM(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+path, nil)
	if err != nil {
		return nil, err
	}
	tok := c.currentToken()
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, &vaultError{status: resp.StatusCode, msg: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// PKISignRequest is the input to SignPKICert. CSRPEMs from operator-facing
// flows (operator-cert handler) are an EC P-256 / RSA key the operator owns;
// CommonName is set by the SERVER to the verified Falcon-ID subject (the
// CSR's claimed CN is ignored — RFC 8705 §2.1 tls_client_auth binding).
type PKISignRequest struct {
	CSRPEM     string        // PEM-encoded PKCS#10 CSR
	CommonName string        // overrides the CSR's CN (server-trusted identity)
	TTL        time.Duration // 0 = role default; capped by the role's max_ttl
	AltNames   []string      // optional DNS SANs
	URISans    []string      // optional URI SANs (e.g. SPIFFE "spiffe://…"); the Vault role's allowed_uri_sans must permit them
	OtherSANs  []string      // optional otherName SANs (e.g. "1.3.6.1.4.1.…;UTF8:foo")
}

// PKISignResponse holds the cert + the issuing CA chain so the caller can
// surface the trust bundle to clients in one round-trip.
type PKISignResponse struct {
	Certificate  string   // PEM
	IssuingCA    string   // PEM
	CAChain      []string // [intermediate1, intermediate2, ...] PEM
	SerialNumber string   // e.g. "01:02:03:..."
	Expiration   time.Time
}

// SignPKICert calls /v1/<mount>/sign/<role> with the supplied CSR + CN. The
// CA private key never leaves Vault. Every issuance lands in Vault's audit
// log. Mount + role are configured separately (vault-jess-ca-pki.tf).
func (c *Client) SignPKICert(ctx context.Context, pkiMount, role string, req PKISignRequest) (*PKISignResponse, error) {
	body := map[string]any{
		"csr":         req.CSRPEM,
		"common_name": req.CommonName,
		// format=pem is the default but be explicit so a misconfigured role
		// can't quietly return DER + break callers expecting PEM.
		"format": "pem",
	}
	if req.TTL > 0 {
		body["ttl"] = fmt.Sprintf("%ds", int(req.TTL.Seconds()))
	}
	if len(req.AltNames) > 0 {
		body["alt_names"] = strings.Join(req.AltNames, ",")
	}
	if len(req.URISans) > 0 {
		// uri_sans is the ONLY parameter that produces a real URI-type SAN.
		// Passing a "spiffe://…" string via alt_names would (at best) be
		// parsed as a DNS SAN and (at worst) rejected — either way the
		// issued cert would carry NO uniformResourceIdentifier SAN, which
		// posture-signer's DeviceCertVerifier requires (it reads cert.URIs).
		body["uri_sans"] = strings.Join(req.URISans, ",")
	}
	if len(req.OtherSANs) > 0 {
		body["other_sans"] = strings.Join(req.OtherSANs, ",")
	}
	var out struct {
		Data struct {
			Certificate  string   `json:"certificate"`
			IssuingCA    string   `json:"issuing_ca"`
			CAChain      []string `json:"ca_chain"`
			SerialNumber string   `json:"serial_number"`
			Expiration   int64    `json:"expiration"` // unix seconds
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/"+pkiMount+"/sign/"+role, body, &out); err != nil {
		return nil, fmt.Errorf("vaultx: pki sign (mount=%s role=%s): %w", pkiMount, role, err)
	}
	if out.Data.Certificate == "" {
		return nil, fmt.Errorf("vaultx: pki sign returned empty certificate")
	}
	return &PKISignResponse{
		Certificate:  out.Data.Certificate,
		IssuingCA:    out.Data.IssuingCA,
		CAChain:      out.Data.CAChain,
		SerialNumber: out.Data.SerialNumber,
		Expiration:   time.Unix(out.Data.Expiration, 0),
	}, nil
}

// RevokePKICert flips the given serial into the next signed CRL via
// /v1/<mount>/revoke. Idempotent: revoking an unknown or already-revoked
// serial returns a successful response (Vault echoes the existing
// revocation_time). Vault audits the call against the calling token's
// identity. Mount must be the same PKI mount that issued the cert.
func (c *Client) RevokePKICert(ctx context.Context, pkiMount, serial string) error {
	body := map[string]any{"serial_number": serial}
	var out struct {
		Data struct {
			RevocationTime int64 `json:"revocation_time"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/"+pkiMount+"/revoke", body, &out); err != nil {
		return fmt.Errorf("vaultx: pki revoke (mount=%s serial=%s): %w", pkiMount, serial, err)
	}
	return nil
}

// DBCredentials reads a dynamic credential pair from the database secrets engine.
func (c *Client) DBCredentials(ctx context.Context, dbMount, role string) (user, password, leaseID string, err error) {
	var out struct {
		LeaseID string `json:"lease_id"`
		Data    struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/"+dbMount+"/creds/"+role, nil, &out); err != nil {
		return "", "", "", fmt.Errorf("vaultx: db creds (role=%s): %w", role, err)
	}
	if out.Data.Username == "" {
		return "", "", "", fmt.Errorf("vaultx: db creds returned empty username")
	}
	return out.Data.Username, out.Data.Password, out.LeaseID, nil
}

// LDAPCredential is one dynamic AD/LDAP credential leased from Vault's LDAP
// secrets engine (the engine that supersedes the deprecated `ad` engine and
// works against any AD/LDAP directory). It carries the username/password the
// engine minted plus the lease metadata so the caller can scope a session to
// the lease TTL.
type LDAPCredential struct {
	Username  string
	Password  string
	DistName  string        // distinguished_name (LDAP DN), when the engine returns it
	LeaseID   string        // Vault lease id (for explicit revoke / lease lookup)
	LeaseTTL  time.Duration // lease_duration — how long the credential is valid
	Renewable bool
}

// LDAPDynamicCredential reads a dynamic credential from Vault's LDAP secrets
// engine dynamic-role endpoint: GET /v1/<ldapMount>/creds/<role>. The engine
// creates an ephemeral directory account bound to the role's creation_ldif and
// auto-deletes it at lease end — so no standing AD credential ever exists
// (ADR 0049 "No standing credentials"). This is the AD-agnostic mechanism the
// platform standardises on; it returns username+password directly, mapping 1:1
// to the RDP broker's NLA credential shape.
//
// The mount + role are caller-supplied (env/config in the broker) — never
// hardcoded — so the same code drives any directory the deploy wires.
func (c *Client) LDAPDynamicCredential(ctx context.Context, ldapMount, role string) (LDAPCredential, error) {
	var out struct {
		LeaseID       string `json:"lease_id"`
		LeaseDuration int    `json:"lease_duration"` // seconds
		Renewable     bool   `json:"renewable"`
		Data          struct {
			Username          string `json:"username"`
			Password          string `json:"password"`
			DistinguishedName string `json:"distinguished_name"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/"+ldapMount+"/creds/"+role, nil, &out); err != nil {
		return LDAPCredential{}, fmt.Errorf("vaultx: ldap creds (mount=%s role=%s): %w", ldapMount, role, err)
	}
	if out.Data.Username == "" || out.Data.Password == "" {
		return LDAPCredential{}, fmt.Errorf("vaultx: ldap creds (mount=%s role=%s) returned empty username/password", ldapMount, role)
	}
	return LDAPCredential{
		Username:  out.Data.Username,
		Password:  out.Data.Password,
		DistName:  out.Data.DistinguishedName,
		LeaseID:   out.LeaseID,
		LeaseTTL:  time.Duration(out.LeaseDuration) * time.Second,
		Renewable: out.Renewable,
	}, nil
}

// TransitSign returns a detached signature over data using the Transit ed25519
// key. The private key never leaves Vault.
func (c *Client) TransitSign(ctx context.Context, transitMount, key string, data []byte) ([]byte, error) {
	body := map[string]any{"input": base64.StdEncoding.EncodeToString(data)}
	var out struct {
		Data struct {
			Signature string `json:"signature"` // "vault:v1:<base64>"
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/"+transitMount+"/sign/"+key, body, &out); err != nil {
		return nil, fmt.Errorf("vaultx: transit sign (key=%s): %w", key, err)
	}
	sig := out.Data.Signature
	if i := strings.LastIndex(sig, ":"); i >= 0 {
		sig = sig[i+1:]
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("vaultx: decode transit signature: %w", err)
	}
	return raw, nil
}

// TransitPublicKey fetches the ed25519 public key for a Transit signing key.
func (c *Client) TransitPublicKey(ctx context.Context, transitMount, key string) (ed25519.PublicKey, error) {
	var out struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"` // PEM
			} `json:"keys"`
			LatestVersion int `json:"latest_version"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/"+transitMount+"/keys/"+key, nil, &out); err != nil {
		return nil, fmt.Errorf("vaultx: transit key read (key=%s): %w", key, err)
	}
	kv, ok := out.Data.Keys[fmt.Sprintf("%d", out.Data.LatestVersion)]
	if !ok || kv.PublicKey == "" {
		return nil, fmt.Errorf("vaultx: transit key %s has no public key for version %d", key, out.Data.LatestVersion)
	}
	// Vault returns ed25519 Transit public keys as base64-encoded raw 32 bytes
	// (NOT PEM — that's the ecdsa/rsa case). Try raw base64 first.
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kv.PublicKey)); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	// PEM/SPKI fallback (defensive — other key types / future formats).
	if block, _ := pem.Decode([]byte(kv.PublicKey)); block != nil {
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
		if len(block.Bytes) > ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes[len(block.Bytes)-ed25519.PublicKeySize:]), nil
		}
	}
	return nil, fmt.Errorf("vaultx: could not parse ed25519 transit public key for %s", key)
}
