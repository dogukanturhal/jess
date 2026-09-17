// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AdminClient is the operator-side HTTP client for the controller's admin
// API (POST/GET/DELETE /grants). The bearer token must be a Falcon-ID OIDC
// token whose `roles` claim carries the configured admin role
// (default platform_admin).
type AdminClient struct {
	BaseURL string       // e.g. https://jess-controller.jess.svc.cluster.local:7103
	Token   string       // Falcon-ID OIDC bearer
	TLS     *tls.Config  // optional — leave nil for system roots
	HTTP    *http.Client // overridable for tests; auto-built when nil
}

// AdminGrant mirrors admin.GrantView so the CLI doesn't import the
// server package (one-way dependency).
type AdminGrant struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	TargetID   string    `json:"target_id"`
	ApprovedBy string    `json:"approved_by"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (a *AdminClient) httpClient() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: a.TLS},
	}
}

func (a *AdminClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.BaseURL, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		// Surface server-side error message verbatim. Common shape: {"error":"..."}.
		var e struct {
			Err string `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		if e.Err != "" {
			return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, e.Err)
		}
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if out != nil && len(rb) > 0 {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// IssueGrant calls POST /grants.
func (a *AdminClient) IssueGrant(ctx context.Context, subject, targetID string, ttl time.Duration) (AdminGrant, error) {
	var g AdminGrant
	err := a.do(ctx, http.MethodPost, "/grants",
		map[string]any{"subject": subject, "target_id": targetID, "ttl_seconds": int(ttl.Seconds())},
		&g)
	return g, err
}

// ListGrants calls GET /grants[?target=X].
func (a *AdminClient) ListGrants(ctx context.Context, targetID string) ([]AdminGrant, error) {
	q := ""
	if targetID != "" {
		q = "?target=" + url.QueryEscape(targetID)
	}
	var gs []AdminGrant
	err := a.do(ctx, http.MethodGet, "/grants"+q, nil, &gs)
	return gs, err
}

// Revoke calls DELETE /grants/{id}. Returns nil on success (204) or for
// 404 (idempotent — already gone or never existed).
func (a *AdminClient) Revoke(ctx context.Context, id string) error {
	return a.do(ctx, http.MethodDelete, "/grants/"+url.PathEscape(id), nil, nil)
}

// AdminRequest mirrors admin.RequestView (Phase 5b workflow).
type AdminRequest struct {
	ID            string     `json:"id"`
	Subject       string     `json:"subject"`
	TargetID      string     `json:"target_id"`
	Reason        string     `json:"reason"`
	RequestedAt   time.Time  `json:"requested_at"`
	State         string     `json:"state"`
	DecidedBy     string     `json:"decided_by,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	DecidedReason string     `json:"decided_reason,omitempty"`
	GrantID       string     `json:"grant_id,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

// SubmitRequest calls POST /requests. The submitter's subject is taken
// from the verified token server-side, not the body. ttlMinutes=0 → server
// default (4h).
func (a *AdminClient) SubmitRequest(ctx context.Context, targetID, reason string, ttlMinutes int) (AdminRequest, error) {
	var r AdminRequest
	err := a.do(ctx, http.MethodPost, "/requests",
		map[string]any{"target_id": targetID, "reason": reason, "request_ttl_minutes": ttlMinutes},
		&r)
	return r, err
}

// ListRequests calls GET /requests[?state=X] (approver workflow).
func (a *AdminClient) ListRequests(ctx context.Context, state string) ([]AdminRequest, error) {
	q := ""
	if state != "" {
		q = "?state=" + url.QueryEscape(state)
	}
	var rs []AdminRequest
	err := a.do(ctx, http.MethodGet, "/requests"+q, nil, &rs)
	return rs, err
}

// ApprovedRequest is the response body of POST /requests/{id}/approve.
type ApprovedRequest struct {
	Request AdminRequest `json:"request"`
	Grant   AdminGrant   `json:"grant"`
}

// ApproveRequest calls POST /requests/{id}/approve.
func (a *AdminClient) ApproveRequest(ctx context.Context, id string, ttl time.Duration) (ApprovedRequest, error) {
	var out ApprovedRequest
	err := a.do(ctx, http.MethodPost, "/requests/"+url.PathEscape(id)+"/approve",
		map[string]any{"ttl_seconds": int(ttl.Seconds())}, &out)
	return out, err
}

// DenyRequest calls POST /requests/{id}/deny.
func (a *AdminClient) DenyRequest(ctx context.Context, id, reason string) (AdminRequest, error) {
	var r AdminRequest
	err := a.do(ctx, http.MethodPost, "/requests/"+url.PathEscape(id)+"/deny",
		map[string]any{"reason": reason}, &r)
	return r, err
}

// OperatorCert is the response body of POST /operator-cert. Mirrors
// admin.OperatorCertResponse so the CLI doesn't import the server pkg.
type OperatorCert struct {
	CertPEM  string    `json:"cert_pem"`
	CAPEM    string    `json:"ca_pem"`
	NotAfter time.Time `json:"not_after"`
}

// SignOperatorCert calls POST /operator-cert. csrPEM is a PEM-encoded
// PKCS#10 CSR; ttl=0 lets the server cap at its default (8h).
func (a *AdminClient) SignOperatorCert(ctx context.Context, csrPEM []byte, ttl time.Duration) (OperatorCert, error) {
	var out OperatorCert
	err := a.do(ctx, http.MethodPost, "/operator-cert",
		map[string]any{"csr_pem": string(csrPEM), "ttl_seconds": int(ttl.Seconds())}, &out)
	return out, err
}

// OperatorCertRevoked is the response from POST /operator-cert/revoke —
// echoes the revoked serial so the caller can confirm what was acted on.
type OperatorCertRevoked struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevokeOperatorCert calls POST /operator-cert/revoke. The serial is the
// hex form openssl prints in `openssl x509 -serial` (colons OK; the server
// normalises). Returns nil if the cert is already revoked (idempotent —
// Vault PKI's /revoke is itself idempotent on a previously-revoked serial).
func (a *AdminClient) RevokeOperatorCert(ctx context.Context, serial string) (OperatorCertRevoked, error) {
	var out OperatorCertRevoked
	err := a.do(ctx, http.MethodPost, "/operator-cert/revoke",
		map[string]any{"serial": serial}, &out)
	return out, err
}

// --- Phase 5j-1 — admin lock primitive surface --------------------------

// Lock mirrors admin.LockView (the GET / POST shape of /locks).
type Lock struct {
	ID         string     `json:"id"`
	TargetType string     `json:"target_type"`
	TargetVal  string     `json:"target_value"`
	Reason     string     `json:"reason"`
	LockedBy   string     `json:"locked_by"`
	LockedAt   time.Time  `json:"locked_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// CreateLock calls POST /locks. targetType ∈ {subject, target,
// cert_serial, mfa_device}. replace=true upserts on duplicate (otherwise
// duplicate returns 409). expiresAt zero = indefinite.
func (a *AdminClient) CreateLock(ctx context.Context, targetType, targetValue, reason string, expiresAt time.Time, replace bool) (Lock, error) {
	body := map[string]any{
		"target_type":  targetType,
		"target_value": targetValue,
		"reason":       reason,
		"replace":      replace,
	}
	if !expiresAt.IsZero() {
		body["expires_at"] = expiresAt
	}
	var out Lock
	err := a.do(ctx, http.MethodPost, "/locks", body, &out)
	return out, err
}

// ListLocks calls GET /locks.
func (a *AdminClient) ListLocks(ctx context.Context) ([]Lock, error) {
	var out []Lock
	err := a.do(ctx, http.MethodGet, "/locks", nil, &out)
	return out, err
}

// DeleteLock calls DELETE /locks/{id} — idempotent.
func (a *AdminClient) DeleteLock(ctx context.Context, lockID string) error {
	return a.do(ctx, http.MethodDelete, "/locks/"+url.PathEscape(lockID), nil, nil)
}

// --- Phase 5e-14/16/19 — tamper-evidence verify surface ------------------

// ChainBreak mirrors jit.ChainBreak.
type ChainBreak struct {
	SessionID string `json:"session_id"`
	Position  int    `json:"position"`
	Reason    string `json:"reason"`
	Expected  string `json:"expected,omitempty"`
	Got       string `json:"got,omitempty"`
}

// ChainReport mirrors jit.ChainReport (the controller admin endpoint
// shape) so jessctl can render verdicts client-side without importing
// the internal jit package.
type ChainReport struct {
	OK          bool         `json:"ok"`
	Total       int          `json:"total"`
	GenesisHash string       `json:"genesis_hash,omitempty"`
	HeadHash    string       `json:"head_hash,omitempty"`
	Breaks      []ChainBreak `json:"breaks,omitempty"`
}

// VerifyChain calls GET /audit/chain/verify (Phase 5e-16).
func (a *AdminClient) VerifyChain(ctx context.Context) (ChainReport, error) {
	var r ChainReport
	err := a.do(ctx, http.MethodGet, "/audit/chain/verify", nil, &r)
	return r, err
}

// BundleVerifyResult mirrors admin.VerifyResponse (Phase 5e-14 + 5e-20).
type BundleVerifyResult struct {
	SessionID         string     `json:"session_id"`
	OK                bool       `json:"ok"`
	SignatureValid    bool       `json:"signature_valid"`
	HashMatch         bool       `json:"hash_match"`
	ChainLinkOK       bool       `json:"chain_link_ok"`
	ChainLinkExpected string     `json:"chain_link_expected,omitempty"`
	ChainLinkGot      string     `json:"chain_link_got,omitempty"`
	KeyID             string     `json:"key_id,omitempty"`
	SealedAt          *time.Time `json:"sealed_at,omitempty"`
	ContentBytes      int64      `json:"content_bytes"`
	ContentSHA256     string     `json:"content_sha256,omitempty"`
	Error             string     `json:"error,omitempty"`
}

// VerifyBundle calls GET /sessions/{id}/recording/verify (Phase 5e-14).
func (a *AdminClient) VerifyBundle(ctx context.Context, sessionID string) (BundleVerifyResult, error) {
	var r BundleVerifyResult
	err := a.do(ctx, http.MethodGet, "/sessions/"+url.PathEscape(sessionID)+"/recording/verify", nil, &r)
	return r, err
}

// --- Phase 5f-2b/5f-2d/5f-9 — RDP probe surfaces ----------------------------

// RDPProbeReport mirrors rdpprobe.Report (the controller endpoint shape).
type RDPProbeReport struct {
	Target            string `json:"target"`
	Reachable         bool   `json:"reachable"`
	ConnectionConfirm bool   `json:"connection_confirm"`
	NegotiatedProto   string `json:"negotiated_protocol,omitempty"`
	NegotiatedFlags   uint32 `json:"negotiated_flags,omitempty"`
	FailureCode       uint32 `json:"failure_code,omitempty"`
	FailureReason     string `json:"failure_reason,omitempty"`
	NLARequired       bool   `json:"nla_required"`
	TLSSupported      bool   `json:"tls_supported"`
	DurationMs        int64  `json:"duration_ms"`
	Error             string `json:"error,omitempty"`
}

// SweepResult is one row in a probe-sweep response.
type SweepResult struct {
	TargetID   string         `json:"target_id"`
	TargetName string         `json:"target_name,omitempty"`
	Address    string         `json:"address"`
	Region     string         `json:"region,omitempty"`
	Probe      RDPProbeReport `json:"probe"`
}

// SweepResponse is the full probe-sweep envelope (Phase 5f-2d).
type SweepResponse struct {
	Total     int           `json:"total"`
	Reachable int           `json:"reachable"`
	Failed    int           `json:"failed"`
	Results   []SweepResult `json:"results"`
	ElapsedMs int64         `json:"elapsed_ms"`
}

// RDPProbeOne calls GET /rdp-probe?target=...
func (a *AdminClient) RDPProbeOne(ctx context.Context, target string) (RDPProbeReport, error) {
	var r RDPProbeReport
	err := a.do(ctx, http.MethodGet, "/rdp-probe?target="+url.QueryEscape(target), nil, &r)
	return r, err
}

// RDPSweep calls GET /rdp-probe/sweep (Phase 5f-2d). Walks the
// catalog filtering by protocol=rdp, returns per-target reports.
func (a *AdminClient) RDPSweep(ctx context.Context) (SweepResponse, error) {
	var r SweepResponse
	err := a.do(ctx, http.MethodGet, "/rdp-probe/sweep", nil, &r)
	return r, err
}

// ---- Phase 7f — admin-API target CRUD --------------------------------

// AdminTarget is the JSON projection returned by /admin/targets[/id].
// Mirrors internal/admin.TargetView so the CLI parses the API
// response verbatim. Loosely typed (map[string]any for the Target
// sub-document) because catalog.Target lives in a different package
// the CLI doesn't otherwise import; the CLI only needs read access
// for the list/get views.
type AdminTarget struct {
	Target    map[string]any `json:"target"`
	AddedBy   string         `json:"added_by"`
	AddedAt   time.Time      `json:"added_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// CreateTarget calls POST /admin/targets. Body is the raw catalog.Target
// JSON — caller's responsibility to assemble it (the operator typically
// passes --json with the file path or a heredoc).
func (a *AdminClient) CreateTarget(ctx context.Context, body map[string]any) (AdminTarget, error) {
	var out AdminTarget
	err := a.do(ctx, http.MethodPost, "/admin/targets", body, &out)
	return out, err
}

// ListTargets calls GET /admin/targets. Returns the in-memory ad-hoc
// catalog (admin-managed entries only — does NOT include static
// ConfigMap / cloud discovered targets).
func (a *AdminClient) ListTargets(ctx context.Context) ([]AdminTarget, error) {
	var out []AdminTarget
	err := a.do(ctx, http.MethodGet, "/admin/targets", nil, &out)
	return out, err
}

// GetTarget calls GET /admin/targets/{id}.
func (a *AdminClient) GetTarget(ctx context.Context, id string) (AdminTarget, error) {
	var out AdminTarget
	err := a.do(ctx, http.MethodGet, "/admin/targets/"+url.PathEscape(id), nil, &out)
	return out, err
}

// PatchTarget calls PATCH /admin/targets/{id}. The id in the body is
// pinned to the URL parameter server-side; callers may omit it.
func (a *AdminClient) PatchTarget(ctx context.Context, id string, body map[string]any) (AdminTarget, error) {
	var out AdminTarget
	err := a.do(ctx, http.MethodPatch, "/admin/targets/"+url.PathEscape(id), body, &out)
	return out, err
}

// DeleteTarget calls DELETE /admin/targets/{id}. Idempotent — returns
// nil on 204 OR 404 (caller doesn't need to distinguish "already gone"
// from "removed by this call").
func (a *AdminClient) DeleteTarget(ctx context.Context, id string) error {
	return a.do(ctx, http.MethodDelete, "/admin/targets/"+url.PathEscape(id), nil, nil)
}

// ListCatalog calls GET /admin/catalog. Returns the unified view
// across ALL discovery providers (static + cloud + admin-api). Each
// target carries its provenance via Source + LastSeen. Empty region
// fetches everywhere; pass a non-empty region to filter.
func (a *AdminClient) ListCatalog(ctx context.Context, region string) ([]map[string]any, error) {
	q := ""
	if region != "" {
		q = "?region=" + url.QueryEscape(region)
	}
	var out []map[string]any
	err := a.do(ctx, http.MethodGet, "/admin/catalog"+q, nil, &out)
	return out, err
}
