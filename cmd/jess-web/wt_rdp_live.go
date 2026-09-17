// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// WebTransport (HTTP/3 over QUIC) transport for the live RDP console — ADR 0055.
//
// This is an ALTERNATIVE carrier for the EXACT same RDP TLV stream the WebSocket
// path (`ws_rdp_live.go`) serves. WebTransport is the right transport for a
// browser→server stream under packet loss: QUIC gives stream multiplexing and no
// TCP head-of-line blocking, so a dropped delta frame doesn't stall the next.
// (WebRTC is deliberately NOT used: its P2P/ICE/TURN/UDP media path would bypass
// the Talon IAP — see the auth note below — and it's the wrong fit for a
// client→server byte stream.)
//
// # How the same engine is reused
//
// A `webtransport.Stream` is an `io.ReadWriteCloser`, which is exactly the
// `client` the RDP bridge engine already takes. So a WebTransport bidirectional
// stream IS the engine's client pipe, carrying the raw `[u32 len][type][payload]`
// TLV framing directly — no WS-style per-message framing translation. The
// browser reads the byte stream and length-frames it itself (the job the WS Go
// handler used to do). Everything else — target resolve, WORM recorder, Vault
// credential mint, session_live bridge — is the same code as the WS path.
//
// # Auth (IAP-bypass-safe)
//
// A WebTransport connection reaches this QUIC listener DIRECTLY, not through the
// Talon IAP, and the browser's WebTransport handshake does NOT carry cookies. So
// auth is split: the `/api/rdp/webtransport-info` endpoint is served on the
// normal HTTP mux BEHIND Talon (real `operatorFromRequest` + the same catalog
// authz `resolveTarget`); it resolves+authorizes the target and hands back a
// one-time, short-lived `ticket`. The WT connection presents that ticket, which
// this server exchanges for the pre-authorized (operator, target, grant). No
// standing credential is ever minted until the ticket is redeemed, and the
// minting itself needs only operatorSub+grant+target (no bearer). So the WT path
// is authenticated, just at a different seam than the cookie-bearing WS path.
//
// # Deployment status (honest)
//
// WebTransport needs HTTP/3 reachable from the browser. Talon/Envoy/Traefik
// terminate HTTP/1.1–2 today, NOT HTTP/3, so this does NOT yet ride the standard
// `*.ops` ingress: it is a DIRECT browser→jess-web QUIC path on a dedicated UDP
// port (JESS_RDP_WEBTRANSPORT_ADDR), advertised to the browser only when
// configured. The WebSocket path remains the default + guaranteed fallback. Full
// gateway integration (HTTP/3 termination through Talon, or a dedicated HTTP/3
// ingress) is the remaining ops step. The server uses a short-lived self-signed
// ECDSA cert pinned in the browser via `serverCertificateHashes`, so no
// publicly-trusted cert is required for the direct path.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"github.com/dogukanturhal/jess/internal/broker"
	"github.com/dogukanturhal/jess/internal/catalog"
)

// wtCertValidity is how long the self-signed WebTransport cert is valid. The
// browser `serverCertificateHashes` option requires a short-lived cert (the spec
// caps it at 14 days); we use 10 and regenerate on each jess-web start.
const wtCertValidity = 10 * 24 * time.Hour

// wtTicketTTL bounds the gap between the (Talon-authenticated) info request that
// issues a ticket and the WebTransport connection that redeems it.
const wtTicketTTL = 30 * time.Second

// wtCloseRevoked is the WebTransport session error code the continuous grant-
// watch uses when it tears a session down (grant revoked / session expired /
// re-check fail-closed). Untyped so it converts to the CloseWithError code
// param exactly like the plain 0 used elsewhere; nonzero distinguishes a
// policy teardown from a clean (0) close in QUIC traces.
const wtCloseRevoked = 1

// wtPending is a target pre-authorized by the info endpoint, awaiting redemption
// by a WebTransport connection. It deliberately holds NO minted credential — the
// credential + recorder are created only when the ticket is redeemed.
type wtPending struct {
	op      string
	sid     string // session id — backs the continuous grant-watch's token refresh
	target  *catalog.Target
	grant   string
	desktop broker.RDPDesktopSize
	exp     time.Time
}

// wtServer carries the live RDP stream over WebTransport. It reuses rdpLiveConfig
// for all auth/target/recorder/credential/engine work.
type wtServer struct {
	rdp        *rdpLiveConfig
	publicHost string // host:port the browser dials for the QUIC endpoint
	server     *webtransport.Server
	// certHashB64 is base64(SHA-256(DER cert)) for the browser's
	// serverCertificateHashes pin.
	certHashB64 string
	// datagrams enables the ADR 0060 loss-resilient media split (H.264 deltas
	// over QUIC datagrams; keyframes + control + AVC444 over the reliable
	// stream). OFF unless JESS_RDP_WEBTRANSPORT_DATAGRAMS is set; when off the
	// WT path is the unchanged single reliable stream.
	datagrams bool

	mu      sync.Mutex
	pending map[string]*wtPending
}

// newWTServer builds the WebTransport server: a self-signed short-lived ECDSA
// cert, an HTTP/3 server bound to `addr` (UDP) routing /wt/rdp-live to the
// bridge handler, and the cert-hash for the browser. `publicHost` is the
// host:port the browser dials (advertised via the info endpoint).
func newWTServer(rdp *rdpLiveConfig, addr, publicHost string) (*wtServer, error) {
	cert, der, err := generateWTCert(publicHost)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	wt := &wtServer{
		rdp:         rdp,
		publicHost:  publicHost,
		certHashB64: base64.StdEncoding.EncodeToString(sum[:]),
		datagrams:   os.Getenv("JESS_RDP_WEBTRANSPORT_DATAGRAMS") != "",
		pending:     make(map[string]*wtPending),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/wt/rdp-live", wt.handle)
	wt.server = &webtransport.Server{
		H3: &http3.Server{
			Addr:            addr,
			Handler:         mux,
			TLSConfig:       &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
			EnableDatagrams: true,
		},
		// Same-origin is not meaningful for a direct QUIC dial (no cookies, no
		// IAP); the ticket is the security boundary, so accept the cross-origin
		// WT handshake and rely on ticket redemption below.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	return wt, nil
}

// listen runs the QUIC/HTTP3 listener. Blocking; run in a goroutine.
func (wt *wtServer) listen() {
	log.Printf("jess-web RDP live: WebTransport listener on %s (public %s, cert sha-256 %s)",
		wt.server.H3.Addr, wt.publicHost, wt.certHashB64)
	if err := wt.server.ListenAndServe(); err != nil {
		log.Printf("jess-web RDP live: WebTransport listener stopped: %v", err)
	}
}

// handleInfo is served on the MAIN (Talon-fronted) HTTP mux. It authenticates
// the operator, authorizes+resolves the target exactly like the WS path, then
// issues a one-time ticket the browser presents on the WT connection.
func (wt *wtServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	op, err := wt.rdp.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	targetID := r.URL.Query().Get("target")
	if targetID == "" {
		writeJSONErr(w, http.StatusBadRequest, "target query param required")
		return
	}
	grant := r.URL.Query().Get("grant")
	desktop := parseRDPDesktopSize(r.URL.Query().Get("w"), r.URL.Query().Get("h"))

	target, err := wt.rdp.resolveTarget(r.Context(), op.Token, targetID)
	if err != nil {
		log.Printf("jess-web RDP live (WT): resolve target FAILED op=%s target=%s: %v", op.Subject, targetID, err)
		writeJSONErr(w, http.StatusBadGateway, clientErrTargetResolve)
		return
	}
	if target.Protocol != catalog.ProtoRDP {
		writeJSONErr(w, http.StatusBadRequest, clientErrNotRDP)
		return
	}

	// ASVS L2 V8 — HARD grant gate at the (Talon-authenticated, bearer-carrying)
	// authz seam, BEFORE a ticket is issued. The WT redemption path holds no
	// bearer, so this is where the WT session's grant MUST be proven active +
	// owned by the operator; the ticket then represents a pre-authorized
	// (operator, target, grant). Parity with the WS handler's assertGrantActive.
	if gerr := wt.rdp.assertGrantActive(r.Context(), op.Token, grant, target.ID); gerr != nil {
		log.Printf("jess-web RDP live (WT): grant gate DENIED op=%s target=%s grant=%q: %v", op.Subject, targetID, grant, gerr)
		writeJSONErr(w, http.StatusForbidden, clientErrNotAuthorized)
		return
	}

	// Session id backs the WT session's continuous grant-watch (token refresh).
	sid := ""
	if ck, cerr := r.Cookie(sessionCookie); cerr == nil {
		sid = ck.Value
	}

	ticket := randomToken()
	wt.mu.Lock()
	wt.sweepLocked()
	wt.pending[ticket] = &wtPending{
		op:      op.Subject,
		sid:     sid,
		target:  target,
		grant:   grant,
		desktop: desktop,
		exp:     time.Now().Add(wtTicketTTL),
	}
	wt.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"available": true,
		"url":       "https://" + wt.publicHost + "/wt/rdp-live",
		"certHash":  wt.certHashB64,
		"ticket":    ticket,
		"ttlMs":     wtTicketTTL.Milliseconds(),
		// ADR 0060: when true the server splits H.264 deltas onto QUIC datagrams,
		// so the browser must read + reassemble the datagram stream too. When
		// false the browser ignores datagrams (none arrive) and uses the reliable
		// stream alone — the unchanged ADR 0055 behaviour.
		"datagrams": wt.datagrams,
	})
}

// handle is served on the WebTransport (HTTP/3) mux. It redeems the ticket,
// upgrades to a WebTransport session, and bridges the browser-opened bidi stream
// to the SAME RDP engine the WS path uses.
func (wt *wtServer) handle(w http.ResponseWriter, r *http.Request) {
	pend := wt.redeem(r.URL.Query().Get("ticket"))
	if pend == nil {
		http.Error(w, "invalid or expired WebTransport ticket", http.StatusForbidden)
		return
	}
	session, err := wt.server.Upgrade(w, r)
	if err != nil {
		log.Printf("jess-web RDP live (WT): upgrade failed: %v", err)
		return
	}
	ctx, cancel := context.WithCancel(session.Context())
	defer cancel()
	defer func() { _ = session.CloseWithError(0, "") }()

	// The browser opens exactly one bidirectional stream carrying the TLV wire.
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		log.Printf("jess-web RDP live (WT): no client stream: %v", err)
		return
	}

	targetID := pend.target.ID
	sessionID := newRDPLiveSessionID(pend.op, targetID)

	// Fail-closed recorder (a Recorded target whose recorder can't open is denied).
	rec, rerr := wt.rdp.openRecorder(ctx, pend.op, pend.grant, pend.target, sessionID)
	if rerr != nil {
		log.Printf("jess-web RDP live (WT): recorder open DENIED op=%s target=%s: %v", pend.op, targetID, rerr)
		writeStreamTLVError(stream, clientErrRecording)
		return
	}

	sec, credSource, err := wt.rdp.credentialFor(ctx, pend.target, pend.op)
	if err != nil {
		if rec != nil {
			_ = rec.CloseEvent()
			_ = rec.Close()
		}
		// Error hygiene (V16): the Vault/mint detail stays server-side only.
		log.Printf("jess-web RDP live (WT): credential mint failed op=%s target=%s grant=%s: %v", pend.op, targetID, pend.grant, err)
		writeStreamTLVError(stream, clientErrCredential)
		return
	}
	log.Printf("jess-web RDP live (WT): session open op=%s target=%s addr=%s grant=%s cred=%s recorded=%v",
		pend.op, targetID, pend.target.Address, pend.grant, credSource, pend.target.Recorded)

	// The WT stream IS the engine's framed-TLV client pipe. By default it carries
	// the wire raw (no translation). With datagrams enabled (ADR 0060) we wrap it
	// so H.264 DELTA frames ride QUIC datagrams (loss-resilient) while keyframes,
	// control, AVC444, and input stay on this reliable stream.
	var clientPipe io.ReadWriteCloser = stream
	if wt.datagrams {
		clientPipe = newWTMediaConn(session, stream)
	}
	sess, err := wt.rdp.engine.OpenSession(ctx, pend.target, sec, clientPipe, rec, pend.desktop)
	if err != nil {
		if rec != nil {
			_ = rec.CloseEvent()
			_ = rec.Close()
		}
		log.Printf("jess-web RDP live (WT): engine open FAILED op=%s target=%s: %v", pend.op, targetID, err)
		writeStreamTLVError(stream, clientErrSessionOpen)
		return
	}
	defer func() {
		if cerr := sess.Close(); cerr != nil {
			log.Printf("jess-web RDP live (WT): WORM SEAL FAILURE op=%s target=%s session=%s: %v", pend.op, targetID, sessionID, cerr)
		}
	}()

	// ASVS L2 V8 — continuous grant re-check on the WT carrier too (parity with
	// the WS path + the controller's tunnel-session watch). A grant revoked mid-
	// session closes the WT session within one interval. Teardown: cancel()
	// SIGKILLs the subprocess and CloseWithError drops the QUIC session, which
	// unblocks the engine's stream copy legs.
	revoke := func(reason string) {
		log.Printf("jess-web RDP live (WT): tearing down session op=%s target=%s grant=%s reason=%s", pend.op, targetID, pend.grant, reason)
		cancel()
		_ = session.CloseWithError(wtCloseRevoked, reason)
	}
	go wt.rdp.watchGrantLive(ctx, pend.sid, pend.op, targetID, pend.grant, revoke)

	if rerr := sess.Run(); rerr != nil {
		log.Printf("jess-web RDP live (WT): session ended with error op=%s target=%s: %v", pend.op, targetID, rerr)
	}
	log.Printf("jess-web RDP live (WT): session closed op=%s target=%s session=%s", pend.op, targetID, sessionID)
}

// redeem atomically removes + returns a non-expired pending entry (one-time use).
func (wt *wtServer) redeem(ticket string) *wtPending {
	if ticket == "" {
		return nil
	}
	wt.mu.Lock()
	defer wt.mu.Unlock()
	p := wt.pending[ticket]
	delete(wt.pending, ticket)
	if p == nil || time.Now().After(p.exp) {
		return nil
	}
	return p
}

// sweepLocked drops expired pending tickets. Caller holds wt.mu.
func (wt *wtServer) sweepLocked() {
	now := time.Now()
	for k, p := range wt.pending {
		if now.After(p.exp) {
			delete(wt.pending, k)
		}
	}
}

// writeStreamTLVError writes a `[u32 len][0xFF][utf8 msg]` error frame to the WT
// stream so the browser surfaces the real reason (mirrors the WS error TLV).
func writeStreamTLVError(stream io.Writer, msg string) {
	body := append([]byte{0xFF}, []byte(msg)...)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(body)))
	_, _ = stream.Write(lp[:])
	_, _ = stream.Write(body)
}

// randomToken returns a 32-byte hex one-time token.
func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// generateWTCert makes a short-lived self-signed ECDSA P-256 cert for the
// WebTransport QUIC listener. P-256 + short validity satisfy the browser's
// serverCertificateHashes constraints. Returns the tls.Certificate and the leaf
// DER bytes (for the SHA-256 the browser pins).
func generateWTCert(host string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "jess-rdp-webtransport"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(wtCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// SAN: the dialed host (DNS or IP) so the cert matches even though the
	// browser ALSO pins it by hash.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if host != "" {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: tmpl}
	return cert, der, nil
}
