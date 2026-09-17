// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rdpprobe implements the OUTERMOST layer of MS-RDPBCGR:
// X.224 Connection Request + Connection Confirm + RDP Negotiation
// Request/Response. Shared between jessctl rdp-probe (CLI), the
// controller's admin /rdp-probe endpoint (Phase 5f-2b), and the
// Rust broker's eventual /api/admin/rdp-probe (Phase 5f-2c).
//
// Wire format references:
//
//	RFC 905                                       (X.224)
//	MS-RDPBCGR §2.2.1.1, §2.2.1.2                 (Connection Request/Confirm)
//	MS-RDPBCGR §2.2.1.1.1, §2.2.1.2.1, §2.2.1.2.2 (RDP Negotiation Request / Response / Failure)
//
// Three things this package intentionally does NOT cover:
//
//   - MCS / GCC / fastpath — that's the full ironrdp_connector path
//     (Phase 5f-2c, Rust side).
//   - TLS handshake — we report whether the server REQUIRES TLS, but
//     we don't actually negotiate it. The probe answers "can we
//     reach + does it speak RDP", not "does the full session work".
//   - CredSSP — same reason. We report "NLA required" if the server
//     says so; we don't relay credentials.
package rdpprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// MS-RDPBCGR §2.2.1.1.1 requestedProtocols flags.
const (
	ProtoRDP                  uint32 = 0x00000000 // standard RDP (no TLS)
	ProtoTLS                  uint32 = 0x00000001
	ProtoCredSSP              uint32 = 0x00000002 // NLA
	ProtoRDSTLS               uint32 = 0x00000004
	ProtoCredSSPEarlyUserAuth uint32 = 0x00000008
)

// FailureReasons — MS-RDPBCGR §2.2.1.2.2 selectedProtocol field when
// the trailer type is RDP_NEG_FAILURE.
var FailureReasons = map[uint32]string{
	1: "SSL_REQUIRED_BY_SERVER (server requires TLS but client did not request it)",
	2: "SSL_NOT_ALLOWED_BY_SERVER",
	3: "SSL_CERT_NOT_ON_SERVER",
	4: "INCONSISTENT_FLAGS",
	5: "HYBRID_REQUIRED_BY_SERVER (server requires NLA/CredSSP)",
	6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

// Report is the structured probe outcome — what callers (CLI, admin
// endpoint, future broker) shape their JSON response from.
type Report struct {
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

// Probe opens a TCP connection to target (host:port) and runs the
// X.224 + RDP Negotiation handshake outer layer. Returns a structured
// report. On network failure, fills Error + returns nil err — the
// "failed to reach the target" case is informational, not a fault.
func Probe(ctx context.Context, target, cookie string, requested uint32, timeout time.Duration) Report {
	r := Report{Target: target}
	t0 := time.Now()
	defer func() { r.DurationMs = time.Since(t0).Milliseconds() }()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()
	r.Reachable = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := WriteX224ConnectionRequest(conn, cookie, requested); err != nil {
		r.Error = "write CR: " + err.Error()
		return r
	}
	confirm, nego, perr := ReadX224ConnectionConfirm(conn)
	if perr != nil {
		r.Error = "read CC: " + perr.Error()
		return r
	}
	r.ConnectionConfirm = confirm
	switch nego.Kind {
	case NegOK:
		r.NegotiatedProto = ProtoName(nego.Selected)
		r.NegotiatedFlags = uint32(nego.Flags)
		r.TLSSupported = nego.Selected&(ProtoTLS|ProtoCredSSP) != 0
		r.NLARequired = nego.Selected&ProtoCredSSP != 0
	case NegFailure:
		r.FailureCode = nego.FailureCode
		r.FailureReason = FailureReasons[nego.FailureCode]
		if r.FailureReason == "" {
			r.FailureReason = fmt.Sprintf("unknown failure code %d", nego.FailureCode)
		}
		// Code 5 = HYBRID_REQUIRED_BY_SERVER (NLA required).
		if nego.FailureCode == 5 {
			r.NLARequired = true
		}
	default:
		// Server sent CC but no NEG_RSP — legacy RDP server (no negotiation extension).
		r.NegotiatedProto = "RDP (legacy, no negotiation response)"
	}
	return r
}

// ParseRequestedProtocols turns "tls,credssp,nla" into the bitset.
// Accepts comma-separated tokens; whitespace tolerant; case
// insensitive. Returns 0 for empty / "rdp" (the legacy protocol IS
// requestedProtocols=0). Returns error on any unknown token.
func ParseRequestedProtocols(s string) (uint32, error) {
	var v uint32
	for _, tok := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(tok)) {
		case "", "rdp":
			// legacy RDP — requestedProtocols=0, no bit to OR
		case "tls":
			v |= ProtoTLS
		case "credssp", "nla":
			v |= ProtoCredSSP
		case "rdstls":
			v |= ProtoRDSTLS
		case "credssp-eua":
			v |= ProtoCredSSPEarlyUserAuth
		default:
			return 0, fmt.Errorf("unknown protocol %q (valid: rdp, tls, credssp, rdstls, credssp-eua)", tok)
		}
	}
	return v, nil
}

// ProtoName decodes a selectedProtocol bitset into a human label.
func ProtoName(p uint32) string {
	if p == 0 {
		return "RDP (no TLS)"
	}
	parts := []string{}
	if p&ProtoTLS != 0 {
		parts = append(parts, "TLS")
	}
	if p&ProtoCredSSP != 0 {
		parts = append(parts, "CredSSP (NLA)")
	}
	if p&ProtoRDSTLS != 0 {
		parts = append(parts, "RDSTLS")
	}
	if p&ProtoCredSSPEarlyUserAuth != 0 {
		parts = append(parts, "CredSSP-EarlyUserAuth")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08X", p)
	}
	return strings.Join(parts, "+")
}

// WriteX224ConnectionRequest emits TPKT + X.224 CR + optional cookie
// + RDP_NEG_REQ. Byte-for-byte spec-compliant per
// MS-RDPBCGR §2.2.1.1.
//
// Frame layout (no cookie):
//
//	TPKT       : 0x03 0x00 LL LL          (4 bytes; LL = total len BE)
//	X.224 CR   : 0x?? 0xE0 0x00 0x00 0x00 0x00 0x00 (7 bytes; first = LI = total-5)
//	RDP_NEG_REQ: 0x01 0x00 0x08 0x00 RF 0x00 PP PP PP PP (8 bytes; PP=LE uint32)
func WriteX224ConnectionRequest(w io.Writer, cookie string, requestedProtos uint32) error {
	x224 := []byte{0, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00} // LI placeholder
	body := []byte{}
	if cookie != "" {
		body = append(body, []byte("Cookie: "+cookie+"\r\n")...)
	}
	negReq := []byte{0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(negReq[4:8], requestedProtos)
	body = append(body, negReq...)
	x224[0] = byte(6 + len(body)) // LI = X.224-hdr-octets-after-LI + body

	total := 4 + len(x224) + len(body)
	tpkt := []byte{0x03, 0x00, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))

	buf := make([]byte, 0, total)
	buf = append(buf, tpkt...)
	buf = append(buf, x224...)
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// NegResponseKind discriminates the trailer's nature.
type NegResponseKind int

const (
	NegAbsent NegResponseKind = iota
	NegOK
	NegFailure
)

// NegResponse is the parsed RDP_NEG_RSP / RDP_NEG_FAILURE trailer.
type NegResponse struct {
	Kind        NegResponseKind
	Selected    uint32 // populated when Kind == NegOK
	Flags       byte
	FailureCode uint32 // populated when Kind == NegFailure
}

// ReadX224ConnectionConfirm parses TPKT + X.224 CC + optional NEG_RSP/FAILURE.
// Returns (confirm-present, parsed-trailer, error). Confirm=true even on
// failure (the CC frame IS present, the negotiation inside it is what
// failed — same as the wire).
func ReadX224ConnectionConfirm(r io.Reader) (bool, NegResponse, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return false, NegResponse{}, err
	}
	if hdr[0] != 0x03 {
		return false, NegResponse{}, fmt.Errorf("bad TPKT version 0x%02X (expected 0x03)", hdr[0])
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < 11 {
		return false, NegResponse{}, fmt.Errorf("TPKT length %d too short for X.224 CC", total)
	}
	rest := make([]byte, total-4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return false, NegResponse{}, fmt.Errorf("read body: %w", err)
	}
	if len(rest) < 7 {
		return false, NegResponse{}, fmt.Errorf("body too short for X.224 CC header")
	}
	if rest[1] != 0xD0 {
		return false, NegResponse{}, fmt.Errorf("not an X.224 Connection Confirm (TPDU code 0x%02X)", rest[1])
	}
	body := rest[7:]
	if len(body) == 0 {
		return true, NegResponse{Kind: NegAbsent}, nil
	}
	if len(body) < 8 {
		return true, NegResponse{Kind: NegAbsent}, fmt.Errorf("partial neg trailer (%d bytes)", len(body))
	}
	switch body[0] {
	case 0x02:
		return true, NegResponse{
			Kind:     NegOK,
			Selected: binary.LittleEndian.Uint32(body[4:8]),
			Flags:    body[1],
		}, nil
	case 0x03:
		return true, NegResponse{
			Kind:        NegFailure,
			FailureCode: binary.LittleEndian.Uint32(body[4:8]),
		}, nil
	default:
		return true, NegResponse{Kind: NegAbsent}, errors.New("unknown negotiation trailer type")
	}
}
