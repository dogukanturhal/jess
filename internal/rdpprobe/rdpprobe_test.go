// SPDX-License-Identifier: AGPL-3.0-or-later

package rdpprobe

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// Wire-format tests moved over from cmd/jessctl/rdp_probe_test.go.
// Keeping them here so the package's spec compliance is self-contained.

func TestWriteX224ConnectionRequest_FrameShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteX224ConnectionRequest(&buf, "", ProtoTLS|ProtoCredSSP); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.Bytes()
	if len(out) != 19 {
		t.Fatalf("total len = %d, want 19; bytes=%v", len(out), out)
	}
	if out[0] != 0x03 || out[1] != 0x00 {
		t.Errorf("TPKT version bad: %02X %02X", out[0], out[1])
	}
	if total := binary.BigEndian.Uint16(out[2:4]); total != 19 {
		t.Errorf("TPKT length = %d, want 19", total)
	}
	if out[4] != 0x0E {
		t.Errorf("X.224 LI = 0x%02X, want 0x0E", out[4])
	}
	if out[5] != 0xE0 {
		t.Errorf("X.224 TPDU code = 0x%02X, want 0xE0", out[5])
	}
	if out[11] != 0x01 || out[12] != 0x00 || out[13] != 0x08 || out[14] != 0x00 {
		t.Errorf("NEG_REQ header bad")
	}
	if p := binary.LittleEndian.Uint32(out[15:19]); p != 0x03 {
		t.Errorf("requestedProtocols = 0x%08X, want 0x03", p)
	}
}

func TestReadX224ConnectionConfirm_OK(t *testing.T) {
	body := []byte{0x0E, 0xD0, 0, 0, 0, 0, 0, 0x02, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00}
	tpkt := []byte{0x03, 0x00, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(body)))
	r := io.MultiReader(bytes.NewReader(tpkt), bytes.NewReader(body))
	confirm, nego, err := ReadX224ConnectionConfirm(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !confirm || nego.Kind != NegOK || nego.Selected != ProtoCredSSP {
		t.Errorf("got confirm=%v kind=%d selected=%X", confirm, nego.Kind, nego.Selected)
	}
}

func TestReadX224ConnectionConfirm_NLAFailure(t *testing.T) {
	body := []byte{0x0E, 0xD0, 0, 0, 0, 0, 0, 0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00}
	tpkt := []byte{0x03, 0x00, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(body)))
	r := io.MultiReader(bytes.NewReader(tpkt), bytes.NewReader(body))
	_, nego, err := ReadX224ConnectionConfirm(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if nego.Kind != NegFailure || nego.FailureCode != 5 {
		t.Errorf("got kind=%d code=%d", nego.Kind, nego.FailureCode)
	}
}

func TestParseRequestedProtocols(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0}, {"rdp", 0}, {"tls", ProtoTLS},
		{"credssp", ProtoCredSSP}, {"nla", ProtoCredSSP},
		{"tls,credssp", ProtoTLS | ProtoCredSSP},
		{"TLS, NLA", ProtoTLS | ProtoCredSSP},
	}
	for _, c := range cases {
		got, err := ParseRequestedProtocols(c.in)
		if err != nil || got != c.want {
			t.Errorf("parse(%q) = (0x%X, %v), want (0x%X, nil)", c.in, got, err, c.want)
		}
	}
	if _, err := ParseRequestedProtocols("bogus"); err == nil {
		t.Errorf("expected error for bogus token")
	}
}

// TestIsAllowedTarget enforces the SSRF gate. Public IPs MUST be
// rejected even when the port is RDP — operators who want to probe
// public Windows servers can do it from their workstation, not via
// the controller's egress.
func TestIsAllowedTarget(t *testing.T) {
	cases := []struct {
		in      string
		allowed bool
	}{
		// RFC1918 + RDP port → allowed
		{"10.0.20.10:3389", true},
		{"10.0.20.10:13389", true},
		{"192.168.1.50:3389", true},
		{"172.16.5.5:3389", true},
		{"127.0.0.1:3389", true},
		// Wrong port
		{"10.0.20.10:22", false},
		{"10.0.20.10:443", false},
		{"10.0.20.10:80", false},
		// Public IPs rejected
		{"1.1.1.1:3389", false},
		{"8.8.8.8:3389", false},
		// Malformed
		{"10.0.20.10", false}, // no port
		{"not a host:3389", false},
	}
	for _, c := range cases {
		err := IsAllowedTarget(c.in)
		if (err == nil) != c.allowed {
			t.Errorf("IsAllowedTarget(%q) err=%v, want allowed=%v", c.in, err, c.allowed)
		}
	}
}
