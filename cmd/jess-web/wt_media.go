// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"io"
	"sync/atomic"
)

// wt_media — WebTransport loss-resilient media split for the RDP live console
// (ADR 0060, building on ADR 0055). OFF by default; the reliable single-stream
// WT path (and WebSocket) are unchanged unless JESS_RDP_WEBTRANSPORT_DATAGRAMS
// is set.
//
// The whole point: the engine writes the SAME framed TLV wire to its `client`
// pipe regardless of transport. This wraps that pipe so that, over WebTransport,
// the H.264 path follows the Media-over-QUIC pattern — the loss-resilient design
// for real-time screen/video over QUIC:
//
//   - RELIABLE bidi STREAM: every control TLV (DESKTOP_SIZE / FRAME / FRAME_WEBP
//     / CLIPBOARD / CLOSE + client→server input) AND H.264 KEYFRAMES (an IDR is
//     load-bearing — losing it corrupts the whole GOP) AND the AVC444 main/aux
//     pair (ADR 0059 — kept reliable + together so the recombine stays in sync).
//   - UNRELIABLE DATAGRAMS (RFC 9221): H.264 DELTA frames only — newer frames are
//     worth more than retransmitting a stale one. A delta is fragmented over the
//     ~1200-byte datagram MTU with a small application header so the browser can
//     reassemble and DISCARD an incomplete/stale frame instead of stalling.
//
// Loss recovery WITHOUT a picture-loss-indication / forced keyframe (RDP gives
// the broker no way to demand an IDR): the browser drops the broken GOP and
// resumes at the next keyframe, which the RDP host emits periodically + via
// intra-refresh — the documented approach for remote-desktop video over an
// unreliable transport. A SendDatagram failure (unsupported / oversized) falls
// the frame back onto the reliable stream, so a frame is NEVER lost to this path.

// Datagram wire (mirrors the browser reassembler in web/src/api/rdpTransport.ts):
//
//	[u8 magic=0xD6][u32 frameSeq BE][u16 fragIdx BE][u16 fragCount BE][chunk]
//
// The concatenation of a frame's chunks (fragIdx 0..fragCount-1) is the INNER
// TLV [type][payload] (i.e. the framed message WITHOUT its u32 length — datagrams
// are self-delimiting). The reliable stream keeps the [u32 len][type][payload]
// framing the WtSocket reader already splits.
const (
	wtDgramMagic     = 0xD6
	wtDgramHeaderLen = 1 + 4 + 2 + 2
	// Conservative payload chunk under the safe ~1200-byte QUIC datagram MTU,
	// leaving room for the header. SendDatagram errors (a path with a smaller
	// max) fall back to the reliable stream, so this need not be exact.
	wtDgramChunk = 1024
)

// TLV wire constants (mirror internal/broker + web/src/api/rdp.ts). Re-declared
// here because the broker's are unexported; the wire is the contract.
const (
	wtMsgH264         = 5
	wtH264FlagKey     = 0b0000_0001 // keyframe (IDR + SPS/PPS) — reliable
	wtH264FlagAVC444  = 0b0000_0010 // AVC444 main view — reliable (keep pair synced)
	wtH264FlagAux     = 0b0000_0100 // AVC444 aux view — reliable
	wtH264DeltaReliab = wtH264FlagKey | wtH264FlagAVC444 | wtH264FlagAux
)

// datagramSender is the slice of *webtransport.Session this needs (testable +
// decoupled from the concrete type).
type datagramSender interface {
	SendDatagram([]byte) error
}

// wtMediaConn wraps the WebTransport bidi stream so the engine's server→client
// TLV writes are split (deltas → datagrams, the rest → the reliable stream),
// while reads (client→server input) and Close pass straight through. It is the
// engine's io.ReadWriteCloser client pipe, so OpenSession is unchanged.
type wtMediaConn struct {
	sess   datagramSender
	stream io.ReadWriteCloser
	buf    []byte // accumulates partial frames across Write calls (single writer)
	seq    uint32 // datagram frame sequence (monotonic; wraps harmlessly)
	// dropped counts deltas that fell back to the reliable stream because a
	// datagram send failed — surfaced for diagnostics only.
	dropped atomic.Uint64
}

func newWTMediaConn(sess datagramSender, stream io.ReadWriteCloser) *wtMediaConn {
	return &wtMediaConn{sess: sess, stream: stream}
}

// Read is client→server input — always reliable, straight from the stream.
func (c *wtMediaConn) Read(p []byte) (int, error) { return c.stream.Read(p) }

func (c *wtMediaConn) Close() error { return c.stream.Close() }

// Write accepts the engine's framed-TLV byte stream (possibly split across
// calls), routing each complete [u32 len][type][payload] frame. Returns len(p)
// — every byte is consumed (buffered or routed) so the engine's writer sees a
// full write.
func (c *wtMediaConn) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	for {
		if len(c.buf) < 4 {
			break
		}
		flen := int(binary.BigEndian.Uint32(c.buf[:4]))
		if len(c.buf) < 4+flen {
			break // incomplete frame — wait for more
		}
		frame := c.buf[:4+flen] // [u32 len][body]
		body := frame[4:]       // [type][payload]
		if err := c.route(frame, body); err != nil {
			return 0, err
		}
		c.buf = c.buf[4+flen:]
	}
	// Reclaim the backing array once fully drained so a long session doesn't
	// retain a grown buffer.
	if len(c.buf) == 0 {
		c.buf = nil
	}
	return len(p), nil
}

// route sends one complete frame: an H.264 DELTA over datagrams (fragmented),
// everything else over the reliable stream verbatim.
func (c *wtMediaConn) route(frame, body []byte) error {
	if c.isDeltaH264(body) {
		if err := c.sendDatagramFrame(body); err == nil {
			return nil
		}
		// Datagram send failed (oversized / unsupported path): never drop the
		// frame — fall back to the reliable stream with its original framing.
		c.dropped.Add(1)
	}
	_, err := c.stream.Write(frame)
	return err
}

// isDeltaH264 reports whether body is a plain AVC420 H.264 DELTA (the only
// datagram-eligible TLV): MSG_H264 with none of keyframe/AVC444/aux set.
func (c *wtMediaConn) isDeltaH264(body []byte) bool {
	return len(body) >= 2 && body[0] == wtMsgH264 && body[1]&wtH264DeltaReliab == 0
}

// sendDatagramFrame fragments body ([type][payload]) across datagrams. Returns
// the FIRST send error so route() can fall back wholesale (partial fallback
// would duplicate already-sent fragments).
func (c *wtMediaConn) sendDatagramFrame(body []byte) error {
	seq := atomic.AddUint32(&c.seq, 1)
	n := len(body)
	fragCount := (n + wtDgramChunk - 1) / wtDgramChunk
	if fragCount == 0 {
		fragCount = 1 // a zero-length body still sends one (empty) fragment
	}
	if fragCount > 0xFFFF {
		return errFrameTooLarge // > 64 MiB; let it fall back to the reliable stream
	}
	for i := 0; i < fragCount; i++ {
		start := i * wtDgramChunk
		end := start + wtDgramChunk
		if end > n {
			end = n
		}
		chunk := body[start:end]
		dg := make([]byte, wtDgramHeaderLen+len(chunk))
		dg[0] = wtDgramMagic
		binary.BigEndian.PutUint32(dg[1:5], seq)
		binary.BigEndian.PutUint16(dg[5:7], uint16(i))
		binary.BigEndian.PutUint16(dg[7:9], uint16(fragCount))
		copy(dg[wtDgramHeaderLen:], chunk)
		if err := c.sess.SendDatagram(dg); err != nil {
			return err
		}
	}
	return nil
}

type frameTooLargeError struct{}

func (frameTooLargeError) Error() string { return "wt media: frame exceeds datagram fragment count" }

var errFrameTooLarge = frameTooLargeError{}
