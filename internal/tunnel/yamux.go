// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/hashicorp/yamux"
)

const maxHeaderBytes = 1 << 16

// streamConn adapts a yamux stream (net.Conn) + its SessionHeader to SessionStream.
type streamConn struct {
	net.Conn
	hdr SessionHeader
}

func (s *streamConn) Header() SessionHeader { return s.hdr }

// writeHeader frames the header as a 4-byte big-endian length + JSON, so the
// reader consumes exactly the header and the raw session stream follows clean.
func writeHeader(w io.Writer, h SessionHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readHeader(r io.Reader) (SessionHeader, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return SessionHeader{}, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n == 0 || n > maxHeaderBytes {
		return SessionHeader{}, fmt.Errorf("tunnel: bad header length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return SessionHeader{}, err
	}
	var h SessionHeader
	return h, json.Unmarshal(buf, &h)
}

// YamuxPool is the controller-side worker pool: each registered worker is a
// yamux server session; the controller opens streams INTO it (workers never
// listen). Implements Pool.
type YamuxPool struct {
	mu       sync.Mutex
	sessions map[string]*yamux.Session
}

// NewYamuxPool returns an empty pool.
func NewYamuxPool() *YamuxPool { return &YamuxPool{sessions: map[string]*yamux.Session{}} }

// Register adopts a worker's (already TLS-handshaken) conn as a yamux session.
func (p *YamuxPool) Register(workerID string, conn net.Conn) error {
	sess, err := yamux.Server(conn, nil)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if old := p.sessions[workerID]; old != nil {
		_ = old.Close()
	}
	p.sessions[workerID] = sess
	p.mu.Unlock()
	return nil
}

// Workers lists currently-connected worker IDs.
func (p *YamuxPool) Workers() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.sessions))
	for id, s := range p.sessions {
		if !s.IsClosed() {
			out = append(out, id)
		}
	}
	return out
}

// Open opens a new session stream into the named worker and writes the header.
func (p *YamuxPool) Open(ctx context.Context, workerID string, hdr SessionHeader) (SessionStream, error) {
	p.mu.Lock()
	sess, ok := p.sessions[workerID]
	p.mu.Unlock()
	if !ok || sess.IsClosed() {
		return nil, fmt.Errorf("tunnel: no connected worker %q", workerID)
	}
	st, err := sess.Open()
	if err != nil {
		return nil, err
	}
	if err := writeHeader(st, hdr); err != nil {
		_ = st.Close()
		return nil, err
	}
	return &streamConn{Conn: st, hdr: hdr}, nil
}

// ServeWorkers accepts worker connections on l, derives each worker's id via
// idFn (TLS peer CommonName / SPIFFE ID), and registers it.
func (p *YamuxPool) ServeWorkers(l net.Listener, idFn func(net.Conn) (string, error)) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			wid, err := idFn(c)
			if err != nil {
				_ = c.Close()
				return
			}
			if err := p.Register(wid, c); err != nil {
				_ = c.Close()
			}
		}(c)
	}
}

// YamuxWorker is the data-plane side: it dials the controller OUTBOUND and
// serves the streams the controller opens. Implements Worker.
type YamuxWorker struct {
	tlsCfg *tls.Config
}

// NewYamuxWorker builds a worker that dials with the given mTLS client config.
func NewYamuxWorker(tlsCfg *tls.Config) *YamuxWorker { return &YamuxWorker{tlsCfg: tlsCfg} }

// Dial connects outbound to the controller and serves controller-opened streams.
func (w *YamuxWorker) Dial(ctx context.Context, controllerAddr string, handle func(SessionStream)) error {
	conn, err := tls.Dial("tcp", controllerAddr, w.tlsCfg)
	if err != nil {
		return err
	}
	sess, err := yamux.Client(conn, nil)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go func(st net.Conn) {
			h, err := readHeader(st)
			if err != nil {
				_ = st.Close()
				return
			}
			handle(&streamConn{Conn: st, hdr: h})
		}(st)
	}
}
