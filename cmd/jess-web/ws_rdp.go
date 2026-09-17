// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5f-7 — WS proxy from jess-web to jess-ironrdp-broker.
//
// SPA opens ws[s]://<jess.ops>/ws/rdp?target=...&grant=...
// jess-web upgrades the WS, dials the broker's /ws/session with the
// operator's bearer (cookie session → JWT), then bidirectionally
// bridges binary + text frames.
//
// Why proxy instead of direct browser→broker:
//   1. Single origin for the SPA (same cookie, no CORS, no second
//      OIDC dance against the broker route)
//   2. broker URL is internal-cluster (jess-ironrdp-broker.jess.svc:7104)
//      and stays that way until internal.example.com goes live in
//      Phase 5f-3 follow-up — even then the dual-origin alternative
//      forces operators through Talon TWICE
//   3. We can synthesise SPA-visible error frames if the broker is
//      unreachable — without a proxy the browser sees an opaque
//      "WebSocket connection closed before handshake" with no diag.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// rdpProxyConfig holds the per-process broker-dial config.
type rdpProxyConfig struct {
	brokerWSBase string        // ws[s]://jess-ironrdp-broker.jess.svc:7104
	sessions     *sessionStore // operator cookie session for auth
}

func newRDPProxyConfig(sessions *sessionStore) *rdpProxyConfig {
	base := os.Getenv("JESS_BROKER_WS_BASE")
	if base == "" {
		base = "ws://jess-ironrdp-broker.jess.svc.cluster.local:7104"
	}
	return &rdpProxyConfig{brokerWSBase: base, sessions: sessions}
}

func (c *rdpProxyConfig) handleRDPSession(w http.ResponseWriter, r *http.Request) {
	op, err := c.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSONErr(w, http.StatusBadRequest, "target query param required")
		return
	}
	grant := r.URL.Query().Get("grant")

	// Upgrade the SPA side FIRST. If the broker dial fails we synthesise
	// a JSON error frame on the upgraded WS so the SPA's renderer can
	// show it (otherwise the browser sees an opaque connection refusal).
	clientWS, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("jess-web RDP proxy: client upgrade failed: %v", err)
		return
	}
	defer clientWS.Close()

	// Dial the broker.
	brokerURL := buildBrokerURL(c.brokerWSBase, target, grant)
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+op.Token)
	brokerWS, resp, err := dialer.Dial(brokerURL, hdr)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		log.Printf("jess-web RDP proxy: broker dial failed op=%s target=%s status=%d err=%v",
			op.Subject, target, status, err)
		_ = clientWS.WriteJSON(map[string]any{
			"type":  "error",
			"stage": "broker_dial",
			"msg":   "broker dial failed: " + err.Error(),
		})
		_ = clientWS.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(1011, "broker dial failed"))
		return
	}
	defer brokerWS.Close()

	// Bidirectional bridge. Two goroutines + a WaitGroup so when either
	// side closes, we tear down both.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go pumpWS(ctx, cancel, &wg, clientWS, brokerWS, "spa→broker")
	go pumpWS(ctx, cancel, &wg, brokerWS, clientWS, "broker→spa")
	wg.Wait()
}

// pumpWS copies frames from src to dst, calling cancel() and returning
// on any read or write error. Preserves the frame type (text/binary)
// so the broker's text-JSON control frames and future binary
// bitmap_update frames both pass through correctly.
func pumpWS(
	ctx context.Context,
	cancel context.CancelFunc,
	wg *sync.WaitGroup,
	src, dst *websocket.Conn,
	dir string,
) {
	defer wg.Done()
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		mt, payload, err := src.ReadMessage()
		if err != nil {
			// Common: 1000 close from the broker after 5f-8a handshake.
			// Don't log noise.
			if _, ok := err.(*websocket.CloseError); !ok {
				log.Printf("jess-web RDP proxy %s: read err: %v", dir, err)
			}
			return
		}
		if err := dst.WriteMessage(mt, payload); err != nil {
			log.Printf("jess-web RDP proxy %s: write err: %v", dir, err)
			return
		}
	}
}

func buildBrokerURL(base, target, grant string) string {
	q := url.Values{}
	q.Set("target", target)
	if grant != "" {
		q.Set("grant", grant)
	}
	return base + "/ws/session?" + q.Encode()
}

// writeJSONErr already exists elsewhere in the package; declared here
// only as a comment-anchor for future readers (move to a shared file
// if pre-handshake errors grow beyond the two cases above).
var _ = json.Marshal
