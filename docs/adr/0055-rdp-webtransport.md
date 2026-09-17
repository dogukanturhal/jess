# ADR 0055 — RDP live console over WebTransport (HTTP/3 / QUIC)

Status: Accepted — 2026-06-24. Implemented (server + browser + auth); builds
clean. Live end-to-end needs a browser + a reachable UDP/QUIC path (see
"Deployment"). OFF by default. WebSocket remains the default + fallback.
Related: ADR 0051 (IronRDP live console / WS TLV wire), ADR 0053 (H.264/EGFX),
internal engineering notes (Talon is the sole IAP).

## Context

The live RDP console streams the P2b TLV wire (`DESKTOP_SIZE`/`FRAME`/`FRAME_WEBP`/
`H264`/`CLOSE` + mouse/key input) between the browser and `session_live` over a
**WebSocket** (`ws_rdp_live.go`). WebSocket runs over TCP, so a single lost
segment head-of-line-blocks every multiplexed message behind it — for an H.264 or
dirty-rect video stream, a dropped delta frame stalls the next one. On a clean
LAN this is invisible; on a lossy/high-latency link it shows as stutter.

**WebTransport** (W3C) is the browser primitive for client→server streams over
**QUIC/HTTP-3**: multiple independent streams + unreliable datagrams, *without*
TCP head-of-line blocking. It is the modern replacement for "WebSocket for binary
realtime" in exactly this client↔server shape.

## Decision: WebTransport, not WebRTC

For a **browser→server** byte stream, WebTransport is the correct transport.
WebRTC DataChannel is built for **peer-to-peer** and drags in ICE/STUN/TURN and a
UDP/DTLS/SCTP media path. That media path would **bypass the Talon IAP** (the
standing rule: Talon is the sole IAP for `*.ops`), which is an architecture
violation, not just extra work. WebTransport is HTTP-based (an Extended-CONNECT
over HTTP/3), so it can be authorized + (eventually) proxied within the IAP model.
So we implement **WebTransport**; WebRTC is explicitly rejected for this stack.

## Implementation

The whole point: WebTransport carries the **exact same TLV stream** as the WS
path and reuses the **same** target-resolve / WORM-recorder / Vault-credential /
`session_live` engine. A `webtransport.Stream` is an `io.ReadWriteCloser` — which
is exactly the `client` the RDP bridge engine already takes — so a WebTransport
bidirectional stream IS the engine's client pipe, carrying the raw
`[u32 len][type][payload]` framing directly. No frame translation server-side; the
browser does the length-framing the WS Go handler used to do.

- **Server** (`cmd/jess-web/wt_rdp_live.go`, `webtransport-go` on `quic-go`): a
  QUIC/HTTP-3 listener on a dedicated UDP port (`JESS_RDP_WEBTRANSPORT_ADDR`,
  unset ⇒ disabled). On connect it redeems a ticket, `Upgrade`s, `AcceptStream`s
  the browser-opened bidi stream, and hands it straight to
  `engine.OpenSession(...)` + `Run()` — the same code path as WS, including the
  fail-closed WORM recorder and the seal-on-close.
- **Browser** (`web/src/api/rdpTransport.ts`): `openRDPSocket()` returns an
  `RDPSocket` (a narrow WebSocket-shaped facade) backed by EITHER a native
  WebSocket OR a `WtSocket` over a WebTransport bidi stream. `RDPCanvas` is
  unchanged except the opener is now async. The `WtSocket` length-frames outbound
  sends and splits the inbound byte stream back into `[type][payload]` messages,
  so `decodeServerTLV` / the input encoders work over either transport.
- **Gating**: WebTransport is attempted only when (a) build/runtime flag
  `VITE_RDP_WEBTRANSPORT` / `localStorage['jess.rdp.webtransport']`, (b)
  `'WebTransport' in window`, and (c) the server advertises it. ANY failure falls
  back to the WebSocket.

## Auth (IAP-bypass-safe)

A WebTransport connection reaches the QUIC listener **directly** (not through
Talon) and its handshake carries **no cookies**, so cookie-based
`operatorFromRequest` can't run on it. Auth is therefore **split**:

1. `GET /api/rdp/webtransport-info` is served on the normal HTTP mux **behind
   Talon**. It runs the real `operatorFromRequest` + the same catalog authz
   (`resolveTarget`) as the WS path, then issues a **one-time, 30 s ticket**
   bound server-side to `(operatorSub, target, grant, desktop)`.
2. The browser presents that ticket on the WebTransport connection. The server
   redeems it (one-time) for the pre-authorized session and only then mints the
   Vault credential + opens the recorder (these need only `operatorSub`/`grant`/
   `target`, no bearer). No standing credential is ever minted for an
   unredeemed/expired ticket.

So the WebTransport path IS authenticated — at a different seam than the
cookie-bearing WS path, but with the same operator identity + target authz.

The QUIC listener uses a **short-lived self-signed ECDSA P-256 cert**
(regenerated each start, ≤14-day validity) pinned in the browser via
`serverCertificateHashes` (SHA-256 of the DER, advertised by the info endpoint),
so the direct path needs no publicly-trusted cert.

## Deployment status (honest)

WebTransport needs **HTTP/3 reachable from the browser**. Talon/Envoy/Traefik
terminate HTTP/1.1–2 today, **not HTTP/3**, so this does NOT yet ride the standard
`*.ops` ingress. It is currently a **direct browser→jess-web QUIC path** on the
dedicated UDP port — usable where that port is reachable (dev, or a future UDP
NodePort/LB), advertised only when `JESS_RDP_WEBTRANSPORT_ADDR` is set. The
remaining ops step for production is HTTP/3 termination integrated with Talon (or
a dedicated HTTP/3 ingress that re-checks the ticket). Until then the WebSocket
path is the default and guaranteed transport; WebTransport is opt-in/experimental.

## Remaining work

1. Live end-to-end verification (a browser + a reachable UDP/QUIC path) — confirm
   the QUIC handshake, ticket redemption, and the TLV stream over the bidi stream.
2. Production ingress: HTTP/3 termination through Talon (preserving the sole-IAP
   model) or a dedicated HTTP/3 ingress that validates the ticket.
3. (Optional) carry H.264 delta frames over QUIC **datagrams** (unreliable) with
   keyframes over a reliable stream, for true loss-resilient video — the biggest
   latency win, once the stream path is proven.
