// rdpTransport — pluggable carrier for the RDP live TLV stream (ADR 0055).
//
// The live console speaks the P2b TLV wire (see rdp.ts). Historically that rode
// a WebSocket; this module lets it ALSO ride WebTransport (HTTP/3 over QUIC),
// which avoids TCP head-of-line blocking under packet loss (a dropped delta
// frame doesn't stall the next). WebTransport is the right transport for a
// browser→server byte stream; WebRTC (P2P/ICE/TURN) is deliberately not used.
//
// Both transports are exposed through `RDPSocket`, a narrow subset of the
// WebSocket interface RDPCanvas already uses, so the canvas's message/input/close
// handling is unchanged — only the opener differs.
//
// FRAMING. The WS server strips the u32 length so the browser gets one binary
// message per TLV ([type][payload]). A WebTransport bidirectional stream is a raw
// byte stream, so the browser does that length-framing itself: outbound sends are
// prefixed with the u32 big-endian length, and the inbound reader splits the
// stream back into [type][payload] messages — identical to what the WS Go handler
// did. So RDPCanvas's `decodeServerTLV(ev.data)` / `send([type][payload])` calls
// work over either transport without change.
//
// FALLBACK. WebTransport is attempted only when enabled + supported + the server
// advertises it (the /api/rdp/webtransport-info endpoint, which is Talon-fronted
// and returns a one-time ticket). ANY failure falls back to the WebSocket.

import { base64ToBytes } from './rdp'

// ADR 0060 datagram framing (mirrors the Go splitter in cmd/jess-web/wt_media.go):
// [u8 magic][u32 frameSeq BE][u16 fragIdx BE][u16 fragCount BE][chunk]. The
// concatenated chunks of a frame are the inner [type][payload] TLV.
const DGRAM_MAGIC = 0xd6
const DGRAM_HEADER = 9

/// The WebSocket subset RDPCanvas relies on. A native `WebSocket` satisfies this
/// structurally; `WtSocket` implements it over a WebTransport stream.
export interface RDPSocket {
  binaryType: string
  /// Numeric ready state; matches WebSocket's (1 = OPEN, 3 = CLOSED) so existing
  /// `readyState === WebSocket.OPEN` checks work for either transport.
  readyState: number
  onopen: (() => void) | null
  onmessage: ((ev: { data: ArrayBuffer }) => void) | null
  onerror: ((ev?: unknown) => void) | null
  onclose: ((ev: { code: number; reason: string }) => void) | null
  send(data: Uint8Array): void
  close(code?: number, reason?: string): void
}

// Build env gate (operator A/B without a server change). WebTransport is also
// runtime-gated by the server only advertising it when configured.
function wtEnabled(): boolean {
  try {
    if (import.meta.env?.VITE_RDP_WEBTRANSPORT === '1') return true
  } catch {
    /* import.meta.env may be absent in some bundles */
  }
  try {
    return localStorage.getItem('jess.rdp.webtransport') === '1'
  } catch {
    return false
  }
}

function wtSupported(): boolean {
  return typeof (globalThis as { WebTransport?: unknown }).WebTransport === 'function'
}

interface WTInfo {
  available?: boolean
  url?: string
  certHash?: string // base64(SHA-256(DER cert))
  ticket?: string
  // ADR 0060: server splits H.264 deltas onto QUIC datagrams. When true the
  // WtSocket also reads + reassembles the datagram stream; when false/absent it
  // uses the reliable stream alone (unchanged ADR 0055 behaviour).
  datagrams?: boolean
}

export interface OpenRDPSocketParams {
  /// The WebSocket URL to use as the default + fallback.
  wsUrl: string
  /// Query params (target, grant, w, h) for the WebTransport info request.
  query: URLSearchParams
}

/// Open the RDP transport: WebTransport when enabled+supported+advertised,
/// otherwise (or on any WT failure) a WebSocket. Always resolves to an open-able
/// `RDPSocket`; never rejects (it falls back to WS).
export async function openRDPSocket(params: OpenRDPSocketParams): Promise<RDPSocket> {
  if (wtEnabled() && wtSupported()) {
    try {
      const wt = await openWebTransport(params.query)
      if (wt) return wt
    } catch (e) {
      console.warn('RDP WebTransport unavailable, falling back to WebSocket:', e)
    }
  }
  const ws = new WebSocket(params.wsUrl)
  ws.binaryType = 'arraybuffer'
  return ws as unknown as RDPSocket
}

async function openWebTransport(query: URLSearchParams): Promise<RDPSocket | null> {
  // Ask the Talon-fronted endpoint for the QUIC URL, cert hash, and a one-time
  // ticket (it authenticates the operator + authorizes the target server-side).
  const res = await fetch(`/api/rdp/webtransport-info?${query.toString()}`, {
    credentials: 'same-origin',
    cache: 'no-store',
  })
  if (!res.ok) return null
  const info = (await res.json()) as WTInfo
  if (!info.available || !info.url || !info.certHash || !info.ticket) return null

  const WT = (globalThis as { WebTransport: new (url: string, opts?: unknown) => WebTransportLike }).WebTransport
  const hash = base64ToBytes(info.certHash)
  const wt = new WT(`${info.url}?ticket=${encodeURIComponent(info.ticket)}`, {
    // Pin the server's short-lived self-signed cert by SHA-256 — no
    // publicly-trusted cert needed for the direct QUIC path.
    serverCertificateHashes: [{ algorithm: 'sha-256', value: hash }],
    allowPooling: false,
  })
  await wt.ready
  const stream = await wt.createBidirectionalStream()
  return new WtSocket(wt, stream, info.datagrams === true)
}

// Minimal ambient WebTransport types (TS's DOM lib may lack them; mirror only
// what we use — same minimal-deps discipline as rdpH264.ts).
interface WebTransportLike {
  ready: Promise<void>
  closed: Promise<unknown>
  close(info?: { closeCode?: number; reason?: string }): void
  createBidirectionalStream(): Promise<WebTransportBidiStreamLike>
  // ADR 0060: the unreliable datagram side (RFC 9221). readable yields one
  // Uint8Array per received datagram.
  datagrams: { readable: ReadableStream<Uint8Array> }
}
interface WebTransportBidiStreamLike {
  readable: ReadableStream<Uint8Array>
  writable: WritableStream<Uint8Array>
}

/// A WebTransport bidirectional stream presented as an `RDPSocket`. Buffers any
/// inbound messages that arrive before `onmessage` is assigned (the opener
/// returns before RDPCanvas wires its handlers), so none are lost.
class WtSocket implements RDPSocket {
  binaryType = 'arraybuffer'
  readyState = 1 // OPEN — `ready` already resolved before construction
  onopen: (() => void) | null = null
  onmessage: ((ev: { data: ArrayBuffer }) => void) | null = null
  onerror: ((ev?: unknown) => void) | null = null
  onclose: ((ev: { code: number; reason: string }) => void) | null = null

  private wt: WebTransportLike
  private writer: WritableStreamDefaultWriter<Uint8Array>
  private reader: ReadableStreamDefaultReader<Uint8Array>
  private pending: ArrayBuffer[] = []
  private closed = false
  // ADR 0060 datagram reassembly. dgramAsm holds in-flight multi-fragment
  // frames keyed by frame seq; dgramHighSeq is the newest seq delivered (for
  // wrap-safe stale-drop). Both unused unless the server splits onto datagrams.
  private dgramAsm = new Map<number, { count: number; got: number; frags: Array<Uint8Array | undefined> }>()
  private dgramHighSeq = 0

  constructor(wt: WebTransportLike, stream: WebTransportBidiStreamLike, useDatagrams = false) {
    this.wt = wt
    this.writer = stream.writable.getWriter()
    this.reader = stream.readable.getReader()
    // Fire onopen + flush after the opener's caller has assigned handlers.
    queueMicrotask(() => {
      this.onopen?.()
      this.flush()
    })
    void this.readLoop()
    // ADR 0060: also drain the datagram side when the server advertised it.
    // The reliable stream still carries keyframes + control, so the datagram
    // path is a pure addition — its failure never closes the session.
    if (useDatagrams) void this.readDatagrams()
    void this.wt.closed.then(
      () => this.fireClose(1000, ''),
      () => this.fireClose(1006, 'transport closed'),
    )
  }

  // Deliver a complete [type][payload] message (or buffer it until onmessage set).
  private deliver(body: ArrayBuffer): void {
    if (this.onmessage) this.onmessage({ data: body })
    else this.pending.push(body)
  }
  private flush(): void {
    if (!this.onmessage) return
    const q = this.pending
    this.pending = []
    for (const b of q) this.onmessage({ data: b })
  }

  // Read the byte stream and split it back into length-prefixed TLV messages:
  // [u32 BE len][len bytes = [type][payload]].
  private async readLoop(): Promise<void> {
    let buf = new Uint8Array(0)
    try {
      for (;;) {
        const { value, done } = await this.reader.read()
        if (done) break
        if (value && value.length) {
          const merged = new Uint8Array(buf.length + value.length)
          merged.set(buf, 0)
          merged.set(value, buf.length)
          buf = merged
        }
        // Drain all complete frames currently buffered.
        for (;;) {
          if (buf.length < 4) break
          const len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0)
          if (buf.length < 4 + len) break
          const body = buf.slice(4, 4 + len)
          this.deliver(body.buffer)
          this.flush()
          buf = buf.slice(4 + len)
        }
      }
      this.fireClose(1000, '')
    } catch (e) {
      this.onerror?.(e)
      this.fireClose(1006, 'read error')
    }
  }

  // readDatagrams drains the unreliable datagram side (ADR 0060): H.264 DELTA
  // frames the server split off the reliable stream. Each datagram is
  // [u8 magic=0xD6][u32 seq][u16 fragIdx][u16 fragCount][chunk]; a frame's chunks
  // concatenate to the inner [type][payload] TLV (no u32 length — datagrams are
  // self-delimiting), delivered through the SAME path as the stream's messages.
  // A datagram-side error is NON-fatal: the reliable stream carries keyframes +
  // control, so the session continues (just without delta smoothing).
  private async readDatagrams(): Promise<void> {
    let reader: ReadableStreamDefaultReader<Uint8Array>
    try {
      reader = this.wt.datagrams.readable.getReader()
    } catch {
      return // no datagram support on this transport
    }
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        if (value && value.length >= DGRAM_HEADER) this.onDatagram(value)
      }
    } catch {
      // non-fatal — see method doc.
    }
  }

  // newerSeq reports whether `a` is newer than `b` in u32 sequence space
  // (wrap-safe: treats the smaller half of the ring as "newer").
  private static newerSeq(a: number, b: number): boolean {
    return ((a - b) >>> 0) < 0x80000000
  }

  private onDatagram(d: Uint8Array): void {
    if (this.closed || d[0] !== DGRAM_MAGIC) return
    const dv = new DataView(d.buffer, d.byteOffset, d.length)
    const seq = dv.getUint32(1)
    const fragIdx = dv.getUint16(5)
    const fragCount = dv.getUint16(7)
    if (fragCount === 0 || fragIdx >= fragCount) return
    // Drop frames not newer than the last one we completed (stale / reordered).
    if (this.dgramHighSeq !== 0 && !WtSocket.newerSeq(seq, this.dgramHighSeq)) return
    const chunk = d.subarray(DGRAM_HEADER)

    if (fragCount === 1) {
      this.dgramHighSeq = seq
      this.deliver(chunk.slice().buffer)
      this.flush()
      return
    }
    let asm = this.dgramAsm.get(seq)
    if (!asm) {
      asm = { count: fragCount, got: 0, frags: new Array(fragCount) }
      this.dgramAsm.set(seq, asm)
      // Bound memory: keep at most 64 in-flight partial frames; drop the oldest
      // (Map preserves insertion order, so the first key is oldest-inserted).
      while (this.dgramAsm.size > 64) {
        const oldest = this.dgramAsm.keys().next().value
        if (oldest === undefined) break
        this.dgramAsm.delete(oldest)
      }
    }
    if (asm.frags[fragIdx]) return // duplicate fragment
    asm.frags[fragIdx] = chunk.slice()
    asm.got++
    if (asm.got !== asm.count) return
    this.dgramAsm.delete(seq)
    this.dgramHighSeq = seq
    let total = 0
    for (const f of asm.frags) total += f ? f.length : 0
    const out = new Uint8Array(total)
    let off = 0
    for (const f of asm.frags) {
      if (!f) continue
      out.set(f, off)
      off += f.length
    }
    this.deliver(out.buffer)
    this.flush()
  }

  private fireClose(code: number, reason: string): void {
    if (this.closed) return
    this.closed = true
    this.readyState = 3 // CLOSED
    this.onclose?.({ code, reason })
  }

  // Prepend the u32 BE length the engine expects, then write to the stream.
  send(data: Uint8Array): void {
    if (this.closed) return
    const framed = new Uint8Array(4 + data.length)
    new DataView(framed.buffer).setUint32(0, data.length)
    framed.set(data, 4)
    void this.writer.write(framed).catch(() => this.fireClose(1006, 'write error'))
  }

  close(code = 1000, reason = ''): void {
    if (this.closed) {
      try {
        this.wt.close()
      } catch {
        /* already closed */
      }
      return
    }
    this.closed = true
    this.readyState = 3
    try {
      void this.writer.close().catch(() => {})
      void this.reader.cancel().catch(() => {})
    } catch {
      /* ignore */
    }
    try {
      this.wt.close({ closeCode: code, reason })
    } catch {
      /* ignore */
    }
  }
}
