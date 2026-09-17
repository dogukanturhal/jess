# ADR 0054 — RDP virtual channels: clipboard sync (implemented) + audio / multi-monitor / drive redirect (design)

**Status:** Accepted — 2026-06-23. **Clipboard (bidirectional TEXT) implemented
end-to-end in this MR**, default OFF (runtime flag `JESS_RDP_CLIPBOARD`). Audio
output, multi-monitor, and drive redirect are **design-only** here (scaffold +
effort + IronRDP-support assessment) — no code beyond this ADR.
**Phase:** 5f-8b Tier-3 (RDP virtual-channel features), branch
`feat/rdp-tier3-clipboard-features`.
**Builds on:** ADR 0051 (IronRDP CredSSP plan + the P2b streaming session core),
ADR 0033 (Rust IronRDP bridge), ADR 0047 (RDP TLS CA scope note).

## Context

The live browser-RDP path (ADR 0051) streams the decoded Windows desktop to the
browser and relays mouse/keyboard back, over a length-prefixed TLV wire protocol
spoken end-to-end:

```
browser  <─ WS BINARY [u8 type][payload] ─>  jess-web  <─ [u32 len][type][payload] ─>  session_live (Rust/IronRDP)  <─ RDP ─>  Windows DC
```

Server→client types were `DESKTOP_SIZE=1`, `FRAME=2`, `CLOSE=3` (+ the jess-web
synthetic `ERROR=0xFF`); client→server were `MOUSE=1`, `KEY=2`. The session
negotiated **no redirection virtual channels** — graphics + input only. The Go
engine's `ChannelPolicy`/`channelGate` seam already enumerated
clipboard/drive/printer/sound for the WORM audit decision, but the Rust side
never advertised any of them (`rdp_live_engine.go`: "session_live does NOT
negotiate clipboard/drive/printer in this milestone").

This ADR adds the **clipboard** virtual channel (the highest-value, lowest-risk
one for a PAM/ZTNA operator console — copy/paste between the operator's browser
and the jump target) and records the design for the remaining channels.

## IronRDP 0.15 support — feasibility verdict

Verified against the locked dep tree (`ironrdp = 0.15.0`, the meta-crate that
re-exports the family):

| Channel | IronRDP crate (via 0.15 meta) | Verdict |
| --- | --- | --- |
| **Clipboard** (MS-RDPECLIP / cliprdr) | `ironrdp-cliprdr 0.6` (`ironrdp/cliprdr` feature) | **Full, production-grade.** `Cliprdr<Client>` is a `SvcClientProcessor` with a complete state machine (capabilities, format-list, format-data, file-list/file-contents, lock/unlock, timeouts) + a `CliprdrBackend` callback trait + `CF_UNICODETEXT` text helpers (`FormatDataResponse::new_unicode_string` / `to_unicode_string`). Clipboard TEXT is fully feasible; this MR implements it. |
| **Audio output** (rdpsnd) | `ironrdp-rdpsnd 0.8` (`ironrdp/rdpsnd` feature) — **present but NOT in our dep tree** | Feasible (server→client PCM/codec audio), client-side. Not wired. |
| **Multi-monitor** | connector `DesktopSize` (single) + `ironrdp-displaycontrol 0.6` (already a transitive via `ironrdp-session`) for *dynamic resize* | Static multi-monitor at connect = connector GCC monitor layout (no IronRDP blocker); the harder part is browser-side multi-canvas + the streaming protocol, not IronRDP. |
| **Drive redirect** (rdpdr) | `ironrdp-rdpdr 0.6` (`ironrdp/rdpdr` feature) — **present but NOT in our dep tree** | Feasible but heavy (a filesystem-emulation device + a security-sensitive data path). Strongly gated. |

**Bottom line:** clipboard is not a scaffold — IronRDP 0.15 ships a complete,
spec-correct cliprdr. The other three are feasible (IronRDP has the crates) but
each is a larger build dominated by the *browser/protocol* side, not by IronRDP.

## Decision — clipboard (implemented)

### Scope

Bidirectional **TEXT** (`CF_UNICODETEXT`) only. Explicitly out of scope for this
milestone (documented as follow-ups below): clipboard **files**
(FileGroupDescriptorW / file-contents — cliprdr implements the whole state
machine, but exposing it to the browser is a drive-redirect-class data path and
a deliberate exfiltration surface), and clipboard **images** (`CF_DIB`).

### Design

```
                 ironrdp_session::ActiveStage (owns the SVC processor set)
                         │  routes inbound CLIPRDR PDUs by MCS channel id
                         ▼
  CliprdrClient (SvcClientProcessor)  ──callbacks──▶  ChannelBackend (CliprdrBackend)
        ▲  initiate_copy / initiate_paste                    │ mpsc events / shared slots
        │  submit_format_data                                ▼
   stream.rs main loop  ◀────────────  ClipboardChannel handle  ────────────▶  CLIPBOARD TLV (0x20)
```

1. **Negotiation** (`connect.rs`): when enabled, register the processor on the
   connector *before* the handshake —
   `ClientConnector::with_static_channel(CliprdrClient::new(backend))`. The
   connector advertises CLIPRDR in the GCC client channel list and joins it
   during channel-connection. `connect_to_connected` returns an
   `Option<ClipboardChannel>` (Some iff CLIPRDR negotiated).

2. **Inbound** (remote → browser): `ActiveStage::process` dispatches CLIPRDR
   server PDUs to the processor automatically, which fires the synchronous
   `CliprdrBackend` callbacks and auto-sends the processor's reply PDUs (e.g.
   `FormatListResponse`) as a `ResponseFrame` the existing loop already writes.
   `ChannelBackend` translates the callbacks into `ClipboardEvent`s on an mpsc
   that the stream loop drains each iteration and serialises to a `CLIPBOARD`
   TLV.

3. **Outbound** (browser → remote): the stream loop fetches the processor back
   out with `ActiveStage::get_svc_processor_mut::<CliprdrClient>()` and calls
   `initiate_copy` (advertise the browser text), `initiate_paste` (request the
   remote text), or `submit_format_data` (answer a remote format-data request
   with the browser-staged text), encoding the result with
   `process_svc_processor_messages` and writing it to the socket. All socket
   writes happen on the single-owner write-half, outside any `select!` arm —
   preserving the P2b cancel-safety invariant.

The synchronous-callback ↔ async-loop bridge is `ChannelBackend` +
`ClipboardChannel`: events flow out on an `mpsc`; browser text + recorded remote
format-data requests flow in via shared `Mutex` slots the loop reads after
`process()`.

### Wire protocol (new TLV)

A single bidirectional message type, deliberately high-numbered to avoid
colliding with the graphics/input types (1/2/3) and the render-path types
siblings add in the 4/5 range:

```
CLIPBOARD = 0x20 :  [u8 0x20][u8 subtype][payload]

server→client subtypes:
  1 REMOTE_TEXT_AVAILABLE  payload: (none)         remote copied text → offer paste-into-browser
  2 REMOTE_TEXT_DATA       payload: UTF-8 text      remote's clipboard text (answer to a request)

client→server subtypes:
  1 LOCAL_TEXT             payload: UTF-8 text      browser clipboard text to push to the remote
  2 REQUEST_REMOTE_TEXT    payload: (none)          ask the remote for its clipboard text
```

(The Rust↔Rust internal layer keeps the `[u32 len]` framing; jess-web strips it
so the browser sees one WS binary frame per message, exactly as for the existing
types.)

### Browser side

`RDPCanvas.tsx` uses the async **Clipboard API**, gated on `document.hasFocus()`
(the API requires focus, and we must not read a remote secret into the local
clipboard when the tab is backgrounded):

- **browser → remote:** on `focus` / a canvas `pointerdown` (a user gesture),
  `navigator.clipboard.readText()` and push it as `LOCAL_TEXT` if changed.
- **remote → browser:** on `REMOTE_TEXT_AVAILABLE` (while focused) send
  `REQUEST_REMOTE_TEXT`; on `REMOTE_TEXT_DATA`, `navigator.clipboard.writeText()`.

A `lastClipText` latch breaks the remote→browser→remote echo loop. CSP note: the
Clipboard API is not subject to the connect-src/img-src restrictions that forced
the avatar/storage workarounds elsewhere — it needs only document focus +
(for read) the `clipboard-read` permission, both satisfied by an in-tab gesture.

### Gating + default

Default **OFF**. The connector advertises CLIPRDR only when `session_live` sees
`JESS_RDP_CLIPBOARD` truthy (`1`/`true`/`yes`/`on`); the Go engine forwards that
env var per session (`rdp_live_engine.go` `sessionEnv` allow-list). Unset ⇒
graphics+input-only, byte-for-byte as before this work. The whole module is also
compile-gated behind the existing `ironrdp_live` cargo feature, so the default
broker build surface is unchanged.

### Recording / audit posture

The Go engine's stdout/stdin tees forward **every** TLV verbatim, and the WORM
v2 recorder's `observeFrame`/`observeInput` switch only on the known
DESKTOP_SIZE/FRAME/CLOSE/MOUSE/KEY types — so the new `CLIPBOARD` (0x20) frames
pass through untouched and the existing graphics/input recording + replay is
**not affected** (no recording-format change, no replay-parser change).

Clipboard **content** is intentionally **not** written into the WORM stream in
this milestone: doing so would change the sealed v2 NDJSON format + the SPA
replay parser + the replay canvas, a meaningful scope expansion, and recording
operator-pasted secrets into the audit bundle is itself a data-handling decision.
session_live logs clipboard *activity* (direction + lengths, never content) to
stderr, which the engine already drains under a per-session prefix — a
lightweight audit trail. **Follow-up:** a dedicated `clipboard` v2 event (length
+ direction + optional hash, not raw text) for tamper-evident clipboard auditing.

### Security notes

- Clipboard is a **bidirectional data path** between the operator's browser/host
  and the jump target — i.e. an exfiltration/infiltration surface. It is OFF by
  default for that reason; a future per-target / per-grant policy toggle (reusing
  the `channelGate` seam) should govern it, and "no clipboard" must remain
  expressible for high-sensitivity targets.
- TEXT-only by construction here removes the file-transfer surface entirely (the
  backend advertises no file formats and declines remote file lists), so the
  cliprdr file/lock state machine stays dormant.
- Remote-supplied text is treated as opaque UTF-8; the browser writes it to the
  clipboard but never executes/interprets it.

## Design (NOT implemented) — audio output redirect (rdpsnd → Web Audio)

- **IronRDP:** `ironrdp-rdpsnd 0.8`. Client-side rdpsnd receives the server audio
  format list + PCM/encoded audio frames over its own static virtual channel; a
  backend trait analogous to `CliprdrBackend` surfaces decoded audio buffers.
- **Design:** register an rdpsnd processor on the connector (same
  `with_static_channel` seam); add an `AUDIO=0x21` server→client TLV carrying
  `[format header][PCM/Opus frame]`; browser feeds frames into a Web Audio
  `AudioWorkletNode` / `AudioBufferSourceNode` ring buffer. Output-only first
  (no mic capture — input audio is a separate, larger surface).
- **Effort:** medium. Risks: format negotiation (PCM vs server codec — prefer
  forcing PCM to avoid a browser-side decoder), buffering/latency, and WS
  bandwidth (audio is continuous, unlike clipboard's burstiness). Add the dep
  (`ironrdp-rdpsnd`), an `audio.rs` module mirroring `clipboard.rs`, and a Web
  Audio sink in the SPA. Gate behind `JESS_RDP_AUDIO` (default off).

## Design (NOT implemented) — multi-monitor

- **IronRDP:** the connector's `Config.desktop_size` is a single `DesktopSize`;
  multi-monitor at connect is the GCC **monitor layout** (multiple monitor
  rectangles). `ironrdp-displaycontrol` (already a transitive) handles *dynamic*
  monitor-layout changes mid-session.
- **Design:** the dominant work is **not** IronRDP — it is (a) the streaming
  protocol carrying per-monitor framebuffers / a virtual-desktop bounding box,
  and (b) the browser rendering N canvases (or one canvas with monitor offsets).
  `DESKTOP_SIZE`/`FRAME` would gain a monitor index, or a new
  `MONITOR_LAYOUT=0x22` TLV would describe the rectangles.
- **Effort:** medium-high, mostly front-end + protocol. No hard IronRDP blocker.
  Lower priority than audio for a console operator (a single large canvas already
  covers most jump-host workflows); revisit if operators request true multi-mon.

## Design (NOT implemented) — drive redirect (rdpdr)

- **IronRDP:** `ironrdp-rdpdr 0.6`. rdpdr is the device-redirection channel
  (drives, printers, smart cards, ports); a redirected drive is a full
  client-side **filesystem emulation** answering the server's create/read/write/
  query IRPs.
- **Design:** a virtual drive backed by browser storage (File System Access API /
  OPFS) or a broker-side scratch area, advertised via an rdpdr device-announce; a
  `DRIVE=0x23` TLV family bridges IRP request/response to the browser. This is
  the **heaviest** of the four and the most security-sensitive (arbitrary file
  read/write between the operator host and the target).
- **Effort:** high, multi-week. Must be **strongly gated** (per-target/per-grant
  policy via `channelGate`, read-only vs read-write, scoped to a single scratch
  dir) and is a candidate for WORM content auditing. Recommend deferring until
  there is a concrete operator need and a policy story; clipboard text already
  covers the common "move a command/string across" case without a filesystem.

## Consequences

- The clipboard channel is real and shipping (behind a default-off flag), giving
  operators copy/paste TEXT between browser and jump target — a top-requested
  PAM-console ergonomics feature — with the exfil surface defaulted closed.
- The `with_static_channel` registration + the `ChannelBackend`/`ClipboardChannel`
  bridge + the `MSG_CLIPBOARD` TLV pattern are reusable templates for the
  remaining channels (audio/drive each follow the same shape with a different
  IronRDP SVC processor + TLV subtype).
- The render/input path, WORM recording, and replay are untouched: clipboard is
  additive and orthogonal, as intended for parallel Tier-1/Tier-2 render work.
- Follow-ups (ordered): per-target clipboard policy toggle (channelGate) → WORM
  clipboard-activity event (length/hash) → audio output (rdpsnd) → multi-monitor
  → drive redirect (strongly gated).
```
