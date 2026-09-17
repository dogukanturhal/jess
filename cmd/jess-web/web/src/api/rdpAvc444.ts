// rdpAvc444 — AVC444 true 4:4:4 chroma recombine (ADR 0059). EXPERIMENTAL.
//
// Builds on the Tier-2 H.264 path (rdpH264.ts / ADR 0053). When the broker
// negotiates MS-RDPEGFX **AVC444** (JESS_RDP_AVC444), a 4:4:4 update arrives as
// TWO MSG_H264 access units: the MAIN view (H264_FLAG_AVC444) — a normal AVC420
// luma + 4:2:0-chroma image — immediately followed by the AUXILIARY view
// (H264_FLAG_AUX), whose luma/chroma planes carry the *missing* chroma samples.
// This module decodes both on their own WebCodecs VideoDecoder, reads back the
// I420 planes, and recombines them into a full-resolution YUV444 image in a
// WebGL2 fragment shader (the exact [MS-RDPEGFX] §3.3.8.3.2 / FreeRDP
// `general_LumaToYUV444` + `general_ChromaV1ToYUV444` plane mapping), then draws
// the 4:4:4 result to an offscreen canvas the caller blits.
//
// BEST-EFFORT + NEVER-REGRESS. Two hard requirements gate the 4:4:4 path:
//   1. WebGL2 is available, AND
//   2. VideoFrame.copyTo({format:'I420'}) actually yields planar YUV.
// (2) is UNRELIABLE for hardware-decoded H.264 — many HW decoders return an
// opaque frame with no readback path (w3c/webcodecs#157/#390). On ANY failure
// this module flips to `mainOnly` mode and just hands the caller the MAIN
// VideoFrame — i.e. the exact AVC420 4:2:0 behaviour we'd have without it.
//
// UNVERIFIED: there is no AVC444-capable Windows host in CI, so the recombine
// (plane layout, the YUV444 index mapping, the YUV→RGB matrix/range) is
// spec-faithful but has NOT been pixel-confirmed. Default-off (JESS_RDP_AVC444
// server-side); a browser only reaches this code when the broker emits aux
// frames. See ADR 0059.

// --- WebCodecs ambient surface (extends rdpH264.ts's minimal slice) -------

type CodecState = 'unconfigured' | 'configured' | 'closed'

interface PlaneLayoutLike {
  readonly offset: number
  readonly stride: number
}

// The richer VideoFrame slice this module needs: coded dims + planar readback.
interface VideoFrameYUV {
  readonly codedWidth: number
  readonly codedHeight: number
  readonly format: string | null
  allocationSize(options?: { format?: string }): number
  copyTo(dest: ArrayBufferView, options?: { format?: string }): Promise<PlaneLayoutLike[]>
  close(): void
}

interface EncodedVideoChunkInitLike {
  type: 'key' | 'delta'
  timestamp: number
  data: BufferSource
}
interface EncodedVideoChunkCtor {
  new (init: EncodedVideoChunkInitLike): unknown
}
interface VideoDecoderConfigLike {
  codec: string
  codedWidth?: number
  codedHeight?: number
  optimizeForLatency?: boolean
}
interface VideoDecoderInitLike {
  output: (frame: VideoFrameYUV) => void
  error: (e: DOMException) => void
}
interface VideoDecoderLike {
  readonly state: CodecState
  configure(config: VideoDecoderConfigLike): void
  decode(chunk: unknown): void
  close(): void
}
interface VideoDecoderCtor {
  new (init: VideoDecoderInitLike): VideoDecoderLike
}

// Reach the WebCodecs constructors WITHOUT augmenting the global Window — both
// because rdpH264.ts already augments it (a second, structurally-different
// augmentation conflicts) and because the platform's own lib.dom WebCodecs types
// would clash with our richer VideoFrameYUV surface. A local cast keeps this
// module's view of the API self-contained.
function webcodecs(): { VideoDecoder?: VideoDecoderCtor; EncodedVideoChunk?: EncodedVideoChunkCtor } {
  return (typeof window !== 'undefined' ? (window as unknown) : {}) as {
    VideoDecoder?: VideoDecoderCtor
    EncodedVideoChunk?: EncodedVideoChunkCtor
  }
}

export interface Avc444Region {
  x: number
  y: number
  w: number
  h: number
}

export interface RDPAvc444Options {
  // Draw a recombined 4:4:4 frame. `img` is valid ONLY during this synchronous
  // call (a reused offscreen canvas, or — in mainOnly fallback — the MAIN
  // VideoFrame); the caller MUST draw it before returning and MUST NOT retain
  // it. This module owns all VideoFrame lifecycle.
  onFrame: (img: CanvasImageSource, region: Avc444Region) => void
  onError: (msg: string) => void
  codec?: string
}

// hasAvc444Support — the capability gate for the recombine path: WebCodecs +
// WebGL2. (copyTo-I420 feasibility can only be discovered at runtime; failure
// there flips to mainOnly, so it isn't part of this static check.)
export function hasAvc444Support(): boolean {
  if (typeof window === 'undefined') return false
  const wc = webcodecs()
  if (!wc.VideoDecoder || !wc.EncodedVideoChunk) {
    return false
  }
  try {
    const c = document.createElement('canvas')
    return !!c.getContext('webgl2')
  } catch {
    return false
  }
}

// A decoded plane set read back from a VideoFrame via copyTo({format:'I420'}).
interface I420 {
  width: number // coded luma width
  height: number // coded luma height
  y: Uint8Array
  yStride: number
  u: Uint8Array
  uStride: number
  v: Uint8Array
  vStride: number
}

// readI420 reads a VideoFrame's planes as I420. Returns null when the frame
// can't be read back as planar YUV (opaque HW frame) — the caller falls back.
async function readI420(frame: VideoFrameYUV): Promise<I420 | null> {
  try {
    const size = frame.allocationSize({ format: 'I420' })
    const buf = new Uint8Array(size)
    const layout = await frame.copyTo(buf, { format: 'I420' })
    if (!layout || layout.length < 3) return null
    const w = frame.codedWidth
    const h = frame.codedHeight
    const ch = (h + 1) >> 1 // chroma plane height (I420)
    const [ly, lu, lv] = layout
    return {
      width: w,
      height: h,
      y: buf.subarray(ly.offset, ly.offset + ly.stride * h),
      yStride: ly.stride,
      u: buf.subarray(lu.offset, lu.offset + lu.stride * ch),
      uStride: lu.stride,
      v: buf.subarray(lv.offset, lv.offset + lv.stride * ch),
      vStride: lv.stride,
    }
  } catch {
    return null
  }
}

// --- GLSL (ES 3.00) -------------------------------------------------------

const VERT = `#version 300 es
in vec2 a_pos;
void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }
`

// Reconstruct YUV444 per output pixel from the 6 planes, then BT.601 full-range
// YUV→RGB. Plane mapping (FreeRDP general_LumaToYUV444 + general_ChromaV1ToYUV444):
//   Y                 = mainY[y][x]
//   y even, x even    = main U/V[y/2][x/2]            (the 4:2:0 chroma)
//   y even, x odd     = aux  U/V[y/2][(x-1)/2]        (B6/B7)
//   y odd  (k=(y-1)/2)= aux Y de-interleaved 16-line blocks (B4/B5):
//                        U row = (k>>3)*16 + (k&7), V row = (k>>3)*16 + 8 + (k&7)
const FRAG = `#version 300 es
precision highp float;
precision highp int;
uniform highp sampler2D mY, mU, mV, aY, aU, aV;
uniform int uW, uH;       // output (coded) luma dims
out vec4 o;
float fetch(highp sampler2D s, int x, int y) { return texelFetch(s, ivec2(x, y), 0).r; }
void main() {
  int x = int(gl_FragCoord.x);
  int y = int(gl_FragCoord.y);
  if (x >= uW || y >= uH) { o = vec4(0.0); return; }
  float Y = fetch(mY, x, y);
  float U, V;
  if ((y & 1) == 0) {
    if ((x & 1) == 0) { U = fetch(mU, x >> 1, y >> 1); V = fetch(mV, x >> 1, y >> 1); }
    else              { U = fetch(aU, (x - 1) >> 1, y >> 1); V = fetch(aV, (x - 1) >> 1, y >> 1); }
  } else {
    int k = (y - 1) >> 1;
    int blk = (k >> 3) * 16;
    int off = k & 7;
    U = fetch(aY, x, blk + off);
    V = fetch(aY, x, blk + 8 + off);
  }
  // BT.601 full-range (JPEG) YUV→RGB; U/V are unsigned [0,1] centred at 0.5.
  float u = U - 0.5;
  float v = V - 0.5;
  float r = Y + 1.402 * v;
  float g = Y - 0.344136 * u - 0.714136 * v;
  float b = Y + 1.772 * u;
  o = vec4(clamp(vec3(r, g, b), 0.0, 1.0), 1.0);
}
`

// --- the recombine GL context --------------------------------------------

class GLRecombine {
  private gl: WebGL2RenderingContext
  private prog: WebGLProgram
  private texs: WebGLTexture[] = []
  private locs: WebGLUniformLocation[] = []
  private uW: WebGLUniformLocation | null
  private uH: WebGLUniformLocation | null
  readonly canvas: HTMLCanvasElement

  constructor() {
    this.canvas = document.createElement('canvas')
    // preserveDrawingBuffer: the caller reads this canvas back via drawImage()
    // (after an async copyTo), so the drawn pixels must survive past the render
    // call rather than being cleared at the next compositing boundary.
    const gl = this.canvas.getContext('webgl2', {
      premultipliedAlpha: false,
      alpha: false,
      preserveDrawingBuffer: true,
    })
    if (!gl) throw new Error('WebGL2 unavailable')
    this.gl = gl
    this.prog = this.link(VERT, FRAG)
    gl.useProgram(this.prog)
    // Full-screen quad (two triangles) in clip space.
    const buf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, buf)
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW)
    const aPos = gl.getAttribLocation(this.prog, 'a_pos')
    gl.enableVertexAttribArray(aPos)
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0)
    const names = ['mY', 'mU', 'mV', 'aY', 'aU', 'aV']
    for (let i = 0; i < 6; i++) {
      const t = gl.createTexture()
      if (!t) throw new Error('texture alloc failed')
      this.texs.push(t)
      const loc = gl.getUniformLocation(this.prog, names[i])
      this.locs.push(loc as WebGLUniformLocation)
    }
    this.uW = gl.getUniformLocation(this.prog, 'uW')
    this.uH = gl.getUniformLocation(this.prog, 'uH')
  }

  private link(vs: string, fs: string): WebGLProgram {
    const gl = this.gl
    const compile = (type: number, src: string): WebGLShader => {
      const s = gl.createShader(type)
      if (!s) throw new Error('shader alloc failed')
      gl.shaderSource(s, src)
      gl.compileShader(s)
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        throw new Error('shader compile: ' + (gl.getShaderInfoLog(s) ?? ''))
      }
      return s
    }
    const p = gl.createProgram()
    if (!p) throw new Error('program alloc failed')
    gl.attachShader(p, compile(gl.VERTEX_SHADER, vs))
    gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fs))
    gl.linkProgram(p)
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
      throw new Error('program link: ' + (gl.getProgramInfoLog(p) ?? ''))
    }
    return p
  }

  // upload an R8 single-channel plane (honouring stride via UNPACK_ROW_LENGTH).
  private plane(unit: number, data: Uint8Array, width: number, height: number, stride: number): void {
    const gl = this.gl
    gl.activeTexture(gl.TEXTURE0 + unit)
    gl.bindTexture(gl.TEXTURE_2D, this.texs[unit])
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1)
    gl.pixelStorei(gl.UNPACK_ROW_LENGTH, stride)
    // R8 unorm; sampled as normalized float [0,1] in the shader's .r.
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, width, height, 0, gl.RED, gl.UNSIGNED_BYTE, data)
    gl.pixelStorei(gl.UNPACK_ROW_LENGTH, 0)
    gl.uniform1i(this.locs[unit], unit)
  }

  // render the recombined 4:4:4 frame (output = main coded dims) into the canvas.
  render(main: I420, aux: I420): void {
    const gl = this.gl
    const w = main.width
    const h = main.height
    const cw = (w + 1) >> 1
    const ch = (h + 1) >> 1
    const acw = (aux.width + 1) >> 1
    const ach = (aux.height + 1) >> 1
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w
      this.canvas.height = h
    }
    gl.viewport(0, 0, w, h)
    gl.useProgram(this.prog)
    this.plane(0, main.y, w, h, main.yStride)
    this.plane(1, main.u, cw, ch, main.uStride)
    this.plane(2, main.v, cw, ch, main.vStride)
    this.plane(3, aux.y, aux.width, aux.height, aux.yStride)
    this.plane(4, aux.u, acw, ach, aux.uStride)
    this.plane(5, aux.v, acw, ach, aux.vStride)
    gl.uniform1i(this.uW, w)
    gl.uniform1i(this.uH, h)
    gl.drawArrays(gl.TRIANGLES, 0, 6)
  }

  dispose(): void {
    const gl = this.gl
    for (const t of this.texs) gl.deleteTexture(t)
    gl.deleteProgram(this.prog)
  }
}

// --- inner single-stream decoder (main or aux) ----------------------------

class View {
  private dec: VideoDecoderLike | null = null
  private configured = false
  private sawKey = false
  private ts = 0
  // FIFO of decoded frames awaiting their pair partner.
  readonly queue: VideoFrameYUV[] = []

  constructor(
    private readonly codec: string,
    private readonly onOut: () => void,
    private readonly onErr: (m: string) => void,
  ) {}

  submit(nal: Uint8Array, keyframe: boolean, w: number, h: number): void {
    if (nal.length === 0) return
    if (!this.sawKey && !keyframe) return
    if (!this.configured) {
      if (!keyframe) return
      if (!this.configure(w, h)) return
    }
    if (keyframe) this.sawKey = true
    const dec = this.dec
    const ChunkCtor = webcodecs().EncodedVideoChunk
    if (!dec || !ChunkCtor || dec.state !== 'configured') return
    try {
      const chunk = new ChunkCtor({ type: keyframe ? 'key' : 'delta', timestamp: this.ts, data: nal.slice() })
      this.ts += 16_666
      dec.decode(chunk)
    } catch (e) {
      this.onErr(`AVC444 decode failed: ${String(e)}`)
    }
  }

  private configure(w: number, h: number): boolean {
    const Ctor = webcodecs().VideoDecoder
    if (!Ctor) {
      this.onErr('VideoDecoder missing')
      return false
    }
    try {
      this.dec = new Ctor({
        output: (frame: VideoFrameYUV) => {
          this.queue.push(frame)
          this.onOut()
        },
        error: (e: DOMException) => this.onErr(`VideoDecoder error: ${e.message ?? String(e)}`),
      })
      this.dec.configure({
        codec: this.codec,
        codedWidth: w || undefined,
        codedHeight: h || undefined,
        optimizeForLatency: true,
      })
      this.configured = true
      return true
    } catch (e) {
      this.onErr(`configure failed: ${String(e)}`)
      return false
    }
  }

  close(): void {
    for (const f of this.queue) f.close()
    this.queue.length = 0
    const dec = this.dec
    this.dec = null
    if (dec && dec.state !== 'closed') {
      try {
        dec.close()
      } catch {
        // already gone
      }
    }
  }
}

// --- the AVC444 decoder ---------------------------------------------------

export class RDPAvc444Decoder {
  private main: View
  private aux: View
  private gl: GLRecombine | null = null
  private mainOnly = false // flipped true on first readback/GL failure
  private closed = false
  private region: Avc444Region = { x: 0, y: 0, w: 0, h: 0 }
  private draining = false

  constructor(private readonly opts: RDPAvc444Options) {
    const codec = opts.codec ?? 'avc1.42E01F'
    const onErr = (m: string) => this.fail(m)
    this.main = new View(codec, () => this.drain(), onErr)
    this.aux = new View(codec, () => this.drain(), onErr)
  }

  submitMain(nal: Uint8Array, keyframe: boolean, region: Avc444Region): void {
    if (this.closed) return
    this.region = region
    this.main.submit(nal, keyframe, region.w, region.h)
  }

  submitAux(nal: Uint8Array, keyframe: boolean): void {
    if (this.closed || this.mainOnly) return // mainOnly ignores the aux stream
    this.aux.submit(nal, keyframe, this.region.w, this.region.h)
  }

  // drain pairs the head of each queue and recombines; mainOnly draws main only.
  private drain(): void {
    if (this.closed || this.draining) return
    this.draining = true
    void this.drainLoop().finally(() => {
      this.draining = false
    })
  }

  private async drainLoop(): Promise<void> {
    if (this.mainOnly) {
      // No recombine — hand each main frame straight to the caller (4:2:0).
      while (!this.closed && this.main.queue.length > 0) {
        const f = this.main.queue.shift() as VideoFrameYUV
        try {
          this.opts.onFrame(f as unknown as CanvasImageSource, this.region)
        } catch {
          // a single paint failure shouldn't kill the session
        } finally {
          f.close()
        }
      }
      // drop any aux frames that slipped in before the flip
      for (const a of this.aux.queue) a.close()
      this.aux.queue.length = 0
      return
    }
    while (!this.closed && this.main.queue.length > 0 && this.aux.queue.length > 0) {
      const m = this.main.queue.shift() as VideoFrameYUV
      const a = this.aux.queue.shift() as VideoFrameYUV
      try {
        const mi = await readI420(m)
        const ai = await readI420(a)
        if (this.closed) return
        if (!mi || !ai) {
          // copyTo unsupported (HW opaque frame) — permanently fall back. Draw
          // THIS main frame directly and route everything to mainOnly hereafter.
          this.flipMainOnly()
          try {
            this.opts.onFrame(m as unknown as CanvasImageSource, this.region)
          } catch {
            /* ignore */
          }
          return
        }
        if (!this.gl) this.gl = new GLRecombine()
        this.gl.render(mi, ai)
        this.opts.onFrame(this.gl.canvas, this.region)
      } catch (e) {
        // GL/readback blew up — fall back rather than kill the session.
        this.flipMainOnly()
        try {
          this.opts.onFrame(m as unknown as CanvasImageSource, this.region)
        } catch {
          /* ignore */
        }
        console.warn('AVC444 recombine failed, falling back to 4:2:0 main view:', String(e))
        return
      } finally {
        m.close()
        a.close()
      }
    }
  }

  private flipMainOnly(): void {
    this.mainOnly = true
    if (this.gl) {
      this.gl.dispose()
      this.gl = null
    }
    this.aux.close()
  }

  private fail(msg: string): void {
    if (this.closed) return
    this.opts.onError(msg)
    this.close()
  }

  close(): void {
    this.closed = true
    this.main.close()
    this.aux.close()
    if (this.gl) {
      this.gl.dispose()
      this.gl = null
    }
  }
}
