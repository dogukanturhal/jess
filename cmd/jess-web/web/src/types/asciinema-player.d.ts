// Minimal type shim for asciinema-player 3.x — the npm package ships
// no .d.ts. We only call create(), which returns an opaque player
// handle; types stay narrow on purpose so future SDK churn surfaces
// here rather than silently typing through.
declare module 'asciinema-player' {
  export interface PlayerOptions {
    cols?: number
    rows?: number
    autoPlay?: boolean
    preload?: boolean
    loop?: boolean | number
    startAt?: number | string
    speed?: number
    idleTimeLimit?: number
    theme?: string
    poster?: string
    fit?: 'width' | 'height' | 'both' | 'none' | false
    fontSize?: string
    terminalFontSize?: string
    terminalFontFamily?: string
    terminalLineHeight?: number
    controls?: boolean | 'auto'
    markers?: Array<[number, string]>
    pauseOnMarkers?: boolean
    logger?: Console
  }

  export interface Player {
    play(): Promise<void>
    pause(): Promise<void>
    seek(where: number | string): Promise<void>
    getCurrentTime(): number
    getDuration(): number | null
    dispose(): void
  }

  export function create(
    src: string | { data: string | ArrayBuffer | Blob | (() => unknown); type?: string },
    element: HTMLElement,
    opts?: PlayerOptions,
  ): Player
}

declare module 'asciinema-player/dist/bundle/asciinema-player.css'
