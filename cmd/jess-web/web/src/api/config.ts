// SPA runtime config — Phase 5e-9. Fetched once on mount, cached by
// the browser per the server's Cache-Control: private, max-age=300.
// Loading state on the wider UI is intentionally NOT shown (the
// affected surfaces all have safe fallbacks when fields are empty).

export interface WebConfig {
  recording_console_url?: string
  app_env?: string
}

const DEFAULT_CONFIG: WebConfig = {}

export async function fetchWebConfig(signal?: AbortSignal): Promise<WebConfig> {
  try {
    const r = await fetch('/api/config', {
      credentials: 'same-origin',
      cache: 'force-cache',
      signal,
    })
    if (!r.ok) return DEFAULT_CONFIG
    return (await r.json()) as WebConfig
  } catch {
    return DEFAULT_CONFIG
  }
}

// recordingConsoleLink builds the MinIO Console deep-link URL for a
// given recording bundle path. MinIO Console's object browser path is
// `<base>/<encodeURIComponent(key)>` — encoding handles special chars
// (slashes inside the key) without breaking the URL structure.
//
// Returns null when no console base is configured (SPA renders the
// chip as copy-only).
export function recordingConsoleLink(cfg: WebConfig | null, recordingPath: string): string | null {
  if (!cfg?.recording_console_url || !recordingPath) return null
  return `${cfg.recording_console_url}/${encodeURIComponent(recordingPath)}`
}
