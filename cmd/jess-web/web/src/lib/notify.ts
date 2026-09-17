// Browser Notifications helper — only fires when the operator opts in.
//
// Policy:
//   - NEVER request permission on page load (irritating + bad-PR pattern)
//   - Only request after an intent gesture (the operator submitted a
//     request, so they want to know when it's decided)
//   - Notification feature gracefully degrades when the API is missing
//     (older browsers, secure-context requirement violation, etc.)
//
// All functions are no-ops in environments without the Notification API
// — callers can wire them unconditionally.

const STORAGE_KEY = 'jess.notify.asked'

function isSupported(): boolean {
  return typeof window !== 'undefined' && 'Notification' in window
}

// requestPermissionOnce asks for permission at most once per device
// (cached in localStorage). Returns the current permission state.
// Safe to call multiple times; the second call short-circuits without
// re-prompting if the user previously dismissed or granted.
export async function requestPermissionOnce(): Promise<NotificationPermission> {
  if (!isSupported()) return 'denied'
  if (Notification.permission === 'granted') return 'granted'
  if (Notification.permission === 'denied') return 'denied'
  // 'default' — never asked. Check our own cache so we don't bug the
  // user once they've dismissed without making a decision.
  try {
    if (localStorage.getItem(STORAGE_KEY)) {
      return Notification.permission
    }
    localStorage.setItem(STORAGE_KEY, '1')
  } catch {
    // intentional — localStorage unavailable; fall through to prompt
  }
  try {
    return await Notification.requestPermission()
  } catch {
    return 'denied'
  }
}

// notify fires a notification if permission was previously granted.
// Silent no-op otherwise. The Notification constructor itself throws
// in some configurations (Service Worker required, etc.); we catch +
// swallow so the UI flow never breaks.
export function notify(title: string, opts?: NotificationOptions): void {
  if (!isSupported() || Notification.permission !== 'granted') return
  try {
    // Tag deduplicates: a re-fired notification with the same tag
    // replaces the previous one rather than stacking. Useful for
    // request-state polling that might fire 'pending → approved'
    // and 'approved' on the same request id.
    new Notification(title, { icon: '/favicon.svg', ...opts })
  } catch {
    // intentional — best effort
  }
}
