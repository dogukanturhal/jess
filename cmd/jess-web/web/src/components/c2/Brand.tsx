// Brand marks for the C2 console.
//
// JessWordmark — the official JESS lettermark (the real brand asset shipped in
// src/assets/jess-wordmark.svg). Drawn in `currentColor` so it themes off the
// surrounding text color (white on the g100 masthead/sign-in, dark on g10).
// `height` drives the size; the width follows the wordmark's ~5.11:1 aspect.
//
// HexMark is the older square hex placeholder — kept exported for back-compat
// (the favicon + any callers that want a square mark) but no longer used for
// primary branding.

const WORDMARK_VIEWBOX = '0 0 4431.85 867.03'
const WORDMARK_RATIO = 4431.85 / 867.03 // ~5.113

export function JessWordmark({
  height = 18,
  className,
  title = 'JESS',
}: {
  height?: number
  className?: string
  title?: string
}) {
  return (
    <svg
      className={className}
      height={height}
      width={Math.round(height * WORDMARK_RATIO)}
      viewBox={WORDMARK_VIEWBOX}
      fill="currentColor"
      role="img"
      aria-label={title}
    >
      <title>{title}</title>
      <path d="M865.73,0v473.04c0,263.09-180.15,393.99-540.43,393.99H0l174.96-225.5h150.34c199.58,0,272.16-40.18,272.16-147.74V0h268.27Z" />
      <path d="M1284.33,336.96h685.59l-155.52,191.81h-530.07v112.75h737.43l-171.07,225.5h-834.63V0h1004.4l-173.67,225.5h-562.47v111.46Z" />
      <path d="M2063.21,867.03l172.37-225.5h663.56c54.43,0,79.06-16.85,79.06-55.73s-25.92-57.02-81.65-57.02h-469.15c-211.25,0-333.07-95.9-333.07-260.5,0-178.85,120.53-268.27,365.47-268.27h758.16l-172.37,225.5h-606.53c-55.73,0-81.65,18.14-81.65,55.73s25.92,57.02,81.65,57.02h473.04c215.14,0,329.19,86.83,329.19,251.43,0,190.51-108.86,277.34-349.92,277.34h-828.15Z" />
      <path d="M3252.93,867.03l172.37-225.5h663.55c54.43,0,79.06-16.85,79.06-55.73s-25.92-57.02-81.65-57.02h-469.15c-211.25,0-333.07-95.9-333.07-260.5,0-178.85,120.53-268.27,365.47-268.27h758.16l-172.37,225.5h-606.53c-110.84-8.05-109.54,120.91,0,112.75,222.42,20.21,829.07-100.93,802.21,251.43.02,190.51-108.85,277.34-349.9,277.34h-828.15Z" />
    </svg>
  )
}

// Hex logo mark — currentColor so it themes via the surrounding text color.
export function HexMark({ size = 22, className }: { size?: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 2.2 20.5 7v10L12 21.8 3.5 17V7L12 2.2Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M12 7.2 16.3 9.6v4.8L12 16.8 7.7 14.4V9.6L12 7.2Z"
        fill="currentColor"
        fillOpacity="0.22"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
    </svg>
  )
}
