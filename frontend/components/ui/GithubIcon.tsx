import * as React from 'react'

/**
 * GitHub mark. lucide-react dropped its brand/logo icons in v1, so we ship the
 * glyph ourselves. The API mirrors a lucide icon (className / size / ...SVG
 * props) so it's a drop-in replacement at the call sites.
 */
export default function GithubIcon({
  className,
  size = 24,
  ...props
}: React.SVGProps<SVGSVGElement> & { size?: number | string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
      {...props}
    >
      <path d="M12 .5C5.37.5 0 5.78 0 12.292c0 5.211 3.438 9.63 8.205 11.188.6.111.82-.254.82-.567 0-.28-.01-1.022-.015-2.005-3.338.711-4.042-1.582-4.042-1.582-.546-1.361-1.333-1.724-1.333-1.724-1.09-.731.083-.716.083-.716 1.205.082 1.84 1.215 1.84 1.215 1.07 1.803 2.807 1.282 3.492.98.108-.763.418-1.282.762-1.577-2.665-.295-5.466-1.309-5.466-5.827 0-1.287.465-2.339 1.235-3.164-.135-.297-.54-1.497.105-3.121 0 0 1.005-.31 3.3 1.209a11.6 11.6 0 0 1 3.003-.397c1.02.005 2.047.131 3.003.397 2.28-1.519 3.285-1.209 3.285-1.209.645 1.624.24 2.824.12 3.121.765.825 1.23 1.877 1.23 3.164 0 4.53-2.805 5.527-5.475 5.817.42.354.81 1.077.81 2.182 0 1.578-.015 2.846-.015 3.229 0 .309.21.678.825.561C20.565 21.917 24 17.495 24 12.292 24 5.78 18.627.5 12 .5Z" />
    </svg>
  )
}
