'use client'

import { useId } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * ThreatOrbit mark - "Convergence".
 *
 * The product's thesis is that the disciplines a SOC normally runs apart - CTI
 * (magenta), SIEM (violet) and SOAR (amber) - converge into one watchful core.
 * The mark draws exactly that: three orbital streams sweep inward as tracked
 * signals (each fades from its tail to a bright leading node, so it reads as
 * motion) and orbit a luminous core whose aperture/iris stands for continuous
 * vigilance. Pure animated SVG, crisp from 16px up.
 */
export default function Logo({
  size = 28,
  className,
  animate = true,
}: {
  size?: number
  className?: string
  animate?: boolean
}) {
  // Unique ids so several logos on a page (navbar, footer, login) don't share
  // gradient definitions.
  const uid = useId().replace(/:/g, '')
  const bloom = `bloom-${uid}`
  const core = `core-${uid}`
  const streamId = (k: string) => `stream-${uid}-${k}`

  // Each stream is the same arc rotated into place; its gradient fades from a
  // faint tail to the bright leading node (the tracked signal).
  const streams = [
    { rotate: 0,   color: '#FF2E97', key: 'cti'  }, // CTI
    { rotate: 120, color: '#7A3CFF', key: 'siem' }, // SIEM
    { rotate: 240, color: '#FFB23E', key: 'soar' }, // SOAR
  ]

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      className={cn('shrink-0', className)}
      aria-label="ThreatOrbit logo"
    >
      <defs>
        <radialGradient id={bloom} cx="50%" cy="50%" r="50%">
          <stop offset="0%"   stopColor="#FF2E97" stopOpacity="0.38" />
          <stop offset="55%"  stopColor="#7A3CFF" stopOpacity="0.10" />
          <stop offset="100%" stopColor="#7A3CFF" stopOpacity="0" />
        </radialGradient>
        {/* Watchful core: warm highlight -> plasma -> deep-violet edge */}
        <radialGradient id={core} cx="38%" cy="34%" r="74%">
          <stop offset="0%"   stopColor="#FFE9C2" />
          <stop offset="22%"  stopColor="#FF9ECB" />
          <stop offset="55%"  stopColor="#FF2E97" />
          <stop offset="100%" stopColor="#591A84" />
        </radialGradient>
        {/* Per-stream tail->head fade (tail faint at the top, bright node at
            the bottom of the un-rotated arc). */}
        {streams.map((s) => (
          <linearGradient key={s.key} id={streamId(s.key)}
            x1="29.81" y1="9.63" x2="29.81" y2="38.37" gradientUnits="userSpaceOnUse">
            <stop offset="0%"   stopColor={s.color} stopOpacity="0.08" />
            <stop offset="100%" stopColor={s.color} stopOpacity="1" />
          </linearGradient>
        ))}
      </defs>

      {/* outer bloom */}
      <circle cx="24" cy="24" r="15.5" fill={`url(#${bloom})`} />

      {/* three converging streams, orbiting the core as one system */}
      <motion.g
        style={{ transformOrigin: '24px 24px' }}
        initial={false}
        animate={animate ? { rotate: 360 } : undefined}
        transition={{ duration: 26, repeat: Infinity, ease: 'linear' }}
      >
        {streams.map((s) => (
          <g key={s.key} transform={`rotate(${s.rotate} 24 24)`}>
            <path d="M 29.81 9.63 A 15.5 15.5 0 0 1 29.81 38.37" fill="none"
              stroke={`url(#${streamId(s.key)})`} strokeWidth="2.8" strokeLinecap="round" />
            {/* tracked-signal node: soft halo + body + specular */}
            <circle cx="29.81" cy="38.37" r="4.2" fill={s.color} opacity="0.28" />
            <circle cx="29.81" cy="38.37" r="2.5" fill={s.color} />
            <circle cx="29.0"  cy="37.4"  r="0.9" fill="#FFFFFF" opacity="0.7" />
          </g>
        ))}
      </motion.g>

      {/* watchful core with a gentle breathe */}
      <motion.g
        style={{ transformOrigin: '24px 24px' }}
        animate={animate ? { scale: [1, 1.04, 1] } : undefined}
        transition={{ duration: 3.6, repeat: Infinity, ease: 'easeInOut' }}
      >
        <circle cx="24" cy="24" r="6.9" fill={`url(#${core})`} />
        <circle cx="24" cy="24" r="6.9" fill="none" stroke="#FFFFFF" strokeOpacity="0.16" strokeWidth="0.5" />
        {/* aperture / iris - the "watch" */}
        <circle cx="24" cy="24" r="2.9" fill="none" stroke="#FFFFFF" strokeOpacity="0.5" strokeWidth="1" />
        {/* specular highlight, upper-left */}
        <ellipse cx="21.5" cy="21.2" rx="2.3" ry="1.5" fill="#FFFFFF" fillOpacity="0.55" transform="rotate(-35 21.5 21.2)" />
      </motion.g>
    </svg>
  )
}
