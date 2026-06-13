'use client'

import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * ThreatOrbit mark - a detection reticle.
 *
 * A SOC's core working is to acquire a threat and contain it: the four corner
 * brackets are a target-lock / detection frame, and the single accent core is
 * the threat held inside it. Deliberately flat, bold and near-monochrome so it
 * stays clean at every size (favicon to hero) and works in one colour - the
 * brackets gently "re-acquire" the lock and the core pulses like a live blip.
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
  const BRACKETS = [
    'M10 17 V11 H17',  // top-left
    'M38 17 V11 H31',  // top-right
    'M10 31 V37 H17',  // bottom-left
    'M38 31 V37 H31',  // bottom-right
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
      {/* target-lock frame */}
      <motion.g
        style={{ transformOrigin: '24px 24px' }}
        animate={animate ? { scale: [1, 0.94, 1] } : undefined}
        transition={{ duration: 4.2, repeat: Infinity, ease: 'easeInOut' }}
      >
        {BRACKETS.map((d) => (
          <path key={d} d={d} fill="none" stroke="#EDE9F2" strokeWidth="2.7"
            strokeLinecap="round" strokeLinejoin="round" />
        ))}
      </motion.g>

      {/* the contained threat - a live blip */}
      <motion.circle
        cx="24" cy="24" r="4.7" fill="#FF2E97"
        style={{ transformOrigin: '24px 24px' }}
        animate={animate ? { scale: [1, 1.14, 1], opacity: [1, 0.82, 1] } : undefined}
        transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
      />
    </svg>
  )
}
