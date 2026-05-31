'use client'

import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * ThreatOrbit mark: a luminous plasma core with nodes orbiting on two
 * tilted elliptical rings. Pure SVG, animated with Framer Motion so it
 * stays crisp at any size and ties into the hero particle field.
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
        <radialGradient id="to-core" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#FFC76B" />
          <stop offset="45%" stopColor="#FF2E97" />
          <stop offset="100%" stopColor="#7A3CFF" />
        </radialGradient>
        <linearGradient id="to-ring" x1="0" y1="0" x2="48" y2="48">
          <stop offset="0%" stopColor="#FF2E97" />
          <stop offset="100%" stopColor="#7A3CFF" />
        </linearGradient>
      </defs>

      {/* Ring 1 */}
      <motion.g
        style={{ transformOrigin: '24px 24px' }}
        animate={animate ? { rotate: 360 } : undefined}
        transition={{ duration: 14, repeat: Infinity, ease: 'linear' }}
      >
        <ellipse
          cx="24"
          cy="24"
          rx="20"
          ry="8"
          stroke="url(#to-ring)"
          strokeWidth="1.5"
          opacity="0.6"
        />
        <circle cx="44" cy="24" r="2.4" fill="#FF2E97" />
      </motion.g>

      {/* Ring 2 (tilted opposite) */}
      <motion.g
        style={{ transformOrigin: '24px 24px' }}
        animate={animate ? { rotate: -360 } : undefined}
        transition={{ duration: 18, repeat: Infinity, ease: 'linear' }}
        transform="rotate(60 24 24)"
      >
        <ellipse
          cx="24"
          cy="24"
          rx="20"
          ry="8"
          stroke="url(#to-ring)"
          strokeWidth="1.5"
          opacity="0.4"
        />
        <circle cx="4" cy="24" r="2" fill="#2DD4BF" />
      </motion.g>

      {/* Core */}
      <motion.circle
        cx="24"
        cy="24"
        r="6.5"
        fill="url(#to-core)"
        animate={animate ? { opacity: [0.85, 1, 0.85], scale: [1, 1.08, 1] } : undefined}
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
        style={{ transformOrigin: '24px 24px' }}
      />
      <circle cx="24" cy="24" r="6.5" fill="url(#to-core)" opacity="0.35" filter="blur(3px)" />
    </svg>
  )
}
