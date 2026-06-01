'use client'

import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * ThreatOrbit mark: a shielded hexagon core (the unified Super SOC) wrapped
 * by three orbital rings that stand for the three disciplines converging into
 * it: CTI (magenta), SIEM (violet), and SOAR (amber). Nodes on the rings are
 * threats under continuous watch. Pure animated SVG, crisp at any size.
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
  const rings = [
    { rotate: 0, color: '#FF2E97', dur: 13, node: { cx: 44, cy: 24 } }, // CTI
    { rotate: 60, color: '#7A3CFF', dur: 17, node: { cx: 4, cy: 24 } }, // SIEM
    { rotate: 120, color: '#FFB23E', dur: 21, node: { cx: 24, cy: 44 } }, // SOAR
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
        <radialGradient id="to-core" cx="50%" cy="40%" r="65%">
          <stop offset="0%" stopColor="#FFC76B" />
          <stop offset="45%" stopColor="#FF2E97" />
          <stop offset="100%" stopColor="#7A3CFF" />
        </radialGradient>
      </defs>

      {rings.map((ring, i) => (
        <motion.g
          key={i}
          style={{ transformOrigin: '24px 24px' }}
          initial={false}
          animate={animate ? { rotate: i % 2 === 0 ? 360 : -360 } : undefined}
          transition={{ duration: ring.dur, repeat: Infinity, ease: 'linear' }}
        >
          <g transform={`rotate(${ring.rotate} 24 24)`}>
            <ellipse
              cx="24"
              cy="24"
              rx="20"
              ry="7.5"
              stroke={ring.color}
              strokeWidth="1.5"
              opacity="0.5"
            />
            <circle cx={ring.node.cx} cy={ring.node.cy} r="2.2" fill={ring.color} />
          </g>
        </motion.g>
      ))}

      {/* Shielded hexagon core */}
      <motion.path
        d="M24 16.5 L30.5 20.25 L30.5 27.75 L24 31.5 L17.5 27.75 L17.5 20.25 Z"
        fill="url(#to-core)"
        animate={animate ? { opacity: [0.9, 1, 0.9] } : undefined}
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
      />
      <path
        d="M24 16.5 L30.5 20.25 L30.5 27.75 L24 31.5 L17.5 27.75 L17.5 20.25 Z"
        fill="url(#to-core)"
        opacity="0.3"
        filter="blur(2.5px)"
      />
    </svg>
  )
}
