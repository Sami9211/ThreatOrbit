'use client'

import { useId } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * ThreatOrbit mark: a faceted, beveled gem core (the unified Super SOC)
 * wrapped by three orbital rings that stand for the disciplines converging
 * into it - CTI (magenta), SIEM (violet), SOAR (amber). The core is rendered
 * with cut-gem facets, a specular highlight and a soft cast shadow so it reads
 * as a 3D object rather than a flat shape; the rings carry a front-to-back
 * gradient for depth. Pure animated SVG, crisp at any size.
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
  // gradient/filter definitions.
  const uid = useId().replace(/:/g, '')
  const core = `core-${uid}`
  const coreDark = `coreD-${uid}`
  const spec = `spec-${uid}`
  const shadow = `shadow-${uid}`
  const ringGrad = (i: number) => `ring-${uid}-${i}`

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
        {/* Lit (upper-left) gem face */}
        <linearGradient id={core} x1="14" y1="15" x2="32" y2="33" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFE3A8" />
          <stop offset="38%" stopColor="#FF6FB4" />
          <stop offset="100%" stopColor="#FF2E97" />
        </linearGradient>
        {/* Shaded (lower-right) gem face */}
        <linearGradient id={coreDark} x1="30" y1="18" x2="20" y2="32" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#C7249B" />
          <stop offset="100%" stopColor="#5B2EC6" />
        </linearGradient>
        {/* Specular highlight near the top facet */}
        <linearGradient id={spec} x1="22" y1="16" x2="26" y2="23" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0" />
        </linearGradient>
        <radialGradient id={shadow} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#000000" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#000000" stopOpacity="0" />
        </radialGradient>
        {rings.map((r, i) => (
          <linearGradient key={i} id={ringGrad(i)} x1="4" y1="24" x2="44" y2="24"
            gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor={r.color} stopOpacity="0.15" />
            <stop offset="50%" stopColor={r.color} stopOpacity="0.85" />
            <stop offset="100%" stopColor={r.color} stopOpacity="0.15" />
          </linearGradient>
        ))}
      </defs>

      {/* Soft cast shadow under the core - grounds the gem in 3D space */}
      <ellipse cx="24" cy="33.5" rx="9" ry="2.6" fill={`url(#${shadow})`} />

      {rings.map((ring, i) => (
        <motion.g
          key={i}
          style={{ transformOrigin: '24px 24px' }}
          initial={false}
          animate={animate ? { rotate: i % 2 === 0 ? 360 : -360 } : undefined}
          transition={{ duration: ring.dur, repeat: Infinity, ease: 'linear' }}
        >
          <g transform={`rotate(${ring.rotate} 24 24)`}>
            <ellipse cx="24" cy="24" rx="20" ry="7.5" stroke={`url(#${ringGrad(i)})`} strokeWidth="1.6" />
            <circle cx={ring.node.cx} cy={ring.node.cy} r="2.4" fill={ring.color} />
            <circle cx={ring.node.cx} cy={ring.node.cy} r="2.4" fill={ring.color} opacity="0.4"
              style={{ filter: 'blur(1.5px)' }} />
          </g>
        </motion.g>
      ))}

      {/* outer glow bloom (behind the core) */}
      <path
        d="M24 16.2 L30.8 20.1 L30.8 27.9 L24 31.8 L17.2 27.9 L17.2 20.1 Z"
        fill="#FF2E97"
        opacity="0.22"
        style={{ filter: 'blur(3px)' }}
      />

      {/* Faceted gem core: two beveled halves + a center ridge + a top
          specular, so it reads as a cut 3D crystal rather than a flat hex. */}
      <motion.g
        animate={animate ? { opacity: [0.94, 1, 0.94] } : undefined}
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
      >
        {/* lit left half */}
        <path d="M24 16.2 L17.2 20.1 L17.2 27.9 L24 31.8 L24 24 Z" fill={`url(#${core})`} />
        {/* shaded right half */}
        <path d="M24 16.2 L30.8 20.1 L30.8 27.9 L24 31.8 L24 24 Z" fill={`url(#${coreDark})`} />
        {/* center ridge highlight */}
        <path d="M24 16.2 L24 31.8" stroke="#FFFFFF" strokeWidth="0.6" opacity="0.35" />
        {/* top crown facet specular */}
        <path d="M24 16.2 L30.8 20.1 L24 22.6 L17.2 20.1 Z" fill={`url(#${spec})`} />
        {/* crisp outline for definition */}
        <path d="M24 16.2 L30.8 20.1 L30.8 27.9 L24 31.8 L17.2 27.9 L17.2 20.1 Z"
          stroke="#FFFFFF" strokeOpacity="0.18" strokeWidth="0.5" fill="none" />
      </motion.g>
    </svg>
  )
}
