'use client'

import { useId } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

/**
 * ThreatOrbit mark: a luminous 3D core (the unified Super SOC) orbited by three
 * rings for the disciplines converging into it - CTI (magenta), SIEM (violet),
 * SOAR (amber). The core is a shaded sphere (light from the upper-left, plasma
 * body, deep-violet terminator) with a specular highlight and a soft bloom, so
 * it reads as a real 3D object rather than a flat shape. Each ring carries one
 * node - a threat under continuous watch. Pure animated SVG, crisp at any size.
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
  const spec = `spec-${uid}`
  const glow = `glow-${uid}`
  const ringGrad = (i: number) => `ring-${uid}-${i}`

  const rings = [
    { rotate: 0,   color: '#FF2E97', dur: 14 }, // CTI
    { rotate: 60,  color: '#7A3CFF', dur: 18 }, // SIEM
    { rotate: 120, color: '#FFB23E', dur: 22 }, // SOAR
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
        {/* Sphere body: highlight (upper-left) -> plasma -> deep-violet edge */}
        <radialGradient id={core} cx="38%" cy="34%" r="74%">
          <stop offset="0%"   stopColor="#FFE9C2" />
          <stop offset="20%"  stopColor="#FF9ECB" />
          <stop offset="52%"  stopColor="#FF2E97" />
          <stop offset="100%" stopColor="#591A84" />
        </radialGradient>
        {/* Glossy specular hotspot */}
        <radialGradient id={spec} cx="50%" cy="50%" r="50%">
          <stop offset="0%"   stopColor="#FFFFFF" stopOpacity="0.92" />
          <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0" />
        </radialGradient>
        {/* Soft bloom behind the core */}
        <radialGradient id={glow} cx="50%" cy="50%" r="50%">
          <stop offset="0%"   stopColor="#FF2E97" stopOpacity="0.55" />
          <stop offset="55%"  stopColor="#FF2E97" stopOpacity="0.13" />
          <stop offset="100%" stopColor="#FF2E97" stopOpacity="0" />
        </radialGradient>
        {/* Front-to-back depth gradient on each ring stroke */}
        {rings.map((r, i) => (
          <linearGradient key={i} id={ringGrad(i)} x1="4" y1="24" x2="44" y2="24"
            gradientUnits="userSpaceOnUse">
            <stop offset="0%"   stopColor={r.color} stopOpacity="0.18" />
            <stop offset="50%"  stopColor={r.color} stopOpacity="0.9" />
            <stop offset="100%" stopColor={r.color} stopOpacity="0.18" />
          </linearGradient>
        ))}
      </defs>

      {/* bloom */}
      <circle cx="24" cy="24" r="13.5" fill={`url(#${glow})`} />

      {/* orbit rings (behind the core); node sits ON the ring, placed by tilt */}
      {rings.map((ring, i) => (
        <motion.g
          key={i}
          style={{ transformOrigin: '24px 24px' }}
          initial={false}
          animate={animate ? { rotate: i % 2 === 0 ? 360 : -360 } : undefined}
          transition={{ duration: ring.dur, repeat: Infinity, ease: 'linear' }}
        >
          <g transform={`rotate(${ring.rotate} 24 24)`}>
            <ellipse cx="24" cy="24" rx="20" ry="7.4" stroke={`url(#${ringGrad(i)})`} strokeWidth="1.5" />
            <circle cx="44" cy="24" r="2.3" fill={ring.color} />
            <circle cx="44" cy="24" r="2.3" fill={ring.color} opacity="0.5" style={{ filter: 'blur(1.6px)' }} />
          </g>
        </motion.g>
      ))}

      {/* 3D core sphere with a gentle breathe */}
      <motion.g
        style={{ transformOrigin: '24px 24px' }}
        animate={animate ? { scale: [1, 1.04, 1] } : undefined}
        transition={{ duration: 3.4, repeat: Infinity, ease: 'easeInOut' }}
      >
        <circle cx="24" cy="24" r="8.4" fill={`url(#${core})`} />
        {/* specular highlight, upper-left, aligned to the light direction */}
        <ellipse cx="20.7" cy="20.3" rx="3.2" ry="2.2" fill={`url(#${spec})`} transform="rotate(-34 20.7 20.3)" />
        {/* crisp edge for definition against any background */}
        <circle cx="24" cy="24" r="8.4" fill="none" stroke="#FFFFFF" strokeOpacity="0.16" strokeWidth="0.5" />
      </motion.g>
    </svg>
  )
}
