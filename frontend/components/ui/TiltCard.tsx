'use client'

import { useRef, useEffect, useCallback } from 'react'
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion'

const SPRING = { stiffness: 220, damping: 24, mass: 0.4 }

interface TiltCardProps {
  children: React.ReactNode
  className?: string
  intensity?: number
  glare?: boolean
  style?: React.CSSProperties
}

export default function TiltCard({
  children,
  className,
  intensity = 14,
  glare = true,
  style,
}: TiltCardProps) {
  const ref  = useRef<HTMLDivElement>(null)
  const rawX = useMotionValue(0)
  const rawY = useMotionValue(0)

  const rotateX = useSpring(useTransform(rawY, [-0.5, 0.5], [ intensity, -intensity]), SPRING)
  const rotateY = useSpring(useTransform(rawX, [-0.5, 0.5], [-intensity,  intensity]), SPRING)
  const scale   = useSpring(1, SPRING)
  const glareX  = useTransform(rawX, [-0.5, 0.5], ['5%',  '95%'])
  const glareY  = useTransform(rawY, [-0.5, 0.5], ['5%',  '95%'])

  const track = useCallback((nx: number, ny: number) => { rawX.set(nx); rawY.set(ny) }, [rawX, rawY])
  const reset = useCallback(() => { rawX.set(0); rawY.set(0); scale.set(1) }, [rawX, rawY, scale])

  /* Mouse */
  const onMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!ref.current) return
    const r = ref.current.getBoundingClientRect()
    track((e.clientX - r.left) / r.width - 0.5, (e.clientY - r.top) / r.height - 0.5)
    scale.set(1.04)
  }

  /* Touch drag - only tilt, don't scale (prevents flicker on tap) */
  const onTouchMove = (e: React.TouchEvent<HTMLDivElement>) => {
    if (!ref.current) return
    const r = ref.current.getBoundingClientRect()
    const t = e.touches[0]
    // Clamp so the tilt only reacts while the finger is over this card
    const nx = Math.max(-0.5, Math.min(0.5, (t.clientX - r.left) / r.width - 0.5))
    const ny = Math.max(-0.5, Math.min(0.5, (t.clientY - r.top)  / r.height - 0.5))
    track(nx, ny)
  }

  /* Device orientation (gyroscope) - accurate mapping.
   *
   * The device is typically held at ~45° tilt (portrait, slight backward lean).
   * gamma = left-right rotation (-90..90), maps to card rotateY.
   * beta  = front-back tilt  (-180..180), maps to card rotateX.
   *
   * We use a narrower input range (±20°) so small hand movements produce
   * satisfying card movement without needing to violently tilt the phone.
   * A -15° beta offset accounts for the natural resting hold angle.
   */
  useEffect(() => {
    const RANGE = 20
    const BETA_OFFSET = -15
    const handler = (e: DeviceOrientationEvent) => {
      if (e.gamma == null || e.beta == null) return
      track(
        Math.max(-0.5, Math.min(0.5,  e.gamma              / RANGE)),
        Math.max(-0.5, Math.min(0.5, (e.beta + BETA_OFFSET) / RANGE)),
      )
    }
    window.addEventListener('deviceorientation', handler, { passive: true })
    return () => window.removeEventListener('deviceorientation', handler)
  }, [track])

  return (
    <motion.div
      ref={ref}
      style={{ rotateX, rotateY, scale, transformStyle: 'preserve-3d', ...style }}
      className={className}
      onMouseMove={onMouseMove}
      onMouseLeave={reset}
      onTouchMove={onTouchMove}
      onTouchEnd={reset}
      onTouchCancel={reset}
    >
      {children}

      {glare && (
        <motion.div
          className="absolute inset-0 pointer-events-none rounded-[inherit]"
          style={{
            background: useTransform(
              [glareX, glareY],
              ([x, y]) =>
                `radial-gradient(circle at ${x} ${y}, rgba(255,255,255,0.09) 0%, transparent 55%)`,
            ),
          }}
        />
      )}
    </motion.div>
  )
}
