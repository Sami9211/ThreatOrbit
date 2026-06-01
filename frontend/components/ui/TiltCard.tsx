'use client'

import { useRef, useEffect } from 'react'
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

  const track = (nx: number, ny: number) => { rawX.set(nx); rawY.set(ny) }
  const reset = () => { rawX.set(0); rawY.set(0); scale.set(1) }

  /* Mouse */
  const onMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!ref.current) return
    const r = ref.current.getBoundingClientRect()
    track((e.clientX - r.left) / r.width - 0.5, (e.clientY - r.top) / r.height - 0.5)
    scale.set(1.04)
  }

  /* Touch drag */
  const onTouchMove = (e: React.TouchEvent<HTMLDivElement>) => {
    if (!ref.current) return
    const r = ref.current.getBoundingClientRect()
    const t = e.touches[0]
    track((t.clientX - r.left) / r.width - 0.5, (t.clientY - r.top) / r.height - 0.5)
  }

  /* Device orientation (gyroscope) for mobile */
  useEffect(() => {
    const handler = (e: DeviceOrientationEvent) => {
      if (e.gamma == null || e.beta == null) return
      /* gamma: -90..90 (left-right), beta: -180..180 (front-back) */
      track(
        Math.max(-0.5, Math.min(0.5, e.gamma / 30)),
        Math.max(-0.5, Math.min(0.5, (e.beta - 20) / 40)),
      )
    }
    window.addEventListener('deviceorientation', handler, { passive: true })
    return () => window.removeEventListener('deviceorientation', handler)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <motion.div
      ref={ref}
      style={{ rotateX, rotateY, scale, transformStyle: 'preserve-3d', ...style }}
      className={className}
      onMouseMove={onMouseMove}
      onMouseLeave={reset}
      onTouchMove={onTouchMove}
      onTouchEnd={reset}
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
