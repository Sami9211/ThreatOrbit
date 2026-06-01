'use client'

import { useRef } from 'react'
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion'

const SPRING = { stiffness: 200, damping: 22, mass: 0.4 }

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
  intensity = 12,
  glare = true,
  style,
}: TiltCardProps) {
  const ref = useRef<HTMLDivElement>(null)

  const rawX = useMotionValue(0)
  const rawY = useMotionValue(0)

  const rotateX = useSpring(useTransform(rawY, [-0.5, 0.5], [intensity, -intensity]), SPRING)
  const rotateY = useSpring(useTransform(rawX, [-0.5, 0.5], [-intensity, intensity]), SPRING)
  const scale   = useSpring(1, SPRING)

  const glareX = useTransform(rawX, [-0.5, 0.5], ['10%', '90%'])
  const glareY = useTransform(rawY, [-0.5, 0.5], ['10%', '90%'])

  const track = (clientX: number, clientY: number) => {
    if (!ref.current) return
    const r = ref.current.getBoundingClientRect()
    rawX.set((clientX - r.left) / r.width - 0.5)
    rawY.set((clientY - r.top)  / r.height - 0.5)
  }

  const reset = () => {
    rawX.set(0)
    rawY.set(0)
    scale.set(1)
  }

  return (
    <motion.div
      ref={ref}
      style={{ rotateX, rotateY, scale, transformStyle: 'preserve-3d', ...style }}
      className={className}
      onMouseMove={(e) => { track(e.clientX, e.clientY); scale.set(1.03) }}
      onMouseLeave={reset}
      onTouchMove={(e) => {
        const t = e.touches[0]
        track(t.clientX, t.clientY)
      }}
      onTouchEnd={reset}
    >
      {children}

      {glare && (
        <motion.div
          className="absolute inset-0 pointer-events-none rounded-[inherit]"
          style={{
            background: useTransform(
              [rawX, rawY],
              ([x, y]) =>
                `radial-gradient(circle at ${50 + (x as number) * 80}% ${50 + (y as number) * 80}%, rgba(255,255,255,0.07) 0%, transparent 55%)`
            ),
          }}
        />
      )}
    </motion.div>
  )
}
