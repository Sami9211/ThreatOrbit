'use client'

import { motion, useInView, type Variants } from 'framer-motion'
import { useRef } from 'react'

type RevealProps = {
  children: React.ReactNode
  className?: string
  delay?: number
  /** bloom = scale+rise (AirDrop-like), rise = translate up, fade = opacity only */
  variant?: 'bloom' | 'rise' | 'fade' | 'left' | 'right'
  once?: boolean
}

const VARIANTS: Record<string, Variants> = {
  bloom: {
    hidden: { opacity: 0, scale: 0.86, y: 40, filter: 'blur(8px)' },
    show: { opacity: 1, scale: 1, y: 0, filter: 'blur(0px)' },
  },
  rise: {
    hidden: { opacity: 0, y: 36 },
    show: { opacity: 1, y: 0 },
  },
  fade: {
    hidden: { opacity: 0 },
    show: { opacity: 1 },
  },
  left: {
    hidden: { opacity: 0, x: -40 },
    show: { opacity: 1, x: 0 },
  },
  right: {
    hidden: { opacity: 0, x: 40 },
    show: { opacity: 1, x: 0 },
  },
}

export default function Reveal({
  children,
  className,
  delay = 0,
  variant = 'rise',
  once = true,
}: RevealProps) {
  const ref = useRef(null)
  const inView = useInView(ref, { once, margin: '-80px' })

  return (
    <motion.div
      ref={ref}
      className={className}
      variants={VARIANTS[variant]}
      initial="hidden"
      animate={inView ? 'show' : 'hidden'}
      transition={{ duration: 0.8, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}
