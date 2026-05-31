'use client'

import { useRef, useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

type MagneticButtonProps = {
  children: ReactNode
  href?: string
  className?: string
  strength?: number
}

/**
 * Button/link that subtly pulls toward the cursor while hovered, then
 * springs back on leave. Gives the page an ActiveTheory-style tactile feel.
 */
export default function MagneticButton({
  children,
  href,
  className,
  strength = 0.4,
}: MagneticButtonProps) {
  const ref = useRef<HTMLAnchorElement>(null)
  const [pos, setPos] = useState({ x: 0, y: 0 })

  const handleMove = (e: React.MouseEvent) => {
    const el = ref.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const x = (e.clientX - (rect.left + rect.width / 2)) * strength
    const y = (e.clientY - (rect.top + rect.height / 2)) * strength
    setPos({ x, y })
  }

  const reset = () => setPos({ x: 0, y: 0 })

  return (
    <motion.a
      ref={ref}
      href={href}
      onMouseMove={handleMove}
      onMouseLeave={reset}
      animate={{ x: pos.x, y: pos.y }}
      transition={{ type: 'spring', stiffness: 220, damping: 16, mass: 0.4 }}
      className={cn('inline-flex items-center justify-center', className)}
    >
      <motion.span
        animate={{ x: pos.x * 0.3, y: pos.y * 0.3 }}
        transition={{ type: 'spring', stiffness: 220, damping: 16, mass: 0.4 }}
        className="inline-flex items-center justify-center gap-2"
      >
        {children}
      </motion.span>
    </motion.a>
  )
}
