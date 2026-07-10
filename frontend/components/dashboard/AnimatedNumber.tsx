'use client'

import { useEffect, useRef } from 'react'
import { animate, useReducedMotion } from 'framer-motion'
import { EASE } from '@/lib/motion'

/**
 * Count-up number: animates from the previously shown value to the new one
 * whenever `value` changes (from 0 on first mount, so data arriving reads as
 * a satisfying tick-up rather than a jump cut).
 *
 * Imperative `animate()` on a text node doesn't go through MotionConfig, so
 * reduced motion is honoured explicitly here via `useReducedMotion` — those
 * users get the final value set instantly.
 */
export default function AnimatedNumber({ value, format, duration = 0.8 }: {
  value: number
  /** Formats each animation frame. Default: rounded + locale separators. */
  format?: (v: number) => string
  duration?: number
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const prev = useRef(0)
  const reduced = useReducedMotion()
  const fmt = format ?? ((v: number) => Math.round(v).toLocaleString())

  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (reduced) {
      el.textContent = fmt(value)
      prev.current = value
      return
    }
    const controls = animate(prev.current, value, {
      duration,
      ease: [...EASE],
      onUpdate: (v) => { el.textContent = fmt(v) },
    })
    prev.current = value
    return () => controls.stop()
    // fmt/duration are stable per call site; re-running on value/reduced only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, reduced])

  // Render the previously committed value, not the target: useEffect runs
  // after paint, so rendering fmt(value) here flashes the final number for a
  // frame before the count-up's first tick overwrites it (observed live).
  return <span ref={ref}>{fmt(prev.current)}</span>
}
