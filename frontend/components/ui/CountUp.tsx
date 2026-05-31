'use client'

import { useEffect, useRef, useState } from 'react'
import { useInView } from 'framer-motion'

type CountUpProps = {
  /** Numeric target. Decimals are honoured (e.g. 99.4). */
  value: number
  /** Text appended after the number, e.g. "M+", "%", "ms". */
  suffix?: string
  /** Text shown before the number, e.g. "<". */
  prefix?: string
  decimals?: number
  duration?: number
  className?: string
}

export default function CountUp({
  value,
  suffix = '',
  prefix = '',
  decimals = 0,
  duration = 1600,
  className,
}: CountUpProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  const [display, setDisplay] = useState(0)

  useEffect(() => {
    if (!inView) return
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      // easeOutExpo
      const eased = t === 1 ? 1 : 1 - Math.pow(2, -10 * t)
      setDisplay(eased * value)
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [inView, value, duration])

  return (
    <span ref={ref} className={className}>
      {prefix}
      {display.toFixed(decimals)}
      {suffix}
    </span>
  )
}
