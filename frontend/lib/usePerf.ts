'use client'

import { useEffect, useRef, useState } from 'react'

/**
 * Shared performance/accessibility signals for heavy (3D) components.
 * - prefersReducedMotion: respect the OS "reduce motion" setting
 * - isLowPower: coarse heuristic for phones / weak GPUs
 */
export function usePerfProfile() {
  const [prefersReducedMotion, setPRM] = useState(false)
  const [isLowPower, setLowPower] = useState(false)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const apply = () => setPRM(mq.matches)
    apply()
    mq.addEventListener('change', apply)

    // Low-power heuristic: touch-primary device, few cores, or small viewport.
    const cores = navigator.hardwareConcurrency ?? 8
    const coarse = window.matchMedia('(pointer: coarse)').matches
    const small = window.innerWidth < 768
    setLowPower(coarse || cores <= 4 || small)

    return () => mq.removeEventListener('change', apply)
  }, [])

  return { prefersReducedMotion, isLowPower }
}

/**
 * IntersectionObserver-based visibility flag.
 * Used to pause WebGL render loops when a canvas scrolls off-screen.
 */
export function useInViewport<T extends HTMLElement>(margin = '200px') {
  const ref = useRef<T>(null)
  const [visible, setVisible] = useState(true)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const io = new IntersectionObserver(
      ([entry]) => setVisible(entry.isIntersecting),
      { rootMargin: margin },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [margin])

  return { ref, visible }
}
