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
 * Clamp a frame delta before integrating it into an animation. With
 * `frameloop: demand` the R3F clock keeps running while a scene is paused
 * (off-screen), so the first resumed frame receives the WHOLE pause as one
 * delta - objects visibly snap to where they "would have been" (the audit's
 * "hero moves unexpectedly when scrolling back to top"). Clamping makes a
 * resume continue smoothly from the frozen pose.
 *
 * (A `useScrollIdle` pause-while-scrolling hook used to live here; it was
 * removed on purpose - freezing the scenes during scroll read as broken.)
 */
export const clampDelta = (dt: number, max = 0.05): number => (dt > max ? max : dt)

/**
 * Visibility flag used to pause WebGL render loops when a canvas scrolls
 * off-screen.
 *
 * IntersectionObserver alone is not enough here: browsers DEFER IO callbacks
 * during momentum scrolling, so a scene entering the viewport stayed paused
 * (visibly static) until the scroll settled, then snapped into motion - and
 * behaved correctly only on subsequent views. We keep IO as the primary signal
 * (it catches layout changes) but add a rAF-throttled, passive scroll/resize
 * fallback that recomputes visibility from getBoundingClientRect immediately,
 * so a scene starts animating *as* it scrolls in, on the very first pass.
 */
export function useInViewport<T extends HTMLElement>(margin = '200px') {
  const ref = useRef<T>(null)
  const [visible, setVisible] = useState(true)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const marginPx = parseInt(margin, 10) || 0
    let raf = 0

    const check = () => {
      raf = 0
      const r = el.getBoundingClientRect()
      const vh = window.innerHeight || document.documentElement.clientHeight
      setVisible(r.bottom >= -marginPx && r.top <= vh + marginPx)
    }
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(check) }

    const io = new IntersectionObserver(
      ([entry]) => setVisible(entry.isIntersecting),
      { rootMargin: margin },
    )
    io.observe(el)
    check()  // sync the initial state (no waiting on the first async IO tick)
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll, { passive: true })
    return () => {
      io.disconnect()
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
      if (raf) cancelAnimationFrame(raf)
    }
  }, [margin])

  return { ref, visible }
}
