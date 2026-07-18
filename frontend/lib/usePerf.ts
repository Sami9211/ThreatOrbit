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
 * True while the user is actively scrolling (and for `idleMs` after the last
 * scroll event). Heavy render loops pause on this signal: during a scroll the
 * scene's last frame stays composited (imperceptible - the page content is
 * moving) and animation resumes the moment scrolling settles. Measured on the
 * production export at 4x CPU throttle, the landing page's WebGL loops cost
 * ~60% of scroll frame time - this recovers it without degrading idle visuals.
 */
export function useScrollIdle(idleMs = 180): boolean {
  const [scrolling, setScrolling] = useState(false)
  useEffect(() => {
    let t: number | undefined
    const onScroll = () => {
      setScrolling(true)
      window.clearTimeout(t)
      t = window.setTimeout(() => setScrolling(false), idleMs)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => { window.removeEventListener('scroll', onScroll); window.clearTimeout(t) }
  }, [idleMs])
  return scrolling
}

/**
 * Clamp a frame delta before integrating it into an animation. With
 * `frameloop: demand` the R3F clock keeps running while a scene is paused
 * (off-screen or mid-scroll), so the first resumed frame receives the WHOLE
 * pause as one delta - objects visibly snap to where they "would have been"
 * (the audit's "hero moves unexpectedly when scrolling back to top").
 * Clamping makes a resume continue smoothly from the frozen pose.
 */
export const clampDelta = (dt: number, max = 0.05): number => (dt > max ? max : dt)

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
