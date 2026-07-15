'use client'

import { useEffect, useState } from 'react'

/**
 * True when the device's *primary* pointer is coarse - i.e. touch-first
 * devices (phones, tablets) where the OS reports `(pointer: coarse)`.
 *
 * Hover-only affordances (a hover-to-reveal sidebar, a 4px hover strip, …)
 * behave erratically on touch: a tap fires a sticky synthetic `mouseenter`
 * and there's no `mouseleave`, so panels open half-way or never close. Use
 * this to swap those for explicit tap toggles on touch while keeping the
 * smooth hover behaviour for mouse/trackpad users.
 *
 * Note: a touch-capable laptop with a trackpad still reports `pointer: fine`
 * (the primary pointer), so it correctly keeps the hover behaviour.
 *
 * SSR-safe: starts `false` and resolves on mount, so server and first client
 * render agree (no hydration mismatch).
 */
export function useCoarsePointer(): boolean {
  const [coarse, setCoarse] = useState(false)
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mq = window.matchMedia('(pointer: coarse)')
    const update = () => setCoarse(mq.matches)
    update()
    mq.addEventListener('change', update)
    return () => mq.removeEventListener('change', update)
  }, [])
  return coarse
}
