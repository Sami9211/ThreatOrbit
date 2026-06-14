'use client'

import { useEffect, useRef } from 'react'

export default function CursorGlow() {
  const glowRef = useRef<HTMLDivElement>(null)
  const pos = useRef({ x: -1000, y: -1000 })
  const current = useRef({ x: -1000, y: -1000 })
  const rafRef = useRef<number | undefined>(undefined)

  useEffect(() => {
    const el = glowRef.current
    if (!el) return

    const onMove = (e: MouseEvent) => {
      pos.current = { x: e.clientX, y: e.clientY }
    }

    function lerp(a: number, b: number, t: number) {
      return a + (b - a) * t
    }

    function animate() {
      current.current.x = lerp(current.current.x, pos.current.x, 0.06)
      current.current.y = lerp(current.current.y, pos.current.y, 0.06)
      if (el) {
        el.style.left = `${current.current.x}px`
        el.style.top = `${current.current.y}px`
      }
      rafRef.current = requestAnimationFrame(animate)
    }
    rafRef.current = requestAnimationFrame(animate)

    window.addEventListener('mousemove', onMove)
    return () => {
      window.removeEventListener('mousemove', onMove)
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [])

  return (
    <div
      ref={glowRef}
      id="cursor-glow"
      aria-hidden
      style={{ position: 'fixed', pointerEvents: 'none', zIndex: 0, borderRadius: '50%',
        width: 480, height: 480,
        background: 'radial-gradient(circle, rgba(255,46,151,0.05) 0%, rgba(122,60,255,0.035) 35%, transparent 70%)',
        transform: 'translate(-50%, -50%)', transition: 'opacity 0.6s' }}
    />
  )
}
