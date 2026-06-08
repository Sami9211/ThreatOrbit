'use client'

import { useEffect, useRef } from 'react'
import { useCursorEffect } from '@/lib/useCursorEffect'

// Brand palette — blobs cycle through these
const BRAND_RGB = [
  [255, 46,  151],  // #FF2E97 magenta
  [122, 60,  255],  // #7A3CFF violet
  [45,  212, 191],  // #2DD4BF teal
  [255, 178, 62],   // #FFB23E amber
  [180, 80,  255],  // purple-magenta bridge
] as const

interface Blob {
  x: number; y: number   // current position
  tx: number; ty: number // target position
  speed: number          // lerp factor per frame
  r: number              // RGB triple index
  g: number
  b: number
  radius: number         // gradient outer radius
  phase: number          // oscillation phase for idle drift
  phaseSpeed: number
}

export default function CursorParticles() {
  const [enabled] = useCursorEffect()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const blobsRef  = useRef<Blob[]>([])
  const cursor    = useRef({ x: -500, y: -500 })
  const raf       = useRef<number>()

  useEffect(() => {
    if (!enabled) return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')!

    function resize() {
      canvas!.width  = window.innerWidth
      canvas!.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    // Place blobs off-screen initially — they flow to cursor on first move
    const startX = -500, startY = -500
    // Speeds deliberately different so blobs stretch into a trail on fast movement
    const speeds  = [0.10, 0.065, 0.042, 0.028, 0.018]
    const radii   = [72, 88, 68, 80, 64]

    blobsRef.current = BRAND_RGB.map(([r, g, b], i) => ({
      x: startX, y: startY,
      tx: startX, ty: startY,
      speed: speeds[i],
      r, g, b,
      radius: radii[i],
      phase: (i / BRAND_RGB.length) * Math.PI * 2,
      phaseSpeed: 0.007 + i * 0.002,
    }))

    function moveTo(x: number, y: number) {
      cursor.current = { x, y }
      blobsRef.current.forEach(b => { b.tx = x; b.ty = y })
    }

    function burst(x: number, y: number) {
      // On tap/touchstart — scatter blobs outward then let them flow back
      blobsRef.current.forEach((b, i) => {
        const angle = (i / blobsRef.current.length) * Math.PI * 2
        const d = 55 + i * 12
        b.x = x + Math.cos(angle) * d
        b.y = y + Math.sin(angle) * d
        b.tx = x; b.ty = y
      })
      cursor.current = { x, y }
    }

    function onMouseMove(e: MouseEvent)  { moveTo(e.clientX, e.clientY) }
    function onTouchMove(e: TouchEvent)  { moveTo(e.touches[0].clientX, e.touches[0].clientY) }
    function onTouchStart(e: TouchEvent) { burst(e.touches[0].clientX,  e.touches[0].clientY) }

    window.addEventListener('mousemove',  onMouseMove)
    window.addEventListener('touchmove',  onTouchMove,  { passive: true })
    window.addEventListener('touchstart', onTouchStart, { passive: true })

    function frame() {
      ctx.clearRect(0, 0, canvas!.width, canvas!.height)

      // 'lighter' makes overlapping blobs brighten — the plasma core effect
      ctx.globalCompositeOperation = 'lighter'

      for (const blob of blobsRef.current) {
        blob.phase += blob.phaseSpeed

        // Smooth lerp toward target
        blob.x += (blob.tx - blob.x) * blob.speed
        blob.y += (blob.ty - blob.y) * blob.speed

        // Gentle idle oscillation — blobs breathe when clustered
        const settled = Math.sqrt((blob.tx - blob.x) ** 2 + (blob.ty - blob.y) ** 2)
        const drift   = Math.max(0, 1 - settled / 80) * 7
        const px = blob.x + Math.sin(blob.phase)          * drift
        const py = blob.y + Math.cos(blob.phase * 0.73)   * drift

        // Subtle size pulse
        const radiusPulse = blob.radius * (1 + Math.sin(blob.phase * 0.5) * 0.06)

        const grad = ctx.createRadialGradient(px, py, 0, px, py, radiusPulse)
        grad.addColorStop(0,    `rgba(${blob.r},${blob.g},${blob.b},0.30)`)
        grad.addColorStop(0.35, `rgba(${blob.r},${blob.g},${blob.b},0.14)`)
        grad.addColorStop(0.7,  `rgba(${blob.r},${blob.g},${blob.b},0.05)`)
        grad.addColorStop(1,    `rgba(${blob.r},${blob.g},${blob.b},0)`)

        ctx.beginPath()
        ctx.arc(px, py, radiusPulse, 0, Math.PI * 2)
        ctx.fillStyle = grad
        ctx.fill()
      }

      ctx.globalCompositeOperation = 'source-over'
      raf.current = requestAnimationFrame(frame)
    }
    raf.current = requestAnimationFrame(frame)

    return () => {
      window.removeEventListener('resize',     resize)
      window.removeEventListener('mousemove',  onMouseMove)
      window.removeEventListener('touchmove',  onTouchMove)
      window.removeEventListener('touchstart', onTouchStart)
      if (raf.current) cancelAnimationFrame(raf.current)
      ctx.globalCompositeOperation = 'source-over'
      ctx.clearRect(0, 0, canvas!.width, canvas!.height)
    }
  }, [enabled])

  if (!enabled) return null

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 9998,
      }}
    />
  )
}
