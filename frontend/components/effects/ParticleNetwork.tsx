'use client'

/**
 * Canvas 2D particle network - replaces Three.js/WebGL entirely.
 * No shader compilation, no GPU context overhead, works natively on mobile.
 * Touch and mouse reactive: particles repel from the pointer.
 */
import { useEffect, useRef } from 'react'

const COLORS = ['#FF2E97', '#7A3CFF', '#FFB23E', '#2DD4BF']
const REPEL_RADIUS = 90
const REPEL_FORCE = 0.28

type P = { x: number; y: number; vx: number; vy: number; r: number; color: string }

export default function ParticleNetwork({ className }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const isMobile = /Mobi|Android/i.test(navigator.userAgent) || window.innerWidth < 768
    const COUNT     = isMobile ? 38 : 80
    const CONNECT   = isMobile ? 110 : 140
    const CONN_SQ   = CONNECT * CONNECT
    const MAX_CONN  = isMobile ? 55 : 110
    const FRAME_MS  = isMobile ? 34 : 16
    const DPR       = Math.min(window.devicePixelRatio || 1, isMobile ? 1.5 : 2)

    let W = 0, H = 0, mx = -9999, my = -9999, raf = 0, last = 0

    const resize = () => {
      const rect = canvas.getBoundingClientRect()
      W = rect.width; H = rect.height
      canvas.width  = W * DPR
      canvas.height = H * DPR
      ctx.scale(DPR, DPR)
    }
    resize()

    const pts: P[] = Array.from({ length: COUNT }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - .5) * .7,
      vy: (Math.random() - .5) * .7,
      r: Math.random() * 2 + 1.5,
      color: COLORS[Math.floor(Math.random() * 4)],
    }))

    /* Pointer tracking */
    const hit = (x: number, y: number) => { mx = x; my = y }
    const miss = () => { mx = -9999; my = -9999 }
    const onMouse = (e: MouseEvent) => {
      const r = canvas.getBoundingClientRect()
      hit(e.clientX - r.left, e.clientY - r.top)
    }
    const onTouch = (e: TouchEvent) => {
      const r = canvas.getBoundingClientRect()
      hit(e.touches[0].clientX - r.left, e.touches[0].clientY - r.top)
    }
    canvas.addEventListener('mousemove', onMouse)
    canvas.addEventListener('mouseleave', miss)
    canvas.addEventListener('touchmove', onTouch, { passive: true })
    canvas.addEventListener('touchend', miss)

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw)
      if (now - last < FRAME_MS) return
      last = now

      ctx.clearRect(0, 0, W, H)

      for (const p of pts) {
        /* Repel from cursor */
        const dx = p.x - mx, dy = p.y - my
        const d2 = dx * dx + dy * dy
        if (d2 < REPEL_RADIUS * REPEL_RADIUS && d2 > 0.5) {
          const d = Math.sqrt(d2)
          const f = (1 - d / REPEL_RADIUS) * REPEL_FORCE
          p.vx += (dx / d) * f
          p.vy += (dy / d) * f
        }
        p.vx *= .976; p.vy *= .976
        p.x += p.vx; p.y += p.vy
        if (p.x < 0)  { p.x = 0;  p.vx =  Math.abs(p.vx) }
        else if (p.x > W) { p.x = W;  p.vx = -Math.abs(p.vx) }
        if (p.y < 0)  { p.y = 0;  p.vy =  Math.abs(p.vy) }
        else if (p.y > H) { p.y = H;  p.vy = -Math.abs(p.vy) }
      }

      /* Connections (capped) */
      let conns = 0
      outer: for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          if (conns >= MAX_CONN) break outer
          const dx = pts[i].x - pts[j].x
          const dy = pts[i].y - pts[j].y
          const d2 = dx * dx + dy * dy
          if (d2 < CONN_SQ) {
            const alpha = (1 - Math.sqrt(d2) / CONNECT) * .22
            const hex = Math.round(alpha * 255).toString(16).padStart(2, '0')
            ctx.beginPath()
            ctx.strokeStyle = pts[i].color.slice(0, 7) + hex
            ctx.lineWidth = .9
            ctx.moveTo(pts[i].x, pts[i].y)
            ctx.lineTo(pts[j].x, pts[j].y)
            ctx.stroke()
            conns++
          }
        }
      }

      /* Dots */
      for (const p of pts) {
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = p.color + 'CC'
        ctx.fill()
      }
    }

    raf = requestAnimationFrame(draw)
    window.addEventListener('resize', resize, { passive: true })

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      canvas.removeEventListener('mousemove', onMouse)
      canvas.removeEventListener('mouseleave', miss)
      canvas.removeEventListener('touchmove', onTouch)
      canvas.removeEventListener('touchend', miss)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={className}
      style={{ width: '100%', height: '100%', display: 'block' }}
      aria-hidden
    />
  )
}
