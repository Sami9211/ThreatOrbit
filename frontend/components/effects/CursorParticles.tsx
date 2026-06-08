'use client'

import { useEffect, useRef } from 'react'
import { useCursorEffect } from '@/lib/useCursorEffect'

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  life: number     // 0..1 remaining life
  decay: number    // per-frame decay rate
  radius: number
  hue: number      // degrees, cycles for variety
}

const MAX = 80
const COLORS = ['#FF2E97', '#7A3CFF', '#FFB23E', '#2DD4BF'] as const

export default function CursorParticles() {
  const [enabled] = useCursorEffect()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const particles = useRef<Particle[]>([])
  const mouse = useRef({ x: -9999, y: -9999, moving: false })
  const raf = useRef<number>()

  useEffect(() => {
    if (!enabled) return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')!

    function resize() {
      canvas!.width = window.innerWidth
      canvas!.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    function spawn(x: number, y: number, burst = 1) {
      for (let i = 0; i < burst; i++) {
        if (particles.current.length >= MAX) particles.current.shift()
        const angle = Math.random() * Math.PI * 2
        const speed = 0.4 + Math.random() * 1.4
        const color = COLORS[Math.floor(Math.random() * COLORS.length)]
        particles.current.push({
          x,
          y,
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed - 0.3, // slight upward drift
          life: 1,
          decay: 0.018 + Math.random() * 0.018,
          radius: 1.5 + Math.random() * 2.5,
          hue: parseInt(color.replace('#', ''), 16),
        })
      }
    }

    let lastX = -1, lastY = -1
    function onMouseMove(e: MouseEvent) {
      const dx = e.clientX - lastX, dy = e.clientY - lastY
      const dist = Math.sqrt(dx * dx + dy * dy)
      mouse.current = { x: e.clientX, y: e.clientY, moving: true }
      if (dist > 6) {          // only emit when actually moving
        spawn(e.clientX, e.clientY, 2)
        lastX = e.clientX; lastY = e.clientY
      }
    }
    function onTouchMove(e: TouchEvent) {
      const t = e.touches[0]
      spawn(t.clientX, t.clientY, 3)
    }
    function onTouchStart(e: TouchEvent) {
      const t = e.touches[0]
      spawn(t.clientX, t.clientY, 6)  // burst on tap
    }

    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('touchmove', onTouchMove, { passive: true })
    window.addEventListener('touchstart', onTouchStart, { passive: true })

    function frame() {
      ctx.clearRect(0, 0, canvas!.width, canvas!.height)

      particles.current = particles.current.filter(p => p.life > 0)

      for (const p of particles.current) {
        p.x += p.vx
        p.y += p.vy
        p.vy += 0.04          // gravity
        p.vx *= 0.97          // friction
        p.life -= p.decay

        const alpha = p.life
        const r = p.radius * p.life

        // soft glowing dot
        const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, r * 4)
        const col = COLORS[Math.floor(p.hue % COLORS.length)]
        grad.addColorStop(0,   col + Math.round(alpha * 0xcc).toString(16).padStart(2, '0'))
        grad.addColorStop(0.5, col + Math.round(alpha * 0x44).toString(16).padStart(2, '0'))
        grad.addColorStop(1,   col + '00')

        ctx.beginPath()
        ctx.arc(p.x, p.y, r * 4, 0, Math.PI * 2)
        ctx.fillStyle = grad
        ctx.fill()

        // bright core
        ctx.beginPath()
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2)
        ctx.fillStyle = col + Math.round(alpha * 0xff).toString(16).padStart(2, '0')
        ctx.fill()
      }

      raf.current = requestAnimationFrame(frame)
    }
    raf.current = requestAnimationFrame(frame)

    return () => {
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('touchmove', onTouchMove)
      window.removeEventListener('touchstart', onTouchStart)
      if (raf.current) cancelAnimationFrame(raf.current)
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
        zIndex: 9998,       // below modals (10000+), above everything else
      }}
    />
  )
}
