'use client'

import { useRef, useEffect, useState } from 'react'
import { motion, useInView, useReducedMotion } from 'framer-motion'
import { ArrowRight, Terminal, Zap } from 'lucide-react'
import GithubIcon from '@/components/ui/GithubIcon'
import Reveal from '@/components/ui/Reveal'
import MagneticButton from '@/components/ui/MagneticButton'
import Logo from '@/components/ui/Logo'

function ParticleBurst({ run }: { run: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animRef   = useRef<number>(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !run) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const W = canvas.offsetWidth
    const H = canvas.offsetHeight
    canvas.width  = W
    canvas.height = H

    const COLORS = ['#FF2E97', '#7A3CFF', '#FFB23E', '#2DD4BF']

    const particles = Array.from({ length: 60 }, (_, i) => {
      const angle  = (i / 60) * Math.PI * 2 + Math.random() * 0.4
      const speed  = 0.3 + Math.random() * 1.2
      const radius = 3 + Math.random() * 4
      return {
        x: W / 2, y: H / 2,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        radius,
        color: COLORS[i % COLORS.length],
        life: 1,
        decay: 0.004 + Math.random() * 0.003,
      }
    })

    let started = false
    const start = () => { started = true }
    const t = setTimeout(start, 200)

    const draw = () => {
      ctx.clearRect(0, 0, W, H)
      if (!started) { animRef.current = requestAnimationFrame(draw); return }

      particles.forEach(p => {
        p.x  += p.vx
        p.y  += p.vy
        p.vx *= 0.997
        p.vy *= 0.997
        p.life -= p.decay
        if (p.life <= 0) {
          const angle = Math.random() * Math.PI * 2
          const speed = 0.3 + Math.random() * 1.2
          p.x = W / 2; p.y = H / 2
          p.vx = Math.cos(angle) * speed
          p.vy = Math.sin(angle) * speed
          p.life = 0.8 + Math.random() * 0.4
        }
        ctx.globalAlpha = p.life * 0.6
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.radius * p.life, 0, Math.PI * 2)
        ctx.fillStyle = p.color
        ctx.fill()
      })

      animRef.current = requestAnimationFrame(draw)
    }

    animRef.current = requestAnimationFrame(draw)
    return () => { cancelAnimationFrame(animRef.current); clearTimeout(t) }
  }, [run])

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none opacity-25"
    />
  )
}

const COMMAND_STEPS = [
  { cmd: 'git clone github.com/Sami9211/ThreatOrbit', delay: 0   },
  { cmd: 'cd ThreatOrbit && cp .env.example .env',     delay: 0.8 },
  { cmd: 'docker compose up -d',                           delay: 1.6 },
  { cmd: '✓ Threat API ready on :8000',                    delay: 2.8, isResult: true },
  { cmd: '✓ Log API ready on :8001',                       delay: 3.2, isResult: true },
]

function AnimatedTerminal({ inView }: { inView: boolean }) {
  const [visible, setVisible] = useState(0)

  useEffect(() => {
    if (!inView) return
    COMMAND_STEPS.forEach((step, i) => {
      const t = setTimeout(() => setVisible(i + 1), step.delay * 1000 + 400)
      return () => clearTimeout(t)
    })
  }, [inView])

  return (
    <div className="glass border border-white/8 rounded-xl p-4 font-mono text-xs leading-relaxed text-left">
      <div className="flex items-center gap-1.5 mb-3">
        <span className="w-2.5 h-2.5 rounded-full bg-threat/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-amber/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-safe/80" />
        <span className="ml-2 text-ink-500 text-[10px]">bash - threatorbit</span>
      </div>
      {COMMAND_STEPS.slice(0, visible).map((step, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, x: -8 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.3 }}
          className={step.isResult ? 'text-safe mb-0.5' : 'text-ink-300 mb-0.5'}
        >
          {!step.isResult && <span className="text-magenta mr-1.5">$</span>}
          {step.cmd}
        </motion.div>
      ))}
      {visible > 0 && visible < COMMAND_STEPS.length && (
        <span className="text-magenta cursor-blink" />
      )}
    </div>
  )
}

export default function CTA() {
  const ref    = useRef<HTMLElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  // Separate, non-sticky visibility for the canvas so the rAF loop pauses when
  // the section scrolls off-screen (and never starts under reduced-motion).
  const liveView = useInView(ref, { margin: '-80px' })
  const reduce   = useReducedMotion()
  const runBurst = liveView && !reduce

  return (
    <section ref={ref} id="cta" className="relative py-28 overflow-hidden">
      {/* Background glows */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[400px] rounded-full bg-magenta/8 blur-[120px]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[300px] rounded-full bg-violet/6 blur-[80px]" />
      </div>

      <div className="max-w-6xl mx-auto px-6">
        <Reveal variant="bloom" className="relative rounded-3xl overflow-hidden">
          <div className="absolute inset-0 bg-surface-2" />
          <div className="absolute inset-0 bg-grid-dim opacity-40" />
          <div className="absolute inset-0 plasma-mesh" />
          <div className="absolute inset-0 rounded-3xl border-animated" />
          <ParticleBurst run={runBurst} />

          <div className="relative px-8 py-16 lg:py-20 grid lg:grid-cols-2 gap-12 items-center">
            {/* Left: CTA content */}
            <div className="text-center lg:text-left">
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={inView ? { opacity: 1, scale: 1 } : {}}
                transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
                className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/3 border border-white/10 mb-8 mx-auto lg:mx-0"
              >
                <Logo size={36} />
              </motion.div>

              <motion.div
                initial={{ opacity: 0 }}
                animate={inView ? { opacity: 1 } : {}}
                transition={{ delay: 0.15 }}
                className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-magenta/20 bg-magenta/5 mb-5"
              >
                <Zap className="w-3 h-3 text-magenta" />
                <span className="text-xs text-magenta tracking-wide">Deploy in under 5 minutes</span>
              </motion.div>

              <motion.h2
                initial={{ opacity: 0, y: 20 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ delay: 0.2, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
                className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight"
              >
                Ready to secure your
                <br />
                <span className="text-gradient-animate">infrastructure?</span>
              </motion.h2>

              <motion.p
                initial={{ opacity: 0, y: 16 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ delay: 0.3 }}
                className="text-ink-300 text-base max-w-md mx-auto lg:mx-0 mb-8"
              >
                Deploy ThreatOrbit in minutes with Docker. Connect your OSINT sources, point it at
                your logs, and push to OpenCTI - all with a single API key.
              </motion.p>

              <motion.div
                initial={{ opacity: 0, y: 16 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ delay: 0.4 }}
                className="flex flex-wrap items-center justify-center lg:justify-start gap-4"
              >
                <MagneticButton
                  href="/docs/docker-deploy"
                  className="px-7 py-3.5 rounded-xl bg-plasma text-white font-semibold text-sm transition-shadow duration-300 hover:shadow-magenta-lg"
                >
                  Deploy Now
                  <ArrowRight className="w-4 h-4" />
                </MagneticButton>
                <MagneticButton
                  href="https://github.com/Sami9211/ThreatOrbit"
                  className="px-7 py-3.5 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:border-white/25 hover:text-white transition-colors duration-300"
                >
                  <GithubIcon className="w-4 h-4" />
                  View on GitHub
                </MagneticButton>
              </motion.div>

              <motion.div
                initial={{ opacity: 0 }}
                animate={inView ? { opacity: 1 } : {}}
                transition={{ delay: 0.55 }}
                className="flex flex-wrap items-center justify-center lg:justify-start gap-5 mt-8"
              >
                {[
                  'Free & open source',
                  'Docker Compose',
                  'No vendor lock-in',
                ].map((item) => (
                  <div key={item} className="flex items-center gap-2 text-xs text-ink-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-safe" />
                    {item}
                  </div>
                ))}
              </motion.div>
            </div>

            {/* Right: animated terminal */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              animate={inView ? { opacity: 1, x: 0 } : {}}
              transition={{ delay: 0.35, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            >
              <AnimatedTerminal inView={inView} />

              <div className="mt-4 flex items-center gap-3">
                <Terminal className="w-3.5 h-3.5 text-ink-500 shrink-0" />
                <p className="text-xs text-ink-500">
                  Full compose file in{' '}
                  <a href="/docs/docker-deploy" className="text-magenta hover:underline">Docker Deploy guide</a>
                </p>
              </div>
            </motion.div>
          </div>
        </Reveal>
      </div>
    </section>
  )
}
