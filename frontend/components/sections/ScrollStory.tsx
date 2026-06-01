'use client'

import { useRef } from 'react'
import dynamic from 'next/dynamic'
import {
  motion, useScroll, useTransform, useSpring,
  useMotionValue, type MotionValue,
} from 'framer-motion'

/* Three.js hex prism — client-only (no SSR) */
const HexPrism = dynamic(() => import('@/components/effects/HexPrism'), { ssr: false })

/* ─── Narrative beat ─────────────────────────────────────────────── */
function Beat({
  progress, range, yFrom = 40, children, className = '',
}: {
  progress: MotionValue<number>
  range: [number, number]
  yFrom?: number
  children: React.ReactNode
  className?: string
}) {
  const [s, e] = range
  const pad = 0.05
  const opacity = useTransform(progress, [s - pad, s, e, e + pad], [0, 1, 1, 0])
  const y       = useTransform(progress, [s - pad, s, e, e + pad], [yFrom, 0, 0, -yFrom])
  return (
    <motion.div style={{ opacity, y }} className={`absolute inset-x-0 px-6 ${className}`}>
      <div className="max-w-3xl mx-auto text-center">{children}</div>
    </motion.div>
  )
}

/* ─── CSS-3D orbital ring ────────────────────────────────────────── */
function Ring({
  color, rotateZ, opacity, label,
}: {
  color: string
  rotateZ: MotionValue<number>
  opacity: MotionValue<number>
  label: string
}) {
  return (
    <motion.div
      aria-label={label}
      style={{
        position: 'absolute', inset: '6%',
        borderRadius: '50%',
        border: `1.5px solid ${color}`,
        rotateX: 72,
        rotateZ,
        opacity,
        transformStyle: 'preserve-3d',
      }}
    >
      <div style={{
        position: 'absolute', right: -5, top: '50%',
        transform: 'translateY(-50%)',
        width: 10, height: 10, borderRadius: '50%',
        background: color,
        boxShadow: `0 0 14px 3px ${color}88, 0 0 4px ${color}`,
      }} />
    </motion.div>
  )
}

/* ─── Orbital stage (rings only — hex handled by WebGL) ──────────── */
function OrbitalStage({
  progress, smoothProgress, mouseX, mouseY,
}: {
  progress: MotionValue<number>
  smoothProgress: MotionValue<number>
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const sp = { stiffness: 55, damping: 18 }
  const tiltX = useSpring(useTransform(mouseY, [-0.5, 0.5], [ 20, -20]), sp)
  const tiltY = useSpring(useTransform(mouseX, [-0.5, 0.5], [-20,  20]), sp)

  const scale     = useTransform(progress, [0, 0.5, 1], [0.72, 1.05, 1.3])
  const scrollRot = useTransform(progress, [0, 1], [0, 360])

  const r1 = useTransform(scrollRot, v => v)
  const r2 = useTransform(scrollRot, v => v + 120)
  const r3 = useTransform(scrollRot, v => v + 240)

  const cti  = useTransform(progress, [0.18, 0.3, 0.42], [0.28, 1, 0.38])
  const siem = useTransform(progress, [0.42, 0.54, 0.66], [0.28, 1, 0.38])
  const soar = useTransform(progress, [0.66, 0.78, 0.9 ], [0.28, 1, 0.38])

  return (
    <motion.div
      style={{ scale }}
      className="relative w-[min(80vw,520px)] aspect-square"
    >
      {/* perspective on plain div so it doesn't fight Framer Motion */}
      <div style={{ perspective: '900px', width: '100%', height: '100%' }}>
        <motion.div style={{
          rotateX: tiltX, rotateY: tiltY,
          transformStyle: 'preserve-3d',
          width: '100%', height: '100%',
          position: 'relative',
        }}>
          <Ring color="#FF2E97" rotateZ={r1} opacity={cti}  label="CTI ring"  />
          <Ring color="#7A3CFF" rotateZ={r2} opacity={siem} label="SIEM ring" />
          <Ring color="#FFB23E" rotateZ={r3} opacity={soar} label="SOAR ring" />
        </motion.div>
      </div>

      {/* Ambient backdrop */}
      <div className="absolute inset-0 -z-10 rounded-full blur-3xl"
        style={{ background: 'radial-gradient(circle, rgba(255,46,151,0.08) 0%, rgba(122,60,255,0.08) 50%, transparent 70%)' }}
      />
    </motion.div>
  )
}

/* ─── Section ────────────────────────────────────────────────────── */
export default function ScrollStory() {
  const ref       = useRef<HTMLElement>(null)
  const stickyRef = useRef<HTMLDivElement>(null)
  const mouseX    = useMotionValue(0)
  const mouseY    = useMotionValue(0)

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start start', 'end end'],
  })

  /* Spring-smoothed — text beats stay smooth at any scroll speed */
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 28,
    restDelta: 0.001,
  })

  /* Hex prism spin: 0 → 360° over full scroll, driven by smooth progress */
  const hexRotY = useTransform(smoothProgress, [0, 1], [0, 360])

  const handleMove = (e: React.MouseEvent) => {
    const el = stickyRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    mouseX.set((e.clientX - r.left) / r.width  - 0.5)
    mouseY.set((e.clientY - r.top)  / r.height - 0.5)
  }
  const handleLeave = () => { mouseX.set(0); mouseY.set(0) }

  return (
    <section ref={ref} className="relative" style={{ height: '460vh' }}>
      <div
        ref={stickyRef}
        className="sticky top-0 h-screen overflow-hidden flex items-center justify-center bg-bg"
        onMouseMove={handleMove}
        onMouseLeave={handleLeave}
      >
        <div className="absolute inset-0 plasma-mesh opacity-50" />
        <div className="absolute inset-0 bg-grid-dim opacity-20" />

        {/* CSS 3D orbital rings */}
        <OrbitalStage
          progress={scrollYProgress}
          smoothProgress={smoothProgress}
          mouseX={mouseX}
          mouseY={mouseY}
        />

        {/* Real 3D hex prism — WebGL, transparent background, layered above rings */}
        <div
          className="absolute pointer-events-none"
          style={{ width: 'min(38vw, 220px)', height: 'min(38vw, 220px)', zIndex: 10 }}
        >
          <HexPrism scrollY={hexRotY} mouseX={mouseX} mouseY={mouseY} />
        </div>

        <Beat progress={smoothProgress} range={[0.0, 0.14]} className="top-[16%]">
          <p className="text-xs tracking-[0.3em] text-magenta uppercase mb-4">This is ThreatOrbit</p>
          <h2 className="font-display text-4xl md:text-6xl font-bold text-white leading-tight">
            A Super SOC,<br />
            <span className="text-gradient-plasma">in one platform.</span>
          </h2>
        </Beat>

        <Beat progress={smoothProgress} range={[0.2, 0.38]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FF2E97' }}>
            01 / Threat Intelligence
          </p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It ingests.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Five OSINT sources stream in continuously, deduplicated, trust-scored, and enriched into
            one unified library of indicators.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.44, 0.62]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#7A3CFF' }}>
            02 / SIEM
          </p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It detects.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Every log line passes through four detectors — pattern, statistical, machine learning, and
            temporal — surfacing the anomalies that matter.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.66, 0.82]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FFB23E' }}>
            03 / SOAR
          </p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It responds.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Findings are bundled as STIX 2.1 and pushed straight to OpenCTI, turning raw signal into
            coordinated action automatically.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.88, 1.0]} className="top-[16%]">
          <h2 className="font-display text-4xl md:text-6xl font-bold text-white leading-tight mb-4">
            One core.<br />
            <span className="text-gradient-animate">Total visibility.</span>
          </h2>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            CTI, SIEM, and SOAR locked in orbit around a single source of truth.
          </p>
        </Beat>

        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-2 text-[10px] text-ink-500 uppercase tracking-widest">
          <span className="w-1.5 h-1.5 rounded-full bg-magenta animate-pulse" />
          Keep scrolling
        </div>
      </div>
    </section>
  )
}
