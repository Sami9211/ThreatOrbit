'use client'

import { useRef } from 'react'
import {
  motion, useScroll, useTransform, useSpring,
  useMotionValue, type MotionValue,
} from 'framer-motion'

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

/* ─── Single CSS-3D orbital ring ─────────────────────────────────── */
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

/* ─── 3D spinning hexagon core ───────────────────────────────────── */
function HexCore({
  opacity,
  rotateY,
}: {
  opacity: MotionValue<number>
  rotateY: MotionValue<number>
}) {
  return (
    <motion.div style={{
      position: 'absolute', inset: '30%',
      opacity,
      translateZ: 28,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      transformStyle: 'preserve-3d',
    }}>
      {/* Inner wrapper receives the Y-spin — uses the outer 900px perspective */}
      <motion.div style={{
        width: '100%', height: '100%',
        rotateY,
      }}>
        <svg viewBox="0 0 100 100" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
          <defs>
            <radialGradient id="hex3d-fill" cx="38%" cy="30%" r="72%">
              <stop offset="0%"   stopColor="rgba(255,255,255,0.95)" />
              <stop offset="22%"  stopColor="#FF2E97" />
              <stop offset="62%"  stopColor="#7A3CFF" />
              <stop offset="100%" stopColor="#2D0553" />
            </radialGradient>
            <linearGradient id="hex3d-sheen" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%"  stopColor="rgba(255,255,255,0.35)" />
              <stop offset="45%" stopColor="rgba(255,255,255,0.00)" />
            </linearGradient>
          </defs>

          {/* Outer glow layer */}
          <path
            d="M50 8 L87 29 L87 71 L50 92 L13 71 L13 29 Z"
            fill="url(#hex3d-fill)" opacity="0.22"
            style={{ filter: 'blur(12px)', transform: 'scale(1.15)', transformOrigin: '50px 50px' }}
          />
          {/* Main body */}
          <path d="M50 8 L87 29 L87 71 L50 92 L13 71 L13 29 Z" fill="url(#hex3d-fill)" />
          {/* Top-left bright facet */}
          <path d="M50 8 L87 29 L50 50 Z" fill="url(#hex3d-sheen)" />
          {/* Left dimmer facet */}
          <path d="M50 8 L13 29 L50 50 Z" fill="rgba(255,255,255,0.04)" />
          {/* Inner ring */}
          <path
            d="M50 20 L78 35 L78 65 L50 80 L22 65 L22 35 Z"
            fill="none" stroke="rgba(255,255,255,0.18)" strokeWidth="0.8"
          />
          {/* Center dot */}
          <circle cx="50" cy="50" r="4" fill="rgba(255,255,255,0.6)" />
        </svg>
      </motion.div>

      {/* Ambient halo */}
      <div style={{
        position: 'absolute', inset: '-50%',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(255,46,151,0.20) 0%, rgba(122,60,255,0.12) 40%, transparent 70%)',
        filter: 'blur(18px)',
        zIndex: -1,
        pointerEvents: 'none',
      }} />
    </motion.div>
  )
}

/* ─── Full 3D orbital stage ──────────────────────────────────────── */
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

  /* Hexagon spins in 3D as sections change — driven by smoothed progress */
  const hexRotY = useTransform(smoothProgress, [0, 1], [0, 360])

  const cti      = useTransform(progress, [0.18, 0.3, 0.42], [0.28, 1, 0.38])
  const siem     = useTransform(progress, [0.42, 0.54, 0.66], [0.28, 1, 0.38])
  const soar     = useTransform(progress, [0.66, 0.78, 0.9 ], [0.28, 1, 0.38])
  const coreGlow = useTransform(progress, [0, 0.85, 1], [0.55, 0.72, 1])

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
          <HexCore opacity={coreGlow} rotateY={hexRotY} />
        </motion.div>
      </div>

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

  /* Spring-smoothed progress — text beats stay smooth regardless of scroll speed */
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 28,
    restDelta: 0.001,
  })

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

        <OrbitalStage
          progress={scrollYProgress}
          smoothProgress={smoothProgress}
          mouseX={mouseX}
          mouseY={mouseY}
        />

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
