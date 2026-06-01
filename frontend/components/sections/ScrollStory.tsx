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

/* ─── Egg-shaped orbital ring ────────────────────────────────────── */
/* A flat ellipse (oval). Each ring carries a different angle via its
   rotateZ value, so the set looks like overlapping orbits — atom style.
   A node dot rides each oval's edge.                                   */
function Ring({ color, rotateZ, opacity, label }: {
  color: string
  rotateZ: MotionValue<number>
  opacity: MotionValue<number>
  label: string
}) {
  return (
    <motion.div
      aria-label={label}
      style={{
        position: 'absolute',
        /* wide + short = egg/oval orbit path */
        left: '2%', right: '2%', top: '32%', bottom: '32%',
        borderRadius: '50%',
        border: `1.5px solid ${color}`,
        rotate: rotateZ,
        opacity,
      }}
    >
      {/* node riding the oval's edge */}
      <div style={{
        position: 'absolute', right: -5, top: '50%',
        transform: 'translateY(-50%)',
        width: 9, height: 9, borderRadius: '50%',
        background: color,
        boxShadow: `0 0 14px 3px ${color}88, 0 0 4px ${color}`,
      }} />
    </motion.div>
  )
}

/* ─── Simple hexagon that spins in 2D ────────────────────────────── */
function HexCore({ opacity, rotate }: { opacity: MotionValue<number>; rotate: MotionValue<number> }) {
  return (
    <motion.div style={{
      position: 'absolute', inset: '30%',
      opacity,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <motion.svg
        viewBox="0 0 100 100"
        style={{ width: '100%', height: '100%', rotate }}
      >
        <defs>
          <radialGradient id="hfill" cx="40%" cy="35%" r="70%">
            <stop offset="0%"   stopColor="#ffffff" stopOpacity="0.9" />
            <stop offset="30%"  stopColor="#FF2E97" />
            <stop offset="70%"  stopColor="#7A3CFF" />
            <stop offset="100%" stopColor="#2D0553" />
          </radialGradient>
          <linearGradient id="hsheen" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"  stopColor="rgba(255,255,255,0.30)" />
            <stop offset="50%" stopColor="rgba(255,255,255,0.00)" />
          </linearGradient>
        </defs>
        {/* Glow */}
        <path d="M50 8 L87 29 L87 71 L50 92 L13 71 L13 29 Z"
          fill="url(#hfill)" opacity="0.2"
          style={{ filter: 'blur(10px)', transform: 'scale(1.18)', transformOrigin: '50px 50px' }} />
        {/* Body */}
        <path d="M50 8 L87 29 L87 71 L50 92 L13 71 L13 29 Z" fill="url(#hfill)" />
        {/* Sheen */}
        <path d="M50 8 L87 29 L50 50 Z" fill="url(#hsheen)" />
        {/* Inner ring */}
        <path d="M50 22 L76 36 L76 64 L50 78 L24 64 L24 36 Z"
          fill="none" stroke="rgba(255,255,255,0.15)" strokeWidth="0.8" />
        {/* Centre dot */}
        <circle cx="50" cy="50" r="4" fill="rgba(255,255,255,0.55)" />
      </motion.svg>

      {/* Halo */}
      <div style={{
        position: 'absolute', inset: '-40%', borderRadius: '50%', zIndex: -1,
        background: 'radial-gradient(circle, rgba(255,46,151,0.18) 0%, rgba(122,60,255,0.10) 45%, transparent 70%)',
        filter: 'blur(16px)', pointerEvents: 'none',
      }} />
    </motion.div>
  )
}

/* ─── Orbital stage ──────────────────────────────────────────────── */
function OrbitalStage({ progress, hexRotate, mouseX, mouseY }: {
  progress: MotionValue<number>
  hexRotate: MotionValue<number>
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const sp    = { stiffness: 55, damping: 18 }
  const tiltX = useSpring(useTransform(mouseY, [-0.5, 0.5], [ 16, -16]), sp)
  const tiltY = useSpring(useTransform(mouseX, [-0.5, 0.5], [-16,  16]), sp)

  const scale     = useTransform(progress, [0, 0.5, 1], [0.72, 1.05, 1.3])
  const scrollRot = useTransform(progress, [0, 1], [0, 360])

  /* Five overlapping oval orbits, evenly spread 36° apart, all spinning */
  const r1 = useTransform(scrollRot, v => v)
  const r2 = useTransform(scrollRot, v => v + 36)
  const r3 = useTransform(scrollRot, v => v + 72)
  const r4 = useTransform(scrollRot, v => v + 108)
  const r5 = useTransform(scrollRot, v => v + 144)

  const cti  = useTransform(progress, [0.18, 0.3, 0.42], [0.32, 1, 0.42])
  const siem = useTransform(progress, [0.42, 0.54, 0.66], [0.32, 1, 0.42])
  const soar = useTransform(progress, [0.66, 0.78, 0.9 ], [0.32, 1, 0.42])
  const dim  = useTransform(progress, [0, 0.5, 1], [0.22, 0.5, 0.6])
  const core = useTransform(progress, [0, 0.85, 1], [0.5, 0.75, 1])

  return (
    <motion.div style={{ scale }} className="relative w-[min(80vw,520px)] aspect-square">
      <div style={{ perspective: '900px', width: '100%', height: '100%' }}>
        <motion.div style={{
          rotateX: tiltX, rotateY: tiltY,
          transformStyle: 'preserve-3d',
          width: '100%', height: '100%', position: 'relative',
        }}>
          <Ring color="#FF2E97" rotateZ={r1} opacity={cti}  label="CTI ring"   />
          <Ring color="#7A3CFF" rotateZ={r2} opacity={siem} label="SIEM ring"  />
          <Ring color="#FFB23E" rotateZ={r3} opacity={soar} label="SOAR ring"  />
          <Ring color="#2DD4BF" rotateZ={r4} opacity={dim}  label="orbit four" />
          <Ring color="#FF6FB5" rotateZ={r5} opacity={dim}  label="orbit five" />
          <HexCore opacity={core} rotate={hexRotate} />
        </motion.div>
      </div>
      <div className="absolute inset-0 -z-10 rounded-full blur-3xl"
        style={{ background: 'radial-gradient(circle, rgba(255,46,151,0.07) 0%, rgba(122,60,255,0.07) 50%, transparent 70%)' }}
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

  const smoothProgress = useSpring(scrollYProgress, { stiffness: 100, damping: 28, restDelta: 0.001 })

  /* Hexagon does a slow 2D spin tied to scroll */
  const hexRotate = useTransform(smoothProgress, [0, 1], [0, 120])

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
          hexRotate={hexRotate}
          mouseX={mouseX}
          mouseY={mouseY}
        />

        <Beat progress={smoothProgress} range={[0.0, 0.14]} className="top-[16%]">
          <p className="text-xs tracking-[0.3em] text-magenta uppercase mb-4">This is ThreatOrbit</p>
          <h2 className="font-display text-4xl md:text-6xl font-bold text-white leading-tight">
            A Super SOC,<br /><span className="text-gradient-plasma">in one platform.</span>
          </h2>
        </Beat>

        <Beat progress={smoothProgress} range={[0.2, 0.38]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FF2E97' }}>01 / Threat Intelligence</p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It ingests.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Five OSINT sources stream in continuously, deduplicated, trust-scored, and enriched into one unified library of indicators.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.44, 0.62]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#7A3CFF' }}>02 / SIEM</p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It detects.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Every log line passes through four detectors — pattern, statistical, machine learning, and temporal — surfacing the anomalies that matter.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.66, 0.82]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FFB23E' }}>03 / SOAR</p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It responds.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Findings are bundled as STIX 2.1 and pushed straight to OpenCTI, turning raw signal into coordinated action automatically.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.88, 1.0]} className="top-[16%]">
          <h2 className="font-display text-4xl md:text-6xl font-bold text-white leading-tight mb-4">
            One core.<br /><span className="text-gradient-animate">Total visibility.</span>
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
