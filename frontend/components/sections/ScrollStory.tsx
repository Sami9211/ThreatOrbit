'use client'

import { useRef } from 'react'
import { motion, useScroll, useTransform, type MotionValue } from 'framer-motion'

/* A beat of background narrative that fades through its scroll window. */
function Beat({
  progress,
  range,
  yFrom = 40,
  children,
  className = '',
}: {
  progress: MotionValue<number>
  range: [number, number]
  yFrom?: number
  children: React.ReactNode
  className?: string
}) {
  const [start, end] = range
  const pad = 0.05
  const opacity = useTransform(progress, [start - pad, start, end, end + pad], [0, 1, 1, 0])
  const y = useTransform(progress, [start - pad, start, end, end + pad], [yFrom, 0, 0, -yFrom])
  return (
    <motion.div style={{ opacity, y }} className={`absolute inset-x-0 px-6 ${className}`}>
      <div className="max-w-3xl mx-auto text-center">{children}</div>
    </motion.div>
  )
}

/* The orbital object at the centre of the stage, driven by scroll. */
function OrbitalStage({ progress }: { progress: MotionValue<number> }) {
  const scale = useTransform(progress, [0, 0.5, 1], [0.72, 1.05, 1.3])
  const rotate = useTransform(progress, [0, 1], [0, 200])

  // Each ring brightens during its narrative beat.
  const cti = useTransform(progress, [0.18, 0.3, 0.42], [0.25, 1, 0.45])
  const siem = useTransform(progress, [0.42, 0.54, 0.66], [0.25, 1, 0.45])
  const soar = useTransform(progress, [0.66, 0.78, 0.9], [0.25, 1, 0.45])
  const coreGlow = useTransform(progress, [0, 0.85, 1], [0.4, 0.6, 1])

  return (
    <motion.div
      style={{ scale, rotate }}
      className="relative w-[min(80vw,560px)] aspect-square"
    >
      <svg viewBox="0 0 400 400" className="w-full h-full" fill="none">
        <defs>
          <radialGradient id="story-core" cx="50%" cy="45%" r="60%">
            <stop offset="0%" stopColor="#FFD08A" />
            <stop offset="40%" stopColor="#FF2E97" />
            <stop offset="100%" stopColor="#7A3CFF" />
          </radialGradient>
        </defs>

        {/* CTI ring */}
        <motion.g style={{ opacity: cti }}>
          <ellipse cx="200" cy="200" rx="180" ry="64" stroke="#FF2E97" strokeWidth="1.5" transform="rotate(0 200 200)" />
          <circle cx="380" cy="200" r="5" fill="#FF2E97" />
        </motion.g>
        {/* SIEM ring */}
        <motion.g style={{ opacity: siem }}>
          <ellipse cx="200" cy="200" rx="180" ry="64" stroke="#7A3CFF" strokeWidth="1.5" transform="rotate(60 200 200)" />
          <circle cx="200" cy="20" r="5" fill="#7A3CFF" transform="rotate(60 200 200)" />
        </motion.g>
        {/* SOAR ring */}
        <motion.g style={{ opacity: soar }}>
          <ellipse cx="200" cy="200" rx="180" ry="64" stroke="#FFB23E" strokeWidth="1.5" transform="rotate(120 200 200)" />
          <circle cx="200" cy="380" r="5" fill="#FFB23E" transform="rotate(120 200 200)" />
        </motion.g>

        {/* Shielded hexagon core */}
        <motion.path
          style={{ opacity: coreGlow }}
          d="M200 150 L243 175 L243 225 L200 250 L157 225 L157 175 Z"
          fill="url(#story-core)"
        />
        <path
          d="M200 150 L243 175 L243 225 L200 250 L157 225 L157 175 Z"
          fill="url(#story-core)"
          opacity="0.3"
          style={{ filter: 'blur(14px)' }}
        />
      </svg>

      {/* Soft plasma halo */}
      <div className="absolute inset-0 -z-10 rounded-full blur-3xl bg-magenta/10" />
    </motion.div>
  )
}

export default function ScrollStory() {
  const ref = useRef<HTMLElement>(null)
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start start', 'end end'],
  })

  return (
    <section ref={ref} className="relative" style={{ height: '460vh' }}>
      <div className="sticky top-0 h-screen overflow-hidden flex items-center justify-center bg-bg">
        {/* Ambient background */}
        <div className="absolute inset-0 plasma-mesh opacity-50" />
        <div className="absolute inset-0 bg-grid-dim opacity-20" />

        {/* Central object */}
        <OrbitalStage progress={scrollYProgress} />

        {/* Narrative beats layered over the object */}
        <Beat progress={scrollYProgress} range={[0.0, 0.14]} className="top-[16%]">
          <p className="text-xs tracking-[0.3em] text-magenta uppercase mb-4">This is ThreatOrbit</p>
          <h2 className="font-display text-4xl md:text-6xl font-bold text-white leading-tight">
            A Super SOC,
            <br />
            <span className="text-gradient-plasma">in one platform.</span>
          </h2>
        </Beat>

        <Beat progress={scrollYProgress} range={[0.2, 0.38]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FF2E97' }}>
            01 / Threat Intelligence
          </p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It ingests.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Five OSINT sources stream in continuously, deduplicated, trust-scored, and enriched into
            one unified library of indicators.
          </p>
        </Beat>

        <Beat progress={scrollYProgress} range={[0.44, 0.62]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#7A3CFF' }}>
            02 / SIEM
          </p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It detects.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Every log line passes through four detectors, pattern, statistical, machine learning, and
            temporal, surfacing the anomalies that matter.
          </p>
        </Beat>

        <Beat progress={scrollYProgress} range={[0.66, 0.82]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FFB23E' }}>
            03 / SOAR
          </p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It responds.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Findings are bundled as STIX 2.1 and pushed straight to OpenCTI, turning raw signal into
            coordinated action automatically.
          </p>
        </Beat>

        <Beat progress={scrollYProgress} range={[0.88, 1.0]} className="top-[16%]">
          <h2 className="font-display text-4xl md:text-6xl font-bold text-white leading-tight mb-4">
            One core.
            <br />
            <span className="text-gradient-animate">Total visibility.</span>
          </h2>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            CTI, SIEM, and SOAR, locked in orbit around a single source of truth.
          </p>
        </Beat>

        {/* Progress hint */}
        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-2 text-[10px] text-ink-500 uppercase tracking-widest">
          <span className="w-1.5 h-1.5 rounded-full bg-magenta animate-pulse" />
          Keep scrolling
        </div>
      </div>
    </section>
  )
}
