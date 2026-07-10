'use client'

import { useRef } from 'react'
import dynamic from 'next/dynamic'
import {
  motion, useScroll, useTransform, useSpring,
  useMotionValue, type MotionValue,
} from 'framer-motion'

import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

const OrbitalScene = dynamic(() => import('@/components/effects/OrbitalScene'), {
  ssr: false,
  loading: () => <ScenePlaceholder />,
})

// Preload the OrbitalScene chunk before the section is reached so the user
// never waits 5-10s for the WebGL canvas to appear.
if (typeof window !== 'undefined') {
  // Fire after the page has settled (fonts, images, hero loaded)
  const preload = () => import('@/components/effects/OrbitalScene')
  if (document.readyState === 'complete') {
    setTimeout(preload, 800)
  } else {
    window.addEventListener('load', () => setTimeout(preload, 800), { once: true })
  }
}

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

  /* spring-smoothed progress for text beats */
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 100, damping: 28, restDelta: 0.001,
  })

  /* 0 → 360° mapped from scroll - drives the orbital group Y rotation.
     Derived from the SPRING-smoothed progress, not raw scrollYProgress:
     wheel scrolling lands in ~100px steps, and mapping those steps straight
     to rotation made the planet snap through discrete angles instead of
     easing between them. */
  const scrollDeg = useTransform(smoothProgress, [0, 1], [0, 360])

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

        {/* Real 3D orbital - a planet circled by rings of orbiting dots.
           Sized generously so the outermost orbit never reaches the canvas
           edge (which would hard-clip it into a visible box). */}
        <div className="w-[min(94vw,760px)] aspect-square relative" aria-hidden>
          <OrbitalScene scrollY={scrollDeg} mouseX={mouseX} mouseY={mouseY} />
        </div>

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
            Five OSINT sources stream in continuously, deduplicated, trust-scored, and enriched into
            one unified library of indicators.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.44, 0.62]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#7A3CFF' }}>02 / SIEM</p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It detects.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Every log line passes through four detectors - pattern, statistical, machine learning, and
            temporal - surfacing the anomalies that matter.
          </p>
        </Beat>

        <Beat progress={smoothProgress} range={[0.66, 0.82]} className="top-[14%]">
          <p className="text-xs tracking-[0.3em] uppercase mb-3" style={{ color: '#FFB23E' }}>03 / SOAR</p>
          <h3 className="font-display text-3xl md:text-5xl font-bold text-white mb-3">It responds.</h3>
          <p className="text-ink-300 text-lg max-w-xl mx-auto">
            Findings are bundled as STIX 2.1 and pushed straight to OpenCTI, turning raw signal into
            coordinated action automatically.
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
