'use client'

import { useEffect, useRef, useState } from 'react'
import dynamic from 'next/dynamic'
import { motion, useInView } from 'framer-motion'
import { Globe2, Activity, ShieldAlert } from 'lucide-react'
import { usePerfProfile } from '@/lib/usePerf'
import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

const ThreatGlobe = dynamic(() => import('@/components/effects/ThreatGlobe'), {
  ssr: false,
  loading: () => <ScenePlaceholder />,
})

const REGIONS = [
  { name: 'North America', pct: 34, color: '#FF2E97' },
  { name: 'Europe',        pct: 28, color: '#7A3CFF' },
  { name: 'Asia-Pacific',  pct: 23, color: '#FFB23E' },
  { name: 'Other',         pct: 15, color: '#2DD4BF' },
]

export default function GlobalThreatMap() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const liveRef = useRef<HTMLDivElement>(null)
  const liveView = useInView(liveRef, { margin: '-40px' })
  const { prefersReducedMotion } = usePerfProfile()

  const [attacks, setAttacks] = useState(48211)
  const [blocked, setBlocked] = useState(47998)

  useEffect(() => {
    if (prefersReducedMotion || !liveView) return
    const t = setInterval(() => {
      const inc = 1 + Math.floor(Math.random() * 6)
      setAttacks((a) => a + inc)
      setBlocked((b) => b + inc - (Math.random() < 0.15 ? 1 : 0))
    }, 1400)
    return () => clearInterval(t)
  }, [prefersReducedMotion, liveView])

  return (
    <section ref={ref} className="relative py-28 bg-bg overflow-hidden">
      <div className="absolute inset-0 plasma-mesh opacity-30 pointer-events-none" />
      <div className="absolute inset-0 bg-grid-dim opacity-10 pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-magenta/20 bg-magenta/5 mb-5">
            <Globe2 className="w-3 h-3 text-magenta" />
            <span className="text-xs text-magenta tracking-wide">Global Threat Telemetry</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight">
            Threats move worldwide.
            <br />
            <span className="text-gradient-plasma">So does your visibility.</span>
          </h2>
          <p className="text-ink-400 mt-4 max-w-xl mx-auto text-sm">
            Drag to spin the globe. Every arc is an indicator correlated across the OSINT mesh in real time.
          </p>
        </motion.div>

        <div ref={liveRef} className="grid lg:grid-cols-[1fr_1.3fr] gap-10 items-center">
          {/* Live stats */}
          <motion.div
            initial={{ opacity: 0, x: -24 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="space-y-5 order-2 lg:order-1"
          >
            <div className="grid grid-cols-2 gap-4">
              <div className="glass border border-white/8 rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="w-4 h-4 text-magenta" strokeWidth={1.5} />
                  <span className="text-[11px] text-ink-400 uppercase tracking-wider">Attacks today</span>
                </div>
                <div className="font-display text-2xl font-bold text-white tabular-nums">
                  {attacks.toLocaleString()}
                </div>
              </div>
              <div className="glass border border-white/8 rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert className="w-4 h-4 text-safe" strokeWidth={1.5} />
                  <span className="text-[11px] text-ink-400 uppercase tracking-wider">Blocked</span>
                </div>
                <div className="font-display text-2xl font-bold text-safe tabular-nums">
                  {blocked.toLocaleString()}
                </div>
              </div>
            </div>

            <div className="glass border border-white/8 rounded-2xl p-5">
              <div className="text-[11px] text-ink-400 uppercase tracking-wider mb-4">Origin distribution</div>
              <div className="space-y-3">
                {REGIONS.map((r, i) => (
                  <div key={r.name}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-ink-300">{r.name}</span>
                      <span className="text-ink-500 font-mono">{r.pct}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={inView ? { width: `${r.pct}%` } : {}}
                        transition={{ duration: 0.9, delay: 0.3 + i * 0.1, ease: [0.22, 1, 0.36, 1] }}
                        className="h-full rounded-full"
                        style={{ background: r.color }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Globe */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={inView ? { opacity: 1, scale: 1 } : {}}
            transition={{ duration: 0.9, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
            className="relative aspect-square w-full max-w-[520px] mx-auto order-1 lg:order-2"
          >
            <ThreatGlobe />
          </motion.div>
        </div>
      </div>
    </section>
  )
}
