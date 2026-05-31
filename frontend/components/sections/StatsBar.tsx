'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'

const STATS = [
  { value: '2.1M+', label: 'IOCs Ingested Daily', color: 'text-cyan' },
  { value: '5', label: 'OSINT Feed Sources', color: 'text-cyan' },
  { value: '4', label: 'Log Parsers', color: 'text-violet' },
  { value: '4', label: 'Anomaly Detectors', color: 'text-violet' },
  { value: 'STIX 2.1', label: 'Export Format', color: 'text-safe' },
  { value: '< 50ms', label: 'API Response Time', color: 'text-safe' },
]

export default function StatsBar() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} className="relative py-12 border-y border-white/5 bg-surface overflow-hidden">
      {/* ticker on small, grid on large */}
      <div className="hidden md:grid grid-cols-6 max-w-7xl mx-auto px-6">
        {STATS.map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, delay: i * 0.07 }}
            className="flex flex-col items-center gap-1 px-4 text-center border-r border-white/5 last:border-0"
          >
            <span className={`font-display text-2xl font-bold ${stat.color}`}>{stat.value}</span>
            <span className="text-xs text-slate-500">{stat.label}</span>
          </motion.div>
        ))}
      </div>

      {/* Mobile ticker */}
      <div className="md:hidden overflow-hidden">
        <div className="flex gap-8 animate-ticker whitespace-nowrap" style={{ width: 'max-content' }}>
          {[...STATS, ...STATS].map((stat, i) => (
            <div key={i} className="flex items-center gap-3 shrink-0">
              <span className={`font-display text-lg font-bold ${stat.color}`}>{stat.value}</span>
              <span className="text-xs text-slate-500">{stat.label}</span>
              <span className="text-slate-700 ml-2">·</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
