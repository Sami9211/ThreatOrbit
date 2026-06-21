'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import CountUp from '@/components/ui/CountUp'

type Stat = {
  num?: number
  prefix?: string
  suffix?: string
  decimals?: number
  text?: string
  label: string
  color: string
}

const STATS: Stat[] = [
  { num: 2.1, suffix: 'M+', decimals: 1, label: 'IOCs Ingested Daily', color: 'text-magenta' },
  { num: 5, label: 'OSINT Feed Sources', color: 'text-magenta' },
  { num: 4, label: 'Log Parsers', color: 'text-violet' },
  { num: 4, label: 'Anomaly Detectors', color: 'text-violet' },
  { text: 'STIX 2.1', label: 'Export Format', color: 'text-amber' },
  { num: 50, prefix: '<', suffix: 'ms', label: 'API Response Time', color: 'text-safe' },
]

function StatValue({ s, className }: { s: Stat; className: string }) {
  if (s.text) return <span className={className}>{s.text}</span>
  return (
    <CountUp
      value={s.num ?? 0}
      prefix={s.prefix}
      suffix={s.suffix}
      decimals={s.decimals ?? 0}
      className={className}
    />
  )
}

export default function StatsBar() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} className="relative py-12 border-y border-white/5 bg-surface overflow-hidden">
      <div className="hidden md:grid grid-cols-6 site-container">
        {STATS.map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, delay: i * 0.07 }}
            className="group flex flex-col items-center gap-1 px-4 text-center border-r border-white/5 last:border-0 transition-transform duration-300 hover:-translate-y-1"
          >
            <StatValue s={stat} className={`font-display text-2xl font-bold ${stat.color} transition-transform duration-300 group-hover:scale-110`} />
            <span className="text-xs text-ink-400 group-hover:text-ink-200 transition-colors">{stat.label}</span>
          </motion.div>
        ))}
      </div>

      <div className="md:hidden overflow-hidden">
        <div className="flex gap-8 animate-ticker whitespace-nowrap" style={{ width: 'max-content' }}>
          {[...STATS, ...STATS].map((stat, i) => (
            <div key={i} className="flex items-center gap-3 shrink-0">
              <span className={`font-display text-lg font-bold ${stat.color}`}>
                {stat.text ?? `${stat.prefix ?? ''}${stat.num}${stat.suffix ?? ''}`}
              </span>
              <span className="text-xs text-ink-400">{stat.label}</span>
              <span className="text-ink-600 ml-2">/</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
