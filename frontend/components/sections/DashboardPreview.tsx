'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { TrendingUp, AlertTriangle, CheckCircle, Clock, Activity } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'

const CHART_BARS = [18, 32, 24, 45, 29, 52, 38, 61, 42, 55, 48, 70, 39, 58, 66, 44, 73, 51, 65, 80]

const KPIS = [
  { icon: TrendingUp, label: 'IOCs Today', value: '14,382', delta: '+12%', color: '#FF2E97' },
  { icon: AlertTriangle, label: 'Active Threats', value: '47', delta: '-3 since yesterday', color: '#FF4D6D' },
  { icon: CheckCircle, label: 'Jobs Complete', value: '128', delta: '100% success', color: '#34F5C5' },
  { icon: Clock, label: 'Avg Analysis', value: '340ms', delta: 'p95 < 800ms', color: '#7A3CFF' },
]

export default function DashboardPreview() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} className="py-28 bg-surface overflow-hidden">
      <div className="max-w-7xl mx-auto px-6">
        <Reveal variant="rise" className="text-center mb-14">
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4">
            Everything visible.
            <br />
            <span className="text-gradient-magenta">Nothing hidden.</span>
          </h2>
          <p className="text-ink-400 max-w-lg mx-auto">
            Full observability across both APIs: IOC counts, anomaly rates, job statuses, and push
            health at a glance.
          </p>
        </Reveal>

        <Reveal variant="bloom" delay={0.1} className="relative">
          <div className="absolute -inset-8 bg-magenta/4 rounded-3xl blur-2xl pointer-events-none" />

          <div className="relative glass border border-white/8 rounded-3xl overflow-hidden shadow-[0_0_0_1px_rgba(255,46,151,0.06),0_32px_80px_rgba(0,0,0,0.6)]">
            <div className="flex items-center gap-2 px-5 py-3.5 border-b border-white/5 bg-white/2">
              <span className="w-2.5 h-2.5 rounded-full bg-threat/70" />
              <span className="w-2.5 h-2.5 rounded-full bg-amber/70" />
              <span className="w-2.5 h-2.5 rounded-full bg-safe/70" />
              <span className="ml-3 text-[11px] text-ink-500 font-mono">ThreatOrbit · Dashboard</span>
              <span className="ml-auto flex items-center gap-1.5 text-[10px] text-safe">
                <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                Live
              </span>
            </div>

            <div className="p-6 grid grid-cols-1 md:grid-cols-4 gap-4">
              {KPIS.map((kpi, i) => {
                const Icon = kpi.icon
                return (
                  <motion.div
                    key={kpi.label}
                    initial={{ opacity: 0, y: 16 }}
                    animate={inView ? { opacity: 1, y: 0 } : {}}
                    transition={{ delay: 0.25 + i * 0.07 }}
                    className="glass border border-white/6 rounded-2xl p-4"
                  >
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center mb-3"
                      style={{ color: kpi.color, backgroundColor: `${kpi.color}1a` }}
                    >
                      <Icon className="w-4 h-4" strokeWidth={1.5} />
                    </div>
                    <div className="font-display text-2xl font-bold mb-1" style={{ color: kpi.color }}>
                      {kpi.value}
                    </div>
                    <div className="text-xs text-ink-400">{kpi.label}</div>
                    <div className="text-[10px] text-ink-500 mt-1">{kpi.delta}</div>
                  </motion.div>
                )
              })}
            </div>

            <div className="px-6 pb-6">
              <div className="glass border border-white/6 rounded-2xl p-5">
                <div className="flex items-center justify-between mb-5">
                  <div>
                    <div className="text-sm font-semibold text-white">IOC Ingestion Rate</div>
                    <div className="text-xs text-ink-500 mt-0.5">Last 20 hours</div>
                  </div>
                  <Activity className="w-4 h-4 text-ink-500" strokeWidth={1.5} />
                </div>

                <div className="flex items-end gap-1.5 h-24">
                  {CHART_BARS.map((h, i) => (
                    <motion.div
                      key={i}
                      initial={{ scaleY: 0 }}
                      animate={inView ? { scaleY: 1 } : {}}
                      transition={{ delay: 0.5 + i * 0.03, duration: 0.4, ease: 'easeOut' }}
                      className="flex-1 rounded-sm"
                      style={{
                        height: `${h}%`,
                        background:
                          h > 60
                            ? 'linear-gradient(180deg, #FF2E97, #7A3CFF)'
                            : h > 40
                            ? 'rgba(255,46,151,0.55)'
                            : 'rgba(122,60,255,0.4)',
                        transformOrigin: 'bottom',
                      }}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  )
}
