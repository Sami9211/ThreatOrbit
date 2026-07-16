'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { TrendingUp, AlertTriangle, CheckCircle, Clock } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'
import { usePerfProfile } from '@/lib/usePerf'

const INITIAL_BARS = [18, 32, 24, 45, 29, 52, 38, 61, 42, 55, 48, 70, 39, 58, 66, 44, 73, 51, 65, 80]

export default function DashboardPreview() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const chartRef = useRef<HTMLDivElement>(null)
  const chartView = useInView(chartRef, { margin: '-40px' })
  const { prefersReducedMotion } = usePerfProfile()

  // Live-shifting chart + ticking KPIs
  const [bars, setBars] = useState(INITIAL_BARS)
  const [iocs, setIocs] = useState(14382)
  const [threats, setThreats] = useState(47)
  const [jobs, setJobs] = useState(128)
  const [latency, setLatency] = useState(340)

  useEffect(() => {
    if (prefersReducedMotion || !chartView) return
    const t = setInterval(() => {
      setBars((prev) => [...prev.slice(1), 20 + Math.floor(Math.random() * 70)])
      setIocs((v) => v + 3 + Math.floor(Math.random() * 18))
      setThreats((v) => Math.max(12, v + (Math.random() < 0.5 ? 1 : -1)))
      setJobs((v) => v + (Math.random() < 0.4 ? 1 : 0))
      setLatency(() => 280 + Math.floor(Math.random() * 140))
    }, 1600)
    return () => clearInterval(t)
  }, [prefersReducedMotion, chartView])

  const KPIS = [
    { icon: TrendingUp,   label: 'IOCs Today',     value: iocs.toLocaleString(), delta: '+12% vs yesterday', color: '#FF2E97' },
    { icon: AlertTriangle,label: 'Active Threats',  value: String(threats),       delta: 'triaged live',       color: '#FF4D6D' },
    { icon: CheckCircle,  label: 'Jobs Complete',   value: String(jobs),          delta: '100% success',       color: '#34F5C5' },
    { icon: Clock,        label: 'Avg Analysis',    value: `${latency}ms`,        delta: 'p95 < 800ms',        color: '#7A3CFF' },
  ]

  return (
    <section ref={ref} className="py-28 bg-surface overflow-hidden">
      <div className="site-container">
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
                    <motion.div
                      key={kpi.value}
                      initial={{ opacity: 0.4, y: -3 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                      className="font-display text-2xl font-bold mb-1 tabular-nums"
                      style={{ color: kpi.color }}
                    >
                      {kpi.value}
                    </motion.div>
                    <div className="text-xs text-ink-400">{kpi.label}</div>
                    <div className="text-[10px] text-ink-500 mt-1">{kpi.delta}</div>
                  </motion.div>
                )
              })}
            </div>

            <div ref={chartRef} className="px-6 pb-6">
              <div className="glass border border-white/6 rounded-2xl p-5">
                <div className="flex items-center justify-between mb-5">
                  <div>
                    <div className="text-sm font-semibold text-white">IOC Ingestion Rate</div>
                    <div className="text-xs text-ink-500 mt-0.5">Live · rolling window</div>
                  </div>
                  <span className="flex items-center gap-1.5 text-[10px] text-safe">
                    <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                    real-time
                  </span>
                </div>

                <div className="flex items-end gap-1.5 h-24">
                  {bars.map((h, i) => (
                    <motion.div
                      key={i}
                      initial={inView ? { scaleY: 0 } : false}
                      animate={{ scaleY: 1, height: `${h}%` }}
                      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                      className="flex-1 rounded-xs"
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
