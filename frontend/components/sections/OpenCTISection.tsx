'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { GitMerge, Upload, BarChart2, CheckCircle2 } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'
import { usePerfProfile } from '@/lib/usePerf'

const INTEGRATIONS = [
  { label: 'STIX 2.1 bundles', status: 'active' },
  { label: 'OpenCTI GraphQL API', status: 'active' },
  { label: 'Indicator sync', status: 'active' },
  { label: 'TLP classification', status: 'active' },
  { label: 'TAXII server export', status: 'planned' },
  { label: 'MISP integration', status: 'planned' },
]

const ENDPOINTS = [
  { endpoint: 'GET /opencti/status', label: 'Health check' },
  { endpoint: 'GET /opencti/indicators', label: 'Query indicators' },
  { endpoint: 'POST /opencti/push', label: 'Push bundle' },
]

export default function OpenCTISection() {
  const flowRef = useRef<HTMLDivElement>(null)
  const flowView = useInView(flowRef, { margin: '-60px' })
  const { prefersReducedMotion } = usePerfProfile()
  const [active, setActive] = useState(0)

  useEffect(() => {
    if (prefersReducedMotion || !flowView) return
    const t = setInterval(() => setActive((a) => (a + 1) % ENDPOINTS.length), 2000)
    return () => clearInterval(t)
  }, [prefersReducedMotion, flowView])

  const animateFlow = !prefersReducedMotion && flowView

  return (
    <section id="opencti" className="py-28 site-container">
      <Reveal variant="rise" className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <GitMerge className="w-3 h-3 text-ink-300" />
          <span className="text-xs text-ink-300 tracking-wide">OpenCTI Integration</span>
        </div>
        <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
          Your CTI platform,
          <br />
          <span className="text-gradient-magenta">supercharged.</span>
        </h2>
        <p className="text-ink-400 max-w-xl mx-auto text-lg">
          ThreatOrbit integrates natively with OpenCTI. Push enriched intelligence bundles, query
          existing indicators, and keep your platform synchronized automatically.
        </p>
      </Reveal>

      <div className="grid lg:grid-cols-3 gap-6">
        <Reveal variant="bloom" className="lg:col-span-2">
          <div ref={flowRef} className="glass border border-white/8 rounded-2xl p-8 relative overflow-hidden h-full">
            <div className="absolute inset-0 bg-grid-dim opacity-40" />

            <div className="relative flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="flex flex-col items-center gap-3">
                <motion.div
                  className="w-16 h-16 rounded-2xl bg-magenta/10 border border-magenta/20 flex items-center justify-center"
                  animate={animateFlow ? { boxShadow: ['0 0 0px #FF2E9700', '0 0 24px #FF2E9755', '0 0 0px #FF2E9700'] } : {}}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <BarChart2 className="w-7 h-7 text-magenta" strokeWidth={1.5} />
                </motion.div>
                <div className="text-sm font-semibold text-white">ThreatOrbit</div>
                <div className="text-[10px] text-ink-500 text-center max-w-[100px]">
                  Ingestion and enrichment
                </div>
              </div>

              {/* Animated connection with a traveling STIX packet */}
              <div className="flex flex-col items-center gap-1 flex-1 max-w-[220px]">
                <div className="relative w-full h-6 flex items-center">
                  <div className="absolute inset-x-0 h-px bg-gradient-to-r from-magenta/30 via-white/15 to-violet/30" />
                  {animateFlow && (
                    <motion.div
                      className="absolute w-7 h-7 -mt-px rounded-lg bg-magenta/15 border border-magenta/40 flex items-center justify-center"
                      style={{ top: '50%', translateY: '-50%' }}
                      initial={{ left: '0%', opacity: 0 }}
                      animate={{ left: ['0%', '100%'], opacity: [0, 1, 1, 0] }}
                      transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
                    >
                      <Upload className="w-3.5 h-3.5 text-magenta" />
                    </motion.div>
                  )}
                </div>
                <div className="flex items-center gap-2 text-[10px] text-ink-500 mt-1">
                  <Upload className="w-3 h-3 text-magenta" />
                  STIX 2.1 bundle
                </div>
              </div>

              <div className="flex flex-col items-center gap-3">
                <motion.div
                  className="w-16 h-16 rounded-2xl bg-violet/10 border border-violet/20 flex items-center justify-center"
                  animate={animateFlow ? { boxShadow: ['0 0 0px #7A3CFF00', '0 0 24px #7A3CFF55', '0 0 0px #7A3CFF00'] } : {}}
                  transition={{ duration: 2, repeat: Infinity, delay: 1 }}
                >
                  <GitMerge className="w-7 h-7 text-violet" strokeWidth={1.5} />
                </motion.div>
                <div className="text-sm font-semibold text-white">OpenCTI</div>
                <div className="text-[10px] text-ink-500 text-center max-w-[100px]">CTI platform</div>
              </div>
            </div>

            <div className="relative mt-8 grid grid-cols-1 sm:grid-cols-3 gap-3">
              {ENDPOINTS.map((item, i) => {
                const live = active === i && animateFlow
                return (
                  <motion.div
                    key={item.endpoint}
                    animate={{
                      borderColor: live ? 'rgba(255,46,151,0.4)' : 'rgba(255,255,255,0.06)',
                      backgroundColor: live ? 'rgba(255,46,151,0.06)' : 'rgba(255,255,255,0.03)',
                    }}
                    transition={{ duration: 0.4 }}
                    className="border rounded-xl p-3"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="font-mono text-[10px] text-magenta">{item.endpoint}</div>
                      {live && <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />}
                    </div>
                    <div className="text-[10px] text-ink-500">{item.label}</div>
                  </motion.div>
                )
              })}
            </div>
          </div>
        </Reveal>

        <Reveal variant="bloom" delay={0.1}>
          <div className="glass border border-white/8 rounded-2xl p-6 flex flex-col h-full">
            <h3 className="font-display font-semibold text-white mb-5">Integrations</h3>
            <div className="space-y-3 flex-1">
              {INTEGRATIONS.map((item) => (
                <div key={item.label} className="flex items-center gap-3">
                  <CheckCircle2
                    className={`w-4 h-4 shrink-0 ${item.status === 'active' ? 'text-safe' : 'text-ink-600'}`}
                    strokeWidth={1.5}
                  />
                  <span className={`text-sm ${item.status === 'active' ? 'text-ink-200' : 'text-ink-500'}`}>
                    {item.label}
                  </span>
                  {item.status === 'planned' && (
                    <span className="ml-auto text-[9px] text-ink-500 border border-white/10 px-1.5 py-0.5 rounded-full">
                      Soon
                    </span>
                  )}
                </div>
              ))}
            </div>

            <div className="mt-6 pt-5 border-t border-white/5">
              <div className="text-xs text-ink-400 mb-3">Deploy OpenCTI locally</div>
              <div className="font-mono text-[11px] text-ink-300 bg-white/3 border border-white/6 rounded-lg p-3">
                <div className="text-ink-500">$ docker compose up -d</div>
                <div className="text-safe mt-0.5">threatorbit ready</div>
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  )
}
