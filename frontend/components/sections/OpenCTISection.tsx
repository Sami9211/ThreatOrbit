'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { GitMerge, Upload, BarChart2, CheckCircle2 } from 'lucide-react'

const INTEGRATIONS = [
  { label: 'STIX 2.1 bundles', status: 'active' },
  { label: 'OpenCTI GraphQL API', status: 'active' },
  { label: 'Indicator sync', status: 'active' },
  { label: 'TLP classification', status: 'active' },
  { label: 'TAXII server export', status: 'planned' },
  { label: 'MISP integration', status: 'planned' },
]

export default function OpenCTISection() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section id="opencti" ref={ref} className="py-28 max-w-7xl mx-auto px-6">
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={inView ? { opacity: 1, y: 0 } : {}}
        className="text-center mb-16"
      >
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <GitMerge className="w-3 h-3 text-slate-400" />
          <span className="text-xs text-slate-400 tracking-wide">OpenCTI Integration</span>
        </div>
        <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
          Your CTI platform,<br />
          <span className="text-gradient-cyan">supercharged.</span>
        </h2>
        <p className="text-slate-500 max-w-xl mx-auto text-lg">
          ThreatOrbit integrates natively with OpenCTI — push enriched intelligence bundles, query existing indicators, and keep your platform synchronized automatically.
        </p>
      </motion.div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Flow diagram */}
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2 glass border border-white/8 rounded-2xl p-8 relative overflow-hidden"
        >
          {/* Background grid */}
          <div className="absolute inset-0 bg-grid-dim opacity-40" />

          <div className="relative flex flex-col md:flex-row items-center justify-between gap-8">
            {/* ThreatOrbit box */}
            <div className="flex flex-col items-center gap-3">
              <div className="w-16 h-16 rounded-2xl bg-cyan/10 border border-cyan/20 flex items-center justify-center">
                <BarChart2 className="w-7 h-7 text-cyan" strokeWidth={1.5} />
              </div>
              <div className="text-sm font-semibold text-white">ThreatOrbit</div>
              <div className="text-[10px] text-slate-500 text-center max-w-[100px]">Ingestion &amp; enrichment</div>
            </div>

            {/* Arrow */}
            <div className="flex flex-col items-center gap-1">
              <div className="flex items-center gap-1">
                {[...Array(5)].map((_, i) => (
                  <motion.div
                    key={i}
                    className="w-1.5 h-1.5 rounded-full bg-cyan/40"
                    animate={{ opacity: [0.2, 1, 0.2] }}
                    transition={{ duration: 1.5, delay: i * 0.2, repeat: Infinity }}
                  />
                ))}
              </div>
              <div className="flex items-center gap-2 text-[10px] text-slate-500 mt-1">
                <Upload className="w-3 h-3 text-cyan" />
                STIX 2.1 bundle
              </div>
            </div>

            {/* OpenCTI box */}
            <div className="flex flex-col items-center gap-3">
              <div className="w-16 h-16 rounded-2xl bg-violet/10 border border-violet/20 flex items-center justify-center">
                <GitMerge className="w-7 h-7 text-violet" strokeWidth={1.5} />
              </div>
              <div className="text-sm font-semibold text-white">OpenCTI</div>
              <div className="text-[10px] text-slate-500 text-center max-w-[100px]">CTI platform</div>
            </div>
          </div>

          {/* API endpoints */}
          <div className="relative mt-8 grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              { endpoint: 'GET /opencti/status', label: 'Health check' },
              { endpoint: 'GET /opencti/indicators', label: 'Query indicators' },
              { endpoint: 'POST /opencti/push', label: 'Push bundle' },
            ].map((item) => (
              <div key={item.endpoint} className="bg-white/3 border border-white/6 rounded-xl p-3">
                <div className="font-mono text-[10px] text-cyan mb-1">{item.endpoint}</div>
                <div className="text-[10px] text-slate-500">{item.label}</div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Integration checklist */}
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.2 }}
          className="glass border border-white/8 rounded-2xl p-6 flex flex-col"
        >
          <h3 className="font-display font-semibold text-white mb-5">Integrations</h3>
          <div className="space-y-3 flex-1">
            {INTEGRATIONS.map((item) => (
              <div key={item.label} className="flex items-center gap-3">
                <CheckCircle2
                  className={`w-4 h-4 shrink-0 ${item.status === 'active' ? 'text-safe' : 'text-slate-700'}`}
                  strokeWidth={1.5}
                />
                <span className={`text-sm ${item.status === 'active' ? 'text-slate-300' : 'text-slate-600'}`}>
                  {item.label}
                </span>
                {item.status === 'planned' && (
                  <span className="ml-auto text-[9px] text-slate-600 border border-white/10 px-1.5 py-0.5 rounded-full">
                    Soon
                  </span>
                )}
              </div>
            ))}
          </div>

          <div className="mt-6 pt-5 border-t border-white/5">
            <div className="text-xs text-slate-500 mb-3">Deploy OpenCTI locally</div>
            <div className="font-mono text-[11px] text-slate-400 bg-white/3 border border-white/6 rounded-lg p-3">
              <div className="text-slate-600">$ </div>
              <div>docker compose up -d</div>
              <div className="text-safe mt-0.5">✓ threatorbit ready</div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
