'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Download, Cpu, ShieldCheck, Send } from 'lucide-react'

const STEPS = [
  {
    num: '01',
    icon: Download,
    title: 'Ingest',
    desc: 'POST /fetch triggers parallel ingestion across 5 OSINT sources. A job_id is returned immediately — no waiting.',
    detail: 'OTX · abuse.ch · RSS · Dark-web · Social OSINT',
    color: 'cyan',
  },
  {
    num: '02',
    icon: Cpu,
    title: 'Enrich',
    desc: 'Each IOC is enriched with VirusTotal reputation data, categorized, deduplicated, and stored with WAL-mode SQLite for concurrent reads.',
    detail: 'VirusTotal · Deduplication · WAL SQLite',
    color: 'violet',
  },
  {
    num: '03',
    icon: ShieldCheck,
    title: 'Analyze',
    desc: 'Log files pass through four detection layers: pattern matching, statistical baselines, ML models, and temporal correlation.',
    detail: 'Pattern · Statistical · ML · Temporal',
    color: 'cyan',
  },
  {
    num: '04',
    icon: Send,
    title: 'Export',
    desc: 'Bundle threats as STIX 2.1 objects and push directly to OpenCTI, or consume the REST API from your SIEM or automation platform.',
    detail: 'STIX 2.1 · OpenCTI · REST API',
    color: 'safe',
  },
]

const COLOR_MAP = {
  cyan: { line: 'from-cyan/30 to-cyan/5', num: 'text-cyan', icon: 'bg-cyan/10 border-cyan/20 text-cyan', dot: 'bg-cyan' },
  violet: { line: 'from-violet/30 to-violet/5', num: 'text-violet', icon: 'bg-violet/10 border-violet/20 text-violet', dot: 'bg-violet' },
  safe: { line: 'from-safe/30 to-safe/5', num: 'text-safe', icon: 'bg-safe/10 border-safe/20 text-safe', dot: 'bg-safe' },
}

export default function HowItWorks() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section id="how-it-works" ref={ref} className="py-28 bg-surface-2 overflow-hidden">
      <div className="max-w-7xl mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-20"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
            <span className="w-1.5 h-1.5 rounded-full bg-violet" />
            <span className="text-xs text-slate-400 tracking-wide">How It Works</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight">
            From raw data to<br />
            <span className="text-gradient-cyan">actionable intelligence.</span>
          </h2>
        </motion.div>

        {/* Step timeline */}
        <div className="relative">
          {/* Connector line (desktop) */}
          <div className="hidden lg:block absolute top-12 left-[calc(12.5%+1rem)] right-[calc(12.5%+1rem)] h-px bg-gradient-to-r from-transparent via-white/8 to-transparent" />

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {STEPS.map((step, i) => {
              const c = COLOR_MAP[step.color as keyof typeof COLOR_MAP]
              const Icon = step.icon
              return (
                <motion.div
                  key={step.num}
                  initial={{ opacity: 0, y: 36 }}
                  animate={inView ? { opacity: 1, y: 0 } : {}}
                  transition={{ duration: 0.6, delay: i * 0.12 }}
                  className="flex flex-col items-center text-center"
                >
                  {/* Icon circle */}
                  <div className={`relative w-14 h-14 rounded-2xl border flex items-center justify-center mb-5 z-10 ${c.icon}`}>
                    <Icon className="w-6 h-6" strokeWidth={1.5} />
                    {/* Glow ring */}
                    <div className={`absolute inset-0 rounded-2xl ${c.dot} opacity-10 blur-md`} />
                  </div>

                  <div className={`text-xs font-mono font-bold mb-2 tracking-widest ${c.num}`}>{step.num}</div>
                  <h3 className="font-display font-bold text-white text-xl mb-3">{step.title}</h3>
                  <p className="text-sm text-slate-500 leading-relaxed mb-4">{step.desc}</p>
                  <div className="text-[10px] text-slate-600 tracking-wide font-mono bg-white/3 border border-white/5 px-3 py-1.5 rounded-full">
                    {step.detail}
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>
      </div>
    </section>
  )
}
