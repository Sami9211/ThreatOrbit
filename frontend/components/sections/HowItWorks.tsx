'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Download, Cpu, ShieldCheck, Send } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'

const STEPS = [
  {
    num: '01',
    icon: Download,
    title: 'Ingest',
    desc: 'POST /fetch triggers parallel ingestion across five OSINT sources. A job_id is returned immediately, so nothing blocks.',
    detail: 'OTX / abuse.ch / RSS / Dark-web / Social OSINT',
    color: '#FF2E97',
  },
  {
    num: '02',
    icon: Cpu,
    title: 'Enrich',
    desc: 'Each IOC is enriched with VirusTotal reputation data, categorized, deduplicated, and stored in WAL-mode SQLite for concurrent reads.',
    detail: 'VirusTotal / Deduplication / WAL SQLite',
    color: '#7A3CFF',
  },
  {
    num: '03',
    icon: ShieldCheck,
    title: 'Analyze',
    desc: 'Log files pass through four detection layers: pattern matching, statistical baselines, ML models, and temporal correlation.',
    detail: 'Pattern / Statistical / ML / Temporal',
    color: '#FFB23E',
  },
  {
    num: '04',
    icon: Send,
    title: 'Export',
    desc: 'Bundle threats as STIX 2.1 objects and push directly to OpenCTI, or consume the REST API from your SIEM or automation platform.',
    detail: 'STIX 2.1 / OpenCTI / REST API',
    color: '#34F5C5',
  },
]

function Step({ step, index }: { step: (typeof STEPS)[number]; index: number }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const Icon = step.icon

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 40, scale: 0.92 }}
      animate={inView ? { opacity: 1, y: 0, scale: 1 } : {}}
      transition={{ duration: 0.7, delay: index * 0.12, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col items-center text-center"
    >
      <div
        className="relative w-14 h-14 rounded-2xl border flex items-center justify-center mb-5 z-10"
        style={{ color: step.color, backgroundColor: `${step.color}1a`, borderColor: `${step.color}33` }}
      >
        <Icon className="w-6 h-6" strokeWidth={1.5} />
        <div
          className="absolute inset-0 rounded-2xl opacity-20 blur-md"
          style={{ backgroundColor: step.color }}
        />
      </div>
      <div className="text-xs font-mono font-bold mb-2 tracking-widest" style={{ color: step.color }}>
        {step.num}
      </div>
      <h3 className="font-display font-bold text-white text-xl mb-3">{step.title}</h3>
      <p className="text-sm text-ink-400 leading-relaxed mb-4">{step.desc}</p>
      <div className="text-[10px] text-ink-500 tracking-wide font-mono bg-white/3 border border-white/5 px-3 py-1.5 rounded-full">
        {step.detail}
      </div>
    </motion.div>
  )
}

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="py-28 bg-surface-2 overflow-hidden">
      <div className="site-container">
        <Reveal variant="rise" className="text-center mb-20">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
            <span className="w-1.5 h-1.5 rounded-full bg-violet" />
            <span className="text-xs text-ink-300 tracking-wide">How It Works</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight">
            From raw data to
            <br />
            <span className="text-gradient-magenta">actionable intelligence.</span>
          </h2>
        </Reveal>

        <div className="relative">
          <div className="hidden lg:block absolute top-12 left-[calc(12.5%+1rem)] right-[calc(12.5%+1rem)] h-px bg-gradient-to-r from-transparent via-white/8 to-transparent" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {STEPS.map((step, i) => (
              <Step key={step.num} step={step} index={i} />
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
