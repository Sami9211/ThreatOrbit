'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import {
  Globe, Database, Brain, FileCode, Layers, Lock,
  Zap, RefreshCw, Eye
} from 'lucide-react'
import { cn } from '@/lib/utils'

const FEATURES = [
  {
    icon: Globe,
    title: 'Multi-Source OSINT Ingestion',
    desc: 'Parallel fetching from OTX, abuse.ch, RSS feeds, dark-web monitors, and social OSINT with ThreadPoolExecutor — all normalized into a unified IOC schema.',
    accent: 'cyan',
    size: 'large',
  },
  {
    icon: Brain,
    title: 'ML Anomaly Detection',
    desc: 'Four-layer detection pipeline: pattern matching, statistical baseline, LSTM-backed ML, and temporal correlation.',
    accent: 'violet',
    size: 'small',
  },
  {
    icon: FileCode,
    title: 'STIX 2.1 Native',
    desc: 'Export any indicator set as standards-compliant STIX bundles, ready for any TAXII-compatible platform.',
    accent: 'cyan',
    size: 'small',
  },
  {
    icon: Database,
    title: 'OpenCTI Integration',
    desc: 'Bidirectional sync with OpenCTI. Query indicators, push enriched bundles, and monitor push health — all via API.',
    accent: 'violet',
    size: 'large',
  },
  {
    icon: Zap,
    title: 'Async Job Pipeline',
    desc: 'POST to /fetch returns a job_id instantly. The full pipeline runs in background threads — no blocking, no timeouts.',
    accent: 'safe',
    size: 'small',
  },
  {
    icon: Lock,
    title: 'Dual API Key Auth',
    desc: 'Standard read keys for analysts, admin keys for write operations. Zero-config backwards compatibility.',
    accent: 'safe',
    size: 'small',
  },
  {
    icon: Layers,
    title: 'Multi-Format Log Parsing',
    desc: 'Parse Apache access logs, syslog, Windows Event XML, and generic structured logs through a unified pipeline.',
    accent: 'cyan',
    size: 'small',
  },
  {
    icon: RefreshCw,
    title: 'VirusTotal Enrichment',
    desc: 'Automatic IOC enrichment with VT reputation scores, category tags, and last-analysis timestamps via connection-pooled session.',
    accent: 'violet',
    size: 'small',
  },
  {
    icon: Eye,
    title: 'Real-Time Monitoring',
    desc: 'Poll job status, stream live IOC counts, and surface threat deltas with minimal overhead from WAL-mode SQLite.',
    accent: 'cyan',
    size: 'small',
  },
]

const ACCENT_STYLES = {
  cyan: {
    icon: 'text-cyan bg-cyan/10 border-cyan/15',
    border: 'hover:border-cyan/25 hover:shadow-cyan-sm',
    tag: 'border-cyan/20 text-cyan/70',
  },
  violet: {
    icon: 'text-violet bg-violet/10 border-violet/15',
    border: 'hover:border-violet/25 hover:shadow-violet-sm',
    tag: 'border-violet/20 text-violet/70',
  },
  safe: {
    icon: 'text-safe bg-safe/10 border-safe/15',
    border: 'hover:border-safe/25',
    tag: 'border-safe/20 text-safe/70',
  },
}

export default function Features() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-100px' })

  return (
    <section id="features" ref={ref} className="py-28 max-w-7xl mx-auto px-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={inView ? { opacity: 1, y: 0 } : {}}
        transition={{ duration: 0.7 }}
        className="text-center mb-16"
      >
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan" />
          <span className="text-xs text-slate-400 tracking-wide">Platform Capabilities</span>
        </div>
        <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
          Everything a security team needs.<br />
          <span className="text-gradient-cyan">Nothing they don&apos;t.</span>
        </h2>
        <p className="text-lg text-slate-500 max-w-xl mx-auto">
          ThreatOrbit combines threat intelligence, log analysis, and CTI platform integration into one coherent API surface.
        </p>
      </motion.div>

      {/* Bento grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FEATURES.map((feat, i) => {
          const styles = ACCENT_STYLES[feat.accent as keyof typeof ACCENT_STYLES]
          const Icon = feat.icon
          return (
            <motion.div
              key={feat.title}
              initial={{ opacity: 0, y: 32 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, delay: i * 0.06 }}
              className={cn(
                'group relative rounded-2xl p-6 glass border border-white/6 transition-all duration-400 cursor-default',
                styles.border,
                feat.size === 'large' && i < 2 ? 'lg:col-span-1' : ''
              )}
            >
              {/* Icon */}
              <div className={cn('w-10 h-10 rounded-xl border flex items-center justify-center mb-4', styles.icon)}>
                <Icon className="w-5 h-5" strokeWidth={1.5} />
              </div>

              <h3 className="font-display font-semibold text-white text-[15px] mb-2 leading-snug">
                {feat.title}
              </h3>
              <p className="text-sm text-slate-500 leading-relaxed">{feat.desc}</p>

              {/* Hover shine */}
              <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                style={{ background: 'radial-gradient(circle at 50% 0%, rgba(0,212,255,0.04), transparent 60%)' }} />
            </motion.div>
          )
        })}
      </div>
    </section>
  )
}
