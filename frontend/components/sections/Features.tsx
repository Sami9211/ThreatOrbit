'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import {
  Globe, Database, Brain, FileCode, Layers, Lock, Zap, RefreshCw, Eye,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Reveal from '@/components/ui/Reveal'
import TiltCard from '@/components/ui/TiltCard'

const FEATURES = [
  {
    icon: Globe,
    title: 'Multi-Source OSINT Ingestion',
    desc: 'Parallel fetching from OTX, abuse.ch, RSS feeds, dark-web monitors, and social OSINT with a thread pool, all normalized into a unified IOC schema.',
    accent: 'magenta',
  },
  {
    icon: Brain,
    title: 'ML Anomaly Detection',
    desc: 'Four-layer detection pipeline: pattern matching, statistical baseline, machine-learning models, and temporal correlation.',
    accent: 'violet',
  },
  {
    icon: FileCode,
    title: 'STIX 2.1 Native',
    desc: 'Export any indicator set as standards-compliant STIX bundles, ready for any TAXII-compatible platform.',
    accent: 'magenta',
  },
  {
    icon: Database,
    title: 'OpenCTI Integration',
    desc: 'Bidirectional sync with OpenCTI. Query indicators, push enriched bundles, and monitor push health, all via API.',
    accent: 'violet',
  },
  {
    icon: Zap,
    title: 'Async Job Pipeline',
    desc: 'POST to /fetch returns a job_id instantly. The full pipeline runs in background threads with no blocking and no timeouts.',
    accent: 'amber',
  },
  {
    icon: Lock,
    title: 'Dual API Key Auth',
    desc: 'Standard read keys for analysts, admin keys for write operations, with zero-config backwards compatibility.',
    accent: 'safe',
  },
  {
    icon: Layers,
    title: 'Multi-Format Log Parsing',
    desc: 'Parse Apache access logs, syslog, Windows Event XML, and generic structured logs through one unified pipeline.',
    accent: 'magenta',
  },
  {
    icon: RefreshCw,
    title: 'VirusTotal Enrichment',
    desc: 'Automatic IOC enrichment with VT reputation scores, category tags, and last-analysis timestamps via a pooled session.',
    accent: 'violet',
  },
  {
    icon: Eye,
    title: 'Real-Time Monitoring',
    desc: 'Poll job status, stream live IOC counts, and surface threat deltas with minimal overhead from WAL-mode SQLite.',
    accent: 'amber',
  },
]

const ACCENT = {
  magenta: { icon: 'text-magenta bg-magenta/10 border-magenta/15', border: 'hover:border-magenta/30' },
  violet: { icon: 'text-violet bg-violet/10 border-violet/15', border: 'hover:border-violet/30' },
  amber: { icon: 'text-amber bg-amber/10 border-amber/20', border: 'hover:border-amber/30' },
  safe: { icon: 'text-safe bg-safe/10 border-safe/15', border: 'hover:border-safe/30' },
}

function FeatureCard({ feat, index }: { feat: (typeof FEATURES)[number]; index: number }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  const styles = ACCENT[feat.accent as keyof typeof ACCENT]
  const Icon = feat.icon

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, scale: 0.85, y: 40, filter: 'blur(8px)' }}
      animate={inView ? { opacity: 1, scale: 1, y: 0, filter: 'blur(0px)' } : {}}
      transition={{ duration: 0.7, delay: (index % 3) * 0.08, ease: [0.22, 1, 0.36, 1] }}
    >
      <TiltCard
        intensity={8}
        className={cn(
          'group relative rounded-2xl p-6 glass border border-white/6 transition-colors duration-300 cursor-default h-full',
          styles.border
        )}
      >
        <div className={cn('w-10 h-10 rounded-xl border flex items-center justify-center mb-4', styles.icon)}>
          <Icon className="w-5 h-5" strokeWidth={1.5} />
        </div>
        <h3 className="font-display font-semibold text-white text-[15px] mb-2 leading-snug">
          {feat.title}
        </h3>
        <p className="text-sm text-ink-400 leading-relaxed">{feat.desc}</p>

        <div
          className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
          style={{ background: 'radial-gradient(circle at 50% 0%, rgba(255,46,151,0.05), transparent 60%)' }}
        />
      </TiltCard>
    </motion.div>
  )
}

export default function Features() {
  return (
    <section id="features" className="py-28 max-w-7xl mx-auto px-6">
      <Reveal variant="rise" className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-magenta" />
          <span className="text-xs text-ink-300 tracking-wide">Platform Capabilities</span>
        </div>
        <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
          Everything a security team needs.
          <br />
          <span className="text-gradient-magenta">Nothing they don&apos;t.</span>
        </h2>
        <p className="text-lg text-ink-400 max-w-xl mx-auto">
          ThreatOrbit combines threat intelligence, log analysis, and CTI platform integration into
          one coherent API surface.
        </p>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FEATURES.map((feat, i) => (
          <FeatureCard key={feat.title} feat={feat} index={i} />
        ))}
      </div>
    </section>
  )
}
