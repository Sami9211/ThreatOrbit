'use client'

import { useRef, useState } from 'react'
import { motion, useInView, AnimatePresence } from 'framer-motion'
import {
  Globe, Database, Brain, FileCode, Layers, Lock, Zap, RefreshCw, Eye, ChevronDown,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Reveal from '@/components/ui/Reveal'
import TiltCard from '@/components/ui/TiltCard'

const FEATURES = [
  {
    icon: Globe,
    title: 'Multi-Source OSINT Ingestion',
    desc: 'Parallel fetching from OTX, abuse.ch, RSS feeds, dark-web monitors, and social OSINT.',
    accent: 'magenta',
    detail: 'The fetch pipeline uses a ThreadPoolExecutor to pull all five sources in parallel. Every indicator is normalised into a unified IOC schema (type, value, source, timestamp, trust score) before hitting the SQLite WAL store. Deduplication is hash-based, so the same IP from two sources counts once with the highest trust score.',
    link: '/platform/threat-intelligence',
  },
  {
    icon: Brain,
    title: 'ML Anomaly Detection',
    desc: 'Four-layer detection pipeline: pattern, statistical, ML, and temporal correlation.',
    accent: 'violet',
    detail: 'Each log line passes through four independent detectors. Pattern matching uses regex rulesets. Statistical detects deviations from a rolling baseline. The ML layer (scikit-learn IsolationForest) scores lines by learned normality. Temporal finds burst events that look normal in isolation but anomalous as a cluster. All four scores are merged into a final severity.',
    link: '/platform/log-analysis',
  },
  {
    icon: FileCode,
    title: 'STIX 2.1 Native',
    desc: 'Export any indicator set as standards-compliant STIX bundles for any TAXII platform.',
    accent: 'magenta',
    detail: 'The /export/stix endpoint builds a full STIX 2.1 Bundle with Indicator SDOs, RelationshipSROs, and a ThreatActor identity object. UUIDs are deterministic from the IOC value so re-exporting the same indicator always produces the same STIX ID - safe for idempotent pushes to OpenCTI.',
    link: '/platform/opencti',
  },
  {
    icon: Database,
    title: 'OpenCTI Integration',
    desc: 'Bidirectional sync with OpenCTI via its GraphQL API. Query, push, and monitor health.',
    accent: 'violet',
    detail: 'ThreatOrbit talks to OpenCTI over its GraphQL API with a long-lived HTTP session. On push, bundles are sent as STIX 2.1 JSON. Query support lets you list existing indicators and filter by type or confidence. The /opencti/status endpoint reports connection health and last-push timestamp so you can alert if sync falls behind.',
    link: '/platform/opencti',
  },
  {
    icon: Zap,
    title: 'Async Job Pipeline',
    desc: 'POST to /fetch returns a job_id instantly. The full pipeline runs in background threads.',
    accent: 'amber',
    detail: 'Heavy operations (OSINT fetch, VirusTotal enrichment, STIX export, OpenCTI push) run as async background jobs. The POST endpoint enqueues the job and returns job_id immediately with a 202. Clients poll GET /jobs/{id} for status (pending → running → complete) and retrieve the result when ready - no timeouts, no blocking, mobile-safe.',
    link: '/docs/rest-api',
  },
  {
    icon: Lock,
    title: 'Dual API Key Auth',
    desc: 'Standard read keys for analysts, admin keys for write operations.',
    accent: 'safe',
    detail: 'The X-API-Key header carries either a standard key (read: list indicators, check status) or an admin key (write: trigger fetch, export STIX, push to OpenCTI). Keys are compared with constant-time equality to prevent timing attacks. If ADMIN_API_KEY is not set, the standard key gains write access automatically - safe for single-operator deployments.',
    link: '/docs/authentication',
  },
  {
    icon: Layers,
    title: 'Multi-Format Log Parsing',
    desc: 'Apache, syslog, Windows Event XML, and generic structured logs in one pipeline.',
    accent: 'magenta',
    detail: 'The log parser auto-detects format from the first 10 lines using pattern sniffing. Apache logs are split into method, path, status, bytes, referrer, and agent fields. Syslog extracts facility, severity, hostname, and process. Windows Event XML is parsed into event ID, provider, channel, and all EventData key-value pairs. Unrecognised logs fall through to a generic field splitter.',
    link: '/platform/log-analysis',
  },
  {
    icon: RefreshCw,
    title: 'VirusTotal Enrichment',
    desc: 'Automatic IOC enrichment with VT reputation scores, tags, and last-analysis timestamps.',
    accent: 'violet',
    detail: 'Enrichment runs after ingestion in a second async pass. A connection-pooled aiohttp session batches indicators into VT lookups (observing the free-tier rate limit). Results are merged back: each IOC gains a vt_score (0-100), up to five category tags, and a last_analysis_date. Indicators with no VT entry are flagged but not discarded.',
    link: '/platform/threat-intelligence',
  },
  {
    icon: Eye,
    title: 'Real-Time Monitoring',
    desc: 'Poll job status, stream live IOC counts, and surface threat deltas from WAL SQLite.',
    accent: 'amber',
    detail: 'WAL mode means reads never block writes, so you can query the indicator count while a fetch job is mid-ingest and always get a consistent view. The /jobs/{id} endpoint supports long-poll (up to 30 s) - the response blocks until the job transitions state, saving you polling round-trips. Delta queries (since parameter) let dashboards fetch only new indicators since last check.',
    link: '/docs/rest-api',
  },
]

const ACCENT = {
  magenta: { icon: 'text-magenta bg-magenta/10 border-magenta/15', border: 'hover:border-magenta/30', color: '#FF2E97' },
  violet:  { icon: 'text-violet bg-violet/10 border-violet/15',   border: 'hover:border-violet/30',  color: '#7A3CFF' },
  amber:   { icon: 'text-amber bg-amber/10 border-amber/20',       border: 'hover:border-amber/30',   color: '#FFB23E' },
  safe:    { icon: 'text-safe bg-safe/10 border-safe/15',          border: 'hover:border-safe/30',    color: '#34F5C5' },
}

function FeatureCard({ feat, index }: { feat: (typeof FEATURES)[number]; index: number }) {
  const ref    = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  const [open, setOpen] = useState(false)
  const styles = ACCENT[feat.accent as keyof typeof ACCENT]
  const Icon   = feat.icon

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, scale: 0.88, y: 40, filter: 'blur(8px)' }}
      animate={inView ? { opacity: 1, scale: 1, y: 0, filter: 'blur(0px)' } : {}}
      transition={{ duration: 0.7, delay: (index % 3) * 0.08, ease: [0.22, 1, 0.36, 1] }}
    >
      <TiltCard
        intensity={9}
        className={cn(
          'group relative rounded-2xl glass border border-white/6 transition-colors duration-300 cursor-pointer overflow-hidden',
          styles.border,
          open ? 'border-opacity-80' : '',
        )}
        style={{ perspective: '800px' }}
      >
        <div className="p-6">
          <div className={cn('w-10 h-10 rounded-xl border flex items-center justify-center mb-4', styles.icon)}>
            <Icon className="w-5 h-5" strokeWidth={1.5} />
          </div>
          <h3 className="font-display font-semibold text-white text-[15px] mb-2 leading-snug">
            {feat.title}
          </h3>
          <p className="text-sm text-ink-400 leading-relaxed mb-3">{feat.desc}</p>

          {/* Expand toggle */}
          <button
            onClick={() => setOpen(v => !v)}
            className="flex items-center gap-1.5 text-[11px] font-medium transition-colors"
            style={{ color: styles.color }}
          >
            {open ? 'Less' : 'Technical details'}
            <motion.span animate={{ rotate: open ? 180 : 0 }} transition={{ duration: 0.25 }}>
              <ChevronDown className="w-3 h-3" />
            </motion.span>
          </button>
        </div>

        {/* Expandable drawer */}
        <AnimatePresence initial={false}>
          {open && (
            <motion.div
              key="detail"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
              className="overflow-hidden"
            >
              <div
                className="px-6 pb-5 pt-1 border-t text-sm text-ink-400 leading-relaxed"
                style={{ borderColor: `${styles.color}22` }}
              >
                {feat.detail}
                <a
                  href={feat.link}
                  className="inline-flex items-center gap-1 mt-3 text-[11px] font-medium hover:underline"
                  style={{ color: styles.color }}
                >
                  Full documentation &rarr;
                </a>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Hover glow */}
        <div
          className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
          style={{ background: `radial-gradient(circle at 50% 0%, ${styles.color}08, transparent 60%)` }}
        />
      </TiltCard>
    </motion.div>
  )
}

export default function Features() {
  return (
    <section id="features" className="py-28 site-container">
      <Reveal variant="rise" className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-magenta" />
          <span className="text-xs text-ink-300 tracking-wide">Platform Capabilities</span>
        </div>
        <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
          Everything a security team needs.<br />
          <span className="text-gradient-magenta">Nothing they don&apos;t.</span>
        </h2>
        <p className="text-lg text-ink-400 max-w-xl mx-auto">
          Click any card to see the technical details behind each capability.
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
