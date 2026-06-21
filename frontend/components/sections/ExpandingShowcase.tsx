'use client'

import { useState } from 'react'
import { motion, AnimatePresence, LayoutGroup } from 'framer-motion'
import { Radio, Activity, GitMerge, ArrowUpRight, ExternalLink } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'

const PANELS = [
  {
    id: 'ingest',
    icon: Radio,
    label: 'Threat Ingestion',
    tag: 'threat_api',
    accent: '#FF2E97',
    blurb: 'Five OSINT sources, one unified feed.',
    href: '/platform/threat-intelligence',
    points: [
      'Parallel fetch across OTX, abuse.ch, RSS, dark-web, and social OSINT',
      'VirusTotal enrichment with reputation scores and category tags',
      'Deduplicated and trust-scored into a single IOC schema',
      'Async job model: POST /fetch returns a job_id instantly',
    ],
  },
  {
    id: 'analyze',
    icon: Activity,
    label: 'Log Analysis',
    tag: 'log_api',
    accent: '#7A3CFF',
    blurb: 'Four detectors run on every line.',
    href: '/platform/log-analysis',
    points: [
      'Parsers for Apache, syslog, Windows Event XML, and generic logs',
      'Pattern, statistical, ML, and temporal detection layers',
      'Consolidated anomaly reports with severity and line references',
      'Synchronous or async (?async=true) analysis modes',
    ],
  },
  {
    id: 'export',
    icon: GitMerge,
    label: 'OpenCTI Export',
    tag: 'stix 2.1',
    accent: '#FFB23E',
    blurb: 'Push enriched intelligence downstream.',
    href: '/platform/opencti',
    points: [
      'Bundle any indicator set as standards-compliant STIX 2.1',
      'Push directly to OpenCTI over its GraphQL API',
      'Query existing indicators and monitor push health',
      'Or consume the REST API from your own SIEM',
    ],
  },
]

export default function ExpandingShowcase() {
  const [active, setActive] = useState<string>('ingest')

  return (
    <section className="py-28 bg-surface overflow-hidden">
      <div className="site-container">
        <Reveal variant="rise" className="text-center mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
            <span className="w-1.5 h-1.5 rounded-full bg-amber" />
            <span className="text-xs text-ink-300 tracking-wide">The Pipeline</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight">
            Three modules.
            <br />
            <span className="text-gradient-plasma">One continuous flow.</span>
          </h2>
          <p className="text-ink-400 mt-4 text-sm">Tap a module to open it.</p>
        </Reveal>

        <LayoutGroup>
          <div className="flex flex-col lg:flex-row gap-4 h-auto lg:h-[420px]">
            {PANELS.map((panel) => {
              const isActive = active === panel.id
              const Icon = panel.icon
              return (
                <motion.div
                  key={panel.id}
                  layout
                  onClick={() => setActive(panel.id)}
                  transition={{ layout: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } }}
                  className="relative rounded-3xl overflow-hidden cursor-pointer glass border border-white/8"
                  style={{
                    flex: isActive ? 3 : 1,
                    minHeight: isActive ? 360 : 88,
                  }}
                  whileHover={!isActive ? { scale: 1.01 } : undefined}
                >
                  {/* Accent glow */}
                  <motion.div
                    layout
                    className="absolute inset-0 pointer-events-none"
                    style={{
                      background: `radial-gradient(ellipse 80% 60% at 0% 0%, ${panel.accent}22, transparent 60%)`,
                      opacity: isActive ? 1 : 0.4,
                    }}
                  />

                  <div className="relative h-full p-6 flex flex-col">
                    {/* Header row (always visible) */}
                    <motion.div layout="position" className="flex items-center gap-3">
                      <div
                        className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border"
                        style={{
                          color: panel.accent,
                          backgroundColor: `${panel.accent}1a`,
                          borderColor: `${panel.accent}33`,
                        }}
                      >
                        <Icon className="w-5 h-5" strokeWidth={1.5} />
                      </div>
                      <div className="min-w-0">
                        <div className="font-display font-semibold text-white text-lg leading-tight">
                          {panel.label}
                        </div>
                        <div className="font-mono text-[10px] text-ink-500">{panel.tag}</div>
                      </div>
                      {isActive && (
                        <ArrowUpRight
                          className="ml-auto w-4 h-4 shrink-0"
                          style={{ color: panel.accent }}
                        />
                      )}
                    </motion.div>

                    {/* Expanded content */}
                    <AnimatePresence mode="wait">
                      {isActive && (
                        <motion.div
                          key="content"
                          initial={{ opacity: 0, y: 16 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: 8 }}
                          transition={{ duration: 0.4, delay: 0.18 }}
                          className="mt-6 flex-1 flex flex-col"
                        >
                          <p className="text-xl md:text-2xl font-display text-white/90 mb-6 max-w-md">
                            {panel.blurb}
                          </p>
                          <ul className="space-y-3 max-w-lg mb-6">
                            {panel.points.map((pt) => (
                              <li key={pt} className="flex items-start gap-3">
                                <span
                                  className="w-1.5 h-1.5 rounded-full mt-2 shrink-0"
                                  style={{ backgroundColor: panel.accent }}
                                />
                                <span className="text-sm text-ink-300 leading-relaxed">{pt}</span>
                              </li>
                            ))}
                          </ul>
                          <a
                            href={panel.href}
                            className="inline-flex items-center gap-1.5 text-xs font-medium hover:underline"
                            style={{ color: panel.accent }}
                          >
                            <ExternalLink className="w-3 h-3" />
                            Full platform details
                          </a>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* Collapsed vertical label hint */}
                    {!isActive && (
                      <motion.div
                        layout="position"
                        className="mt-auto text-xs text-ink-500 hidden lg:block"
                      >
                        {panel.blurb}
                      </motion.div>
                    )}
                  </div>
                </motion.div>
              )
            })}
          </div>
        </LayoutGroup>
      </div>
    </section>
  )
}
