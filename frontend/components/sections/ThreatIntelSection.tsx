'use client'

import { useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { Globe, Radio, AlertTriangle, Hash, Link2, Server } from 'lucide-react'

const MOCK_IOCS = [
  { type: 'ip', value: '185.234.218.xxx', score: 94, source: 'OTX', tags: ['C2', 'botnet'] },
  { type: 'domain', value: 'malware-c2.xyz', score: 87, source: 'abuse.ch', tags: ['malware'] },
  { type: 'hash', value: 'a3f1b2c9d8e7...', score: 76, source: 'VT', tags: ['trojan', 'dropper'] },
  { type: 'url', value: 'http://phish.ru/auth', score: 91, source: 'RSS', tags: ['phishing'] },
  { type: 'ip', value: '45.12.34.xxx', score: 62, source: 'OSINT', tags: ['scanner'] },
  { type: 'domain', value: 'update-mirror.cc', score: 83, source: 'OTX', tags: ['C2'] },
]

const TYPE_CONFIG = {
  ip: { icon: Server, color: 'text-magenta', bg: 'bg-magenta/10' },
  domain: { icon: Globe, color: 'text-violet', bg: 'bg-violet/10' },
  hash: { icon: Hash, color: 'text-amber', bg: 'bg-amber/10' },
  url: { icon: Link2, color: 'text-safe', bg: 'bg-safe/10' },
}

function ScoreBadge({ score }: { score: number }) {
  const color =
    score > 85
      ? 'text-threat bg-threat/10 border-threat/20'
      : score > 70
      ? 'text-amber bg-amber/10 border-amber/20'
      : 'text-safe bg-safe/10 border-safe/20'
  return (
    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${color}`}>
      {score}
    </span>
  )
}

export default function ThreatIntelSection() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const [activeRow, setActiveRow] = useState<string | null>(null)

  return (
    <section id="threat-intel" ref={ref} className="py-28 max-w-7xl mx-auto px-6">
      <div className="grid lg:grid-cols-2 gap-16 items-center">
        <motion.div
          initial={{ opacity: 0, x: -32 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.7 }}
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-magenta/20 bg-magenta/5 mb-6">
            <Radio className="w-3 h-3 text-magenta" />
            <span className="text-xs text-magenta tracking-wide">Threat Intelligence API</span>
          </div>

          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight mb-6">
            Unified IOC ingestion
            <br />
            <span className="text-gradient-magenta">from five live sources.</span>
          </h2>

          <p className="text-ink-300 leading-relaxed mb-8">
            ThreatOrbit&apos;s Threat API pulls from AlienVault OTX, abuse.ch, curated RSS feeds,
            dark-web OSINT monitors, and social OSINT channels simultaneously, then deduplicates,
            normalizes, and enriches with VirusTotal scores.
          </p>

          <div className="space-y-3 mb-8">
            {[
              { label: 'AlienVault OTX', detail: 'Pulse-based IOC sync' },
              { label: 'abuse.ch URLhaus & MalwareBazaar', detail: 'Malware hashes and URLs' },
              { label: 'RSS threat feeds', detail: 'Security blog and advisory feeds' },
              { label: 'Dark-web OSINT', detail: 'Onion site monitoring' },
              { label: 'Social OSINT', detail: 'Security researcher channels' },
            ].map((item) => (
              <div key={item.label} className="flex items-start gap-3">
                <span className="w-1.5 h-1.5 rounded-full bg-magenta mt-2 shrink-0" />
                <div>
                  <span className="text-sm text-ink-200 font-medium">{item.label}</span>
                  <span className="text-xs text-ink-500 ml-2">{item.detail}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="glass border border-white/8 rounded-xl p-4 font-mono text-xs text-ink-300">
            <div className="text-ink-500 mb-1"># Trigger ingestion</div>
            <div>
              <span className="text-magenta">POST</span> /api/fetch{' '}
              <span className="text-ink-500">X-API-Key: &lt;admin_key&gt;</span>
            </div>
            <div className="mt-1">
              <span className="text-safe">{'{ "job_id": "a3f8d2...", "status": "running" }'}</span>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 32 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.15 }}
          className="glass border border-white/8 rounded-2xl overflow-hidden"
        >
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-white/2">
            <AlertTriangle className="w-3.5 h-3.5 text-threat" strokeWidth={1.5} />
            <span className="text-xs text-ink-300 font-medium">Live IOC Feed</span>
            <span className="ml-auto w-2 h-2 rounded-full bg-safe animate-pulse" />
          </div>

          <div className="divide-y divide-white/4">
            {MOCK_IOCS.map((ioc, i) => {
              const cfg = TYPE_CONFIG[ioc.type as keyof typeof TYPE_CONFIG]
              const Icon = cfg.icon
              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: 20 }}
                  animate={inView ? { opacity: 1, x: 0 } : {}}
                  transition={{ delay: 0.2 + i * 0.07 }}
                  onMouseEnter={() => setActiveRow(ioc.value)}
                  onMouseLeave={() => setActiveRow(null)}
                  className={`flex items-center gap-3 px-4 py-3 transition-colors duration-200 cursor-default ${
                    activeRow === ioc.value ? 'bg-white/3' : ''
                  }`}
                >
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${cfg.bg}`}>
                    <Icon className={`w-3.5 h-3.5 ${cfg.color}`} strokeWidth={1.5} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-ink-200 truncate">{ioc.value}</div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      {ioc.tags.map((t) => (
                        <span key={t} className="text-[9px] text-ink-500 bg-white/5 px-1.5 py-0.5 rounded">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-ink-500">{ioc.source}</span>
                    <ScoreBadge score={ioc.score} />
                  </div>
                </motion.div>
              )
            })}
          </div>

          <div className="px-4 py-3 border-t border-white/5 text-[10px] text-ink-500 font-mono">
            GET /api/indicators?type=ip&amp;limit=50
          </div>
        </motion.div>
      </div>
    </section>
  )
}
