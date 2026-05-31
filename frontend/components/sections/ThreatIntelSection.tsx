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
  ip: { icon: Server, color: 'text-cyan', bg: 'bg-cyan/10' },
  domain: { icon: Globe, color: 'text-violet', bg: 'bg-violet/10' },
  hash: { icon: Hash, color: 'text-threat', bg: 'bg-threat/10' },
  url: { icon: Link2, color: 'text-safe', bg: 'bg-safe/10' },
}

function ScoreBadge({ score }: { score: number }) {
  const color = score > 85 ? 'text-threat bg-threat/10 border-threat/20' : score > 70 ? 'text-[#FFB300] bg-[#FFB300]/10 border-[#FFB300]/20' : 'text-safe bg-safe/10 border-safe/20'
  return (
    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${color}`}>
      {score}
    </span>
  )
}

export default function ThreatIntelSection() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const [active, setActive] = useState<string | null>(null)

  return (
    <section id="threat-intel" ref={ref} className="py-28 max-w-7xl mx-auto px-6">
      <div className="grid lg:grid-cols-2 gap-16 items-center">
        {/* Left content */}
        <motion.div
          initial={{ opacity: 0, x: -32 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.7 }}
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/20 bg-cyan/5 mb-6">
            <Radio className="w-3 h-3 text-cyan" />
            <span className="text-xs text-cyan tracking-wide">Threat Intelligence API</span>
          </div>

          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight mb-6">
            Unified IOC ingestion<br />
            <span className="text-gradient-cyan">from 5 live sources.</span>
          </h2>

          <p className="text-slate-400 leading-relaxed mb-8">
            ThreatOrbit&apos;s Threat API pulls from AlienVault OTX, abuse.ch, curated RSS feeds, dark-web OSINT monitors, and social OSINT channels simultaneously — then deduplicates, normalizes, and enriches with VirusTotal scores.
          </p>

          <div className="space-y-3 mb-8">
            {[
              { label: 'AlienVault OTX', detail: 'Pulse-based IOC sync' },
              { label: 'abuse.ch URLhaus & MalwareBazaar', detail: 'Malware hashes + URLs' },
              { label: 'RSS threat feeds', detail: 'Security blog + advisory feeds' },
              { label: 'Dark-web OSINT', detail: 'Onion site monitoring' },
              { label: 'Social OSINT', detail: 'Twitter/Mastodon security researchers' },
            ].map((item) => (
              <div key={item.label} className="flex items-start gap-3">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan mt-2 shrink-0" />
                <div>
                  <span className="text-sm text-slate-300 font-medium">{item.label}</span>
                  <span className="text-xs text-slate-500 ml-2">{item.detail}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Code snippet */}
          <div className="glass border border-white/8 rounded-xl p-4 font-mono text-xs text-slate-400">
            <div className="text-slate-600 mb-1"># Trigger ingestion</div>
            <div><span className="text-cyan">POST</span> /api/fetch &nbsp;<span className="text-slate-600">X-API-Key: &lt;admin_key&gt;</span></div>
            <div className="mt-1"><span className="text-safe">{'{'}  "job_id": "a3f8d2...", "status": "running" {'}'}</span></div>
          </div>
        </motion.div>

        {/* Right — IOC table */}
        <motion.div
          initial={{ opacity: 0, x: 32 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.15 }}
          className="glass border border-white/8 rounded-2xl overflow-hidden"
        >
          {/* Header */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-white/2">
            <AlertTriangle className="w-3.5 h-3.5 text-threat" strokeWidth={1.5} />
            <span className="text-xs text-slate-400 font-medium">Live IOC Feed</span>
            <span className="ml-auto w-2 h-2 rounded-full bg-safe animate-pulse" />
          </div>

          {/* Table */}
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
                  onMouseEnter={() => setActive(ioc.value)}
                  onMouseLeave={() => setActive(null)}
                  className={`flex items-center gap-3 px-4 py-3 transition-colors duration-200 cursor-default
                    ${active === ioc.value ? 'bg-white/3' : ''}`}
                >
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${cfg.bg}`}>
                    <Icon className={`w-3.5 h-3.5 ${cfg.color}`} strokeWidth={1.5} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-slate-300 truncate">{ioc.value}</div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      {ioc.tags.map((t) => (
                        <span key={t} className="text-[9px] text-slate-600 bg-white/5 px-1.5 py-0.5 rounded">{t}</span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-slate-600">{ioc.source}</span>
                    <ScoreBadge score={ioc.score} />
                  </div>
                </motion.div>
              )
            })}
          </div>

          <div className="px-4 py-3 border-t border-white/5 text-[10px] text-slate-600 font-mono">
            GET /api/indicators?type=ip&amp;limit=50
          </div>
        </motion.div>
      </div>
    </section>
  )
}
