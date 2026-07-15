'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence, useInView } from 'framer-motion'
import { Globe, Radio, AlertTriangle, Hash, Link2, Server } from 'lucide-react'
import { usePerfProfile } from '@/lib/usePerf'

type IOC = {
  id: number
  type: 'ip' | 'domain' | 'hash' | 'url'
  value: string
  score: number
  source: string
  tags: string[]
}

const TYPE_CONFIG = {
  ip: { icon: Server, color: 'text-magenta', bg: 'bg-magenta/10' },
  domain: { icon: Globe, color: 'text-violet', bg: 'bg-violet/10' },
  hash: { icon: Hash, color: 'text-amber', bg: 'bg-amber/10' },
  url: { icon: Link2, color: 'text-safe', bg: 'bg-safe/10' },
}

/* -- Procedural IOC generator for the live feed -- */
const SOURCES = ['OTX', 'abuse.ch', 'VT', 'RSS', 'OSINT', 'URLhaus', 'MalwareBazaar']
const TLDS = ['xyz', 'ru', 'cc', 'top', 'info', 'su', 'tk', 'biz']
const TAG_POOL = {
  ip: [['C2', 'botnet'], ['scanner'], ['bruteforce'], ['C2'], ['proxy', 'tor']],
  domain: [['malware'], ['C2'], ['phishing'], ['fastflux'], ['dga']],
  hash: [['trojan', 'dropper'], ['ransomware'], ['stealer'], ['loader'], ['rat']],
  url: [['phishing'], ['exploit-kit'], ['credential-harvest'], ['malware']],
}
const HEX = '0123456789abcdef'
const rnd = (n: number) => Math.floor(Math.random() * n)
const pick = <T,>(a: T[]): T => a[rnd(a.length)]
const hex = (n: number) => Array.from({ length: n }, () => HEX[rnd(16)]).join('')

function makeIOC(id: number): IOC {
  const type = pick(['ip', 'domain', 'hash', 'url'] as const)
  let value = ''
  if (type === 'ip') value = `${rnd(223) + 1}.${rnd(255)}.${rnd(255)}.xxx`
  else if (type === 'domain') value = `${pick(['secure', 'update', 'cdn', 'login', 'mail', 'api'])}-${hex(4)}.${pick(TLDS)}`
  else if (type === 'hash') value = `${hex(12)}...`
  else value = `http://${hex(5)}.${pick(TLDS)}/${pick(['auth', 'login', 'pay', 'verify', 'cmd'])}`
  return {
    id,
    type,
    value,
    score: 55 + rnd(45),
    source: pick(SOURCES),
    tags: pick(TAG_POOL[type]),
  }
}

/* Static seed so server and client render identically (no hydration mismatch).
   The procedural generator only kicks in after mount. */
const INITIAL: IOC[] = [
  { id: 0, type: 'ip',     value: '185.234.218.xxx',     score: 94, source: 'OTX',      tags: ['C2', 'botnet'] },
  { id: 1, type: 'domain', value: 'secure-9a3f.xyz',     score: 87, source: 'abuse.ch', tags: ['malware'] },
  { id: 2, type: 'hash',   value: 'a3f1b2c9d8e7...',     score: 76, source: 'VT',       tags: ['trojan', 'dropper'] },
  { id: 3, type: 'url',    value: 'http://b2c9f.ru/auth',score: 91, source: 'RSS',      tags: ['phishing'] },
  { id: 4, type: 'ip',     value: '45.12.34.xxx',        score: 62, source: 'OSINT',    tags: ['scanner'] },
  { id: 5, type: 'domain', value: 'update-7e1a.cc',      score: 83, source: 'URLhaus',  tags: ['C2'] },
]

function ScoreBadge({ score }: { score: number }) {
  const color =
    score > 85
      ? 'text-threat bg-threat/10 border-threat/20'
      : score > 70
      ? 'text-amber bg-amber/10 border-amber/20'
      : 'text-safe bg-safe/10 border-safe/20'
  return (
    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded-sm border ${color}`}>
      {score}
    </span>
  )
}

export default function ThreatIntelSection() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const liveRef = useRef<HTMLDivElement>(null)
  const feedVisible = useInView(liveRef, { margin: '-40px' })
  const [activeRow, setActiveRow] = useState<number | null>(null)
  const { prefersReducedMotion } = usePerfProfile()

  const [feed, setFeed] = useState<IOC[]>(INITIAL)
  const [count, setCount] = useState(2_148_392)
  const idRef = useRef(INITIAL.length)

  // Stream new IOCs while the feed is on-screen
  useEffect(() => {
    if (prefersReducedMotion || !feedVisible) return
    const t = setInterval(() => {
      setFeed((prev) => {
        const next = makeIOC(idRef.current++)
        return [next, ...prev].slice(0, 7)
      })
      setCount((c) => c + 1 + rnd(4))
    }, 1900)
    return () => clearInterval(t)
  }, [prefersReducedMotion, feedVisible])

  return (
    <section id="threat-intel" ref={ref} className="py-28 site-container overflow-x-clip">
      <div className="grid lg:grid-cols-2 gap-16 items-center">
        <motion.div
          initial={{ opacity: 0, x: -32 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.7 }}
          className="min-w-0"
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

          <div className="glass border border-white/8 rounded-xl p-4 font-mono text-xs text-ink-300 overflow-x-auto">
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
          ref={liveRef}
          initial={{ opacity: 0, x: 32 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.15 }}
          className="glass border border-white/8 rounded-2xl overflow-hidden"
        >
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-white/2">
            <AlertTriangle className="w-3.5 h-3.5 text-threat" strokeWidth={1.5} />
            <span className="text-xs text-ink-300 font-medium">Live IOC Feed</span>
            <span className="ml-auto flex items-center gap-1.5 text-[10px] text-safe">
              <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
              streaming
            </span>
          </div>

          {/* total counter */}
          <div className="flex items-baseline justify-between px-4 py-2.5 border-b border-white/5">
            <span className="text-[10px] text-ink-500 uppercase tracking-widest">Indicators tracked</span>
            <span className="font-mono text-sm font-bold text-magenta tabular-nums">
              {count.toLocaleString()}
            </span>
          </div>

          <div className="divide-y divide-white/4 min-h-[336px]">
            <AnimatePresence initial={false}>
              {feed.map((ioc) => {
                const cfg = TYPE_CONFIG[ioc.type]
                const Icon = cfg.icon
                return (
                  <motion.div
                    key={ioc.id}
                    layout
                    initial={{ opacity: 0, height: 0, backgroundColor: 'rgba(255,46,151,0.10)' }}
                    animate={{ opacity: 1, height: 'auto', backgroundColor: 'rgba(255,46,151,0)' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
                    onMouseEnter={() => setActiveRow(ioc.id)}
                    onMouseLeave={() => setActiveRow(null)}
                    className={`flex items-center gap-3 px-4 py-3 overflow-hidden cursor-default ${
                      activeRow === ioc.id ? 'bg-white/3' : ''
                    }`}
                  >
                    <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${cfg.bg}`}>
                      <Icon className={`w-3.5 h-3.5 ${cfg.color}`} strokeWidth={1.5} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-mono text-ink-200 truncate">{ioc.value}</div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        {ioc.tags.map((t) => (
                          <span key={t} className="text-[9px] text-ink-500 bg-white/5 px-1.5 py-0.5 rounded-sm">
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
            </AnimatePresence>
          </div>

          <div className="px-4 py-3 border-t border-white/5 text-[10px] text-ink-500 font-mono">
            GET /api/indicators?type=ip&amp;limit=50
          </div>
        </motion.div>
      </div>
    </section>
  )
}
