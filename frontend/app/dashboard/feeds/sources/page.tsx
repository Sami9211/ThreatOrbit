'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchFeeds, toggleFeed as apiToggleFeed, type Feed as ApiFeed } from '@/lib/api'
import {
  Radio, Plus, RefreshCw, XCircle, Settings, Key, Link2,
  Clock, Tag, SlidersHorizontal, Activity, ShieldCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type FeedType = 'OSINT' | 'Commercial' | 'Government' | 'Community'
type FeedFormat = 'STIX 2.1' | 'MISP' | 'CSV' | 'JSON' | 'TAXII'
type Reliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F'

interface FeedSource {
  id: string
  name: string
  type: FeedType
  format: FeedFormat
  iocsPerDay: number
  lastPull: string
  reliability: Reliability
  enabled: boolean
  url: string
  apiKeyConfigured: boolean
  pullInterval: string
  taxiiCollection: string
  confidenceWeight: number
  tagMapping: string[]
}

const FEEDS: FeedSource[] = [
  { id: 'f01', name: 'MISP — Internal Sharing',     type: 'Community',  format: 'MISP',      iocsPerDay: 4820,  lastPull: '2m ago',  reliability: 'A', enabled: true,  url: 'https://misp.corp.local/feeds', apiKeyConfigured: true,  pullInterval: '15m', taxiiCollection: 'org-default',          confidenceWeight: 90, tagMapping: ['tlp:amber', 'apt', 'internal'] },
  { id: 'f02', name: 'AlienVault OTX',              type: 'Community',  format: 'STIX 2.1',  iocsPerDay: 12400, lastPull: '1m ago',  reliability: 'B', enabled: true,  url: 'https://otx.alienvault.com/api/v1/pulses', apiKeyConfigured: true,  pullInterval: '30m', taxiiCollection: 'subscribed-pulses', confidenceWeight: 65, tagMapping: ['osint', 'community'] },
  { id: 'f03', name: 'Abuse.ch — URLhaus',         type: 'OSINT',      format: 'CSV',       iocsPerDay: 8200,  lastPull: '4m ago',  reliability: 'A', enabled: true,  url: 'https://urlhaus.abuse.ch/downloads/csv', apiKeyConfigured: false, pullInterval: '10m', taxiiCollection: 'n/a',                 confidenceWeight: 88, tagMapping: ['malware-url', 'osint'] },
  { id: 'f04', name: 'Abuse.ch — ThreatFox',       type: 'OSINT',      format: 'JSON',      iocsPerDay: 5600,  lastPull: '3m ago',  reliability: 'A', enabled: true,  url: 'https://threatfox-api.abuse.ch/api/v1', apiKeyConfigured: true,  pullInterval: '10m', taxiiCollection: 'n/a',                 confidenceWeight: 85, tagMapping: ['ioc', 'malware'] },
  { id: 'f05', name: 'Abuse.ch — Feodo Tracker',   type: 'OSINT',      format: 'CSV',       iocsPerDay: 320,   lastPull: '6m ago',  reliability: 'B', enabled: true,  url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', apiKeyConfigured: false, pullInterval: '30m', taxiiCollection: 'n/a',     confidenceWeight: 80, tagMapping: ['botnet-c2', 'ip'] },
  { id: 'f06', name: 'GreyNoise',                  type: 'Commercial', format: 'JSON',      iocsPerDay: 9800,  lastPull: '5m ago',  reliability: 'A', enabled: true,  url: 'https://api.greynoise.io/v3', apiKeyConfigured: true,  pullInterval: '20m', taxiiCollection: 'n/a',                 confidenceWeight: 92, tagMapping: ['scanner', 'noise', 'context'] },
  { id: 'f07', name: 'Shodan',                     type: 'Commercial', format: 'JSON',      iocsPerDay: 2100,  lastPull: '12m ago', reliability: 'B', enabled: true,  url: 'https://api.shodan.io', apiKeyConfigured: true,  pullInterval: '60m', taxiiCollection: 'n/a',                 confidenceWeight: 70, tagMapping: ['exposure', 'recon'] },
  { id: 'f08', name: 'AbuseIPDB',                  type: 'Community',  format: 'JSON',      iocsPerDay: 6400,  lastPull: '2m ago',  reliability: 'B', enabled: true,  url: 'https://api.abuseipdb.com/api/v2/blacklist', apiKeyConfigured: true,  pullInterval: '15m', taxiiCollection: 'n/a',          confidenceWeight: 72, tagMapping: ['malicious-ip', 'community'] },
  { id: 'f09', name: 'Recorded Future',            type: 'Commercial', format: 'STIX 2.1',  iocsPerDay: 18200, lastPull: '8m ago',  reliability: 'A', enabled: true,  url: 'https://api.recordedfuture.com/v2', apiKeyConfigured: true,  pullInterval: '30m', taxiiCollection: 'risk-lists',      confidenceWeight: 95, tagMapping: ['premium', 'risk-score', 'apt'] },
  { id: 'f10', name: 'Mandiant Advantage',         type: 'Commercial', format: 'TAXII',     iocsPerDay: 14600, lastPull: '9m ago',  reliability: 'A', enabled: false, url: 'https://api.intelligence.mandiant.com/v4/taxii2', apiKeyConfigured: true, pullInterval: '60m', taxiiCollection: 'fireeye-indicators', confidenceWeight: 96, tagMapping: ['premium', 'attribution', 'apt'] },
  { id: 'f11', name: 'CISA AIS',                   type: 'Government', format: 'TAXII',     iocsPerDay: 3400,  lastPull: '22m ago', reliability: 'B', enabled: true,  url: 'https://ais2.cisa.dhs.gov/taxii2', apiKeyConfigured: true,  pullInterval: '60m', taxiiCollection: 'cisa-ais',         confidenceWeight: 82, tagMapping: ['gov', 'tlp:amber', 'us-cert'] },
  { id: 'f12', name: 'SpamHaus DROP',             type: 'OSINT',      format: 'CSV',       iocsPerDay: 1200,  lastPull: '40m ago', reliability: 'A', enabled: true,  url: 'https://www.spamhaus.org/drop/drop.txt', apiKeyConfigured: false, pullInterval: '120m', taxiiCollection: 'n/a',          confidenceWeight: 90, tagMapping: ['bogon', 'ip-block'] },
  { id: 'f13', name: 'Emerging Threats',          type: 'Community',  format: 'CSV',       iocsPerDay: 4100,  lastPull: '7m ago',  reliability: 'B', enabled: true,  url: 'https://rules.emergingthreats.net/blockrules', apiKeyConfigured: false, pullInterval: '30m', taxiiCollection: 'n/a',         confidenceWeight: 68, tagMapping: ['ids', 'suricata'] },
  { id: 'f14', name: 'VirusTotal Intelligence',   type: 'Commercial', format: 'JSON',      iocsPerDay: 7800,  lastPull: '3m ago',  reliability: 'A', enabled: true,  url: 'https://www.virustotal.com/api/v3', apiKeyConfigured: true,  pullInterval: '20m', taxiiCollection: 'n/a',               confidenceWeight: 89, tagMapping: ['hash', 'file', 'premium'] },
  { id: 'f15', name: 'PhishTank',                 type: 'Community',  format: 'CSV',       iocsPerDay: 2600,  lastPull: '15m ago', reliability: 'C', enabled: false, url: 'https://data.phishtank.com/data/online-valid.csv', apiKeyConfigured: false, pullInterval: '60m', taxiiCollection: 'n/a',      confidenceWeight: 55, tagMapping: ['phishing', 'url'] },
  { id: 'f16', name: 'CIRCL OSINT Feed',          type: 'Government', format: 'MISP',      iocsPerDay: 1900,  lastPull: '18m ago', reliability: 'B', enabled: true,  url: 'https://www.circl.lu/doc/misp/feed-osint', apiKeyConfigured: false, pullInterval: '60m', taxiiCollection: 'circl-osint',  confidenceWeight: 78, tagMapping: ['osint', 'eu-cert', 'misp'] },
]

const TYPE_CONFIG: Record<FeedType, string> = {
  OSINT:      'text-safe bg-safe/10 border-safe/20',
  Commercial: 'text-magenta bg-magenta/10 border-magenta/20',
  Government: 'text-amber bg-amber/10 border-amber/20',
  Community:  'text-violet bg-violet/10 border-violet/20',
}

const RELIABILITY_COLOR: Record<Reliability, string> = {
  A: 'text-safe border-safe/30 bg-safe/10',
  B: 'text-violet border-violet/30 bg-violet/10',
  C: 'text-amber border-amber/30 bg-amber/10',
  D: 'text-amber border-amber/30 bg-amber/10',
  E: 'text-threat border-threat/30 bg-threat/10',
  F: 'text-threat border-threat/30 bg-threat/10',
}

export default function FeedSourcesPage() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<'all' | FeedType>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const [feeds, setFeeds] = useState<FeedSource[]>(FEEDS)

  useEffect(() => {
    fetchFeeds().then((data: ApiFeed[]) => {
      if (data.length > 0) {
        const mapped: FeedSource[] = data.map(f => ({
          id: f.id,
          name: f.name,
          type: (f.type === 'commercial' ? 'Commercial' : f.type === 'government' ? 'Government' : f.type === 'community' ? 'Community' : 'OSINT') as FeedType,
          format: 'STIX 2.1' as FeedFormat,
          iocsPerDay: f.indicators,
          lastPull: f.lastSync ?? 'Never',
          reliability: 'B' as Reliability,
          enabled: f.enabled,
          url: f.url ?? '',
          apiKeyConfigured: false,
          pullInterval: '30m',
          taxiiCollection: 'n/a',
          confidenceWeight: 75,
          tagMapping: [],
        }))
        setFeeds(mapped)
      }
    }).catch(() => {})
  }, [])

  const toggleFeed = (id: string) => {
    const feed = feeds.find(f => f.id === id)
    if (!feed) return
    setFeeds(prev => prev.map(f => (f.id === id ? { ...f, enabled: !f.enabled } : f)))
    apiToggleFeed(id, !feed.enabled).catch(() => {
      setFeeds(prev => prev.map(f => (f.id === id ? { ...f, enabled: feed.enabled } : f)))
    })
  }

  const setWeight = (id: string, weight: number) => {
    setFeeds(prev => prev.map(f => (f.id === id ? { ...f, confidenceWeight: weight } : f)))
  }

  const filtered = feeds.filter(f => {
    if (typeFilter !== 'all' && f.type !== typeFilter) return false
    if (search && !f.name.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const selectedFeed = feeds.find(f => f.id === selected) ?? null

  const activeFeeds = feeds.filter(f => f.enabled).length
  const iocsToday = feeds.filter(f => f.enabled).reduce((acc, f) => acc + f.iocsPerDay, 0)

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Feed Sources</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Manage upstream threat intelligence providers</p>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold">
          <Plus className="w-3.5 h-3.5" />
          Add Feed
        </button>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Active Feeds', value: activeFeeds,                            color: 'text-safe'    },
          { label: 'IOCs Today',   value: `${(iocsToday / 1000).toFixed(1)}k`,    color: 'text-magenta' },
          { label: 'Avg Latency',  value: '1.2s',                                 color: 'text-violet'  },
          { label: 'Dedup Rate',   value: '34%',                                  color: 'text-amber'   },
        ].map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-white/4 shrink-0">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search feeds..."
          className="flex-1 max-w-xs bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-ink-600 outline-none focus:border-magenta/30"
        />
        {(['all', 'OSINT', 'Commercial', 'Government', 'Community'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTypeFilter(t)}
            className={cn(
              'px-3 py-1 rounded-full text-[11px] font-medium transition-colors',
              typeFilter === t
                ? 'bg-magenta/20 text-magenta border border-magenta/30'
                : 'bg-white/4 text-ink-500 border border-white/8 hover:text-ink-200',
            )}
          >
            {t === 'all' ? 'All' : t}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-[#0A0612] border-b border-white/8">
            <tr>
              {['Source Name', 'Type', 'Format', 'IOCs/day', 'Last Pull', 'Reliability', 'Status'].map(h => (
                <th key={h} className="text-left px-4 py-2.5 text-[10px] text-ink-500 font-semibold uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((feed, i) => (
              <motion.tr
                key={feed.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.03 }}
                onClick={() => setSelected(selected === feed.id ? null : feed.id)}
                className={cn(
                  'border-b border-white/4 cursor-pointer transition-colors',
                  selected === feed.id ? 'bg-magenta/5 border-l-2 border-l-magenta/50' : 'hover:bg-white/3',
                  i % 2 !== 0 && selected !== feed.id && 'bg-white/[0.01]',
                  !feed.enabled && 'opacity-50',
                )}
              >
                <td className="px-4 py-3 font-medium text-ink-100">{feed.name}</td>
                <td className="px-4 py-3">
                  <span className={cn('px-2 py-0.5 rounded-full border text-[10px] font-semibold', TYPE_CONFIG[feed.type])}>
                    {feed.type}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-ink-400 text-[10px]">{feed.format}</td>
                <td className="px-4 py-3 font-mono text-violet text-right">{feed.iocsPerDay.toLocaleString()}</td>
                <td className="px-4 py-3 text-ink-500 whitespace-nowrap">{feed.lastPull}</td>
                <td className="px-4 py-3">
                  <span className={cn('inline-flex items-center justify-center w-6 h-6 rounded-md border font-bold font-mono text-[11px]', RELIABILITY_COLOR[feed.reliability])}>
                    {feed.reliability}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={e => { e.stopPropagation(); toggleFeed(feed.id) }}
                    className={cn(
                      'relative w-9 h-5 rounded-full transition-colors',
                      feed.enabled ? 'bg-safe/40' : 'bg-white/10',
                    )}
                    aria-label="Toggle feed"
                  >
                    <span
                      className={cn(
                        'absolute top-0.5 w-4 h-4 rounded-full transition-all',
                        feed.enabled ? 'left-4 bg-safe' : 'left-0.5 bg-ink-500',
                      )}
                    />
                  </button>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>

        {/* Detail panel */}
        <AnimatePresence>
          {selectedFeed && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              className="mx-4 my-4 p-5 rounded-2xl border border-magenta/20 bg-magenta/3 glass"
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="font-semibold text-white">{selectedFeed.name}</h3>
                  <p className="text-xs text-ink-500">{selectedFeed.type} · {selectedFeed.format} · Reliability {selectedFeed.reliability}</p>
                </div>
                <button onClick={() => setSelected(null)} className="p-1.5 rounded-lg hover:bg-white/8 text-ink-500">
                  <XCircle className="w-4 h-4" />
                </button>
              </div>

              <div className="grid sm:grid-cols-2 gap-4 mb-5">
                <div>
                  <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1 flex items-center gap-1"><Link2 className="w-3 h-3" /> Feed URL</p>
                  <p className="text-xs font-mono text-ink-200 break-all">{selectedFeed.url}</p>
                </div>
                <div>
                  <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1 flex items-center gap-1"><Key className="w-3 h-3" /> API Key</p>
                  <span className={cn(
                    'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-semibold',
                    selectedFeed.apiKeyConfigured ? 'text-safe bg-safe/10 border-safe/20' : 'text-ink-400 bg-white/5 border-white/10',
                  )}>
                    <ShieldCheck className="w-3 h-3" />
                    {selectedFeed.apiKeyConfigured ? 'Configured' : 'Not required'}
                  </span>
                </div>
                <div>
                  <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1 flex items-center gap-1"><Clock className="w-3 h-3" /> Pull Interval</p>
                  <p className="text-sm font-mono text-ink-200">{selectedFeed.pullInterval}</p>
                </div>
                <div>
                  <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1 flex items-center gap-1"><SlidersHorizontal className="w-3 h-3" /> STIX / TAXII Collection</p>
                  <p className="text-sm font-mono text-ink-200">{selectedFeed.taxiiCollection}</p>
                </div>
              </div>

              {/* Confidence weighting slider */}
              <div className="mb-5">
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-[10px] text-ink-600 uppercase tracking-wider">Confidence Weighting</p>
                  <span className="text-xs font-mono text-magenta">{selectedFeed.confidenceWeight}%</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={selectedFeed.confidenceWeight}
                  onChange={e => setWeight(selectedFeed.id, Number(e.target.value))}
                  className="w-full accent-magenta"
                />
              </div>

              {/* Tag mapping */}
              <div className="mb-5">
                <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-2 flex items-center gap-1"><Tag className="w-3 h-3" /> Tag Mapping</p>
                <div className="flex flex-wrap gap-1.5">
                  {selectedFeed.tagMapping.map(t => (
                    <span key={t} className="text-[10px] px-2 py-0.5 rounded-full bg-violet/10 text-violet border border-violet/20 font-mono">{t}</span>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button className="px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white flex items-center gap-1.5">
                  <Settings className="w-3.5 h-3.5" />
                  Configure
                </button>
                <button className="px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white flex items-center gap-1.5">
                  <RefreshCw className="w-3.5 h-3.5" />
                  Pull Now
                </button>
                <button className="px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Test Connection
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
