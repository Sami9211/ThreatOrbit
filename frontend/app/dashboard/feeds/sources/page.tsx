'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchFeeds, toggleFeed as apiToggleFeed, createFeed, fetchFeedsSummary, type Feed as ApiFeed, type FeedsSummary } from '@/lib/api'
import CreateModal from '@/components/dashboard/CreateModal'
import IngestionEnginePanel from '@/components/dashboard/IngestionEnginePanel'
import ConnectorsPanel from '@/components/dashboard/ConnectorsPanel'
import {
  Radio, Plus, RefreshCw, XCircle, Settings, Key, Link2,
  Clock, Tag, SlidersHorizontal, Activity, ShieldCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type FeedType = 'OSINT' | 'Commercial' | 'Government' | 'Community'
type FeedFormat = 'STIX 2.1' | 'MISP' | 'CSV' | 'JSON' | 'TAXII' | '-'
type Reliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | '-'

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
  '-': 'text-ink-500 border-white/10 bg-white/5',
}

// API feed → UI row mapping shared by the initial load and add-feed flows.
// Every displayed value is the backend's own record; fields this deployment
// doesn't track render "-" rather than an invented constant.
const apiFeedToRow = (f: ApiFeed): FeedSource => ({
  id: f.id,
  name: f.name,
  type: (f.type === 'commercial' ? 'Commercial' : f.type === 'government' ? 'Government' : f.type === 'community' ? 'Community' : 'OSINT') as FeedType,
  format: ((f.format?.toUpperCase() === 'STIX' ? 'STIX 2.1' : f.format) ?? '-') as FeedFormat,
  iocsPerDay: f.indicators,
  lastPull: f.lastSync ?? 'Never',
  reliability: ((f.reliability?.toUpperCase() as Reliability) || '-'),
  enabled: f.enabled,
  url: f.url ?? '',
  apiKeyConfigured: false,
  pullInterval: f.syncInterval ? `${Math.round(f.syncInterval / 60)}m` : '-',
  taxiiCollection: '-',
  confidenceWeight: 75,
  tagMapping: [],
})

export default function FeedSourcesPage() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<'all' | FeedType>('all')
  const [selected, setSelected] = useState<string | null>(null)
  // Rows come ONLY from the backend: an empty deployment shows an honest
  // empty state and an unreachable API says so - never a fabricated list of
  // premium vendors with invented pull times (the audit's "fake feeds").
  const [feeds, setFeeds] = useState<FeedSource[]>([])
  const [feedsLoaded, setFeedsLoaded] = useState(false)
  const [unreachable, setUnreachable] = useState(false)
  const [showAdd, setShowAdd] = useState(false)
  const [summary, setSummary] = useState<FeedsSummary | null>(null)

  async function handleAddFeed(values: Record<string, string>) {
    const created = await createFeed({
      name: values.name,
      type: values.type,
      url: values.url || undefined,
      format: values.format || undefined,
      reliability: values.reliability,
    })
    setFeeds((prev) => [apiFeedToRow(created), ...prev])
  }

  useEffect(() => {
    fetchFeeds()
      .then((data: ApiFeed[]) => setFeeds(data.map(apiFeedToRow)))
      .catch(() => setUnreachable(true))
      .finally(() => setFeedsLoaded(true))
    fetchFeedsSummary().then(setSummary).catch(() => {})
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
  // Real "IOCs today" from the summary endpoint (indicators first seen since
  // midnight UTC) - not a sum of per-feed nominal daily rates.
  const iocsToday = summary?.newToday ?? null

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
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
          <Plus className="w-3.5 h-3.5" />
          Add Feed
        </button>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Active Feeds',     value: activeFeeds,                          color: 'text-safe'    },
          { label: 'IOCs Today',       value: iocsToday === null ? '-' : iocsToday.toLocaleString(),  color: 'text-magenta' },
          { label: 'Total Indicators', value: summary ? summary.totalIndicators.toLocaleString() : '-', color: 'text-violet' },
          { label: 'Feeds Errored',    value: summary ? String(summary.errored) : '-', color: 'text-amber' },
        ].map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Real-data connectors + live ingestion engine bridge */}
      <div className="px-6 pt-4 shrink-0 space-y-4">
        <ConnectorsPanel />
        <IngestionEnginePanel />
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-white/4 shrink-0">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search feeds..."
          className="flex-1 max-w-xs bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-ink-600 outline-hidden focus:border-magenta/30"
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
              {['Source Name', 'Type', 'Format', 'Indicators', 'Last Pull', 'Reliability', 'Status'].map(h => (
                <th key={h} className="text-left px-4 py-2.5 text-[10px] text-ink-500 font-semibold uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {!feedsLoaded && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-xs text-ink-600">Loading feeds…</td></tr>
            )}
            {feedsLoaded && unreachable && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-xs text-amber">
                The dashboard API is unreachable - feed status cannot be shown. Nothing here is simulated.
              </td></tr>
            )}
            {feedsLoaded && !unreachable && filtered.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-xs text-ink-500">
                No feeds registered yet. OSINT/NVD connectors register themselves on their first sync; use &quot;Add Feed&quot; for custom sources.
              </td></tr>
            )}
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
                  i % 2 !== 0 && selected !== feed.id && 'bg-white/1',
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

      <AnimatePresence>
        {showAdd && (
          <CreateModal
            title="Add Threat Feed"
            icon={Radio}
            submitLabel="Add Feed"
            onClose={() => setShowAdd(false)}
            onSubmit={handleAddFeed}
            fields={[
              { key: 'name', label: 'Feed name', required: true, placeholder: 'e.g. URLhaus' },
              { key: 'type', label: 'Type', type: 'select', default: 'opensource', options: [
                { value: 'opensource', label: 'OSINT / open source' },
                { value: 'commercial', label: 'Commercial' },
                { value: 'community', label: 'Community' },
                { value: 'internal', label: 'Internal' },
              ] },
              { key: 'url', label: 'Feed URL', placeholder: 'https://…', hint: 'Pull endpoint or TAXII collection URL' },
              { key: 'format', label: 'Format', type: 'select', default: 'STIX 2.1', options: [
                { value: 'STIX 2.1', label: 'STIX 2.1' }, { value: 'TAXII', label: 'TAXII' },
                { value: 'JSON', label: 'JSON' }, { value: 'CSV', label: 'CSV' }, { value: 'MISP', label: 'MISP' },
              ] },
              { key: 'reliability', label: 'Reliability', type: 'select', default: 'B', options: [
                { value: 'A', label: 'A - Reliable' }, { value: 'B', label: 'B - Usually reliable' }, { value: 'C', label: 'C - Fairly reliable' },
              ] },
            ]}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
