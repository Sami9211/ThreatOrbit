'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  EyeOff, KeyRound, ShoppingCart, AtSign, MessageSquare, Network,
  ShieldAlert, Search, X, Copy, CheckCircle, Clock,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchDarkWebFindings, fetchDarkWebSummary, updateDarkWebFinding, requestTakedown,
  type DarkWebFinding, type DarkWebSummary,
} from '@/lib/api'
import ReportButton from '@/components/dashboard/ReportButton'
import SavedViewsButton from '@/components/dashboard/SavedViewsButton'
import { SkeletonRows } from '@/components/dashboard/Skeleton'
import { tk } from '@/lib/colors'

const CATEGORY_META: Record<string, { label: string; icon: React.ComponentType<any>; color: string }> = {
  'credential-leak': { label: 'Credential Leak',  icon: KeyRound,      color: tk('magenta') },
  'data-for-sale':   { label: 'Data for Sale',    icon: ShoppingCart,  color: tk('threat') },
  'brand-mention':   { label: 'Brand Mention',    icon: AtSign,        color: tk('amber') },
  'actor-chatter':   { label: 'Actor Chatter',    icon: MessageSquare, color: tk('violet') },
  'infrastructure':  { label: 'Access Listing',   icon: Network,       color: tk('teal') },
}

const SEV_COLOR: Record<string, string> = {
  critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe'),
}

const STATUS_META: Record<string, { label: string; cls: string }> = {
  new:                  { label: 'New',           cls: 'text-threat border-threat/25 bg-threat/10' },
  investigating:        { label: 'Investigating', cls: 'text-amber border-amber/25 bg-amber/10' },
  'takedown-requested': { label: 'Takedown requested', cls: 'text-violet border-violet/25 bg-violet/10' },
  mitigated:            { label: 'Mitigated',     cls: 'text-safe border-safe/25 bg-safe/10' },
  dismissed:            { label: 'Dismissed',     cls: 'text-ink-400 border-white/10 bg-white/5' },
}

function relTime(iso: string): string {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

export default function DarkWebPage() {
  const [findings, setFindings] = useState<DarkWebFinding[]>([])
  const [summary, setSummary] = useState<DarkWebSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [catFilter, setCatFilter] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<DarkWebFinding | null>(null)
  const [copiedUrl, setCopiedUrl] = useState(false)
  useEffect(() => { setCopiedUrl(false) }, [selected?.id])

  const load = useCallback(() => {
    fetchDarkWebFindings({ limit: '200' })
      .then((d) => setFindings(d.items))
      .catch(() => {})
      .finally(() => setLoading(false))
    fetchDarkWebSummary().then(setSummary).catch(() => {})
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)  // live refresh
    return () => clearInterval(t)
  }, [load])

  function setStatus(f: DarkWebFinding, status: DarkWebFinding['status']) {
    setFindings((prev) => prev.map((x) => (x.id === f.id ? { ...x, status } : x)))
    setSelected((s) => (s?.id === f.id ? { ...s, status } : s))
    updateDarkWebFinding(f.id, status).catch(() => load())
  }

  const filtered = findings.filter((f) =>
    (catFilter === 'all' || f.category === catFilter) &&
    (!search || f.title.toLowerCase().includes(search.toLowerCase()) ||
     f.entity.toLowerCase().includes(search.toLowerCase())))

  const kpis = [
    { label: 'Total Findings', value: summary?.total ?? findings.length, color: 'text-white' },
    { label: 'Critical', value: summary?.critical ?? 0, color: 'text-magenta' },
    { label: 'Credential Leaks', value: summary?.credentialLeaks ?? 0, color: 'text-threat' },
    { label: 'Open', value: summary?.open ?? 0, color: 'text-amber' },
  ]

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 px-6 py-4 border-b border-white/5 shrink-0 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <EyeOff className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Dark Web Monitoring</h1>
            <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border border-safe/25 bg-safe/10 text-safe font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" /> Live
            </span>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">External exposure - leaked credentials, data sales, brand mentions & threat-actor chatter</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search entity or title…"
              className="w-56 pl-8 pr-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-[11px] text-ink-100 placeholder-ink-600 focus:outline-hidden focus:border-magenta/40" />
          </div>
          <SavedViewsButton
            section="darkweb"
            filters={{ q: search, category: catFilter }}
            onApply={(f) => { setSearch(f.q ?? ''); setCatFilter(f.category ?? 'all') }}
          />
          <ReportButton kind="darkweb" label="Dark Web Exposure" />
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {kpis.map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Category filter */}
      <div className="flex items-center gap-1.5 px-6 py-2.5 border-b border-white/4 shrink-0 overflow-x-auto">
        {['all', ...Object.keys(CATEGORY_META)].map((c) => (
          <button key={c} onClick={() => setCatFilter(c)}
            className={cn('flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium whitespace-nowrap transition-colors',
              catFilter === c ? 'bg-magenta/15 text-magenta border border-magenta/30' : 'bg-white/4 text-ink-500 border border-white/8 hover:text-ink-200')}>
            {c !== 'all' && CATEGORY_META[c] && <span className="w-2 h-2 rounded-full" style={{ background: CATEGORY_META[c].color }} />}
            {c === 'all' ? 'All' : CATEGORY_META[c]?.label}
            {summary && c !== 'all' && <span className="text-ink-600">{summary.byCategory[c] ?? 0}</span>}
          </button>
        ))}
      </div>

      {/* Findings */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {loading && <SkeletonRows rows={8} className="px-0" />}
        {!loading && filtered.length === 0 && (
          <p className="text-xs text-ink-600 py-8 text-center">No findings yet - the engine surfaces these as it monitors. Check back shortly.</p>
        )}
        {filtered.map((f) => {
          const cat = CATEGORY_META[f.category] ?? CATEGORY_META['brand-mention']
          const Icon = cat.icon
          return (
            <motion.div key={f.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
              onClick={() => setSelected(f)}
              className="flex items-center gap-3 p-3 rounded-xl border border-white/8 bg-surface hover:border-white/15 cursor-pointer transition-colors">
              <div className="p-2 rounded-lg shrink-0" style={{ background: `${cat.color}18` }}>
                <Icon className="w-4 h-4" style={{ color: cat.color }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-semibold text-white truncate">{f.title}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase" style={{ color: SEV_COLOR[f.severity], background: `${SEV_COLOR[f.severity]}18` }}>{f.severity}</span>
                </div>
                <p className="text-[10px] text-ink-600 mt-0.5 truncate">
                  {cat.label} · {f.source} · {f.entity}{f.actor ? ` · ${f.actor}` : ''} · {relTime(f.ts)}
                </p>
              </div>
              <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border shrink-0', STATUS_META[f.status].cls)}>
                {STATUS_META[f.status].label}
              </span>
            </motion.div>
          )
        })}
      </div>

      {/* Detail panel */}
      <AnimatePresence>
        {selected && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs" onClick={() => setSelected(null)}>
            <motion.div initial={{ x: 440 }} animate={{ x: 0 }} exit={{ x: 440 }} transition={{ type: 'tween', duration: 0.2 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto">
              {(() => {
                const cat = CATEGORY_META[selected.category] ?? CATEGORY_META['brand-mention']
                const Icon = cat.icon
                return (
                  <div className="p-5 space-y-5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="p-2 rounded-lg shrink-0" style={{ background: `${cat.color}18` }}><Icon className="w-4 h-4" style={{ color: cat.color }} /></div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-white">{cat.label}</p>
                          <p className="text-[10px] text-ink-500">{selected.source} · {relTime(selected.ts)}</p>
                        </div>
                      </div>
                      <button onClick={() => setSelected(null)} className="p-1 rounded-sm text-ink-500 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
                    </div>

                    <div>
                      <p className="text-sm text-white leading-snug">{selected.title}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase" style={{ color: SEV_COLOR[selected.severity], background: `${SEV_COLOR[selected.severity]}18` }}>{selected.severity}</span>
                        <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border', STATUS_META[selected.status].cls)}>{STATUS_META[selected.status].label}</span>
                      </div>
                    </div>

                    {/* Entity + actor drill down to their records - they were dead text. */}
                    <div className="flex items-center justify-between gap-2 py-1.5 border-b border-white/5 text-xs">
                      <span className="text-ink-500">Affected entity</span>
                      <a href={`/dashboard/scanner?value=${encodeURIComponent(selected.entity)}&run=1`}
                        title="Look up in IntelScope"
                        className="text-ink-200 font-mono text-right truncate underline-offset-2 hover:underline hover:text-magenta transition-colors">{selected.entity}</a>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1.5 border-b border-white/5 text-xs">
                      <span className="text-ink-500">Threat actor</span>
                      {selected.actor ? (
                        <a href={`/dashboard/cti/actors?q=${encodeURIComponent(selected.actor)}`}
                          title="Open actor profile"
                          className="text-ink-200 font-mono text-right truncate underline-offset-2 hover:underline hover:text-magenta transition-colors">{selected.actor}</a>
                      ) : <span className="text-ink-200 font-mono">-</span>}
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1.5 border-b border-white/5 text-xs">
                      <span className="text-ink-500">Source</span><span className="text-ink-200 font-mono text-right truncate">{selected.source}</span>
                    </div>

                    <div>
                      <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-1.5">Detail</p>
                      <p className="text-xs text-ink-300 leading-relaxed">{selected.detail}</p>
                    </div>

                    {/* Dark-web source URL: deliberately NOT an outbound link
                        (often .onion / hostile); copying is the real action.
                        The old ExternalLink icon looked clickable but did nothing. */}
                    <button
                      onClick={() => { navigator.clipboard?.writeText(selected.url).then(() => setCopiedUrl(true)).catch(() => {}) }}
                      title="Copy source URL"
                      className="w-full flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-2/60 border border-white/8 text-[10px] text-ink-500 font-mono hover:border-white/20 hover:text-ink-300 transition-colors">
                      {copiedUrl ? <CheckCircle className="w-3 h-3 shrink-0 text-safe" /> : <Copy className="w-3 h-3 shrink-0" />}
                      <span className="truncate">{selected.url}</span>
                      {copiedUrl && <span className="ml-auto text-safe shrink-0">copied</span>}
                    </button>

                    <div>
                      <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2">Triage</p>
                      <div className="grid grid-cols-2 gap-2">
                        {(['investigating', 'mitigated', 'dismissed', 'new'] as const).map((st) => (
                          <button key={st} onClick={() => setStatus(selected, st)}
                            className={cn('flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-[11px] font-medium border transition-colors',
                              selected.status === st ? STATUS_META[st].cls : 'text-ink-400 border-white/10 hover:text-white hover:border-white/20')}>
                            {st === 'mitigated' ? <CheckCircle className="w-3 h-3" /> : st === 'investigating' ? <Clock className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                            {STATUS_META[st].label}
                          </button>
                        ))}
                      </div>
                      {/* Takedown workflow: stamps the request + notifies external services */}
                      <button onClick={() => {
                        requestTakedown(selected.id).then(() => load()).catch(() => {})
                      }}
                        disabled={selected.status === 'takedown-requested'}
                        className={cn('w-full mt-2 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-[11px] font-semibold border transition-colors',
                          selected.status === 'takedown-requested'
                            ? 'text-violet border-violet/25 bg-violet/10 cursor-default'
                            : 'text-violet border-violet/30 bg-violet/12 hover:bg-violet/20')}>
                        <ShieldAlert className="w-3 h-3" />
                        {selected.status === 'takedown-requested' ? 'Takedown requested' : 'Request takedown'}
                      </button>
                    </div>
                  </div>
                )
              })()}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
