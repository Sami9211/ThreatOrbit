'use client'
import { tk } from '@/lib/colors'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Fingerprint, X, ShieldCheck, ShieldOff, Eye, Clock,
  TrendingDown, RefreshCw, Loader2, Share2, Sparkles,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchIocs, fetchIoc, addIocSighting, setIocKnownGood, removeIocKnownGood, runIocDecay,
  fetchStixBundle, enrichIoc, type Ioc, type IocDetail, type EnrichmentResult,
} from '@/lib/api'

const VERDICT_COLOR: Record<string, string> = {
  malicious: tk('magenta'), suspicious: tk('amber'), benign: tk('safe'), clean: tk('safe'), unknown: '#665B7D',
}

const SEV_COLOR: Record<string, string> = {
  critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe'), info: tk('violet'),
}
const STATUS_STYLE: Record<string, { color: string; label: string }> = {
  active: { color: tk('safe'), label: 'Active' },
  expired: { color: '#665B7D', label: 'Expired' },
  'known-good': { color: tk('violet'), label: 'Known-good' },
}
const FILTERS = ['all', 'active', 'expired', 'known-good']

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * IOC database with lifecycle - confidence decay, sightings, expiry and
 * known-good handling. The effective-confidence bar shows decay against the
 * asserted value; analysts can record a sighting (refreshes/reactivates) or
 * whitelist an indicator (stops it matching).
 */
export default function IocLifecyclePanel() {
  const [items, setItems] = useState<Ioc[]>([])
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState<IocDetail | null>(null)
  const [busy, setBusy] = useState(false)
  const [decaying, setDecaying] = useState(false)
  const [enrichment, setEnrichment] = useState<EnrichmentResult | null>(null)
  const [enriching, setEnriching] = useState(false)

  const load = useCallback(() => {
    const params: Record<string, string> = { limit: '60', sort: 'last_seen', order: 'desc' }
    if (filter !== 'all') params.status = filter
    fetchIocs(params).then(({ items }) => setItems(items)).catch(() => {}).finally(() => setLoading(false))
  }, [filter])
  useEffect(() => { load() }, [load])

  function open(id: string) {
    setEnrichment(null)
    fetchIoc(id).then(setDetail).catch(() => {})
  }
  function enrich() {
    if (!detail || enriching) return
    setEnriching(true)
    enrichIoc(detail.id).then(setEnrichment).catch(() => {}).finally(() => setEnriching(false))
  }
  function refreshDetail(id: string) {
    fetchIoc(id).then(setDetail).catch(() => {})
    load()
  }

  function sight() {
    if (!detail || busy) return
    setBusy(true)
    addIocSighting(detail.id, 'analyst', 'Confirmed from CTI console')
      .then((d) => { setDetail(d); load() }).catch(() => {}).finally(() => setBusy(false))
  }
  function toggleKnownGood() {
    if (!detail || busy) return
    setBusy(true)
    const fn = detail.lifecycle.status === 'known-good' ? removeIocKnownGood : setIocKnownGood
    fn(detail.id).then(() => refreshDetail(detail.id)).catch(() => {}).finally(() => setBusy(false))
  }
  function decay() {
    setDecaying(true)
    runIocDecay().then(() => load()).catch(() => {}).finally(() => setDecaying(false))
  }
  function exportStix() {
    fetchStixBundle().then((b) => {
      const blob = new Blob([JSON.stringify(b, null, 2)], { type: 'application/stix+json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threatorbit-stix-bundle-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    }).catch(() => {})
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
          <Fingerprint className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">IOC database &amp; lifecycle</h3>
          <p className="text-[10px] text-ink-500">Confidence decay · sightings · expiry · known-good handling</p>
        </div>
        <div className="ml-auto flex items-center gap-1">
          {FILTERS.map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className={cn('px-2.5 py-1 rounded-lg text-[11px] font-medium capitalize transition-colors',
                filter === f ? 'bg-violet/15 text-violet border border-violet/30' : 'text-ink-500 hover:text-ink-200 border border-white/8')}>
              {f}
            </button>
          ))}
          <button onClick={decay} disabled={decaying} title="Run decay maintenance"
            className="ml-1 p-1.5 rounded-lg text-ink-500 hover:text-violet hover:bg-violet/10 transition-colors">
            {decaying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
          </button>
          <button onClick={exportStix} title="Export STIX 2.1 bundle (also served via TAXII 2.1 at /taxii2/)"
            className="p-1.5 rounded-lg text-ink-500 hover:text-violet hover:bg-violet/10 transition-colors">
            <Share2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="divide-y divide-white/4 max-h-96 overflow-y-auto">
        {loading && <p className="text-[11px] text-ink-600 py-8 text-center animate-pulse">Loading indicators…</p>}
        {!loading && items.length === 0 && (
          <p className="text-[11px] text-ink-600 py-8 text-center">No indicators{filter !== 'all' ? ` (${filter})` : ''} yet.</p>
        )}
        {items.map((i) => {
          const st = STATUS_STYLE[i.status] ?? STATUS_STYLE.active
          const decayed = i.effectiveConfidence < i.confidence - 2
          return (
            <button key={i.id} onClick={() => open(i.id)}
              className="w-full text-left flex items-center gap-3 px-5 py-2.5 hover:bg-white/3 transition-colors">
              <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-white/5 text-ink-400 shrink-0 w-12 text-center">{i.type}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-white truncate">{i.value}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold shrink-0"
                    style={{ color: st.color, background: `${st.color}15` }}>{st.label}</span>
                </div>
                <p className="text-[10px] text-ink-600 mt-0.5 truncate">
                  {i.threatType || 'indicator'} · {i.sightings} sighting{i.sightings !== 1 ? 's' : ''} · {relTime(i.lastSeen)}
                </p>
              </div>
              {/* effective vs asserted confidence */}
              <div className="w-24 shrink-0 hidden sm:block">
                <div className="flex items-center justify-between text-[9px] mb-0.5">
                  <span className="text-ink-600 flex items-center gap-0.5">{decayed && <TrendingDown className="w-2.5 h-2.5 text-amber" />}conf</span>
                  <span style={{ color: SEV_COLOR[i.severity] ?? tk('violet') }}>{i.effectiveConfidence}<span className="text-ink-700">/{i.confidence}</span></span>
                </div>
                <div className="h-1.5 rounded-full bg-white/8 overflow-hidden relative">
                  <div className="absolute inset-y-0 left-0 rounded-full bg-white/15" style={{ width: `${i.confidence}%` }} />
                  <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${i.effectiveConfidence}%`, background: SEV_COLOR[i.severity] ?? tk('violet') }} />
                </div>
              </div>
            </button>
          )
        })}
      </div>

      {/* Detail drawer */}
      <AnimatePresence>
        {detail && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-sm" onClick={() => setDetail(null)}>
            <motion.div initial={{ x: 440 }} animate={{ x: 0 }} exit={{ x: 440 }} transition={{ type: 'tween', duration: 0.2 }}
              onClick={(e) => e.stopPropagation()} className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto p-5 space-y-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] text-ink-500 uppercase">{detail.type} indicator</p>
                  <h2 className="text-sm font-semibold text-white font-mono break-all">{detail.value}</h2>
                </div>
                <button onClick={() => setDetail(null)} className="p-1.5 rounded-lg text-ink-500 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
              </div>

              {/* Lifecycle */}
              {(() => {
                const lc = detail.lifecycle
                const st = STATUS_STYLE[lc.status] ?? STATUS_STYLE.active
                return (
                  <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-ink-500 uppercase tracking-wider">Lifecycle</span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                        style={{ color: st.color, background: `${st.color}18` }}>{st.label}</span>
                    </div>
                    <div>
                      <div className="flex items-center justify-between text-[10px] mb-1">
                        <span className="text-ink-500">Effective confidence (decayed)</span>
                        <span className="font-mono text-white">{lc.effectiveConfidence}<span className="text-ink-600"> / {lc.assertedConfidence}</span></span>
                      </div>
                      <div className="h-2 rounded-full bg-white/8 overflow-hidden relative">
                        <div className="absolute inset-y-0 left-0 rounded-full bg-white/15" style={{ width: `${lc.assertedConfidence}%` }} />
                        <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${lc.effectiveConfidence}%`, background: SEV_COLOR[detail.severity] ?? tk('violet') }} />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center">
                      {[
                        { label: 'age', value: `${lc.ageDays}d` },
                        { label: 'half-life', value: `${lc.halfLifeDays}d` },
                        { label: lc.status === 'expired' ? 'expired' : 'expires in', value: lc.expiresInDays == null ? '-' : `${lc.expiresInDays}d` },
                      ].map((m) => (
                        <div key={m.label} className="rounded-lg bg-surface-2/60 border border-white/6 px-2 py-1.5">
                          <div className="text-xs font-mono text-white">{m.value}</div>
                          <div className="text-[9px] text-ink-600">{m.label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })()}

              {/* Actions */}
              <div className="flex items-center gap-2">
                <button onClick={sight} disabled={busy}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-safe/15 border border-safe/30 text-safe hover:bg-safe/25 transition-colors">
                  {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />} Record sighting
                </button>
                <button onClick={toggleKnownGood} disabled={busy}
                  className={cn('flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-colors',
                    detail.lifecycle.status === 'known-good'
                      ? 'bg-magenta/12 border-magenta/30 text-magenta hover:bg-magenta/20'
                      : 'bg-violet/12 border-violet/30 text-violet hover:bg-violet/20')}>
                  {detail.lifecycle.status === 'known-good'
                    ? <><ShieldOff className="w-3.5 h-3.5" /> Un-whitelist</>
                    : <><ShieldCheck className="w-3.5 h-3.5" /> Mark known-good</>}
                </button>
                <button onClick={enrich} disabled={enriching}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-amber/12 border border-amber/30 text-amber hover:bg-amber/20 transition-colors">
                  {enriching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />} Enrich
                </button>
              </div>

              {/* Enrichment results */}
              {enrichment && (
                <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-ink-500 uppercase tracking-wider">Enrichment</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                      style={{ color: VERDICT_COLOR[enrichment.verdict] ?? '#665B7D', background: `${VERDICT_COLOR[enrichment.verdict] ?? '#665B7D'}18` }}>
                      {enrichment.verdict}
                    </span>
                  </div>
                  {enrichment.providers.map((p) => (
                    <div key={p.provider} className="flex items-start gap-2.5">
                      <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                        style={{ background: p.available ? (VERDICT_COLOR[p.verdict] ?? '#665B7D') : '#3a3450' }} />
                      <div className="min-w-0 flex-1">
                        <p className="text-[11px] text-ink-200 capitalize">
                          {p.provider}
                          {!p.available && <span className="ml-1.5 text-[9px] text-ink-600">not configured</span>}
                          {p.cached && <span className="ml-1.5 text-[9px] text-ink-700">cached</span>}
                        </p>
                        <p className="text-[10px] text-ink-500">{p.available ? p.summary : p.reason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                {[
                  ['Severity', detail.severity], ['Threat type', detail.threatType || '-'],
                  ['Actor', detail.actor || '-'], ['Source', detail.source || '-'],
                  ['First seen', relTime(detail.firstSeen)], ['Last seen', relTime(detail.lastSeen)],
                ].map(([k, v]) => (
                  <div key={k} className="px-3 py-2 rounded-lg bg-surface-2/40 border border-white/5">
                    <div className="text-[9px] text-ink-600 uppercase">{k}</div>
                    <div className="text-ink-200 truncate capitalize">{v}</div>
                  </div>
                ))}
              </div>

              {/* Sightings timeline */}
              <div>
                <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Clock className="w-3 h-3" /> Sightings ({detail.sightingsHistory.length})
                </p>
                <div className="space-y-1.5">
                  {detail.sightingsHistory.length === 0 && <p className="text-[10px] text-ink-600">No recorded sightings yet.</p>}
                  {detail.sightingsHistory.map((s) => (
                    <div key={s.id} className="flex items-start gap-2 px-2.5 py-1.5 rounded-lg bg-surface-2/40 border border-white/5">
                      <span className="w-1.5 h-1.5 rounded-full bg-safe mt-1 shrink-0" />
                      <div className="min-w-0">
                        <p className="text-[10px] text-ink-300">{s.source} <span className="text-ink-600">· {relTime(s.ts)}</span></p>
                        {s.context && <p className="text-[10px] text-ink-600 truncate">{s.context}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
