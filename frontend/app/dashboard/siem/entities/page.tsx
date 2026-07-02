'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Users, User, Server, Globe, X, ExternalLink, Activity } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchEntities, fetchEntityDetail, type RiskEntity, type EntityDetail } from '@/lib/api'
import { tk } from '@/lib/colors'

const BAND_COLOR: Record<string, string> = {
  critical: tk('magenta'), high: tk('threat'), elevated: tk('amber'), normal: tk('safe'),
}
const SEV_COLOR: Record<string, string> = {
  critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe'), info: tk('violet'),
}
const TYPE_ICON: Record<string, React.ComponentType<any>> = { user: User, host: Server, ip: Globe }

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

export default function EntityRiskPage() {
  const [type, setType] = useState('all')
  const [data, setData] = useState<{ entities: RiskEntity[]; summary: { tracked: number; highRisk: number } } | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<EntityDetail | null>(null)

  const load = useCallback(() => {
    fetchEntities(type, 40).then(setData).catch(() => {}).finally(() => setLoading(false))
  }, [type])
  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [load])

  function openEntity(e: RiskEntity) {
    fetchEntityDetail(e.type, e.value).then(setSelected).catch(() => {})
  }

  const kpis = [
    { label: 'Entities tracked', value: data?.summary.tracked ?? 0, color: 'text-white' },
    { label: 'High risk', value: data?.summary.highRisk ?? 0, color: 'text-magenta' },
  ]
  const maxTimeline = selected ? Math.max(1, ...selected.timeline.map((t) => t.count)) : 1

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      <div className="flex items-center justify-between gap-3 px-6 py-4 border-b border-white/5 shrink-0 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-violet" />
            <h1 className="text-lg font-display font-semibold text-white">Entity Risk (UEBA)</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Users, hosts &amp; IPs ranked by behavioural risk from their alert history</p>
        </div>
        <div className="flex items-center gap-1">
          {['all', 'user', 'host', 'ip'].map((t) => (
            <button key={t} onClick={() => setType(t)}
              className={cn('px-2.5 py-1 rounded-lg text-[11px] font-medium capitalize transition-colors',
                type === t ? 'bg-magenta/15 text-magenta border border-magenta/30' : 'text-ink-500 hover:text-ink-200 border border-white/8')}>
              {t === 'ip' ? 'IPs' : t}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {kpis.map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {loading && <p className="text-xs text-ink-600 py-10 text-center animate-pulse">Computing entity risk…</p>}
        {!loading && data?.entities.length === 0 && (
          <p className="text-xs text-ink-600 py-10 text-center">No entities with alert activity yet.</p>
        )}
        {data?.entities.map((e) => {
          const Icon = TYPE_ICON[e.type]
          return (
            <motion.button key={`${e.type}-${e.value}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
              onClick={() => openEntity(e)}
              className="w-full text-left flex items-center gap-3 p-3 rounded-xl border border-white/8 bg-surface hover:border-white/15 transition-colors">
              <div className="p-2 rounded-lg shrink-0" style={{ background: `${BAND_COLOR[e.band]}18` }}>
                <Icon className="w-4 h-4" style={{ color: BAND_COLOR[e.band] }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-white font-mono truncate">{e.value}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold" style={{ color: BAND_COLOR[e.band], background: `${BAND_COLOR[e.band]}18` }}>{e.band}</span>
                </div>
                <p className="text-[10px] text-ink-600 mt-0.5">
                  {e.type} · {e.alerts} alerts ({e.open} open) · {e.techniqueCount} techniques · {relTime(e.lastSeen)}
                </p>
              </div>
              {/* risk bar */}
              <div className="w-28 shrink-0 hidden sm:block">
                <div className="flex items-center justify-between text-[9px] text-ink-600 mb-0.5"><span>risk</span><span style={{ color: BAND_COLOR[e.band] }}>{e.risk}</span></div>
                <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${e.risk}%`, background: BAND_COLOR[e.band] }} />
                </div>
              </div>
            </motion.button>
          )
        })}
      </div>

      <AnimatePresence>
        {selected && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-sm" onClick={() => setSelected(null)}>
            <motion.div initial={{ x: 460 }} animate={{ x: 0 }} exit={{ x: 460 }} transition={{ type: 'tween', duration: 0.2 }}
              onClick={(e) => e.stopPropagation()} className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto p-5 space-y-5">
              <div className="flex items-start justify-between">
                <div className="min-w-0">
                  <p className="text-[10px] text-ink-500 uppercase">{selected.type}</p>
                  <h2 className="text-sm font-semibold text-white font-mono break-all">{selected.value}</h2>
                </div>
                <button onClick={() => setSelected(null)} className="p-1.5 rounded-lg text-ink-500 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="px-3 py-2.5 rounded-xl bg-surface-2/60 border border-white/8">
                  <div className="text-lg font-bold font-mono" style={{ color: selected.risk >= 45 ? tk('magenta') : tk('safe') }}>{selected.risk}</div>
                  <div className="text-[10px] text-ink-500">risk score</div>
                </div>
                <div className="px-3 py-2.5 rounded-xl bg-surface-2/60 border border-white/8">
                  <div className="text-lg font-bold font-mono text-white">{selected.alertCount}</div>
                  <div className="text-[10px] text-ink-500">alerts</div>
                </div>
              </div>

              {/* Timeline */}
              {selected.timeline.length > 0 && (
                <div>
                  <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2 flex items-center gap-1.5"><Activity className="w-3 h-3" /> Activity timeline</p>
                  <div className="flex items-end gap-1 h-16">
                    {selected.timeline.map((t) => (
                      <div key={t.day} className="flex-1 flex flex-col items-center justify-end" title={`${t.day}: ${t.count}`}>
                        <div className="w-full rounded-t bg-magenta/60" style={{ height: `${(t.count / maxTimeline) * 100}%`, minHeight: 2 }} />
                        <span className="text-[7px] text-ink-700 mt-0.5">{t.day.slice(5)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Learned baseline (deviation-from-norm) */}
              {selected.baseline && selected.baseline.confidence !== 'insufficient-history' && (
                <div className={cn('rounded-xl border p-3',
                  selected.baseline.deviating ? 'border-magenta/30 bg-magenta/8' : 'border-white/8 bg-surface-2/50')}>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-ink-500 uppercase tracking-wider">Behavioural baseline</span>
                    {selected.baseline.deviating
                      ? <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-magenta/15 text-magenta font-semibold uppercase">deviating</span>
                      : <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-safe/12 text-safe font-semibold uppercase">normal</span>}
                  </div>
                  <p className="text-[11px] text-ink-300 mt-1.5">
                    Today <b className="font-mono text-white">{selected.baseline.current}</b> vs norm{' '}
                    <span className="font-mono">{selected.baseline.mean}±{selected.baseline.stdDev}</span>/day ·
                    z-score <b className="font-mono" style={{ color: selected.baseline.deviating ? tk('magenta') : tk('safe') }}>{selected.baseline.zScore}</b>
                  </p>
                </div>
              )}

              {/* Top techniques */}
              {selected.topTechniques.length > 0 && (
                <div>
                  <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2">Top techniques</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.topTechniques.map((t) => (
                      <span key={t.technique} className="text-[10px] px-2 py-0.5 rounded bg-violet/10 text-violet border border-violet/20 font-mono">{t.technique} ×{t.count}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Contributing alerts */}
              <div>
                <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2">Contributing alerts</p>
                <div className="space-y-1.5">
                  {selected.alerts.map((a) => (
                    <div key={a.id} className="flex items-start gap-2 px-2.5 py-2 rounded-lg bg-surface-2/40 border border-white/5">
                      <span className="w-1.5 h-1.5 rounded-full mt-1 shrink-0" style={{ background: SEV_COLOR[a.severity] }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] text-ink-200 truncate">{a.title}</p>
                        <p className="text-[9px] text-ink-600">{a.rule_name} · {relTime(a.ts)} · {a.status}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <a href={`/dashboard/siem?q=${encodeURIComponent(selected.value)}`} className="flex items-center gap-1.5 mt-3 text-[11px] text-magenta hover:underline">
                  <ExternalLink className="w-3.5 h-3.5" /> View all in SIEM queue
                </a>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
