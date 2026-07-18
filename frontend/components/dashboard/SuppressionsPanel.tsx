'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { BellOff, Plus, Trash2, Loader2, ShieldCheck, ShieldOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchSuppressions, createSuppression, deleteSuppression, type Suppression } from '@/lib/api'

const FIELDS = [
  { value: 'src_ip', label: 'Source IP' },
  { value: 'username', label: 'Username' },
  { value: 'hostname', label: 'Hostname' },
]

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * Alert-tuning workbench - suppressions & allow-lists. A suppression matches an
 * entity (src_ip / username / hostname) and drops future detections for it,
 * retro-closing any open alerts it covers; the hit counter shows how many alerts
 * it has prevented. "Allow" marks the entity known-good. This is the real
 * false-positive feedback loop, not a cosmetic toggle.
 */
export default function SuppressionsPanel() {
  const [items, setItems] = useState<Suppression[]>([])
  const [loading, setLoading] = useState(true)
  const [field, setField] = useState('src_ip')
  const [value, setValue] = useState('')
  const [mode, setMode] = useState('suppress')
  const [reason, setReason] = useState('')
  const [expiresHours, setExpiresHours] = useState('')   // '' = permanent
  const [windowStart, setWindowStart] = useState('')     // HH:MM UTC, optional pair
  const [windowEnd, setWindowEnd] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    fetchSuppressions().then(setItems).catch(() => {}).finally(() => setLoading(false))
  }, [])
  useEffect(() => { load() }, [load])

  function add() {
    const v = value.trim()
    if (!v || busy) return
    setBusy(true)
    setError(null)
    createSuppression({
      value: v, field, mode, reason: reason.trim() || undefined,
      expiresHours: expiresHours.trim() ? Number(expiresHours) : undefined,
      windowStart: windowStart.trim() || undefined,
      windowEnd: windowEnd.trim() || undefined,
    })
      .then(() => { setValue(''); setReason(''); setExpiresHours(''); setWindowStart(''); setWindowEnd(''); load() })
      .catch((e) => setError(e?.message || 'Could not create suppression'))
      .finally(() => setBusy(false))
  }

  function remove(id: string) {
    const prev = items
    setItems((xs) => xs.filter((x) => x.id !== id))
    deleteSuppression(id).catch(() => setItems(prev))
  }

  const totalHits = items.reduce((acc, s) => acc + (s.hits || 0), 0)

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      id="suppressions"
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-amber/15 border border-amber/25 shrink-0">
          <BellOff className="w-4 h-4 text-amber" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Suppressions &amp; allow-lists</h3>
          <p className="text-[10px] text-ink-500">Drop noisy detections per entity - retro-closes open alerts, blocks future ones</p>
        </div>
        <div className="ml-auto flex items-center gap-3 text-[10px]">
          <span className="text-ink-500"><b className="text-white font-mono">{items.length}</b> rules</span>
          <span className="text-ink-500"><b className="text-amber font-mono">{totalHits}</b> alerts dropped</span>
        </div>
      </div>

      {/* Add form */}
      <div className="p-4 border-b border-white/5 space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <select value={field} onChange={(e) => setField(e.target.value)}
            className="px-2.5 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-hidden focus:border-amber/40">
            {FIELDS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
          <input value={value} onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') add() }}
            placeholder="value to match (e.g. 45.9.1.2)"
            className="flex-1 min-w-[160px] px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-100 focus:outline-hidden focus:border-amber/40 placeholder-ink-600" />
          <div className="flex items-center rounded-lg border border-white/8 overflow-hidden">
            {(['suppress', 'allow'] as const).map((m) => (
              <button key={m} onClick={() => setMode(m)}
                className={cn('px-2.5 py-2 text-[11px] font-medium transition-colors flex items-center gap-1',
                  mode === m
                    ? (m === 'suppress' ? 'bg-magenta/15 text-magenta' : 'bg-safe/15 text-safe')
                    : 'text-ink-500 hover:text-ink-200')}>
                {m === 'suppress' ? <ShieldOff className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                {m}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <input value={reason} onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') add() }}
            placeholder="reason (optional) - e.g. known vuln scanner"
            className="flex-1 min-w-[200px] px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-hidden focus:border-amber/40 placeholder-ink-600" />
          {/* Time-boxing: expiry in hours and/or a daily UTC window */}
          <input value={expiresHours} onChange={(e) => setExpiresHours(e.target.value.replace(/\D/g, ''))}
            placeholder="expires (h)" title="Auto-expire after this many hours (blank = permanent)"
            className="w-20 px-2 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-200 focus:outline-hidden focus:border-amber/40 placeholder-ink-600" />
          <div className="flex items-center gap-1" title="Recurring daily window (UTC) in which this rule applies - e.g. a 02:00-04:00 maintenance window">
            <input value={windowStart} onChange={(e) => setWindowStart(e.target.value)}
              placeholder="HH:MM"
              className="w-16 px-2 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-200 focus:outline-hidden focus:border-amber/40 placeholder-ink-600" />
            <span className="text-[10px] text-ink-600">-</span>
            <input value={windowEnd} onChange={(e) => setWindowEnd(e.target.value)}
              placeholder="HH:MM"
              className="w-16 px-2 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-200 focus:outline-hidden focus:border-amber/40 placeholder-ink-600" />
          </div>
          <button onClick={add} disabled={busy || !value.trim()}
            className={cn('flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold transition-all',
              value.trim() && !busy ? 'bg-amber/20 border border-amber/35 text-amber hover:bg-amber/30' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            Add rule
          </button>
        </div>
        {error && <p className="text-[11px] text-threat">{error}</p>}
      </div>

      {/* List */}
      <div className="divide-y divide-white/4 max-h-80 overflow-y-auto">
        {loading && <p className="text-[11px] text-ink-600 py-8 text-center animate-pulse">Loading suppressions…</p>}
        {!loading && items.length === 0 && (
          <p className="text-[11px] text-ink-600 py-8 text-center">
            No suppressions yet. Add one above, or click <b className="text-ink-400">Suppress</b> on any alert.
          </p>
        )}
        <AnimatePresence>
          {items.map((s) => (
            <motion.div key={s.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, height: 0 }}
              className="flex items-center gap-3 px-5 py-3 group">
              <div className={cn('p-1.5 rounded-lg shrink-0',
                s.mode === 'allow' ? 'bg-safe/12' : 'bg-magenta/12')}>
                {s.mode === 'allow'
                  ? <ShieldCheck className="w-3.5 h-3.5 text-safe" />
                  : <ShieldOff className="w-3.5 h-3.5 text-magenta" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-mono text-white truncate">
                    {FIELDS.find((f) => f.value === s.field)?.label ?? s.field}={s.value}
                  </span>
                  <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold',
                    s.mode === 'allow' ? 'text-safe bg-safe/12' : 'text-magenta bg-magenta/12')}>{s.mode}</span>
                  {s.ruleId && s.ruleId !== '*' && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded-sm bg-violet/10 text-violet font-mono">{s.ruleId}</span>
                  )}
                  {/* time-boxed entries show whether they apply right now */}
                  {(s.expiresAt || s.windowStart) && (
                    <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold',
                      s.active ? 'text-safe bg-safe/12' : 'text-ink-500 bg-white/6')}>
                      {s.active ? 'active' : 'inactive'}
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-ink-600 mt-0.5 truncate">
                  {s.reason ? `${s.reason} · ` : ''}{relTime(s.createdAt)}{s.createdBy ? ` · ${s.createdBy}` : ''}
                  {s.windowStart && s.windowEnd ? ` · daily ${s.windowStart}-${s.windowEnd} UTC` : ''}
                  {s.expiresAt ? ` · expires ${new Date(s.expiresAt).toLocaleString()}` : ''}
                </p>
              </div>
              <div className="text-right shrink-0">
                <div className="text-xs font-bold font-mono text-amber">{s.hits}</div>
                <div className="text-[9px] text-ink-600">dropped</div>
              </div>
              <button onClick={() => remove(s.id)}
                className="p-1.5 rounded-lg text-ink-600 hover:text-threat hover:bg-threat/10 transition-colors opacity-0 group-hover:opacity-100 shrink-0"
                title="Remove suppression">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}
