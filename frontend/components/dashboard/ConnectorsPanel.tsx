'use client'

import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plug, RefreshCw, Plus, X, Trash2, Play, Pause, CheckCircle,
  AlertTriangle, Loader2, Database,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchConnectors, fetchConnectorKinds, createConnector, patchConnector,
  deleteConnector, runConnector,
  type Connector, type ConnectorKind,
} from '@/lib/api'

const STATUS_META: Record<string, { label: string; cls: string; dot: string }> = {
  ok:      { label: 'Synced',  cls: 'text-safe border-safe/25 bg-safe/10',     dot: 'bg-safe' },
  idle:    { label: 'Idle',    cls: 'text-ink-400 border-white/10 bg-white/5',  dot: 'bg-ink-500' },
  running: { label: 'Syncing', cls: 'text-violet border-violet/25 bg-violet/10', dot: 'bg-violet animate-pulse' },
  error:   { label: 'Error',   cls: 'text-threat border-threat/25 bg-threat/10', dot: 'bg-threat' },
}

function relTime(iso: string | null): string {
  if (!iso) return 'never'
  const secs = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s ago`
  const m = Math.floor(secs / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * Connector manager - the real-data control surface. Lists every threat-intel
 * connector (built-in OSINT engine, NVD, plus any custom source you add),
 * shows live sync status + indicator counts, and lets you sync now, pause,
 * add, or remove. This is what makes the dashboard show real, live data.
 */
export default function ConnectorsPanel() {
  const [connectors, setConnectors] = useState<Connector[] | null>(null)
  const [kinds, setKinds] = useState<ConnectorKind[]>([])
  const [unavailable, setUnavailable] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [showAdd, setShowAdd] = useState(false)

  const load = () => {
    fetchConnectors().then(setConnectors).catch(() => setUnavailable(true))
  }
  useEffect(() => {
    load()
    fetchConnectorKinds().then(setKinds).catch(() => {})
  }, [])

  function flash(text: string) {
    setMsg(text)
    setTimeout(() => setMsg(null), 6000)
  }

  function sync(c: Connector) {
    if (busy) return
    setBusy(c.id)
    setConnectors((prev) => prev?.map((x) => (x.id === c.id ? { ...x, status: 'running' } : x)) ?? prev)
    runConnector(c.id)
      .then(({ result, connector }) => {
        setConnectors((prev) => prev?.map((x) => (x.id === c.id ? connector : x)) ?? prev)
        flash(result.error
          ? `${c.name}: ${result.error}`
          : `${c.name}: imported ${result.imported ?? 0} new indicators (${result.duplicates ?? 0} already known)`)
      })
      .catch(() => flash(`${c.name}: sync failed - is the dashboard API running?`))
      .finally(() => setBusy(null))
  }

  function toggle(c: Connector) {
    const next = !c.enabled
    setConnectors((prev) => prev?.map((x) => (x.id === c.id ? { ...x, enabled: next ? 1 : 0 } : x)) ?? prev)
    patchConnector(c.id, { enabled: next }).catch(() => load())
  }

  function remove(c: Connector) {
    if (!window.confirm(`Remove connector "${c.name}"?`)) return
    setConnectors((prev) => prev?.filter((x) => x.id !== c.id) ?? prev)
    deleteConnector(c.id).catch(() => load())
  }

  async function add(values: Record<string, string>) {
    const fieldMap: Record<string, string> = {}
    for (const k of ['value', 'type', 'threat_type', 'confidence', 'severity', 'tags']) {
      if (values[`fm_${k}`]?.trim()) fieldMap[k] = values[`fm_${k}`].trim()
    }
    const created = await createConnector({
      name: values.name, kind: values.kind,
      url: values.url || undefined,
      api_key: values.api_key || undefined,
      interval_minutes: values.interval_minutes ? Number(values.interval_minutes) : undefined,
      field_map: Object.keys(fieldMap).length ? fieldMap : undefined,
    })
    setConnectors((prev) => [...(prev ?? []), created])
    setShowAdd(false)
    flash(`Connector "${created.name}" added - press Sync to pull data now.`)
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25 shrink-0">
          <Plug className="w-4 h-4 text-magenta" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Threat Intel Connectors</h3>
          <p className="text-[10px] text-ink-500">Real indicators flow from these into your CTI store</p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
          <Plus className="w-3.5 h-3.5" /> Add Connector
        </button>
      </div>

      {msg && <div className="px-5 py-2 text-[11px] text-safe bg-safe/5 border-b border-safe/15" role="status">{msg}</div>}

      <div className="p-4 space-y-2.5">
        {unavailable && (
          <p className="text-xs text-ink-600 py-4 text-center">Connector store unavailable. Start the dashboard API.</p>
        )}
        {!unavailable && connectors === null && (
          <p className="text-xs text-ink-600 py-4 text-center animate-pulse">Loading connectors…</p>
        )}
        {!unavailable && connectors?.length === 0 && (
          <p className="text-xs text-ink-600 py-4 text-center">No connectors yet - add one to start ingesting real data.</p>
        )}
        {connectors?.map((c) => {
          const st = STATUS_META[c.status] ?? STATUS_META.idle
          return (
            <div key={c.id} className="flex items-center gap-3 p-3 rounded-xl border border-white/8 bg-surface">
              <div className="p-2 rounded-lg bg-violet/10 shrink-0"><Database className="w-4 h-4 text-violet" /></div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-semibold text-white truncate">{c.name}</span>
                  {Boolean(c.builtin) && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-white/5 text-ink-400 border border-white/10">built-in</span>}
                  <span className={cn('flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full border', st.cls)}>
                    <span className={cn('w-1.5 h-1.5 rounded-full', st.dot)} />{st.label}
                  </span>
                </div>
                <p className="text-[10px] text-ink-600 mt-0.5 truncate">
                  {c.kind} · {c.indicatorCount.toLocaleString()} indicators · every {c.intervalMinutes}m · last {relTime(c.lastRun)}
                  {c.lastError ? <span className="text-threat"> · {c.lastError.slice(0, 60)}</span> : ''}
                </p>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => sync(c)}
                  disabled={busy === c.id}
                  title="Sync now"
                  className="p-1.5 rounded-lg text-ink-400 hover:text-magenta hover:bg-magenta/10 transition-colors disabled:opacity-50">
                  {busy === c.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => toggle(c)}
                  title={c.enabled ? 'Pause auto-sync' : 'Resume auto-sync'}
                  className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors">
                  {c.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </button>
                {!c.builtin && (
                  <button onClick={() => remove(c)} title="Delete connector"
                    className="p-1.5 rounded-lg text-ink-400 hover:text-threat hover:bg-threat/5 transition-colors">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      <AnimatePresence>
        {showAdd && <AddConnectorModal kinds={kinds} onClose={() => setShowAdd(false)} onAdd={add} />}
      </AnimatePresence>
    </motion.div>
  )
}

/* ── Add-connector modal ─────────────────────────────────────────── */
function AddConnectorModal({ kinds, onClose, onAdd }: {
  kinds: ConnectorKind[]
  onClose: () => void
  onAdd: (values: Record<string, string>) => Promise<void>
}) {
  const [kind, setKind] = useState('json')
  const [values, setValues] = useState<Record<string, string>>({ name: '', url: '', api_key: '', interval_minutes: '' })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const preset = kinds.find((k) => k.kind === kind)
  const isCustom = kind === 'json' || kind === 'csv' || kind === 'stix'
  const set = (k: string) => (v: string) => setValues((s) => ({ ...s, [k]: v }))

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!values.name.trim() || submitting) return
    if (preset?.needs_key && !values.api_key.trim()) { setError('This source needs an API key.'); return }
    setSubmitting(true)
    setError(null)
    try {
      await onAdd({ ...values, kind })
    } catch (err) {
      setError(err instanceof Error && err.message.includes('key')
        ? 'This source needs an API key.'
        : 'Could not add the connector. Check the URL and that you have admin access.')
      setSubmitting(false)
    }
  }

  const input = 'w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 placeholder-ink-600'

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 backdrop-blur-sm p-6" onClick={onClose}>
      <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-2xl border border-white/10 bg-surface p-6 max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-magenta/15"><Plug className="w-4 h-4 text-magenta" /></div>
            <h2 className="text-sm font-semibold text-white">Add Threat Intel Connector</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5"><X className="w-4 h-4" /></button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Source type</label>
            <select value={kind} onChange={(e) => { setKind(e.target.value); const p = kinds.find(k => k.kind === e.target.value); if (p) setValues(s => ({ ...s, url: p.default_url, interval_minutes: String(p.default_interval) })) }} className={input}>
              {kinds.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}
            </select>
            {preset && <p className="text-[10px] text-ink-600 mt-1">{preset.description}</p>}
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Connector name <span className="text-magenta">*</span></label>
            <input value={values.name} onChange={(e) => set('name')(e.target.value)} placeholder="e.g. My ThreatFox feed" className={input} />
          </div>

          {kind !== 'threatorbit' && (
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Source URL</label>
              <input value={values.url} onChange={(e) => set('url')(e.target.value)} placeholder={preset?.default_url || 'https://your-source/api/indicators'} className={cn(input, 'font-mono text-xs')} />
            </div>
          )}

          {preset?.needs_key !== undefined && kind !== 'threatorbit' && kind !== 'nvd' && (
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">
                API key {preset?.needs_key && <span className="text-magenta">*</span>}
                {!preset?.needs_key && <span className="text-ink-600">(optional)</span>}
              </label>
              <input type="password" value={values.api_key} onChange={(e) => set('api_key')(e.target.value)} placeholder="paste your key" className={cn(input, 'font-mono text-xs')} />
            </div>
          )}

          {isCustom && (
            <div className="rounded-xl border border-white/8 bg-surface-2/40 p-3 space-y-3">
              <p className="text-[11px] text-ink-400">
                Field mapping - tell us which {kind === 'csv' ? 'columns' : 'fields'} hold each value.
                Leave <span className="font-mono">type</span> blank to auto-detect (ip / domain / url / hash / cve).
              </p>
              <div className="grid grid-cols-2 gap-2">
                {[['value', 'Indicator value *'], ['type', 'Type'], ['threat_type', 'Threat type'], ['confidence', 'Confidence'], ['severity', 'Severity'], ['tags', 'Tags']].map(([k, label]) => (
                  <div key={k}>
                    <label className="block text-[10px] text-ink-500 mb-1">{label}</label>
                    <input value={values[`fm_${k}`] ?? ''} onChange={(e) => set(`fm_${k}`)(e.target.value)} placeholder={k} className="w-full px-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 font-mono focus:outline-none focus:border-magenta/40 placeholder-ink-700" />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Auto-sync every (minutes)</label>
            <input type="number" value={values.interval_minutes} onChange={(e) => set('interval_minutes')(e.target.value)} placeholder={String(preset?.default_interval ?? 60)} className={input} />
          </div>

          {error && <p className="flex items-center gap-2 px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert"><AlertTriangle className="w-3.5 h-3.5 shrink-0" />{error}</p>}

          <button type="submit" disabled={!values.name.trim() || submitting}
            className={cn('w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold transition-all',
              values.name.trim() && !submitting ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Adding…</> : <><CheckCircle className="w-4 h-4" /> Add Connector</>}
          </button>
        </form>
      </motion.div>
    </motion.div>
  )
}
