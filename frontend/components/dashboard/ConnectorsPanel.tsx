'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plug, RefreshCw, Plus, X, Trash2, Play, Pause, CheckCircle,
  AlertTriangle, Loader2, Database, Pencil,
} from 'lucide-react'
import { cn, formatEvery } from '@/lib/utils'
import { usePermissions } from '@/lib/usePermissions'
import {
  fetchConnectors, fetchConnectorKinds, createConnector, patchConnector,
  deleteConnector, runConnector, fetchConnectorWorks,
  type Connector, type ConnectorKind, type ConnectorWork,
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
  const [presetKind, setPresetKind] = useState<string | undefined>(undefined)
  const [showCatalog, setShowCatalog] = useState(false)
  const [editing, setEditing] = useState<Connector | null>(null)
  // Connector mutations require the connectors.manage capability. Non-admins
  // see the state (read-only) with the controls disabled + a clear reason,
  // rather than buttons that 403 on click.
  const { can } = usePermissions()
  const canManage = can('connectors.manage')  // false until confirmed (open-closed)
  const adminOnly = 'Requires administrator privileges'

  const [works, setWorks] = useState<ConnectorWork[]>([])

  const load = useCallback(() => {
    fetchConnectors()
      .then((c) => { setConnectors(c); setUnavailable(false) })
      .catch(() => setUnavailable(true))
    fetchConnectorWorks(20).then(setWorks).catch(() => {})
  }, [])

  // Newest work per connector. The endpoint returns running works first, so the
  // entry we keep is the in-flight run when there is one, else the last finished.
  const workOf = useMemo(() => {
    const m = new Map<string, ConnectorWork>()
    for (const w of works) if (w.connectorId && !m.has(w.connectorId)) m.set(w.connectorId, w)
    return m
  }, [works])
  const importing = works.some((w) => w.status === 'running')

  useEffect(() => {
    fetchConnectorKinds().then(setKinds).catch(() => {})
  }, [])

  useEffect(() => {
    load()
    // Connectors sync on their own cadence. This panel used to load exactly once,
    // so a background sync never appeared: the rows sat on a stale "Idle - last
    // never" and automatic syncing looked broken even while it was working. Poll
    // quickly while an import is in flight, slowly when nothing is happening.
    const t = window.setInterval(load, importing ? 2000 : 15000)
    return () => window.clearInterval(t)
  }, [load, importing])

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
    // Only send an interval when it parses to a real number. `Number("undefined")`
    // is NaN, which serialises to null and makes the API reject the whole create
    // with a 422 - never let a bad field value block an otherwise valid connector.
    // NOTE: values.interval_minutes holds SECONDS (the field is labelled in
    // seconds); it is sent as interval_seconds, which the API treats as the
    // source of truth. Sending it as minutes would read 30s as 30 minutes.
    const interval = Number(values.interval_minutes)
    // Managed providers (OTX/NVD/the bundled engine) advertise needsUrl:false and
    // the UI hides their URL field - so don't send one. The backend fills its own
    // fixed endpoint. Echoing the preset's default back would also (correctly)
    // trip the SSRF guard for the bundled engine, whose endpoint is loopback.
    const kindPreset = kinds.find((k) => k.kind === values.kind)
    const sendUrl = kindPreset?.needsUrl === false ? undefined : (values.url || undefined)
    const created = await createConnector({
      name: values.name, kind: values.kind,
      url: sendUrl,
      api_key: values.api_key || undefined,
      interval_seconds: Number.isFinite(interval) && interval > 0 ? interval : undefined,
      field_map: Object.keys(fieldMap).length ? fieldMap : undefined,
    })
    setConnectors((prev) => [...(prev ?? []), created])
    setShowAdd(false)
    flash(`Connector "${created.name}" added - press Sync to pull data now.`)
  }

  // Reconfigure an existing connector: only changed fields are sent, and the
  // API key is left untouched unless a new one is typed (it never leaves the
  // server, so we can't prefill it).
  async function update(c: Connector, values: Record<string, string>) {
    const patch: Parameters<typeof patchConnector>[1] = {}
    if (values.name?.trim() && values.name.trim() !== c.name) patch.name = values.name.trim()
    if (values.url !== undefined && values.url.trim() !== (c.url ?? '')) patch.url = values.url.trim()
    if (values.interval_minutes?.trim()) {          // holds SECONDS - see add()
      const n = Number(values.interval_minutes)
      const currentSecs = c.intervalSeconds || c.intervalMinutes * 60
      if (Number.isFinite(n) && n > 0 && n !== currentSecs) patch.interval_seconds = n
    }
    if (values.api_key?.trim()) patch.api_key = values.api_key.trim()
    if (['json', 'csv', 'stix'].includes(c.kind)) {
      const fm: Record<string, string> = {}
      for (const k of ['value', 'type', 'threat_type', 'confidence', 'severity', 'tags']) {
        if (values[`fm_${k}`]?.trim()) fm[k] = values[`fm_${k}`].trim()
      }
      // Only replace the map when the analyst actually supplied one.
      if (Object.keys(fm).length) patch.field_map = fm
    }
    if (Object.keys(patch).length === 0) { setEditing(null); return }
    const updated = await patchConnector(c.id, patch)
    setConnectors((prev) => prev?.map((x) => (x.id === c.id ? updated : x)) ?? prev)
    setEditing(null)
    flash(`Connector "${updated.name}" updated.`)
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
          onClick={() => setShowCatalog((s) => !s)}
          className={cn('ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
            showCatalog ? 'border-magenta/40 text-magenta bg-magenta/10' : 'border-white/10 text-ink-300 hover:text-white')}>
          <Plug className="w-3.5 h-3.5" /> Browse catalogue
        </button>
        <button
          onClick={() => { setPresetKind(undefined); setShowAdd(true) }}
          disabled={!canManage}
          title={canManage ? undefined : adminOnly}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed">
          <Plus className="w-3.5 h-3.5" /> Add Connector
        </button>
      </div>

      {msg && <div className="px-5 py-2 text-[11px] text-safe bg-safe/5 border-b border-safe/15" role="status">{msg}</div>}

      {/* Connector catalogue - browsable list of supported integrations, each
         with its description + whether it needs an API key, and a one-click
         Configure that opens the add form pre-set to that kind. */}
      {showCatalog && (
        <div className="p-4 border-b border-white/8 bg-surface-2/30">
          <p className="text-[11px] text-ink-500 mb-2.5">Supported integrations — pick one to configure it with only the fields it needs.</p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {kinds.map((k) => {
              const configured = connectors?.some((c) => c.kind === k.kind)
              return (
                <div key={k.kind} className="flex flex-col rounded-xl border border-white/8 bg-surface p-3">
                  <div className="flex items-center gap-2 mb-1">
                    <Database className="w-3.5 h-3.5 text-violet shrink-0" />
                    <span className="text-xs font-semibold text-white truncate">{k.label}</span>
                    {configured && <CheckCircle className="w-3.5 h-3.5 text-safe shrink-0" aria-label="configured" />}
                  </div>
                  <p className="text-[10px] text-ink-500 leading-relaxed flex-1">{k.description}</p>
                  <div className="flex items-center justify-between gap-2 mt-2">
                    <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border',
                      k.needsKey ? 'text-amber border-amber/25 bg-amber/10' : 'text-safe border-safe/25 bg-safe/10')}>
                      {k.needsKey ? 'API key required' : 'No key needed'}
                    </span>
                    <button
                      onClick={() => { setPresetKind(k.kind); setShowAdd(true); setShowCatalog(false) }}
                      disabled={!canManage}
                      title={canManage ? undefined : adminOnly}
                      className="text-[11px] font-semibold text-magenta hover:underline disabled:opacity-40 disabled:no-underline disabled:cursor-not-allowed shrink-0">
                      Configure →
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

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
          const w = workOf.get(c.id)
          const live = w?.status === 'running'
          const st = live ? STATUS_META.running : (STATUS_META[c.status] ?? STATUS_META.idle)
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
                  {c.kind} · {c.indicatorCount.toLocaleString()} indicators · every {formatEvery(c.intervalSeconds || c.intervalMinutes * 60)} · last {relTime(c.lastRun)}
                </p>
                {/* The failure reason gets its own wrapped line. Truncated to 60
                    characters on the summary line it lost exactly the part that
                    says what to do - "...cannot reach X, this is not an API-key
                    problem" cuts to "...cannot reach X from thi". */}
                {c.lastError && (
                  <p className="text-[10px] text-threat mt-1 leading-relaxed break-words">{c.lastError}</p>
                )}
                {/* Live progress for a sync in flight, so a long import reads as
                    working rather than as a row that has stopped changing. */}
                {live && w && (
                  <div className="mt-1.5">
                    <div className="h-1 rounded-full bg-white/8 overflow-hidden">
                      <div className="h-full rounded-full bg-violet transition-[width] duration-500"
                        style={{ width: `${w.percent}%` }} />
                    </div>
                    <p className="text-[10px] text-violet mt-1 tabular-nums">
                      {w.processed.toLocaleString()}{w.expected ? ` / ${w.expected.toLocaleString()}` : ''} processed
                      {w.ratePerSec ? ` · ${w.ratePerSec.toLocaleString()}/s` : ''}
                    </p>
                  </div>
                )}
                {/* What the last completed run actually produced - the panel used
                    to show only a timestamp, never an amount. */}
                {!live && w && w.status === 'completed' && (
                  <p className="text-[10px] text-ink-600 mt-0.5 tabular-nums">
                    last run: <span className="text-safe">{w.imported.toLocaleString()} new</span>
                    {w.duplicates > 0 && ` · ${w.duplicates.toLocaleString()} already known`}
                    {w.ratePerSec ? ` · ${w.ratePerSec.toLocaleString()}/s` : ''}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => sync(c)}
                  disabled={busy === c.id || !canManage}
                  title={canManage ? 'Sync now' : adminOnly}
                  className="p-1.5 rounded-lg text-ink-400 hover:text-magenta hover:bg-magenta/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-ink-400 disabled:hover:bg-transparent">
                  {busy === c.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => toggle(c)}
                  disabled={!canManage}
                  title={!canManage ? adminOnly : c.enabled ? 'Pause auto-sync' : 'Resume auto-sync'}
                  className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-ink-400 disabled:hover:bg-transparent">
                  {c.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => setEditing(c)}
                  disabled={!canManage}
                  title={canManage ? 'Edit / reconfigure' : adminOnly}
                  className="p-1.5 rounded-lg text-ink-400 hover:text-violet hover:bg-violet/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-ink-400 disabled:hover:bg-transparent">
                  <Pencil className="w-3.5 h-3.5" />
                </button>
                {!c.builtin && (
                  <button onClick={() => remove(c)} disabled={!canManage}
                    title={canManage ? 'Delete connector' : adminOnly}
                    className="p-1.5 rounded-lg text-ink-400 hover:text-threat hover:bg-threat/5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-ink-400 disabled:hover:bg-transparent">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          )
        })}
        {connectors && connectors.length > 0 && !canManage && (
          <p className="text-[10px] text-ink-600 text-center pt-1">
            View-only — managing connectors requires administrator privileges.
          </p>
        )}
      </div>

      <AnimatePresence>
        {showAdd && <AddConnectorModal kinds={kinds} initialKind={presetKind} onClose={() => setShowAdd(false)} onAdd={add} />}
        {editing && <EditConnectorModal connector={editing} onClose={() => setEditing(null)} onSave={update} />}
      </AnimatePresence>
    </motion.div>
  )
}

/* -- Add-connector modal ------------------------------------------- */
function AddConnectorModal({ kinds, onClose, onAdd, initialKind }: {
  kinds: ConnectorKind[]
  onClose: () => void
  onAdd: (values: Record<string, string>) => Promise<void>
  initialKind?: string
}) {
  const [kind, setKind] = useState(initialKind ?? 'json')
  const initPreset = kinds.find((k) => k.kind === (initialKind ?? 'json'))
  const [values, setValues] = useState<Record<string, string>>({
    name: '', url: initPreset?.defaultUrl ?? '', api_key: '',
    interval_minutes: initPreset ? String(initPreset.defaultInterval * 60) : '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const preset = kinds.find((k) => k.kind === kind)
  const isCustom = kind === 'json' || kind === 'csv' || kind === 'stix'
  const set = (k: string) => (v: string) => setValues((s) => ({ ...s, [k]: v }))

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!values.name.trim() || submitting) return
    if (preset?.needsKey && !values.api_key.trim()) { setError('This source needs an API key.'); return }
    setSubmitting(true)
    setError(null)
    try {
      await onAdd({ ...values, kind })
    } catch (err) {
      // Show what the server ACTUALLY said. The old copy guessed ("check the URL
      // and that you have admin access"), which sent operators hunting a URL
      // problem when the real cause was something else entirely.
      setError(err instanceof Error && err.message
        ? err.message
        : 'Could not add the connector.')
      setSubmitting(false)
    }
  }

  const input = 'w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-hidden focus:border-magenta/40 placeholder-ink-600'

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-70 flex items-center justify-center bg-black/60 backdrop-blur-xs p-6" onClick={onClose}>
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
            <select value={kind} onChange={(e) => { setKind(e.target.value); const p = kinds.find(k => k.kind === e.target.value); if (p) setValues(s => ({ ...s, url: p.defaultUrl, interval_minutes: String(p.defaultInterval * 60) })) }} className={input}>
              {kinds.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}
            </select>
            {preset && <p className="text-[10px] text-ink-600 mt-1">{preset.description}</p>}
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Connector name <span className="text-magenta">*</span></label>
            <input value={values.name} onChange={(e) => set('name')(e.target.value)} placeholder="e.g. My ThreatFox feed" className={input} />
          </div>

          {/* URL field only for kinds the operator actually configures a URL for
              (custom JSON/CSV/STIX/TAXII/dark-web). Managed providers - OTX, NVD,
              the bundled engine - hide it; the backend uses their fixed endpoint.
              The fallback lists the managed kinds explicitly so that even if the
              `/kinds` response is stale or omits needs_url, OTX/NVD never wrongly
              ask for a URL. */}
          {(preset?.needsUrl ?? !['threatorbit', 'nvd', 'otx'].includes(kind)) && (
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Source URL</label>
              <input value={values.url} onChange={(e) => set('url')(e.target.value)} placeholder={preset?.defaultUrl || 'https://your-source/api/indicators'} className={cn(input, 'font-mono text-xs')} />
            </div>
          )}

          {/* Key field for every kind that can take one. Gated on the KIND, not on
              the preset being loaded: keying it off `preset?.needsKey !== undefined`
              meant a missing/renamed field silently hid the field entirely, so an
              OTX connector could never be created. */}
          {kind !== 'threatorbit' && kind !== 'nvd' && (
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">
                API key {preset?.needsKey && <span className="text-magenta">*</span>}
                {!preset?.needsKey && <span className="text-ink-600">(optional)</span>}
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
                    <input value={values[`fm_${k}`] ?? ''} onChange={(e) => set(`fm_${k}`)(e.target.value)} placeholder={k} className="w-full px-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 font-mono focus:outline-hidden focus:border-magenta/40 placeholder-ink-700" />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Auto-sync every (seconds)</label>
            <input type="number" value={values.interval_minutes} onChange={(e) => set('interval_minutes')(e.target.value)} placeholder={String((preset?.defaultInterval ?? 60) * 60)} className={input} />
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

/* -- Edit-connector modal ------------------------------------------ */
function EditConnectorModal({ connector, onClose, onSave }: {
  connector: Connector
  onClose: () => void
  onSave: (c: Connector, values: Record<string, string>) => Promise<void>
}) {
  const c = connector
  const isCustom = c.kind === 'json' || c.kind === 'csv' || c.kind === 'stix'
  const [values, setValues] = useState<Record<string, string>>(() => ({
    name: c.name,
    url: c.url ?? '',
    interval_minutes: String(c.intervalSeconds || (c.intervalMinutes ?? 0) * 60 || ''),
    api_key: '',
    ...Object.fromEntries(Object.entries(c.fieldMap ?? {}).map(([k, v]) => [`fm_${k}`, String(v)])),
  }))
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = (k: string) => (v: string) => setValues((s) => ({ ...s, [k]: v }))

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!values.name.trim() || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await onSave(c, values)
    } catch (err) {
      setError(err instanceof Error && err.message
        ? err.message
        : 'Could not update the connector.')
      setSubmitting(false)
    }
  }

  const input = 'w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-hidden focus:border-magenta/40 placeholder-ink-600'

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-70 flex items-center justify-center bg-black/60 backdrop-blur-xs p-6" onClick={onClose}>
      <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-2xl border border-white/10 bg-surface p-6 max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2 min-w-0">
            <div className="p-2 rounded-lg bg-violet/15 shrink-0"><Pencil className="w-4 h-4 text-violet" /></div>
            <h2 className="text-sm font-semibold text-white truncate">Edit {c.name}</h2>
            {Boolean(c.builtin) && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-white/5 text-ink-400 border border-white/10 shrink-0">built-in</span>}
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5"><X className="w-4 h-4" /></button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Connector name <span className="text-magenta">*</span></label>
            <input value={values.name} onChange={(e) => set('name')(e.target.value)} className={input} />
          </div>

          {/* Built-in + managed-endpoint connectors (OTX/NVD/engine) have a fixed
              source URL; only cadence + key are tunable. */}
          {!c.builtin && !['threatorbit', 'nvd', 'otx'].includes(c.kind) && (
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Source URL</label>
              <input value={values.url} onChange={(e) => set('url')(e.target.value)} placeholder="https://your-source/api/indicators" className={cn(input, 'font-mono text-xs')} />
            </div>
          )}

          {c.kind !== 'threatorbit' && c.kind !== 'nvd' && (
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">
                API key <span className="text-ink-600">{c.hasKey ? '(configured - leave blank to keep)' : '(optional)'}</span>
              </label>
              <input type="password" value={values.api_key} onChange={(e) => set('api_key')(e.target.value)}
                placeholder={c.hasKey ? '•••••••• stored - type to replace' : 'paste your key'} className={cn(input, 'font-mono text-xs')} />
            </div>
          )}

          {isCustom && (
            <div className="rounded-xl border border-white/8 bg-surface-2/40 p-3 space-y-3">
              <p className="text-[11px] text-ink-400">Field mapping - leave all blank to keep the current map.</p>
              <div className="grid grid-cols-2 gap-2">
                {[['value', 'Indicator value'], ['type', 'Type'], ['threat_type', 'Threat type'], ['confidence', 'Confidence'], ['severity', 'Severity'], ['tags', 'Tags']].map(([k, label]) => (
                  <div key={k}>
                    <label className="block text-[10px] text-ink-500 mb-1">{label}</label>
                    <input value={values[`fm_${k}`] ?? ''} onChange={(e) => set(`fm_${k}`)(e.target.value)} placeholder={k} className="w-full px-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 font-mono focus:outline-hidden focus:border-magenta/40 placeholder-ink-700" />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Auto-sync every (seconds)</label>
            <input type="number" value={values.interval_minutes} onChange={(e) => set('interval_minutes')(e.target.value)} className={input} />
          </div>

          {error && <p className="flex items-center gap-2 px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert"><AlertTriangle className="w-3.5 h-3.5 shrink-0" />{error}</p>}

          <button type="submit" disabled={!values.name.trim() || submitting}
            className={cn('w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold transition-all',
              values.name.trim() && !submitting ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</> : <><CheckCircle className="w-4 h-4" /> Save Changes</>}
          </button>
        </form>
      </motion.div>
    </motion.div>
  )
}
