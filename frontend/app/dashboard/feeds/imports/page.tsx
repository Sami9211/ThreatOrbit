'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import {
  Download, RefreshCw, Loader2, Database, Activity, CheckCircle,
  AlertTriangle, Clock, Gauge, Pause, Play, Save, Zap,
} from 'lucide-react'
import { cn, isSimulatedSource } from '@/lib/utils'
import { SEVERITY_COLOR as SEV_COLOR } from '@/lib/colors'
import { usePermissions } from '@/lib/usePermissions'
import {
  fetchConnectors, runConnector, patchConnector, fetchEngineStatus, fetchJobs, fetchIocs,
  fetchConnectorWorks,
  type Connector, type EngineStatus, type JobEntry, type Ioc, type ConnectorWork,
} from '@/lib/api'

function relTime(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/** How long a run took (or has been running). Sub-second matters here: a 24k
 *  import that lands in 600ms should not round to "0s". */
function durationOf(from: string, to: string): string {
  const ms = new Date(to).getTime() - new Date(from).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

const CONN_STATUS: Record<string, { label: string; cls: string; dot: string }> = {
  ok:      { label: 'Synced',  cls: 'text-safe border-safe/25 bg-safe/10',     dot: 'bg-safe' },
  idle:    { label: 'Idle',    cls: 'text-ink-400 border-white/10 bg-white/5',  dot: 'bg-ink-500' },
  running: { label: 'Importing', cls: 'text-violet border-violet/25 bg-violet/10', dot: 'bg-violet animate-pulse' },
  error:   { label: 'Error',   cls: 'text-threat border-threat/25 bg-threat/10', dot: 'bg-threat' },
}

const WORK_STATUS: Record<string, { label: string; cls: string; dot: string }> = {
  running:   { label: 'Importing', cls: 'text-violet border-violet/25 bg-violet/10', dot: 'bg-violet animate-pulse' },
  completed: { label: 'Done',      cls: 'text-safe border-safe/25 bg-safe/10',       dot: 'bg-safe' },
  failed:    { label: 'Failed',    cls: 'text-threat border-threat/25 bg-threat/10', dot: 'bg-threat' },
}

const JOB_STATUS: Record<string, string> = {
  done: 'text-safe', complete: 'text-safe', success: 'text-safe',
  running: 'text-violet', queued: 'text-amber', pending: 'text-amber',
  error: 'text-threat', failed: 'text-threat',
}

/* -- Import source (connector) row with a live interval control ------ */
function SourceRow({ c, canManage, onChanged }: {
  c: Connector; canManage: boolean; onChanged: () => void
}) {
  const st = CONN_STATUS[c.status] ?? CONN_STATUS.idle
  const secsOf = (x: typeof c) => x.intervalSeconds || x.intervalMinutes * 60
  const [interval, setInterval] = useState(String(secsOf(c)))
  const [busy, setBusy] = useState<'sync' | 'save' | null>(null)
  useEffect(() => { setInterval(String(secsOf(c))) }, [c.intervalSeconds, c.intervalMinutes])

  const dirty = interval !== String(secsOf(c)) && Number(interval) > 0

  async function sync() {
    if (busy) return
    setBusy('sync')
    try { await runConnector(c.id) } catch { /* surfaced via status */ } finally { setBusy(null); onChanged() }
  }
  async function saveInterval() {
    if (!dirty || busy) return
    setBusy('save')
    try { await patchConnector(c.id, { interval_seconds: Number(interval) }) } catch { /* ignore */ }
    finally { setBusy(null); onChanged() }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 p-3 rounded-xl border border-white/8 bg-surface">
      <div className="p-2 rounded-lg bg-violet/10 shrink-0"><Database className="w-4 h-4 text-violet" /></div>
      <div className="flex-1 min-w-[180px]">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-white truncate">{c.name}</span>
          <span className={cn('flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full border', st.cls)}>
            <span className={cn('w-1.5 h-1.5 rounded-full', st.dot)} />{st.label}
          </span>
        </div>
        <p className="text-[10px] text-ink-600 mt-0.5 truncate">
          {c.kind} · {c.indicatorCount.toLocaleString()} indicators · last import {relTime(c.lastRun)}
          {c.lastError ? <span className="text-threat" title={c.lastError}> · {c.lastError}</span> : ''}
        </p>
      </div>
      {/* Each source's own auto-import cadence, in seconds (sub-minute allowed) */}
      <div className="flex items-center gap-1.5 shrink-0">
        <label className="text-[10px] text-ink-500">every</label>
        <input type="number" min={1} value={interval} disabled={!canManage}
          onChange={(e) => setInterval(e.target.value)}
          title={canManage ? 'Minutes between auto-imports' : 'Requires administrator privileges'}
          className="w-14 px-2 py-1 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 text-center focus:outline-hidden focus:border-magenta/40 disabled:opacity-50" />
        <span className="text-[10px] text-ink-500">sec</span>
        {dirty && canManage && (
          <button onClick={saveInterval} disabled={busy === 'save'} title="Save cadence"
            className="p-1.5 rounded-lg text-safe hover:bg-safe/10 transition-colors">
            {busy === 'save' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
          </button>
        )}
        <button onClick={sync} disabled={busy === 'sync' || !canManage}
          title={canManage ? 'Import now' : 'Requires administrator privileges'}
          className="p-1.5 rounded-lg text-ink-400 hover:text-magenta hover:bg-magenta/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
          {busy === 'sync' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
        </button>
      </div>
    </div>
  )
}

/* -- One import run, live -------------------------------------------- */
function WorkRow({ w }: { w: ConnectorWork }) {
  const st = WORK_STATUS[w.status] ?? WORK_STATUS.completed
  const running = w.status === 'running'
  return (
    <div className="px-3 py-2.5 rounded-xl border border-white/8 bg-surface">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-semibold text-white truncate">{w.connector}</span>
        <span className={cn('flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full border', st.cls)}>
          <span className={cn('w-1.5 h-1.5 rounded-full', st.dot)} />{st.label}
        </span>
        <span className="ml-auto text-[10px] text-ink-600 tabular-nums shrink-0">
          {durationOf(w.startedAt, w.updatedAt)}
          {w.ratePerSec ? <span className="text-teal"> · {w.ratePerSec.toLocaleString()}/s</span> : null}
          {!running && <> · {relTime(w.startedAt)}</>}
        </span>
      </div>
      {/* The batch size is known before the first insert, so this bar tracks
          real completion rather than a guess that jumps to 100%. */}
      <div className="mt-2 h-1.5 rounded-full bg-white/8 overflow-hidden">
        <div className={cn('h-full rounded-full transition-[width] duration-500',
          w.status === 'failed' ? 'bg-threat' : running ? 'bg-violet' : 'bg-safe')}
          style={{ width: `${w.status === 'failed' ? Math.max(2, w.percent) : w.percent}%` }} />
      </div>
      <p className="text-[10px] text-ink-600 mt-1.5 tabular-nums">
        {w.processed.toLocaleString()}{w.expected ? ` / ${w.expected.toLocaleString()}` : ''} processed
        {w.imported > 0 && <span className="text-safe"> · {w.imported.toLocaleString()} new</span>}
        {w.duplicates > 0 && <span> · {w.duplicates.toLocaleString()} already known</span>}
        {w.skipped > 0 && <span className="text-amber"> · {w.skipped.toLocaleString()} unparseable</span>}
      </p>
      {w.message && <p className="text-[10px] text-threat mt-1 break-words">{w.message}</p>}
    </div>
  )
}

export default function ImportsPage() {
  const { can } = usePermissions()
  const canManage = can('connectors.manage')
  const [connectors, setConnectors] = useState<Connector[] | null>(null)
  const [engine, setEngine] = useState<EngineStatus | null>(null)
  const [jobs, setJobs] = useState<JobEntry[]>([])
  const [recent, setRecent] = useState<Ioc[] | null>(null)
  const [works, setWorks] = useState<ConnectorWork[] | null>(null)

  const load = useCallback(() => {
    fetchConnectors().then(setConnectors).catch(() => setConnectors([]))
    fetchEngineStatus().then(setEngine).catch(() => setEngine(null))
    fetchJobs(15).then(setJobs).catch(() => setJobs([]))
    fetchConnectorWorks(12).then(setWorks).catch(() => setWorks([]))
    // Most-recently first-seen indicators = what just landed in the store.
    fetchIocs().then((r) =>
      setRecent([...r.items].sort((a, b) => (b.firstSeen ?? '').localeCompare(a.firstSeen ?? '')).slice(0, 25))
    ).catch(() => setRecent([]))
  }, [])

  const importing = (works ?? []).some((w) => w.status === 'running')
  useEffect(() => {
    load()
    // A live import moves thousands of indicators a second; polling it every 15s
    // renders as a frozen bar. Tighten the loop only while one is in flight, so
    // an idle dashboard still costs one request per 15s.
    const t = window.setInterval(load, importing ? 2000 : 15000)
    return () => window.clearInterval(t)
  }, [load, importing])

  const totalIndicators = (connectors ?? []).reduce((n, c) => n + c.indicatorCount, 0)
  // Import-centric health, all derived from real connector state.
  const okSources = (connectors ?? []).filter((c) => c.status === 'ok').length
  const failedSources = (connectors ?? []).filter((c) => c.status === 'error').length
  const lastImportAt = (connectors ?? [])
    .map((c) => c.lastRun).filter(Boolean)
    .sort().slice(-1)[0] ?? null
  // Soonest upcoming sync across enabled connectors (cadence - elapsed).
  const nextSyncIn = (() => {
    const due = (connectors ?? []).filter((c) => c.enabled).map((c) => {
      const every = c.intervalSeconds || c.intervalMinutes * 60
      if (!c.lastRun) return 0
      const elapsed = Math.floor((Date.now() - new Date(c.lastRun).getTime()) / 1000)
      return Math.max(0, every - elapsed)
    })
    return due.length ? Math.min(...due) : null
  })()
  // Most recent finished run, for the "how much, how fast" tile.
  const lastWork = (works ?? []).find((w) => w.status !== 'running' && w.processed > 0) ?? null

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Download className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Imports</h1>
            {engine && (
              <span className={cn('flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-medium',
                engine.running ? 'border-safe/25 bg-safe/10 text-safe' : 'border-ink-500/25 bg-white/5 text-ink-400')}>
                {engine.running ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
                {engine.running ? 'Processing' : 'Paused'}
              </span>
            )}
          </div>
          <p className="text-xs text-ink-500 mt-0.5">
            Live ingestion of threat intelligence from your connectors — queue, cadence, logs and freshly imported indicators.
          </p>
        </div>
        <Link href="/dashboard/feeds/sources"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors">
          <Database className="w-3.5 h-3.5" /> Manage connectors
        </Link>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Pipeline summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {/* Every tile is about IMPORTS. This page used to show the DETECTION
              queue depth/lag and the synthetic engine's "burst cadence" - numbers
              that say nothing about whether intel is arriving, and that read as
              broken ("Processing queue 0") while imports were working fine. */}
          {[
            { label: 'Sources syncing', value: `${okSources}/${(connectors ?? []).length}`,
              sub: failedSources ? `${failedSources} failing` : 'all healthy',
              icon: Activity, color: failedSources ? 'text-threat' : 'text-safe' },
            { label: 'Last import', value: lastImportAt ? relTime(lastImportAt) : '—',
              sub: lastWork
                ? `${lastWork.processed.toLocaleString()} in ${durationOf(lastWork.startedAt, lastWork.updatedAt)}`
                : (lastImportAt ? 'most recent sync' : 'no sync yet'),
              icon: Clock, color: 'text-violet' },
            { label: 'Next sync in', value: nextSyncIn !== null ? `${nextSyncIn}s` : '—',
              sub: 'soonest connector cadence', icon: Gauge, color: 'text-teal' },
            { label: 'Total indicators', value: totalIndicators.toLocaleString(), sub: `${(connectors ?? []).length} sources`, icon: Zap, color: 'text-amber' },
          ].map((k) => (
            <div key={k.label} className="glass border border-white/5 rounded-xl p-3">
              <div className="flex items-center gap-1.5 text-[10px] text-ink-500 uppercase tracking-wide">
                <k.icon className={cn('w-3 h-3', k.color)} /> {k.label}
              </div>
              <p className="text-xl font-bold text-white mt-1 tabular-nums">{k.value}</p>
              <p className="text-[10px] text-ink-600 mt-0.5">{k.sub}</p>
            </div>
          ))}
        </div>

        {/* Honest import state. This used to report the DETECTION queue being
            empty, which read as "nothing works" even while connectors were
            importing normally. Now it reflects what actually happened. */}
        {connectors && connectors.length > 0 && (
          failedSources > 0 ? (
            <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border border-threat/25 bg-threat/10 text-xs text-threat">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                <b>{failedSources} of {connectors.length} sources failed to sync.</b> The reason is
                shown on each source below. A source that cannot resolve or reach its endpoint is
                usually blocked by DNS or a firewall on this host — the other sources keep importing.
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2.5 px-4 py-3 rounded-xl border border-white/8 bg-surface text-xs text-ink-400">
              <CheckCircle className="w-4 h-4 text-safe shrink-0" />
              <span>
                All {connectors.length} sources are syncing.{' '}
                {totalIndicators.toLocaleString()} indicators imported so far
                {lastImportAt ? `, most recently ${relTime(lastImportAt)}` : ''}.
              </span>
            </div>
          )
        )}

        {/* Live import pipeline. Each row is one run of one source, updated while
            it is still going - so a big sync reads as "moving at 4,800/s", not as
            an empty page that only fills in once it has finished. */}
        <section>
          <div className="flex items-center gap-2 mb-2">
            <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider">Import pipeline</h2>
            {importing && (
              <span className="flex items-center gap-1 text-[10px] text-violet">
                <Loader2 className="w-3 h-3 animate-spin" /> live
              </span>
            )}
          </div>
          <div className="space-y-2">
            {works === null && <p className="text-xs text-ink-600 py-4 text-center animate-pulse">Loading pipeline…</p>}
            {works?.length === 0 && (
              <p className="text-xs text-ink-600 py-4 text-center">
                No imports yet. Runs appear here the moment a source starts, with live counts and throughput.
              </p>
            )}
            {works?.map((w) => <WorkRow key={w.id} w={w} />)}
          </div>
        </section>

        {/* Import sources */}
        <section>
          <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider mb-2">Import sources</h2>
          <div className="space-y-2">
            {connectors === null && <p className="text-xs text-ink-600 py-4 text-center animate-pulse">Loading sources…</p>}
            {connectors?.length === 0 && (
              <p className="text-xs text-ink-600 py-4 text-center">
                No connectors configured. <Link href="/dashboard/feeds/sources" className="text-magenta hover:underline">Add one</Link> to start importing.
              </p>
            )}
            {connectors?.map((c) => <SourceRow key={c.id} c={c} canManage={canManage} onChanged={load} />)}
            {connectors && connectors.length > 0 && !canManage && (
              <p className="text-[10px] text-ink-600 text-center pt-1">View-only — changing import cadence or importing now requires administrator privileges.</p>
            )}
          </div>
        </section>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Recent import jobs (success/failure log) */}
          <section>
            <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider mb-2">Recent import jobs</h2>
            <div className="space-y-1.5">
              {jobs.length === 0 && <p className="text-xs text-ink-600 py-4 text-center">No import jobs recorded yet.</p>}
              {jobs.map((j) => (
                <div key={j.id} className="flex items-center gap-3 px-3 py-2 rounded-lg border border-white/8 bg-surface">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-ink-200 truncate">
                      {j.kind}
                      <span className={cn('ml-2 text-[10px] font-semibold', JOB_STATUS[j.status] ?? 'text-ink-500')}>{j.status}</span>
                    </p>
                    <p className="text-[10px] text-ink-600">{relTime(j.updatedAt || j.createdAt)}</p>
                  </div>
                  {j.progress > 0 && j.progress < 100 ? (
                    <div className="w-20 h-1.5 rounded-full bg-white/8 overflow-hidden shrink-0">
                      <div className="h-full rounded-full bg-violet" style={{ width: `${j.progress}%` }} />
                    </div>
                  ) : (
                    (JOB_STATUS[j.status] ?? '').includes('threat')
                      ? <AlertTriangle className="w-4 h-4 text-threat shrink-0" />
                      : <CheckCircle className="w-4 h-4 text-safe shrink-0" />
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Recently imported indicators (real time) */}
          <section>
            <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider mb-2">Recently imported indicators</h2>
            <div className="space-y-1.5">
              {recent === null && <p className="text-xs text-ink-600 py-4 text-center animate-pulse">Loading…</p>}
              {recent?.length === 0 && <p className="text-xs text-ink-600 py-4 text-center">No indicators imported yet — they appear here as connectors run.</p>}
              {recent?.map((ioc) => (
                <Link key={ioc.id} href={`/dashboard/scanner?value=${encodeURIComponent(ioc.value)}&run=1`}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg border border-white/8 bg-surface hover:border-white/15 transition-colors group">
                  <span className="w-1 h-6 rounded-full shrink-0" style={{ background: SEV_COLOR[ioc.severity] ?? '#666' }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-ink-200 truncate group-hover:text-white">{ioc.value}</p>
                    <p className="text-[10px] text-ink-600 flex items-center gap-1.5 flex-wrap">
                      <span>{ioc.type} · {ioc.source || 'unknown source'} · {relTime(ioc.firstSeen)}</span>
                      {isSimulatedSource(ioc.source) && (
                        <span title="Generated by the Live Processing Engine - not observed threat intelligence"
                          className="px-1.5 py-0.5 rounded-full border border-amber/30 bg-amber/10 text-amber text-[9px] uppercase tracking-wider">
                          Simulated
                        </span>
                      )}
                    </p>
                  </div>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold shrink-0"
                    style={{ color: SEV_COLOR[ioc.severity] ?? '#999', background: `${SEV_COLOR[ioc.severity] ?? '#999'}1a` }}>
                    {ioc.severity}
                  </span>
                </Link>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}
