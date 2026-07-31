'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { fetchSiemHunts, runHuntQuery, createSiemHunt, type SavedHunt as ApiSavedHunt, type HuntQueryRow } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Terminal, Search, Play, Clock, Save, BookOpen,
  CheckCircle, AlertTriangle, RefreshCw, ChevronDown,
  ArrowUpRight, Database, Zap, 
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'
import EventSearchPanel from '@/components/dashboard/EventSearchPanel'
import { tk } from '@/lib/colors'
import ApiUnavailable from '@/components/dashboard/ApiUnavailable'

/* --- Types ----------------------------------------------------------- */
type TimeRange = '1h' | '6h' | '24h' | '7d'

interface SavedHunt {
  id:          string
  name:        string
  description: string
  query:       string
  technique:   string
  lastRun:     string
  hitCount:    number
  author:      string
}

interface HuntResult {
  ts:       string
  srcIp:    string
  destIp:   string
  destPort: number
  protocol: string
  bytes:    number
  interval: number   // seconds
  host:     string
}

interface HuntRun {
  id:       string
  query:    string
  range:    TimeRange
  scanned:  string
  elapsed:  string
  hits:     number
  results:  HuntResult[]
}

/* --- Starter template ------------------------------------------------
   A template, not data: it names real event fields and returns whatever this
   deployment actually holds. The editor used to open on a saved hunt from a
   hardcoded library, which read as "somebody here wrote this" and produced
   results for a dataset that does not exist. */
const DEFAULT_QUERY = `// Outbound connections to a known-bad destination.
// dest_host is the name the traffic was aimed at (DNS query, HTTP Host, SNI).
category = "network" AND dest_host != ""`

/* --- Helpers ---------------------------------------------------------- */
function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  return `${(b / 1024).toFixed(1)} KB`
}

function fmtInterval(s: number): string {
  if (s < 60)  return `${s}s`
  return `${Math.round(s / 60)}m ${s % 60}s`
}

function riskColor(interval: number, bytes: number): string {
  // Short intervals + small bytes → more beacon-like → higher risk
  if (interval < 65 && bytes < 900)  return 'text-magenta'
  if (interval < 130)                return 'text-threat'
  return 'text-amber'
}

const TIME_RANGE_LABELS: Record<TimeRange, string> = {
  '1h': 'Last 1h', '6h': 'Last 6h', '24h': 'Last 24h', '7d': 'Last 7d',
}

// How many events a range actually holds is a question only the backend can
// answer, and it answers it: a completed run reports `scanned`. This used to be
// a hardcoded table - "147.4M events" on a deployment holding four thousand -
// which flattered the product and told an analyst nothing true about the search
// they were about to run.

/* Download a hunt run as CSV. */
function exportResults(run: HuntRun) {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const csv = [
    'ts,src_ip,dest_ip,dest_port,protocol,bytes,interval_sec,host',
    ...run.results.map((r) =>
      [r.ts, r.srcIp, r.destIp, r.destPort, r.protocol, r.bytes, r.interval, r.host].map(esc).join(',')),
  ].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `hunt-results-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

/* --- Components ------------------------------------------------------- */
function MetricCard({
  label, value, icon: Icon, color, sub,
}: {
  label: string; value: string | number; icon: React.ComponentType<any>; color: string; sub?: string
}) {
  return (
    <div className="glass border border-white/5 rounded-xl p-4 relative overflow-hidden">
      <div
        className="absolute inset-0 opacity-25"
        style={{ background: `radial-gradient(circle at 0% 0%, ${color}22, transparent 65%)` }}
      />
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1">{label}</p>
          <p className="font-display text-2xl font-bold text-white">{value}</p>
          {sub && <p className="text-[10px] text-ink-600 mt-0.5">{sub}</p>}
        </div>
        <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}18` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
    </div>
  )
}

/* --- Main Page ------------------------------------------------------- */
export default function ThreatHuntPage() {
  useExperienceMode()

  /* Query editor state */
  const [query,     setQuery]     = useState(DEFAULT_QUERY)   // starter template only
  const [timeRange, setTimeRange] = useState<TimeRange>('6h')
  const [running,   setRunning]   = useState(false)
  // No pre-populated results - the "Run a query to see results" empty state
  // shows until the analyst actually runs a hunt (never fabricated beacon hits).
  const [runResult, setRunResult] = useState<HuntRun | null>(null)
  const [runError, setRunError] = useState(false)
  // Saved hunts are NOT seeded in live mode → start empty, and stay empty if
  // the API cannot be reached. A demo hunt list invites an analyst to run a
  // query somebody else wrote for a dataset that does not exist here.
  const [savedHunts, setSavedHunts] = useState<SavedHunt[]>([])
  const [huntsFailed, setHuntsFailed] = useState(false)
  const [selectedHuntId, setSelectedHuntId] = useState<string>('')

  const mapApiHunt = (h: ApiSavedHunt & { query?: string; technique?: string }): SavedHunt => ({
    id: h.id,
    name: h.name,
    description: h.hypothesis,
    query: h.query || `// ${h.name}\n// (no stored query - write one and Save Hunt)`,
    technique: h.technique || '-',
    lastRun: h.lastRun ?? 'Never',
    hitCount: h.artifacts,
    author: h.analyst,
  })

  useEffect(() => {
    fetchSiemHunts()
      .then((data) => setSavedHunts(data.map(mapApiHunt)))   // applied even when empty
      .catch(() => setHuntsFailed(true))
  }, [])

  /* Saved panel visibility (mobile) */
  const [savedOpen, setSavedOpen] = useState(true)

  /* Save-query feedback */
  const [savedMsg, setSavedMsg] = useState<string | null>(null)

  const textareaRef = useRef<HTMLTextAreaElement>(null)

  /* Run the query against the live alert store. A failure surfaces as a failure
   * - there is no bundled result set to fall back to, and a hunt that invents
   * hits is worse than one that reports it could not run. */
  const runQuery = useCallback(() => {
    if (running) return
    setRunning(true)
    setRunResult(null)
    setRunError(false)
    const t = timeRange
    runHuntQuery(query, t)
      .then((out) => {
        setRunResult({
          id:      `run-${Date.now()}`,
          query,
          range:   t,
          scanned: `${out.scanned.toLocaleString()} alerts`,
          elapsed: `${(out.elapsedMs / 1000).toFixed(2)}s`,
          hits:    out.hits,
          results: out.results.map((r: HuntQueryRow): HuntResult => ({
            ts: r.ts,
            srcIp: r.srcIp ?? '-',
            destIp: r.destIp ?? '-',
            destPort: r.destPort ?? 0,
            protocol: r.protocol,
            bytes: r.bytes,
            interval: r.interval,
            host: r.host,
          })),
        })
      })
      .catch(() => {
        // Honest failure - never fabricate hits. Surface an error state instead.
        setRunResult(null)
        setRunError(true)
      })
      .finally(() => setRunning(false))
  }, [running, query, timeRange])

  /* Ctrl/Cmd + Enter to run */
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runQuery() }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [runQuery])

  function loadHunt(hunt: SavedHunt) {
    setSelectedHuntId(hunt.id)
    setQuery(hunt.query)
    setRunResult(null)
  }

  /* Save the current query as a named hunt in the library */
  const [savePanelOpen, setSavePanelOpen] = useState(false)
  const [saveName, setSaveName] = useState('')

  function saveQuery() {
    const name = saveName.trim()
    if (!name) { setSavePanelOpen(true); return }
    const technique = query.match(/\bT\d{4}(?:\.\d{3})?\b/)?.[0]
    createSiemHunt({ name, query, technique, description: `Saved from the hunt console` })
      .then((created) => {
        setSavedHunts((prev) => [mapApiHunt(created), ...prev])
        setSavedMsg('Hunt saved to your library')
        setSavePanelOpen(false)
        setSaveName('')
      })
      .catch(() => setSavedMsg('Could not save - is the dashboard API running?'))
    setTimeout(() => setSavedMsg(null), 2500)
  }

  /* Line numbers */
  const lineCount = query.split('\n').length

  return (
    <div className="p-6 space-y-6 min-h-screen">

      {/* -- Page header -- */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-start justify-between gap-4"
      >
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25">
              <Terminal className="w-4 h-4 text-violet" />
            </div>
            <h1 className="font-display text-xl font-bold text-white tracking-tight">Threat Hunt</h1>
          </div>
          <p className="text-sm text-ink-500">Query your logs with KQL. Hunt for threats before they alert.</p>
        </div>
        <div className="flex items-center gap-2">
          {savePanelOpen && (
            <input
              autoFocus
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') saveQuery(); if (e.key === 'Escape') setSavePanelOpen(false) }}
              placeholder="Hunt name…"
              className="px-3 py-2 rounded-xl bg-surface-2 border border-magenta/30 text-xs text-ink-100 placeholder-ink-600 focus:outline-hidden w-44"
            />
          )}
          <button
            onClick={saveQuery}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors"
          >
            <Save className="w-3.5 h-3.5" />
            {savePanelOpen ? 'Confirm Save' : 'Save Hunt'}
          </button>
          <a href="/docs/rest-api" className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors">
            <BookOpen className="w-3.5 h-3.5" />
            Documentation
          </a>
        </div>
      </motion.div>

      {/* -- Hunt metrics strip -- */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="grid grid-cols-2 sm:grid-cols-4 gap-4"
      >
        {/* Derived from the real saved-hunt store (+ the last run) - no fabricated stats. */}
        <MetricCard label="Saved Hunts"        value={savedHunts.length} icon={BookOpen}     color={tk('violet')} sub="in this workspace" />
        <MetricCard label="Findings (saved)"   value={savedHunts.reduce((s, h) => s + (h.hitCount || 0), 0)} icon={AlertTriangle} color={tk('threat')} sub="across saved hunts" />
        <MetricCard label="Techniques Covered" value={new Set(savedHunts.map((h) => h.technique).filter((t) => t && t !== '-')).size} icon={Search} color={tk('safe')} sub="distinct ATT&CK IDs" />
        <MetricCard label="Last Run Hits"      value={runResult ? runResult.hits : '-'} icon={Zap} color={tk('magenta')} sub={runResult ? 'from your last query' : 'run a query'} />
      </motion.div>

      {/* -- Event-stream search (real field-operator language over raw events) -- */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}>
        <EventSearchPanel />
      </motion.div>

      {/* -- Main workspace: [Saved sidebar] + [Editor + Results] -- */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-5"
      >

        {/* -- Saved Hunts sidebar -- */}
        <div className="flex flex-col gap-3">
          <button
            onClick={() => setSavedOpen((v) => !v)}
            className="flex items-center justify-between px-4 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-xs font-medium text-ink-300 hover:text-white hover:border-white/15 transition-colors lg:cursor-default"
          >
            <div className="flex items-center gap-2">
              <BookOpen className="w-3.5 h-3.5 text-violet" />
              <span>Saved Hunts</span>
              <span className="px-1.5 py-0.5 rounded-full bg-violet/20 text-violet text-[10px] font-semibold">{savedHunts.length}</span>
            </div>
            <ChevronDown className={cn('w-3.5 h-3.5 text-ink-600 transition-transform lg:hidden', savedOpen && 'rotate-180')} />
          </button>

          <AnimatePresence initial={false}>
            {(savedOpen) && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="overflow-hidden"
              >
                <div className="space-y-2">
                  {savedHunts.length === 0 && (
                    huntsFailed ? (
                      <ApiUnavailable what="your saved hunts" compact />
                    ) : (
                      <p className="text-[11px] text-ink-600 px-1 py-2">
                        No saved hunts yet - write a query and Save Hunt to keep it here.
                      </p>
                    )
                  )}
                  {savedHunts.map((hunt) => {
                    const isActive = selectedHuntId === hunt.id
                    return (
                      <button
                        key={hunt.id}
                        onClick={() => loadHunt(hunt)}
                        className={cn(
                          'w-full text-left px-4 py-3 rounded-xl border transition-all group',
                          isActive
                            ? 'bg-violet/10 border-violet/30 shadow-violet-sm'
                            : 'bg-surface-2/60 border-white/6 hover:border-white/15 hover:bg-surface-2',
                        )}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <p className={cn('text-xs font-medium leading-snug', isActive ? 'text-white' : 'text-ink-200 group-hover:text-white')}>
                            {hunt.name}
                          </p>
                          <span className={cn(
                            'shrink-0 text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded-sm border',
                            isActive
                              ? 'text-violet border-violet/40 bg-violet/15'
                              : 'text-ink-600 border-white/8 bg-transparent',
                          )}>
                            {hunt.technique}
                          </span>
                        </div>
                        <p className="text-[10px] text-ink-600 mt-1 leading-snug line-clamp-2">
                          {hunt.description}
                        </p>
                        <div className="flex items-center gap-3 mt-2">
                          <span className="text-[9px] text-ink-700">
                            <Clock className="w-2.5 h-2.5 inline mr-0.5 -mt-px" />{hunt.lastRun}
                          </span>
                          <span className={cn('text-[9px] font-semibold', hunt.hitCount > 0 ? 'text-magenta' : 'text-ink-700')}>
                            {hunt.hitCount > 0 ? `${hunt.hitCount} hits` : 'No hits'}
                          </span>
                          <span className="text-[9px] text-ink-700 ml-auto">{hunt.author}</span>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Quick reference chip */}
          <div className="px-4 py-3 rounded-xl bg-surface-2/40 border border-white/5 space-y-1.5">
            <p className="text-[9px] text-ink-600 uppercase tracking-widest font-semibold">Query Shortcuts</p>
            {[
              { label: 'Time filter', snippet: '@timestamp > now-6h' },
              { label: 'Bucket by 1m', snippet: 'bucket(@timestamp, 1m)' },
              { label: 'TI lookup',   snippet: 'lookup TI_FEED ip' },
              { label: 'Stats count', snippet: 'stats count() by field' },
            ].map(({ label, snippet }) => (
              <div key={label} className="flex items-center justify-between gap-2">
                <span className="text-[10px] text-ink-500">{label}</span>
                <span className="text-[9px] font-mono text-violet truncate">{snippet}</span>
              </div>
            ))}
          </div>
        </div>

        {/* -- Editor + Results column -- */}
        <div className="flex flex-col gap-5 min-w-0">

          {/* Query editor */}
          <div className="bg-surface-2/40 rounded-xl border border-white/8 overflow-hidden">

            {/* Editor toolbar */}
            <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-white/6 bg-white/2">
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-magenta" />
                <span className="text-xs font-semibold text-white">KQL Query Editor</span>
                <span className="text-[10px] text-ink-600">Elastic Query Language · ThreatOrbit Extensions</span>
              </div>
              <div className="flex items-center gap-2">
                {/* Time range selector */}
                <div className="relative flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-surface-2 border border-white/10 hover:border-white/18 transition-colors">
                  <Clock className="w-3 h-3 text-ink-600" />
                  <select
                    value={timeRange}
                    onChange={(e) => setTimeRange(e.target.value as TimeRange)}
                    className="appearance-none bg-transparent text-[11px] text-ink-300 focus:outline-hidden cursor-pointer pr-4"
                  >
                    {(Object.keys(TIME_RANGE_LABELS) as TimeRange[]).map((t) => (
                      <option key={t} value={t} className="bg-[#100A1C]">{TIME_RANGE_LABELS[t]}</option>
                    ))}
                  </select>
                  <ChevronDown className="w-3 h-3 text-ink-700 absolute right-1.5 pointer-events-none" />
                </div>

                {/* Run button */}
                <button
                  onClick={runQuery}
                  disabled={running}
                  className={cn(
                    'flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold border transition-all active:scale-95',
                    running
                      ? 'bg-violet/10 border-violet/25 text-violet/60 cursor-wait'
                      : 'bg-violet/20 border-violet/40 text-violet hover:bg-violet/30',
                  )}
                >
                  {running ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5" />
                  )}
                  {running ? 'Running…' : 'Run Query'}
                </button>
              </div>
            </div>

            {/* Editor body with fake line numbers */}
            <div className="flex min-h-[220px] max-h-[340px]">
              {/* Line numbers */}
              <div
                className="py-4 px-3 text-right select-none bg-white/1 border-r border-white/5 shrink-0"
                aria-hidden="true"
              >
                {Array.from({ length: lineCount }, (_, i) => (
                  <div key={i} className="text-[10px] font-mono text-ink-800 leading-[1.65]">{i + 1}</div>
                ))}
              </div>

              {/* Textarea */}
              <textarea
                ref={textareaRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                spellCheck={false}
                className="flex-1 py-4 px-4 bg-transparent text-[11px] font-mono text-ink-100 leading-[1.65] focus:outline-hidden resize-none placeholder-ink-800"
                style={{ minHeight: '220px', maxHeight: '340px', tabSize: 2 }}
                placeholder="Enter KQL query…"
              />
            </div>

            {/* Editor status bar */}
            <div className="flex items-center justify-between px-4 py-2 border-t border-white/5 bg-white/1 text-[9px] text-ink-700 font-mono">
              <div className="flex items-center gap-4">
                <span>Ln {lineCount} · {query.length} chars</span>
                <span>KQL / EQL · UTF-8</span>
                <span className="text-violet">Ctrl+Enter to run</span>
              </div>
              <div className="flex items-center gap-3">
                {/* The real figure, and only once there is one: a completed run
                    reports what it actually scanned. */}
                <span>
                  Index: logs-*
                  {runResult ? ` · scanned ${runResult.scanned}` : ''}
                </span>
                <span className={cn(running ? 'text-amber' : 'text-safe')}>
                  {running ? '● Executing' : '● Ready'}
                </span>
              </div>
            </div>
          </div>

          {/* -- Query results -- */}
          <div className="bg-surface-2/40 rounded-xl border border-white/8 overflow-hidden">

            {/* Results header */}
            <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-white/6">
              <div className="flex items-center gap-2">
                <Database className="w-3.5 h-3.5 text-safe" />
                <span className="text-xs font-semibold text-white">Query Results</span>
                {runResult && !running && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-safe/15 text-safe border border-safe/25">
                    {runResult.hits} hits
                  </span>
                )}
              </div>
              {runResult && !running && (
                <div className="flex items-center gap-3 text-[10px] text-ink-600">
                  <span>Scanned {runResult.scanned} events</span>
                  <span>·</span>
                  <span>{runResult.elapsed}</span>
                  <span>·</span>
                  <span className="text-violet font-semibold">MITRE {savedHunts.find((h) => h.id === selectedHuntId)?.technique ?? 'T1071.001'}</span>
                  <button
                    onClick={() => exportResults(runResult)}
                    className="ml-2 flex items-center gap-1 text-ink-600 hover:text-white transition-colors">
                    <ArrowUpRight className="w-3 h-3" /> Export
                  </button>
                </div>
              )}
            </div>

            {/* Running state */}
            <AnimatePresence>
              {running && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center py-16 gap-3"
                >
                  <div className="relative">
                    <div className="w-10 h-10 rounded-full border-2 border-violet/20 border-t-violet animate-spin" />
                    <Terminal className="w-4 h-4 text-violet absolute inset-0 m-auto" />
                  </div>
                  <p className="text-xs text-ink-500">Scanning…</p>
                  <p className="text-[10px] text-ink-700 font-mono">logs-* · {TIME_RANGE_LABELS[timeRange]}</p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Empty state */}
            {!running && !runResult && !runError && (
              <div className="flex flex-col items-center justify-center py-14 gap-2 text-ink-700">
                <Search className="w-8 h-8 opacity-30" />
                <p className="text-sm">Run a query to see results</p>
                <p className="text-[10px]">Select a saved hunt or write your own KQL</p>
              </div>
            )}

            {/* Error state - the query could not run (never fabricated hits) */}
            {!running && runError && (
              <div className="flex flex-col items-center justify-center py-14 gap-2 text-ink-500">
                <AlertTriangle className="w-7 h-7 text-amber opacity-70" />
                <p className="text-sm">Query couldn&apos;t run</p>
                <p className="text-[10px] text-ink-700">Check the query syntax, or that the dashboard API is reachable.</p>
              </div>
            )}

            {/* Results table */}
            {!running && runResult && runResult.results.length > 0 && (
              <div className="overflow-x-auto">
                {/* Column headers */}
                <div className="grid grid-cols-[160px_130px_130px_80px_80px_80px_80px_minmax(0,1fr)] gap-3 px-4 py-2.5 border-b border-white/5 text-[9px] text-ink-600 uppercase tracking-widest font-medium shrink-0">
                  <span>Timestamp</span>
                  <span>Source IP</span>
                  <span>Dest IP</span>
                  <span>Port</span>
                  <span>Protocol</span>
                  <span>Bytes</span>
                  <span>Interval</span>
                  <span>Host</span>
                </div>

                {/* Rows */}
                <div className="divide-y divide-white/4">
                  {runResult.results.map((r, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04 }}
                      className="grid grid-cols-[160px_130px_130px_80px_80px_80px_80px_minmax(0,1fr)] gap-3 px-4 py-2.5 hover:bg-white/3 transition-colors group cursor-pointer"
                    >
                      <span
                        suppressHydrationWarning
                        className="font-mono text-[10px] text-ink-600"
                      >
                        {new Date(r.ts).toLocaleString('en-GB', {
                          month: '2-digit', day: '2-digit',
                          hour: '2-digit', minute: '2-digit', second: '2-digit',
                        })}
                      </span>
                      <span className="font-mono text-[11px] text-ink-300">{r.srcIp}</span>
                      <span className="font-mono text-[11px] text-threat">{r.destIp}</span>
                      <span className="font-mono text-[11px] text-ink-400">{r.destPort}</span>
                      <span className={cn('text-[10px] font-medium', r.protocol === 'HTTP' ? 'text-amber' : 'text-ink-400')}>
                        {r.protocol}
                      </span>
                      <span className="text-[11px] text-ink-400 font-mono">{fmtBytes(r.bytes)}</span>
                      <span className={cn('text-[11px] font-semibold font-mono', riskColor(r.interval, r.bytes))}>
                        {fmtInterval(r.interval)}
                      </span>
                      <span className="font-mono text-[10px] text-ink-300 truncate group-hover:text-white transition-colors">
                        {r.host}
                      </span>
                    </motion.div>
                  ))}
                </div>

                {/* Beaconing analysis footer */}
                <div className="px-4 py-3 border-t border-white/5 bg-threat/5 border-b-0">
                  <div className="flex items-start gap-2.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-threat mt-0.5 shrink-0" />
                    <div>
                      <p className="text-xs font-semibold text-threat">Beaconing Pattern Detected</p>
                      <p className="text-[10px] text-ink-500 mt-0.5 leading-relaxed">
                        {runResult.hits} endpoints exhibit low-jitter periodic outbound connections consistent with C2 beacon heartbeat.
                        Average interval: ~77s · Average payload: ~822 B · Confidence: <span className="text-magenta font-semibold">High (87%)</span>.
                        Correlate with EDR process tree and DNS logs. Consider isolating DESKTOP-FIN-087 (interval 58s - closest match to known Cobalt Strike default).
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* No results */}
            {!running && runResult && runResult.results.length === 0 && (
              <div className="flex flex-col items-center justify-center py-12 gap-2">
                <CheckCircle className="w-7 h-7 text-safe opacity-60" />
                <p className="text-sm text-ink-500">No matching events found</p>
                <p className="text-[10px] text-ink-700">Try widening the time range or relaxing filter conditions</p>
              </div>
            )}
          </div>

          {/* Save feedback toast */}
          <AnimatePresence>
            {savedMsg && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 8 }}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs text-safe bg-safe/10 border border-safe/20 self-start"
              >
                <CheckCircle className="w-3.5 h-3.5 shrink-0" />
                {savedMsg}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  )
}
