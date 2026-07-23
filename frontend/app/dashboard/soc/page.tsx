'use client'

/**
 * SOC Console - the analyst-facing operational view, distinct from the
 * executive Overview. Everything here is live from the backend: the open-alert
 * queue and SLA breaches come from /siem/triage (ages computed from real alert
 * timestamps), response metrics from /siem/kpis, pipeline backpressure from
 * /config/engine, MITRE coverage from /siem/attack-coverage, and the ingest
 * listeners from /siem/log-listeners. Only the SLA thresholds are policy.
 */
import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  Gauge, AlertTriangle, Clock, User, Activity, Zap, ShieldCheck,
  RefreshCw, ArrowUpRight, Wifi, Server, Timer, Inbox, Flame, Rss, Search, UserPlus,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { SEVERITY_COLOR as SEV_COLOR, tk, withAlpha } from '@/lib/colors'
import { useAuth } from '@/lib/auth-context'
import {
  fetchTriage, fetchSiemKpis, fetchEngineStatus, fetchAttackCoverage, fetchLogListeners,
  fetchFeedsSummary, fetchSiemAlerts, patchAlert,
  type SocTriage, type SiemKpis, type EngineStatus, type AttackCoverage, type LogListenerStatus,
  type FeedsSummary, type SiemAlert,
} from '@/lib/api'
const STATUS_LABEL: Record<string, string> = {
  new: 'New', assigned: 'Assigned', 'in-progress': 'In Progress', pending: 'Pending',
}

/** Minutes → compact age string (e.g. 1450 → "1d 0h"). */
function age(mins: number): string {
  if (mins < 60) return `${Math.round(mins)}m`
  if (mins < 1440) return `${Math.floor(mins / 60)}h ${Math.round(mins % 60)}m`
  return `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h`
}

function KpiTile({ label, value, sub, color, icon: Icon }: {
  label: string; value: string | number; sub?: string; color: string; icon: React.ComponentType<any>
}) {
  return (
    <div className="px-5 py-3">
      <div className="flex items-center gap-1.5 text-[10px] text-ink-600 uppercase tracking-wide">
        <Icon className="w-3 h-3" style={{ color }} />{label}
      </div>
      <div className={cn('text-xl font-bold font-mono mt-0.5')} style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-ink-600">{sub}</div>}
    </div>
  )
}

function Panel({ title, icon: Icon, children, action }: {
  title: string; icon: React.ComponentType<any>; children: React.ReactNode; action?: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-white/8 bg-surface">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Icon className="w-3.5 h-3.5 text-violet" />
          <h2 className="text-xs font-semibold text-white">{title}</h2>
        </div>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

export default function SocConsolePage() {
  const { user } = useAuth()
  const [triage, setTriage] = useState<SocTriage | null>(null)
  const [kpis, setKpis] = useState<SiemKpis | null>(null)
  const [engine, setEngine] = useState<EngineStatus | null>(null)
  const [coverage, setCoverage] = useState<AttackCoverage | null>(null)
  const [listeners, setListeners] = useState<LogListenerStatus | null>(null)
  const [feeds, setFeeds] = useState<FeedsSummary | null>(null)
  const [alerts, setAlerts] = useState<SiemAlert[]>([])
  const [qSearch, setQSearch] = useState('')
  const [qSev, setQSev] = useState('all')
  const [qAssign, setQAssign] = useState('all') // all | mine | unassigned
  const [assigning, setAssigning] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [updated, setUpdated] = useState<Date | null>(null)

  const load = useCallback(async () => {
    setRefreshing(true)
    const [t, k, e, c, l, f, a] = await Promise.allSettled([
      fetchTriage(), fetchSiemKpis(), fetchEngineStatus(), fetchAttackCoverage(), fetchLogListeners(),
      fetchFeedsSummary(), fetchSiemAlerts({ limit: '150' }),
    ])
    if (t.status === 'fulfilled') setTriage(t.value)
    if (k.status === 'fulfilled') setKpis(k.value)
    if (e.status === 'fulfilled') setEngine(e.value)
    if (c.status === 'fulfilled') setCoverage(c.value)
    if (l.status === 'fulfilled') setListeners(l.value)
    if (f.status === 'fulfilled') setFeeds(f.value)
    if (a.status === 'fulfilled') setAlerts(a.value.items)
    setUpdated(new Date())
    setLoading(false)
    setRefreshing(false)
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 20000)   // analyst console: live refresh
    return () => clearInterval(id)
  }, [load])

  const open = triage?.open
  const queue = engine?.queue
  const breaches = triage?.sla.breaches ?? []
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'] as const

  // --- Investigation queue: the live analyst work surface ---
  const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  const OPEN_STATUS = ['new', 'assigned', 'in-progress', 'pending']
  const myName = user?.name ?? user?.email ?? ''
  const openAlerts = alerts.filter((a) => OPEN_STATUS.includes(a.status))
  const queueRows = openAlerts.filter((a) => {
    if (qSev !== 'all' && a.severity !== qSev) return false
    if (qAssign === 'mine' && a.owner !== myName) return false
    if (qAssign === 'unassigned' && a.owner) return false
    if (qSearch) {
      const q = qSearch.toLowerCase()
      const hay = [a.title, a.ruleName, a.srcIp, a.hostname, a.username, a.owner]
        .filter(Boolean).join(' ').toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  }).sort((x, y) => (SEV_RANK[y.severity] - SEV_RANK[x.severity]) || (Date.parse(y.ts) - Date.parse(x.ts)))
  // Analyst workload: open alerts grouped by assignee (who's carrying what).
  const workload = Object.entries(
    openAlerts.reduce<Record<string, number>>((m, a) => {
      const k = a.owner || 'unassigned'; m[k] = (m[k] ?? 0) + 1; return m
    }, {}),
  ).sort((a, b) => b[1] - a[1])

  async function assignToMe(a: SiemAlert) {
    if (!myName || assigning) return
    setAssigning(a.id)
    try {
      const nextStatus = a.status === 'new' ? 'assigned' : a.status
      await patchAlert(a.id, { owner: myName, status: nextStatus })
      setAlerts((prev) => prev.map((x) => x.id === a.id ? { ...x, owner: myName, status: nextStatus } : x))
    } catch { /* backend enforces perms; leave as-is on failure */ }
    finally { setAssigning(null) }
  }

  return (
    <div className="flex flex-col h-full bg-bg">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 px-6 py-4 border-b border-white/5 shrink-0 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Gauge className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">SOC Console</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Live analyst operations - open queue, SLA timers, pipeline health</p>
        </div>
        <div className="flex items-center gap-3">
          {updated && (
            <span className="text-[10px] text-ink-600">
              Updated {updated.toLocaleTimeString()}
            </span>
          )}
          <button onClick={load} disabled={refreshing}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium text-ink-300 border border-white/8 hover:border-white/15 hover:text-white transition-colors disabled:opacity-50">
            <RefreshCw className={cn('w-3 h-3', refreshing && 'animate-spin')} />Refresh
          </button>
        </div>
      </div>

      {/* KPI strip - live operational numbers */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 divide-x divide-white/5 border-b border-white/5 shrink-0">
        <KpiTile label="Open queue" value={open?.total ?? '-'} icon={Inbox} color="#fff"
          sub={open ? `${open.unassigned} unassigned` : undefined} />
        <KpiTile label="Critical open" value={open?.critical ?? '-'} icon={Flame} color={SEV_COLOR.critical} />
        <KpiTile label="SLA breaches" value={triage?.sla.breachCount ?? '-'} icon={AlertTriangle}
          color={triage && triage.sla.breachCount > 0 ? SEV_COLOR.high : tk('safe')} />
        <KpiTile label="Oldest open" value={triage ? age(triage.oldestOpenMinutes) : '-'} icon={Clock} color={tk('amber')} />
        <KpiTile label="MTTA" value={kpis ? `${kpis.mtta}m` : '-'} icon={Timer} color={tk('violet')} />
        <KpiTile label="MTTR" value={kpis ? `${kpis.mttr}m` : '-'} icon={Timer} color={tk('violet')} />
        <KpiTile label="Ingest EPS" value={kpis?.totalEps ?? '-'} icon={Activity} color={tk('safe')} />
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {loading ? (
          <p className="text-xs text-ink-600 py-16 text-center animate-pulse">Loading live SOC telemetry…</p>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* -- Investigation queue: live analyst work surface ---------- */}
            <div className="lg:col-span-3">
              <Panel title={`Investigation Queue · ${queueRows.length}`} icon={Inbox}
                action={<Link href="/dashboard/siem" className="text-[11px] text-magenta hover:underline flex items-center gap-0.5">Open in SIEM<ArrowUpRight className="w-3 h-3" /></Link>}>
                {/* Search + filters */}
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  <div className="relative flex-1 min-w-[180px]">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
                    <input value={qSearch} onChange={(e) => setQSearch(e.target.value)}
                      placeholder="Search title, rule, IP, host, user, owner…" aria-label="Search queue"
                      className="w-full pl-8 pr-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 placeholder-ink-600 focus:outline-hidden focus:border-magenta/40" />
                  </div>
                  <select value={qSev} onChange={(e) => setQSev(e.target.value)} aria-label="Severity"
                    className="px-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-300 focus:outline-hidden focus:border-magenta/40">
                    {['all', 'critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s}>{s === 'all' ? 'All severities' : s}</option>)}
                  </select>
                  <div className="flex items-center rounded-lg border border-white/8 overflow-hidden">
                    {(['all', 'mine', 'unassigned'] as const).map((a) => (
                      <button key={a} onClick={() => setQAssign(a)}
                        className={cn('px-2.5 py-1.5 text-[11px] capitalize transition-colors',
                          qAssign === a ? 'bg-magenta/20 text-magenta' : 'text-ink-500 hover:text-ink-200')}>{a}</button>
                    ))}
                  </div>
                </div>
                {/* Analyst workload */}
                {workload.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 mb-3">
                    <span className="text-[9px] text-ink-600 uppercase tracking-wide">Workload</span>
                    {workload.slice(0, 6).map(([owner, n]) => (
                      <span key={owner} className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-white/5 border border-white/8 text-ink-300">
                        <User className="w-2.5 h-2.5" />{owner}<span className="text-ink-600">×{n}</span>
                      </span>
                    ))}
                  </div>
                )}
                {/* Queue rows */}
                {queueRows.length === 0 ? (
                  <div className="flex items-center gap-2 py-8 justify-center text-xs text-ink-500">
                    <ShieldCheck className="w-4 h-4 text-safe" />
                    {openAlerts.length === 0 ? 'No open alerts — the queue is clear.' : 'No alerts match the current filters.'}
                  </div>
                ) : (
                  <div className="space-y-1.5 max-h-[420px] overflow-y-auto">
                    {queueRows.slice(0, 60).map((a) => (
                      <div key={a.id} className="flex items-center gap-3 p-2.5 rounded-lg border border-white/8 bg-surface hover:border-white/15 transition-colors group">
                        <span className="w-1.5 h-8 rounded-full shrink-0" style={{ background: SEV_COLOR[a.severity] ?? '#666' }} />
                        <Link href={`/dashboard/siem?alert=${a.id}`} className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium text-white truncate group-hover:text-magenta">{a.title}</span>
                            <span className="text-[9px] px-1.5 py-0.5 rounded-sm uppercase shrink-0 bg-white/5 text-ink-400">{STATUS_LABEL[a.status] ?? a.status}</span>
                          </div>
                          <div className="flex items-center gap-2 mt-0.5 text-[10px] text-ink-500">
                            <span className="truncate">{a.ruleName || a.mitreTactic || '—'}</span>
                            {a.srcIp && <span className="font-mono text-ink-600">{a.srcIp}</span>}
                          </div>
                        </Link>
                        <div className="text-right shrink-0 flex items-center gap-2">
                          <span className="inline-flex items-center gap-1 text-[10px] text-ink-500">
                            <User className="w-2.5 h-2.5" />{a.owner || 'unassigned'}
                          </span>
                          {a.owner !== myName && myName && (
                            <button onClick={() => assignToMe(a)} disabled={assigning === a.id}
                              title="Assign to me"
                              className="inline-flex items-center gap-1 text-[10px] px-1.5 py-1 rounded-lg border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors disabled:opacity-50">
                              <UserPlus className="w-3 h-3" /> me
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                    {queueRows.length > 60 && (
                      <p className="text-[10px] text-ink-600 text-center pt-1">+{queueRows.length - 60} more — refine filters or open the SIEM queue</p>
                    )}
                  </div>
                )}
              </Panel>
            </div>

            {/* -- SLA breach queue (primary work surface) ----------------- */}
            <div className="lg:col-span-2">
              <Panel title={`SLA Breach Queue${triage ? ` · ${triage.sla.breachCount}` : ''}`} icon={AlertTriangle}
                action={<Link href="/dashboard/siem" className="text-[11px] text-magenta hover:underline flex items-center gap-0.5">Full queue<ArrowUpRight className="w-3 h-3" /></Link>}>
                {triage && triage.open.total === 0 ? (
                  /* Honest empty state: an empty queue in live mode means no
                     telemetry is flowing yet - say so and point at the fix,
                     instead of a blank room with unexplained zeros. */
                  <div className="flex flex-col items-center gap-3 py-10 text-center">
                    <ShieldCheck className="w-6 h-6 text-safe" />
                    <div>
                      <p className="text-xs font-medium text-ink-200">The SIEM alert queue is empty.</p>
                      <p className="text-[11px] text-ink-500 mt-1 max-w-sm">
                        This console activates when telemetry flows. Forward real logs
                        (the runbook is <span className="font-mono">docs/GOING_LIVE.md</span>)
                        {engine && !engine.enabled ? ', or resume the demo engine for evaluation data' : ''}.
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Link href="/dashboard/siem/sources"
                        className="px-2.5 py-1.5 rounded-lg text-[11px] font-medium text-ink-200 border border-white/10 hover:border-white/20 hover:text-white transition-colors">
                        Log sources
                      </Link>
                      <Link href="/dashboard/config"
                        className="px-2.5 py-1.5 rounded-lg text-[11px] font-medium text-ink-200 border border-white/10 hover:border-white/20 hover:text-white transition-colors">
                        Settings
                      </Link>
                    </div>
                  </div>
                ) : breaches.length === 0 ? (
                  <div className="flex items-center gap-2 py-8 justify-center text-xs text-ink-500">
                    <ShieldCheck className="w-4 h-4 text-safe" />All open alerts within SLA.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {breaches.map((b, i) => (
                      <motion.div key={b.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: Math.min(i * 0.02, 0.3) }}>
                        <Link href={`/dashboard/siem?q=${encodeURIComponent(b.srcIp || b.title)}`}
                          className="flex items-center gap-3 p-2.5 rounded-lg border border-white/8 bg-bg hover:border-white/15 transition-colors group">
                          <span className="w-1.5 h-8 rounded-full shrink-0" style={{ background: SEV_COLOR[b.severity] }} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-medium text-white truncate">{b.title}</span>
                              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-sm uppercase shrink-0"
                                style={{ background: withAlpha(b.slaType === 'ack' ? SEV_COLOR.high : SEV_COLOR.medium, 0.13),
                                         color: b.slaType === 'ack' ? SEV_COLOR.high : SEV_COLOR.medium }}>
                                {b.slaType === 'ack' ? 'Unacked' : 'Overdue'}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 mt-0.5 text-[10px] text-ink-500">
                              <span>{b.ruleName || b.mitreTactic || '-'}</span>
                              {b.srcIp && <span className="font-mono text-ink-600">{b.srcIp}</span>}
                              <span className="flex items-center gap-0.5"><User className="w-2.5 h-2.5" />{b.owner ?? 'unassigned'}</span>
                            </div>
                          </div>
                          <div className="text-right shrink-0">
                            <div className="text-xs font-mono font-bold" style={{ color: SEV_COLOR[b.severity] }}>{age(b.ageMinutes)}</div>
                            <div className="text-[9px] text-ink-600">SLA {age(b.thresholdMinutes)}</div>
                          </div>
                          <ArrowUpRight className="w-3.5 h-3.5 text-ink-700 group-hover:text-magenta transition-colors shrink-0" />
                        </Link>
                      </motion.div>
                    ))}
                    {triage && triage.sla.breachCount > breaches.length && (
                      <p className="text-[10px] text-ink-600 text-center pt-1">
                        +{triage.sla.breachCount - breaches.length} more - showing worst {breaches.length}
                      </p>
                    )}
                  </div>
                )}
              </Panel>
            </div>

            {/* -- Right rail: pipeline + breakdowns ----------------------- */}
            <div className="space-y-4">
              {/* Pipeline health */}
              <Panel title="Pipeline Health" icon={Zap}>
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-ink-400">Engine</span>
                    <span className={cn('font-medium flex items-center gap-1.5',
                      engine?.running ? 'text-safe' : 'text-ink-500')}>
                      <span className={cn('w-1.5 h-1.5 rounded-full', engine?.running ? 'bg-safe animate-pulse' : 'bg-ink-600')} />
                      {engine?.running ? 'Running' : engine?.enabled ? 'Enabled' : 'Paused'}
                      {engine ? ` · ${engine.tickSeconds}s` : ''}
                    </span>
                  </div>
                  {queue ? (
                    <>
                      <div className="grid grid-cols-3 gap-2 pt-1">
                        <div className="text-center">
                          <div className="text-base font-bold font-mono text-white">{queue.depth}</div>
                          <div className="text-[9px] text-ink-600">Backlog</div>
                        </div>
                        <div className="text-center">
                          <div className="text-base font-bold font-mono text-violet">{queue.inFlight}</div>
                          <div className="text-[9px] text-ink-600">In flight</div>
                        </div>
                        <div className="text-center">
                          <div className="text-base font-bold font-mono" style={{ color: queue.lagSeconds > 60 ? SEV_COLOR.high : tk('safe') }}>
                            {queue.lagSeconds}s
                          </div>
                          <div className="text-[9px] text-ink-600">Lag</div>
                        </div>
                      </div>
                      {queue.maxBacklog > 0 && (
                        <div className="pt-1">
                          <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
                            <div className="h-full rounded-full transition-all"
                              style={{ width: `${Math.min(100, (queue.depth / queue.maxBacklog) * 100)}%`,
                                       background: queue.shedding ? SEV_COLOR.critical : tk('violet') }} />
                          </div>
                          <div className="flex justify-between text-[9px] text-ink-600 mt-1">
                            <span>{queue.shedding ? 'Shedding load' : 'Capacity'}</span>
                            <span>{queue.depth}/{queue.maxBacklog}</span>
                          </div>
                        </div>
                      )}
                    </>
                  ) : <p className="text-[10px] text-ink-600">Queue telemetry unavailable.</p>}
                  <div className="flex items-center justify-between text-xs pt-1 border-t border-white/5">
                    <span className="text-ink-400 flex items-center gap-1.5"><Activity className="w-3 h-3" />Ingest EPS</span>
                    <span className="font-mono text-safe">{kpis?.totalEps ?? '-'}</span>
                  </div>
                </div>
              </Panel>

              {/* Intel activity - the platform's living side. In live mode the
                 alert queue can be legitimately empty (no logs forwarded yet)
                 while the intel pipeline is fully active; surfacing it here
                 keeps the console honest about what IS happening. */}
              {feeds && (
                <Panel title="Intel Activity" icon={Rss}
                  action={<Link href="/dashboard/feeds" className="text-[11px] text-magenta hover:underline flex items-center gap-0.5">Feeds<ArrowUpRight className="w-3 h-3" /></Link>}>
                  <div className="space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-ink-400">Indicators tracked</span>
                      <span className="font-mono text-white">{feeds.totalIndicators.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-ink-400">New today</span>
                      <span className={cn('font-mono', feeds.newToday > 0 ? 'text-safe' : 'text-ink-500')}>
                        {feeds.newToday.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-ink-400">Feed sources</span>
                      <span className="font-mono text-white">
                        {feeds.active}<span className="text-ink-600">/{feeds.totalFeeds} active</span>
                        {feeds.errored > 0 && <span className="text-threat"> · {feeds.errored} erroring</span>}
                      </span>
                    </div>
                  </div>
                </Panel>
              )}

              {/* Open by severity */}
              <Panel title="Open by Severity" icon={Inbox}>
                <div className="space-y-1.5">
                  {open && sevOrder.map((s) => {
                    const v = open[s] ?? 0
                    const pct = open.total ? (v / open.total) * 100 : 0
                    return (
                      <div key={s} className="flex items-center gap-2">
                        <span className="text-[10px] text-ink-500 capitalize w-12 shrink-0">{s}</span>
                        <div className="flex-1 h-1.5 rounded-full bg-white/8 overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${pct}%`, background: SEV_COLOR[s] }} />
                        </div>
                        <span className="text-[10px] font-mono text-ink-300 w-6 text-right shrink-0">{v}</span>
                      </div>
                    )
                  })}
                </div>
              </Panel>

              {/* Triage state */}
              <Panel title="Triage State" icon={User}>
                <div className="grid grid-cols-2 gap-2">
                  {triage && Object.entries(STATUS_LABEL).map(([k, label]) => (
                    <div key={k} className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-bg border border-white/5">
                      <span className="text-[10px] text-ink-500">{label}</span>
                      <span className="text-xs font-mono font-bold text-white">{triage.byStatus[k] ?? 0}</span>
                    </div>
                  ))}
                </div>
              </Panel>

              {/* MITRE coverage */}
              {coverage && (
                <Panel title="ATT&CK Coverage" icon={ShieldCheck}
                  action={<Link href="/dashboard/siem/attack" className="text-[11px] text-magenta hover:underline flex items-center gap-0.5">Navigator<ArrowUpRight className="w-3 h-3" /></Link>}>
                  <div className="flex items-center gap-3">
                    <div className="relative w-14 h-14 shrink-0">
                      <svg viewBox="0 0 36 36" className="w-14 h-14 -rotate-90">
                        <circle cx="18" cy="18" r="15.9" fill="none" stroke="#ffffff14" strokeWidth="3" />
                        <circle cx="18" cy="18" r="15.9" fill="none" stroke={tk('safe')} strokeWidth="3"
                          strokeDasharray={`${coverage.summary.coveragePct} 100`} strokeLinecap="round" />
                      </svg>
                      <span className="absolute inset-0 flex items-center justify-center text-xs font-bold font-mono text-white">
                        {coverage.summary.coveragePct}%
                      </span>
                    </div>
                    <div className="flex-1 text-[11px] space-y-1">
                      <div className="flex justify-between"><span className="text-ink-500">Techniques</span><span className="font-mono text-white">{coverage.summary.techniques}</span></div>
                      <div className="flex justify-between"><span className="text-ink-500">Covered</span><span className="font-mono text-safe">{coverage.summary.covered}</span></div>
                      <div className="flex justify-between"><span className="text-ink-500">Gaps</span><span className="font-mono text-magenta">{coverage.summary.gaps}</span></div>
                    </div>
                  </div>
                </Panel>
              )}

              {/* Ingest listeners */}
              {listeners && (
                <Panel title="Ingest Listeners" icon={Server}>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-ink-400 flex items-center gap-1.5"><Wifi className="w-3 h-3" />Syslog
                        {listeners.syslogPort ? <span className="text-ink-600 font-mono">:{listeners.syslogPort}</span> : null}</span>
                      <span className={cn('font-medium', listeners.syslogEnabled ? 'text-safe' : 'text-ink-600')}>
                        {listeners.syslogEnabled ? 'Listening' : 'Off'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-ink-400 flex items-center gap-1.5"><Server className="w-3 h-3" />File watch</span>
                      <span className={cn('font-medium', listeners.watchEnabled ? 'text-safe' : 'text-ink-600')}>
                        {listeners.watchEnabled ? `Every ${listeners.watchIntervalSeconds}s` : 'Off'}
                      </span>
                    </div>
                  </div>
                </Panel>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
