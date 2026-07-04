'use client'
import { tk, withAlpha } from '@/lib/colors'

import { useState, useEffect, useMemo } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertTriangle, Shield, Activity, Zap, Globe, TrendingUp,
  TrendingDown, ArrowUpRight, Clock, Eye, Radio, Filter,
  Bug, CheckCircle2, XCircle, Flame, BookOpen, ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { openDetail } from '@/components/dashboard/DetailDrawer'
import ReportButton from '@/components/dashboard/ReportButton'
import WorldMap from '@/components/dashboard/WorldMap'
import OnboardingCard from '@/components/dashboard/OnboardingCard'
import { useExperienceMode } from '@/lib/useExperienceMode'
import {
  fetchKpis, fetchRecentAlerts, fetchRecentIncidents,
  fetchTopActors, fetchHourly, fetchVectors, fetchLiveFeed,
  fetchRiskDistribution, fetchHeatmap, fetchSiemKpis, fetchSoarMetrics,
  fetchFleetVulnFindings, fetchServicesStatus,
  type OverviewKpis, type OverviewAlert, type Incident,
  type TopActor, type ThreatVector, type LiveFeedItem, type RiskDistribution,
  type SiemKpis, type SoarMetrics, type FleetVulnFinding, type ServicesStatus,
} from '@/lib/api'

const SEVERITY_COLOR: Record<string, string> = {
  critical: tk('magenta'),
  high:     tk('threat'),
  medium:   tk('amber'),
  low:      tk('safe'),
} as const

/* ── KPI Card ────────────────────────────────────────────────────── */
function KPICard({
  label, value, sub, icon: Icon, color, trend, trendVal,
}: {
  label: string
  value: string
  sub?: string
  icon: React.ComponentType<any>
  color: string
  trend?: 'up' | 'down'
  trendVal?: string
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/5 rounded-xl p-5 relative overflow-hidden"
    >
      <div className="absolute inset-0 opacity-30"
        style={{ background: `radial-gradient(circle at 0% 0%, ${color}18, transparent 70%)` }}
      />
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs text-ink-500 mb-1.5">{label}</p>
          <p className="font-display text-2xl font-bold text-white">{value}</p>
          {sub && <p className="text-xs text-ink-400 mt-0.5">{sub}</p>}
        </div>
        <div className="p-2.5 rounded-xl" style={{ background: `${color}18` }}>
          <Icon className="w-4.5 h-4.5" style={{ color }} />
        </div>
      </div>
      {trend && trendVal && (
        <div className={cn(
          'flex items-center gap-1 mt-3 text-xs font-medium',
          trend === 'up' ? 'text-threat' : 'text-safe',
        )}>
          {trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          {trendVal} vs yesterday
        </div>
      )}
    </motion.div>
  )
}

/* ── Trending CVEs (static - no CVE endpoint yet) ────────────────── */
function TrendingCVEs() {
  const [cves, setCves] = useState<FleetVulnFinding[]>([])
  useEffect(() => {
    fetchFleetVulnFindings()
      .then((rows) => {
        // "Trending" = highest-impact open vulns first: KEV / exploited, then CVSS.
        const sorted = [...rows].sort((a, b) =>
          Number(b.kev) - Number(a.kev) || Number(b.exploit) - Number(a.exploit) || b.cvss - a.cvss)
        setCves(sorted.slice(0, 5))
      })
      .catch(() => {})
  }, [])

  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Bug className="w-3.5 h-3.5 text-threat" />
          <h3 className="text-sm font-semibold text-white">Trending CVEs</h3>
        </div>
        <Link href="/dashboard/assets/vulns" className="text-xs text-magenta hover:underline">Vulns →</Link>
      </div>
      {cves.length === 0 ? (
        <div className="px-5 py-10 text-center">
          <Bug className="w-6 h-6 text-ink-700 mx-auto mb-2" />
          <p className="text-xs text-ink-400">No fleet vulnerabilities yet</p>
          <p className="text-[10px] text-ink-600 mt-1">Run an asset scan to surface CVEs here.</p>
        </div>
      ) : (
      <div className="divide-y divide-white/4">
        {cves.map((cve, i) => {
          const tag = cve.kev ? 'KEV' : cve.exploit ? 'Exploit' : (cve.severity || 'CVE')
          const color = cve.cvss >= 9 ? tk('magenta') : cve.cvss >= 7 ? tk('threat') : tk('amber')
          const affected = cve.products?.[0] ?? cve.summary ?? '—'
          return (
          <motion.div
            key={cve.cve}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.06 }}
            className="flex items-center gap-3 px-5 py-2.5 hover:bg-white/2 transition-colors cursor-pointer group"
          >
            <span className="text-[10px] text-ink-600 w-3 shrink-0">{i + 1}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-xs font-mono text-ink-200 group-hover:text-white transition-colors">{cve.cve}</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded-full font-medium" style={{ background: `${color}1a`, color }}>{tag}</span>
              </div>
              <p className="text-[10px] text-ink-500 truncate">{affected}</p>
            </div>
            <div className="text-right shrink-0">
              <p className="text-xs font-bold" style={{ color }}>{cve.cvss.toFixed(1)}</p>
              <p className="text-[9px] text-ink-600">CVSS</p>
            </div>
            <div className="shrink-0">
              {cve.fixedIn
                ? <CheckCircle2 className="w-3.5 h-3.5 text-safe" aria-label="Patch available" />
                : <XCircle className="w-3.5 h-3.5 text-threat animate-pulse" aria-label="No patch" />}
            </div>
          </motion.div>
          )
        })}
      </div>
      )}
    </div>
  )
}

/* ── Intel Brief ─────────────────────────────────────────────────── */

function timeAgo(iso: string) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function IntelBrief({ alerts }: { alerts: OverviewAlert[] }) {
  // Honest empty state: an empty store means "no briefs yet", never fabricated
  // headlines badged as live (fresh real-data installs start empty).
  const live = alerts.length > 0
  const items = live
    ? alerts.slice(0, 4).map((a) => ({
        headline: a.title,
        severity: a.severity,
        age: timeAgo(a.time),
        src: a.src,
      }))
    : []
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <BookOpen className="w-3.5 h-3.5 text-violet" />
          <h3 className="text-sm font-semibold text-white">Today&apos;s Intel Brief</h3>
        </div>
        {live && (
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-safe/10 border border-safe/20 text-safe font-medium">Live</span>
        )}
      </div>
      {!live ? (
        <div className="flex-1 flex items-center justify-center px-5 py-8">
          <p className="text-[11px] text-ink-500 text-center leading-relaxed">
            No intel briefs yet — they appear as alerts arrive.<br />
            Connect feeds (Feeds → Sources) or forward logs (SIEM → Sources).
          </p>
        </div>
      ) : (
      <div className="flex-1 divide-y divide-white/4">
        {items.map((item, i) => (
          <div key={i}
            onClick={() => openDetail({
              title: item.headline, subtitle: `${item.src} · ${item.age}`, severity: item.severity,
              rows: [{ label: 'Source', value: item.src, mono: true }, { label: 'Severity', value: item.severity }, { label: 'Observed', value: item.age }],
              actions: [{ label: 'Investigate in SIEM', href: `/dashboard/siem?q=${encodeURIComponent(item.headline)}` }],
            })}
            className="flex items-start gap-3 px-5 py-3 hover:bg-white/2 transition-colors cursor-pointer group">
            <span
              className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
              style={{ background: SEVERITY_COLOR[item.severity as keyof typeof SEVERITY_COLOR] }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-xs text-ink-200 group-hover:text-white transition-colors leading-snug">{item.headline}</p>
              <p className="text-[10px] text-ink-600 mt-0.5 font-mono">{item.src} · {item.age}</p>
            </div>
            <ChevronRight className="w-3 h-3 text-ink-700 group-hover:text-magenta transition-colors shrink-0 mt-0.5" />
          </div>
        ))}
      </div>
      )}
      <div className="px-5 py-2.5 border-t border-white/5 bg-white/1">
        <div className="flex items-center justify-between text-[10px] text-ink-600">
          <span>Aggregated across your intelligence sources</span>
          <Link href="/dashboard/cti" className="text-magenta hover:underline">View all →</Link>
        </div>
      </div>
    </div>
  )
}

// Aligned with the platform-wide STATUS_COLORS semantics (lib/colors.ts):
// open work = threat red, active alerts = magenta, resolved work = safe green.
const STATUS_COLOR: Record<string, string> = { active: tk('magenta'), triaged: tk('amber'), open: tk('threat'), 'in-progress': tk('amber'), resolved: tk('safe'), closed: tk('safe') }
const STATUS_BG:    Record<string, string> = { active: withAlpha(tk('magenta'), 0.06), triaged: withAlpha(tk('amber'), 0.06), open: withAlpha(tk('threat'), 0.06), 'in-progress': withAlpha(tk('amber'), 0.06), resolved: withAlpha(tk('safe'), 0.06), closed: withAlpha(tk('safe'), 0.06) }

function ActiveIncidents({ incidents }: { incidents: Incident[] }) {
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Flame className="w-3.5 h-3.5 text-threat" />
          <h3 className="text-sm font-semibold text-white">Active Incidents</h3>
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-threat/10 border border-threat/20 text-threat font-semibold">
            {incidents.filter((i) => i.status === 'active' || i.status === 'open').length} open
          </span>
        </div>
        <Link href="/dashboard/siem" className="text-xs text-magenta hover:underline">SIEM →</Link>
      </div>

      {/* Severity bar */}
      {incidents.length > 0 && (() => {
        const crit = incidents.filter(i => i.severity === 'critical').length
        const high = incidents.filter(i => i.severity === 'high').length
        const med  = incidents.filter(i => i.severity === 'medium').length
        const tot  = incidents.length || 1
        return (
          <>
            <div className="flex h-1.5 mx-5 mt-3 rounded-full overflow-hidden gap-px">
              {[
                { pct: Math.round(crit/tot*100), color: tk('magenta') },
                { pct: Math.round(high/tot*100), color: tk('threat') },
                { pct: Math.round(med/tot*100),  color: tk('amber') },
                { pct: Math.max(0, 100 - Math.round(crit/tot*100) - Math.round(high/tot*100) - Math.round(med/tot*100)), color: tk('teal') },
              ].map(({ pct, color }, i) => (
                <motion.div key={i} initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                  transition={{ duration: 0.8, delay: i * 0.1, ease: 'easeOut' }}
                  className="h-full" style={{ background: color }} />
              ))}
            </div>
            <div className="flex justify-between px-5 pt-1 pb-3 text-[9px] text-ink-600">
              <span>{crit} critical</span><span>{high} high</span><span>{med} med</span><span>-</span>
            </div>
          </>
        )
      })()}

      <div className="divide-y divide-white/4">
        {incidents.map((inc) => (
          <div key={inc.id}
            onClick={() => openDetail({
              title: inc.title, subtitle: `${inc.id} · ${inc.category}`, severity: inc.severity,
              rows: [
                { label: 'Status', value: inc.status }, { label: 'Category', value: inc.category },
                { label: 'Assigned', value: inc.assigned }, { label: 'Age', value: timeAgo(inc.age) },
              ],
              actions: [{ label: 'Open in SOAR cases', href: '/dashboard/soar' }],
            })}
            className="flex items-center gap-3 px-5 py-2.5 hover:bg-white/2 transition-colors cursor-pointer group">
            <span className="w-1.5 h-1.5 rounded-full shrink-0 ring-2 ring-current/10"
              style={{ background: SEVERITY_COLOR[inc.severity as keyof typeof SEVERITY_COLOR] }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-xs text-ink-200 group-hover:text-white transition-colors truncate">{inc.title}</p>
              <p className="text-[10px] text-ink-600 mt-0.5 font-mono">{inc.id} · {inc.category} · {inc.assigned}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span
                className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold capitalize"
                style={{ background: STATUS_BG[inc.status] ?? '#ffffff10', color: STATUS_COLOR[inc.status] ?? '#aaa' }}
              >
                {inc.status}
              </span>
              <span className="text-[10px] text-ink-600">{timeAgo(inc.age)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function RecentAlerts({ alerts }: { alerts: OverviewAlert[] }) {
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <h3 className="text-sm font-semibold text-white">Recent Alerts</h3>
        <Link href="/dashboard/siem" className="text-xs text-magenta hover:underline">View all</Link>
      </div>
      <div className="divide-y divide-white/4">
        {alerts.map((a) => (
          <div key={a.id}
            onClick={() => openDetail({
              title: a.title, subtitle: `Alert ${a.id}`, severity: a.severity,
              rows: [
                { label: 'Source', value: a.src, mono: true }, { label: 'Severity', value: a.severity },
                { label: 'Time', value: a.time },
              ],
              actions: [{ label: 'Open in SIEM alert queue', href: '/dashboard/siem' }],
            })}
            className="flex items-start gap-3 px-5 py-3 hover:bg-white/2 transition-colors cursor-pointer group">
            <span
              className="mt-1 w-2 h-2 rounded-full shrink-0 ring-2 ring-current/20"
              style={{ color: SEVERITY_COLOR[a.severity as keyof typeof SEVERITY_COLOR], background: SEVERITY_COLOR[a.severity as keyof typeof SEVERITY_COLOR] }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-xs text-ink-200 group-hover:text-white transition-colors truncate">{a.title}</p>
              <p className="text-[10px] text-ink-600 mt-0.5 font-mono">{a.src}</p>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <span className={cn(
                'text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase tracking-wide',
                a.severity === 'critical' ? 'bg-magenta/10 text-magenta' :
                a.severity === 'high' ? 'bg-threat/10 text-threat' :
                'bg-amber/10 text-amber',
              )}>
                {a.severity}
              </span>
              <span className="text-[10px] text-ink-600">{timeAgo(a.time)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

const ACTOR_COLORS = [tk('magenta'), tk('violet'), tk('amber'), tk('teal'), tk('threat')]

function TopActors({ actors }: { actors: TopActor[] }) {
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <h3 className="text-sm font-semibold text-white">Top Threat Actors</h3>
        <Link href="/dashboard/cti" className="text-xs text-magenta hover:underline">CTI →</Link>
      </div>
      <div className="p-4 space-y-3">
        {actors.length === 0 && (
          <p className="text-[11px] text-ink-600 py-6 text-center">
            No actor activity observed yet. Tracked actors light up here as the engine
            attributes indicators to them.
          </p>
        )}
        {actors.map((a, i) => (
          <div key={a.name} className="flex items-center gap-3">
            <span className="text-[10px] text-ink-600 w-4">{i + 1}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-ink-200">{a.name}</span>
                <span className="text-[10px] text-ink-500">{a.origin}</span>
              </div>
              <div className="h-1 bg-surface-3 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(a.score / 10) * 100}%` }}
                  transition={{ delay: i * 0.1, duration: 0.8, ease: 'easeOut' }}
                  className="h-full rounded-full"
                  style={{ background: ACTOR_COLORS[i % ACTOR_COLORS.length] }}
                />
              </div>
            </div>
            <span className="text-[10px] font-mono text-ink-400 w-12 text-right">{a.attacks} att.</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function AttackVectors({ vectors }: { vectors: ThreatVector[] }) {
  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <h3 className="text-sm font-semibold text-white mb-4">Attack Vectors (24h)</h3>
      <div className="space-y-3">
        {vectors.map((v) => (
          <div key={v.label}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-ink-300">{v.label}</span>
              <span className="text-xs font-mono text-ink-400">{v.pct}%</span>
            </div>
            <div className="h-1.5 bg-surface-3 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${v.pct}%` }}
                transition={{ duration: 0.9, ease: 'easeOut' }}
                className="h-full rounded-full"
                style={{ background: v.color }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

const RISK_AXIS_META: Record<string, { label: string; color: string }> = {
  vulnerability: { label: 'Vulnerabilities', color: tk('magenta') },
  exposure:      { label: 'Exposure',        color: tk('amber') },
  patch:         { label: 'Patch Hygiene',   color: tk('violet') },
  alerts:        { label: 'Alert Pressure',  color: tk('threat') },
}

function AssetRiskDrivers({ dist }: { dist: RiskDistribution | null }) {
  if (!dist) return null
  const maxContrib = Math.max(...dist.axisContribution.map((a) => a.avgContribution), 1)
  const driverLabel = dist.topDriver ? (RISK_AXIS_META[dist.topDriver]?.label ?? dist.topDriver) : '-'
  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Asset Risk Drivers</h3>
        <span className="text-[10px] text-ink-500">
          {dist.total} assets · top driver <span className="text-ink-300">{driverLabel}</span>
        </span>
      </div>
      {/* Band summary */}
      <div className="flex items-center gap-2 mb-4">
        {([['critical', tk('magenta')], ['at-risk', tk('amber')], ['clean', tk('safe')]] as const).map(([band, color]) => (
          <div key={band} className="flex-1 rounded-lg border border-white/6 bg-white/[0.02] px-2 py-1.5 text-center">
            <p className="text-base font-bold" style={{ color }}>{dist.bands[band] ?? 0}</p>
            <p className="text-[9px] text-ink-600 capitalize">{band}</p>
          </div>
        ))}
      </div>
      {/* Mean contribution per axis */}
      <div className="space-y-3">
        {dist.axisContribution.map((a) => {
          const m = RISK_AXIS_META[a.axis] ?? { label: a.axis, color: tk('safe') }
          return (
            <div key={a.axis}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-ink-300">{m.label}</span>
                <span className="text-xs font-mono text-ink-400">+{a.avgContribution}</span>
              </div>
              <div className="h-1.5 bg-surface-3 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(a.avgContribution / maxContrib) * 100}%` }}
                  transition={{ duration: 0.9, ease: 'easeOut' }}
                  className="h-full rounded-full"
                  style={{ background: m.color }}
                />
              </div>
            </div>
          )
        })}
      </div>
      <p className="text-[10px] text-ink-600 mt-3">Mean points each axis adds to asset risk, fleet-wide.</p>
    </div>
  )
}


function EventTimeline({ hourly }: { hourly: number[] }) {
  // Honest empty state: no 24h series yet → flat zero bars, never a fabricated
  // volume shape (fresh real-data installs start empty).
  const data = hourly.length === 24 ? hourly : Array(24).fill(0)
  const max = Math.max(...data, 1)
  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Events / Hour</h3>
        <div className="flex items-center gap-1.5 text-xs text-ink-500">
          <Clock className="w-3 h-3" />
          Last 24 hours
        </div>
      </div>
      <div className="flex items-end gap-1 h-20">
        {data.map((v, i) => (
          <motion.div
            key={i}
            initial={{ height: 0 }}
            animate={{ height: `${(v / max) * 100}%` }}
            transition={{ delay: i * 0.02, duration: 0.6, ease: 'easeOut' }}
            className="flex-1 rounded-sm min-w-0"
            style={{
              background: v > 50 ? tk('magenta') : v > 35 ? tk('amber') : withAlpha(tk('violet'), 0.5),
            }}
            title={`Hour ${i}: ${v} events`}
          />
        ))}
      </div>
      <div className="flex justify-between mt-2 text-[9px] text-ink-600">
        <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
      </div>
    </div>
  )
}

/* ── Threat Heatmap ──────────────────────────────────────────────── */

function ThreatHeatmap({ rows }: { rows: Array<{ label: string; vals: number[] }> }) {
  // Live rows are MITRE tactics over six ~28h windows. Honest empty state when
  // no detections exist yet — never a fabricated heatmap on a fresh install.
  const live = rows.length > 0
  const data = rows
  const nCols = data[0]?.vals.length ?? 6
  const cols: string[] = Array.from({ length: nCols }, (_, i) =>
    (i === nCols - 1 ? 'Now' : `-${nCols - 1 - i}d`))
  const allVals = data.flatMap((r) => r.vals)
  const maxV = Math.max(...allVals, 1)

  function heatColor(v: number) {
    const t = v / maxV
    if (t > 0.8) return tk('magenta')
    if (t > 0.6) return tk('threat')
    if (t > 0.4) return tk('amber')
    if (t > 0.2) return tk('violet')
    return 'rgba(255,255,255,0.05)'
  }

  if (!live) {
    return (
      <div className="glass border border-white/5 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4">MITRE Tactic Heatmap (7d)</h3>
        <p className="text-[11px] text-ink-500 text-center py-8 leading-relaxed">
          No detections in the last 7 days — the heatmap builds as alerts arrive.
        </p>
      </div>
    )
  }
  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">MITRE Tactic Heatmap (7d)</h3>
        <div className="flex items-center gap-1.5 text-[9px] text-ink-600">
          {[['Low',tk('violet')],['Med',tk('amber')],['High',tk('threat')],['Crit',tk('magenta')]].map(([l,c]) => (
            <span key={l} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm" style={{ background: c }} />{l}
            </span>
          ))}
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: `110px repeat(${cols.length}, 1fr)`, gap: '2px' }}>
        <div />
        {cols.map((c) => (
          <div key={c} className="text-center text-[8px] text-ink-600 truncate pb-0.5">{c}</div>
        ))}
        {data.flatMap((row, ri) => [
          <div key={`lbl-${row.label}`} className="text-[9px] text-ink-600 flex items-center truncate pr-1">{row.label}</div>,
          ...row.vals.map((v, ci) => (
            <motion.div
              key={`${row.label}-${ci}`}
              initial={{ opacity: 0, scale: 0.6 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: (ri * cols.length + ci) * 0.008 }}
              className="h-6 rounded-sm cursor-pointer hover:opacity-80 transition-opacity"
              style={{ background: heatColor(v) }}
              title={`${row.label}: ${v}`}
            />
          )),
        ])}
      </div>
    </div>
  )
}

/* ── Live Threat Feed (with filters) ─────────────────────────────── */
const REGIONS = ['All', 'N. America', 'S. America', 'Europe', 'Africa', 'Asia', 'Oceania']
const SEVS = ['All', 'critical', 'high', 'medium', 'low'] as const

function LiveThreatFeed({ seed }: { seed: LiveFeedItem[] }) {
  const [feeds, setFeeds] = useState<LiveFeedItem[]>(seed)
  const [paused, setPaused] = useState(false)
  const [region, setRegion] = useState('All')
  const [sev, setSev] = useState<string>('All')

  useEffect(() => { if (seed.length > 0) setFeeds(seed) }, [seed])

  useEffect(() => {
    if (paused || seed.length === 0) return
    let counter = 1000
    const id = setInterval(() => {
      const base = seed[counter % seed.length]
      setFeeds((prev) => [{ ...base, id: String(counter++) }, ...prev].slice(0, 40))
    }, 3500)
    return () => clearInterval(id)
  }, [paused, seed])

  const filtered = useMemo(
    () =>
      feeds.filter(
        (f) =>
          (region === 'All' || f.region === region) &&
          (sev === 'All' || f.severity === sev),
      ),
    [feeds, region, sev],
  )

  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden flex flex-col">
      {/* header + filters */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 flex-wrap">
        <Radio className="w-4 h-4 text-magenta" />
        <h3 className="text-sm font-semibold text-white">Live Threat Feed</h3>
        <button
          onClick={() => setPaused((p) => !p)}
          aria-label={paused ? 'Resume feed' : 'Pause feed'}
          className={cn(
            'ml-1 flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full border',
            paused ? 'text-ink-500 border-white/10' : 'text-safe border-safe/25 bg-safe/8',
          )}
        >
          <span className={cn('w-1.5 h-1.5 rounded-full', !paused && 'bg-safe animate-pulse')} style={paused ? { background: '#665B7D' } : {}} />
          {paused ? 'Paused' : 'Live'}
        </button>

        <div className="ml-auto flex items-center gap-2">
          <Filter className="w-3 h-3 text-ink-600" />
          <select
            value={region}
            onChange={(e) => setRegion(e.target.value)}
            aria-label="Filter by region"
            className="bg-surface-2 border border-white/8 rounded-md text-[10px] text-ink-300 px-1.5 py-1 focus:outline-none focus:border-magenta/40"
          >
            {REGIONS.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <select
            value={sev}
            onChange={(e) => setSev(e.target.value)}
            aria-label="Filter by severity"
            className="bg-surface-2 border border-white/8 rounded-md text-[10px] text-ink-300 px-1.5 py-1 capitalize focus:outline-none focus:border-magenta/40"
          >
            {SEVS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* rows */}
      <div className="overflow-y-auto max-h-[300px]">
        <AnimatePresence initial={false}>
          {filtered.map((f) => (
            <motion.div
              key={f.id}
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              onClick={() => openDetail({
                title: `${f.type} · ${f.ip}`, subtitle: f.detail, severity: f.severity,
                rows: [
                  { label: 'Type', value: f.type }, { label: 'Indicator', value: f.ip, mono: true },
                  { label: 'Region', value: f.region }, { label: 'Detail', value: f.detail },
                ],
                actions: [
                  { label: 'Look up in CTI scanner', href: '/dashboard/scanner' },
                  { label: 'Open threat feeds', href: '/dashboard/feeds' },
                ],
              })}
              className="flex items-center gap-3 px-4 py-2.5 border-b border-white/4 hover:bg-white/2 cursor-pointer"
            >
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEVERITY_COLOR[f.severity] }} />
              <span className="text-[11px] font-medium text-ink-200 w-24 shrink-0 truncate">{f.type}</span>
              <span className="text-[11px] text-ink-400 flex-1 min-w-0 truncate">{f.detail}</span>
              <span className="text-[10px] font-mono text-ink-600 hidden md:block w-28 truncate">{f.ip}</span>
              <span className="text-[10px] text-ink-500 hidden sm:block w-20 text-right shrink-0">{f.region}</span>
              <span
                className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase shrink-0"
                style={{ background: `${SEVERITY_COLOR[f.severity]}1a`, color: SEVERITY_COLOR[f.severity] }}
              >
                {f.severity}
              </span>
            </motion.div>
          ))}
        </AnimatePresence>
        {filtered.length === 0 && (
          <div className="py-10 text-center text-xs text-ink-600">No threats match the current filters</div>
        )}
      </div>
    </div>
  )
}

/* ── Normal Mode Dashboard ───────────────────────────────────────── */
function NormalDashboard({ count, alerts, incidents, siem, soar }: {
  count: { threats: number; iocs: number; sources: number; score: number }
  alerts: OverviewAlert[]; incidents: Incident[]
  siem: SiemKpis | null; soar: SoarMetrics | null
}) {
  // Real, actionable alerts (highest severity first) - no hardcoded data.
  const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  const topAlerts = [...alerts]
    .sort((a, b) => (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0))
    .slice(0, 5)
  const openIncidents = incidents.filter((i) => !['resolved', 'closed'].includes(i.status))
  // `count.score` is the org RISK (higher = worse); this gauge shows security
  // HEALTH (higher = better), so invert it. A healthy/empty org now reads as
  // high health instead of the bogus 0 it showed before.
  const score = Math.max(0, Math.min(100, 100 - Math.round(Number(count.score ?? 0))))
  const band = score >= 80 ? 'Strong' : score >= 60 ? 'Good' : score >= 40 ? 'At risk' : 'Critical'
  const bandColor = score >= 60 ? 'text-safe' : score >= 40 ? 'text-amber' : 'text-threat'
  const clampPct = (n: number) => Math.max(0, Math.min(100, Math.round(n)))
  // Posture pillars from REAL telemetry (not fixed demo numbers): Detection =
  // inverse of the live false-positive rate; Response = live SLA compliance;
  // Prevention = the overall health score. Each falls back to the health score.
  const pillars = [
    { label: 'Detection',  score: siem ? clampPct(100 - siem.fpRate) : score },
    { label: 'Response',   score: soar && soar.openCases > 0 ? clampPct((1 - (soar.slaBreached ?? 0) / soar.openCases) * 100) : (soar ? 100 : score) },
    { label: 'Prevention', score },
  ].map((p) => ({ ...p, color: p.score >= 60 ? 'text-safe' : p.score >= 40 ? 'text-amber' : 'text-threat' }))
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-display text-2xl font-bold text-white">Security Status</h1>
          <p className="text-sm text-ink-400 mt-1">Your organization's security at a glance</p>
        </div>
        <div className="flex items-center gap-2">
          <ReportButton kind="executive" label="Overall Report" />
          <span className="flex items-center gap-1.5 text-[10px] px-2.5 py-1.5 rounded-full border border-safe/25 bg-safe/10 text-safe font-medium">
            <Eye className="w-3 h-3" /> Normal mode
          </span>
        </div>
      </div>

      {/* Top row: health gauge + key status cards — fills wide screens */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Health Score */}
      <div className="lg:col-span-5 xl:col-span-4 glass border border-white/5 rounded-2xl p-8 text-center relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(ellipse 70% 60% at 50% 100%, rgb(var(--violet) / 0.08), transparent)' }} />
        <p className="text-sm text-ink-400 mb-6 relative">Overall Security Health</p>
        <div className="relative inline-flex">
          <svg viewBox="0 0 160 160" className="w-44 h-44">
            <circle cx="80" cy="80" r="68" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
            <motion.circle
              cx="80" cy="80" r="68" fill="none"
              stroke="url(#normalHealthGrad)"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={427}
              initial={{ strokeDashoffset: 427 }}
              animate={{ strokeDashoffset: 427 * (1 - score / 100) }}
              transition={{ duration: 1.6, ease: 'easeOut', delay: 0.2 }}
              transform="rotate(-90 80 80)"
            />
            <defs>
              <linearGradient id="normalHealthGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="rgb(var(--violet))" />
                <stop offset="100%" stopColor="rgb(var(--safe))" />
              </linearGradient>
            </defs>
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-display text-5xl font-bold text-white">{score}</span>
            <span className="text-sm text-ink-500 mt-0.5">/ 100</span>
          </div>
        </div>
        <div className="mt-5 relative">
          <p className={cn('font-semibold text-xl', bandColor)}>{band}</p>
          <p className="text-sm text-ink-400 mt-1">
            {openIncidents.length} open incident{openIncidents.length !== 1 ? 's' : ''} · {topAlerts.filter(a => a.severity === 'critical').length} critical alert{topAlerts.filter(a => a.severity === 'critical').length !== 1 ? 's' : ''} need review
          </p>
        </div>
        <div className="flex justify-center gap-3 mt-6 relative">
          {pillars.map((m) => (
            <div key={m.label} className="px-4 py-2.5 rounded-xl bg-white/4 border border-white/6 text-center min-w-[72px]">
              <p className={cn('text-base font-bold', m.color)}>{m.score}</p>
              <p className="text-[10px] text-ink-500 mt-0.5">{m.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Key status cards (right column of the top row) */}
      <div className="lg:col-span-7 xl:col-span-8 grid grid-cols-1 sm:grid-cols-3 gap-4 content-start">
        {[
          { icon: AlertTriangle, label: 'Active Threats',       value: count.threats.toLocaleString(), sub: `${count.iocs.toLocaleString()} indicators tracked`, iconCls: 'text-threat', bgCls: 'bg-threat/10', borderCls: 'border-threat/20', subCls: 'text-ink-500' },
          { icon: CheckCircle2,  label: 'Sources Online',       value: count.sources.toLocaleString(), sub: 'feeds & connectors active',   iconCls: 'text-safe',   bgCls: 'bg-safe/10',   borderCls: 'border-safe/20',   subCls: 'text-ink-500'  },
          { icon: Clock,         label: 'Alerts Pending Review', value: String(topAlerts.length || alerts.length), sub: `${topAlerts.filter(a => ['critical','high'].includes(a.severity)).length} high priority`, iconCls: 'text-amber',  bgCls: 'bg-amber/10',  borderCls: 'border-amber/20',  subCls: 'text-threat' },
        ].map((c, i) => (
          <motion.div key={c.label}
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 + i * 0.08 }}
            className={cn('glass border rounded-xl p-6 text-center', c.borderCls)}>
            <div className={cn('w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4', c.bgCls)}>
              <c.icon className={cn('w-7 h-7', c.iconCls)} />
            </div>
            <p className="font-display text-4xl font-bold text-white mb-1.5">{c.value}</p>
            <p className="text-sm text-ink-400">{c.label}</p>
            <p className={cn('text-xs font-medium mt-2', c.subCls)}>{c.sub}</p>
          </motion.div>
        ))}
      </div>
      </div>

      {/* Priority actions (primary) + Quick access — two columns on wide screens */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Priority actions */}
      <div className="lg:col-span-7 xl:col-span-8 glass border border-white/5 rounded-xl overflow-hidden self-start">
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/5">
          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-threat animate-pulse" />
            <h2 className="text-base font-semibold text-white">Requires Your Attention</h2>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-threat/10 text-threat font-semibold border border-threat/20">{topAlerts.length}</span>
          </div>
          <Link href="/dashboard/siem" className="text-xs text-magenta hover:underline transition-colors">View All Alerts →</Link>
        </div>
        <div className="divide-y divide-white/4">
          {topAlerts.length === 0 && (
            <div className="px-6 py-8 text-center text-sm text-ink-500">No open alerts need attention right now.</div>
          )}
          {topAlerts.map((a, i) => (
            <motion.div key={a.id}
              initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 + i * 0.07 }}
              onClick={() => openDetail({
                title: a.title, subtitle: `Alert ${a.id}`, severity: a.severity,
                rows: [
                  { label: 'Source', value: a.src, mono: true }, { label: 'Severity', value: a.severity },
                  { label: 'Time', value: a.time },
                ],
                actions: [{ label: 'Investigate in SIEM', href: `/dashboard/siem?q=${encodeURIComponent(a.src || a.title)}` }],
              })}
              className="flex items-center gap-4 px-6 py-4 hover:bg-white/2 transition-colors group cursor-pointer">
              <div className={cn('w-11 h-11 rounded-xl flex items-center justify-center shrink-0',
                a.severity === 'critical' ? 'bg-magenta/10' : 'bg-threat/10')}>
                <AlertTriangle className={cn('w-5 h-5', a.severity === 'critical' ? 'text-magenta' : 'text-threat')} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-ink-100 group-hover:text-white transition-colors truncate">{a.title}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={cn('text-[10px] px-1.5 py-0.5 rounded-full font-semibold uppercase tracking-wide',
                    a.severity === 'critical' ? 'bg-magenta/10 text-magenta' : 'bg-threat/10 text-threat'
                  )}>{a.severity}</span>
                  <span className="text-[11px] text-ink-600 font-mono">{a.src} · {timeAgo(a.time)}</span>
                </div>
              </div>
              <Link href={`/dashboard/siem?q=${encodeURIComponent(a.src || a.title)}`} onClick={(e) => e.stopPropagation()}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-magenta/10 text-magenta hover:bg-magenta/20 transition-colors border border-magenta/20 shrink-0">
                Investigate →
              </Link>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Quick Access */}
      <div className="lg:col-span-5 xl:col-span-4 glass border border-white/5 rounded-xl p-6 self-start">
        <h2 className="text-base font-semibold text-white mb-5">Quick Access</h2>
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: 'Run Security Scan', icon: Shield,        href: '/dashboard/scanner', color: 'text-violet', bg: 'bg-violet/10', border: 'border-violet/15' },
            { label: 'Review Alerts',     icon: AlertTriangle, href: '/dashboard/siem',    color: 'text-threat', bg: 'bg-threat/10', border: 'border-threat/15' },
            { label: 'View Assets',       icon: Globe,         href: '/dashboard/assets',  color: 'text-teal',   bg: 'bg-teal/10',   border: 'border-teal/15'   },
            { label: 'Threat Feeds',      icon: Radio,         href: '/dashboard/feeds',   color: 'text-amber',  bg: 'bg-amber/10',  border: 'border-amber/15'  },
          ].map((q) => (
            <Link key={q.label} href={q.href}
              className={cn('flex flex-col items-center gap-3 p-5 rounded-xl border hover:bg-white/3 transition-all group text-center', q.border)}>
              <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center', q.bg)}>
                <q.icon className={cn('w-6 h-6', q.color)} />
              </div>
              <span className="text-sm text-ink-300 group-hover:text-white transition-colors">{q.label}</span>
            </Link>
          ))}
        </div>
      </div>

      </div>

      {/* Switch to Power Mode CTA */}
      <div className="glass border border-white/5 rounded-xl p-5 flex items-center gap-4">
        <div className="p-2.5 rounded-xl bg-magenta/10 shrink-0">
          <Zap className="w-5 h-5 text-magenta" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-white">Switch to Power User mode for full analyst access</p>
          <p className="text-xs text-ink-400 mt-0.5">Unlocks SIEM console, SOAR playbooks, CTI investigation graph, MITRE ATT&CK, threat hunting, and raw log access</p>
        </div>
        <span className="text-xs text-ink-500 shrink-0 hidden sm:block">Toggle in top bar →</span>
      </div>
    </div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function DashboardOverview() {
  const [kpis, setKpis]           = useState<OverviewKpis>({ threats: 0, iocs: 0, sources: 0, score: 0 })
  const [recentAlerts, setRecentAlerts]     = useState<OverviewAlert[]>([])
  const [incidents, setIncidents]           = useState<Incident[]>([])
  const [topActors, setTopActors]           = useState<TopActor[]>([])
  const [hourly, setHourly]                 = useState<number[]>([])
  const [vectors, setVectors]               = useState<ThreatVector[]>([])
  const [liveFeed, setLiveFeed]             = useState<LiveFeedItem[]>([])
  const [riskDist, setRiskDist]             = useState<RiskDistribution | null>(null)
  const [heatmap, setHeatmap]               = useState<Array<{ label: string; vals: number[] }>>([])
  const [siemKpis, setSiemKpis]             = useState<SiemKpis | null>(null)
  const [soarMetrics, setSoarMetrics]       = useState<SoarMetrics | null>(null)
  const [services, setServices]             = useState<ServicesStatus | null>(null)
  const [mode] = useExperienceMode()
  const isPower = mode === 'power'

  useEffect(() => {
    fetchKpis().then(setKpis).catch(() => {})
    fetchSiemKpis().then(setSiemKpis).catch(() => {})
    fetchSoarMetrics().then(setSoarMetrics).catch(() => {})
    fetchRecentAlerts(8).then(setRecentAlerts).catch(() => {})
    fetchRecentIncidents(6).then(setIncidents).catch(() => {})
    fetchTopActors(5).then(setTopActors).catch(() => {})
    fetchHourly().then(setHourly).catch(() => {})
    fetchVectors().then(setVectors).catch(() => {})
    fetchLiveFeed(20).then(setLiveFeed).catch(() => {})
    fetchRiskDistribution().then(setRiskDist).catch(() => {})
    fetchHeatmap().then(setHeatmap).catch(() => {})
    fetchServicesStatus().then(setServices).catch(() => {})
  }, [])

  if (!isPower) return <NormalDashboard count={kpis} alerts={recentAlerts} incidents={incidents} siem={siemKpis} soar={soarMetrics} />

  const fmtScore = Number(kpis.score ?? 0).toFixed(1)
  // Real security-posture HEALTH (higher = better) = inverse of the org RISK
  // score the API returns — same derivation the Normal dashboard uses, so the
  // gauge is never a hardcoded number.
  const health = Math.max(0, Math.min(100, 100 - Math.round(Number(kpis.score ?? 0))))
  const healthBand = health >= 80 ? 'Strong' : health >= 60 ? 'Good' : health >= 40 ? 'At risk' : 'Critical'
  const healthColor = health >= 60 ? 'text-safe' : health >= 40 ? 'text-amber' : 'text-threat'

  return (
    <div className="p-6 space-y-6">
      {/* First-run onboarding (real-state checklist; hides when done/dismissed) */}
      <OnboardingCard />

      {/* Header / mode pill */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Security Overview</h1>
          <p className="text-xs text-ink-500 mt-0.5">Real-time threat posture across all monitored assets and feeds</p>
        </div>
        <div className="flex items-center gap-2">
          <ReportButton kind="executive" label="Overall Report" />
          <span className={cn('flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-full border shrink-0',
            isPower ? 'border-magenta/25 bg-magenta/10 text-magenta' : 'border-safe/25 bg-safe/10 text-safe')}>
            {isPower ? <Zap className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
            {isPower ? 'Power User' : 'Normal mode'}
          </span>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard label="Active Threats" value={kpis.threats.toLocaleString()} sub="across all sources" icon={AlertTriangle} color={tk('magenta')} />
        <KPICard label="IOCs Tracked"   value={kpis.iocs.toLocaleString()}    sub="in threat database" icon={Eye}           color={tk('violet')} />
        <KPICard label="Sources Online" value={`${kpis.sources}`}             sub="active feeds"       icon={Globe}         color={tk('teal')} />
        <KPICard label="Avg Risk Score" value={fmtScore}                      sub="weighted mean"      icon={Shield}        color={tk('amber')} />
      </div>

      {/* SOC operations metrics (Power User only) */}
      {isPower && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-0 glass border border-white/5 rounded-xl overflow-hidden">
          {(() => {
            const fmtMin = (m?: number) => m == null ? '-'
              : m < 1 ? `${Math.round(m * 60)}s` : `${Math.floor(m)}m ${String(Math.round((m % 1) * 60)).padStart(2, '0')}s`
            const slaComp = soarMetrics && soarMetrics.openCases > 0
              ? `${Math.round((1 - (soarMetrics.slaBreached ?? 0) / soarMetrics.openCases) * 100)}%`
              : soarMetrics ? '100%' : '-'
            return [
            { label: 'MTTD',            value: fmtMin(siemKpis?.mttd), sub: '< 10m target', color: 'text-safe' },
            { label: 'MTTA',            value: fmtMin(siemKpis?.mtta), sub: '< 15m target', color: 'text-safe' },
            { label: 'MTTR',            value: fmtMin(siemKpis?.mttr), sub: '< 30m target', color: 'text-amber' },
            { label: 'Open Incidents',  value: String(incidents.filter(i => !['resolved','closed'].includes(i.status)).length), sub: `${incidents.filter(i => i.severity === 'critical' && !['resolved','closed'].includes(i.status)).length} critical`, color: 'text-magenta' },
            { label: 'Automation Rate', value: soarMetrics ? `${Math.round(soarMetrics.automationRate)}%` : '-', sub: 'SOAR-handled', color: 'text-violet' },
            { label: 'SLA Compliance',  value: slaComp, sub: `${soarMetrics?.slaBreached ?? 0} breached`, color: 'text-amber' },
          ]})().map((m) => (
            <div key={m.label} className="px-4 py-3 border-r border-white/5 last:border-r-0">
              <p className="text-[10px] text-ink-600 uppercase tracking-wide">{m.label}</p>
              <p className={cn('text-lg font-bold mt-0.5', m.color)}>{m.value}</p>
              <p className="text-[10px] text-ink-500 mt-0.5">{m.sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* Intel Brief Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TrendingCVEs />
        <IntelBrief alerts={recentAlerts} />
        <ActiveIncidents incidents={incidents} />
      </div>

      {/* World Map + Live Feed */}
      <div className="grid grid-cols-1 xl:grid-cols-[2.2fr_1fr] gap-4">
        <div className="h-[480px] w-full">
          <WorldMap />
        </div>
        <LiveThreatFeed seed={liveFeed} />
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <RecentAlerts alerts={recentAlerts} />
        <div className="space-y-4">
          <EventTimeline hourly={hourly} />
          <AttackVectors vectors={vectors} />
          <AssetRiskDrivers dist={riskDist} />
        </div>
      </div>

      {/* Threat Heatmap */}
      <ThreatHeatmap rows={heatmap} />

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TopActors actors={topActors} />

        {/* Security Posture + System Status */}
        <div className="glass border border-white/5 rounded-xl p-5 flex flex-col gap-5">
          {/* Posture gauge */}
          <div className="flex items-center gap-4">
            <div className="relative w-20 h-20 shrink-0">
              <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                <circle cx="40" cy="40" r="33" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="7" />
                <motion.circle
                  cx="40" cy="40" r="33" fill="none"
                  stroke="url(#postureGrad)"
                  strokeWidth="7"
                  strokeLinecap="round"
                  strokeDasharray={207.3}
                  initial={{ strokeDashoffset: 207.3 }}
                  animate={{ strokeDashoffset: 207.3 * (1 - health / 100) }}
                  transition={{ duration: 1.4, ease: 'easeOut', delay: 0.3 }}
                />
                <defs>
                  <linearGradient id="postureGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor={tk('violet')} />
                    <stop offset="100%" stopColor={tk('safe')} />
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-display text-xl font-bold text-white">{health}</span>
                <span className="text-[9px] text-ink-600">/100</span>
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold text-white mb-0.5">Security Posture</p>
              <p className={cn('text-[10px] font-medium', healthColor)}>{healthBand}</p>
              <p className="text-[10px] text-ink-500 mt-1">Derived from live org risk</p>
            </div>
          </div>

          <div className="border-t border-white/5 pt-4 space-y-2.5">
            <h3 className="text-[10px] uppercase tracking-widest text-ink-600 font-semibold">System Status</h3>
            {/* Real service reachability from /services/status — the Dashboard API
                is up by definition (this page loaded from it). No fabricated rows. */}
            {[
              { label: 'Dashboard API', up: true },
              { label: 'Threat API',    up: services?.threatApi.available ?? null },
              { label: 'Log Ingestion', up: services?.logApi.available ?? null },
            ].map(({ label, up }) => {
              const state = up === null ? 'Checking…' : up ? 'Healthy' : 'Unreachable'
              const color = up === null ? 'ink' : up ? 'safe' : 'threat'
              return (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs text-ink-400">{label}</span>
                  <div className="flex items-center gap-1.5">
                    <span className={cn('w-1.5 h-1.5 rounded-full', color === 'safe' ? 'bg-safe' : color === 'threat' ? 'bg-threat animate-pulse' : 'bg-ink-600')} />
                    <span className={cn('text-xs font-medium', color === 'safe' ? 'text-safe' : color === 'threat' ? 'text-threat' : 'text-ink-500')}>
                      {state}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="glass border border-white/5 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Quick Actions</h3>
          <div className="space-y-2">
            {[
              { label: 'Run Threat Scan',     href: '/dashboard/scanner', icon: Activity,  color: tk('magenta') },
              { label: 'View Live Feeds',     href: '/dashboard/feeds',   icon: Zap,        color: tk('violet') },
              { label: 'Open SIEM',           href: '/dashboard/siem',    icon: Eye,        color: tk('amber') },
              { label: 'CTI Intelligence',    href: '/dashboard/cti',     icon: Shield,     color: tk('teal') },
              { label: 'SOAR Playbooks',      href: '/dashboard/soar',    icon: ArrowUpRight,color: tk('threat') },
            ].map(({ label, href, icon: Icon, color }) => (
              <Link
                key={href}
                href={href}
                className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-white/5 transition-colors group"
              >
                <div className="p-1.5 rounded-md" style={{ background: `${color}18` }}>
                  <Icon className="w-3.5 h-3.5" style={{ color }} />
                </div>
                <span className="text-xs text-ink-300 group-hover:text-white transition-colors">{label}</span>
                <ArrowUpRight className="w-3 h-3 text-ink-600 ml-auto group-hover:text-magenta transition-colors" />
              </Link>
            ))}
          </div>

          {/* Geopolitical risk summary */}
          <div className="mt-4 pt-4 border-t border-white/5">
            <h4 className="text-[10px] uppercase tracking-widest text-ink-600 font-semibold mb-3">Geopolitical Risk</h4>
            <div className="space-y-2">
              {[
                { region: 'Russia / Ukraine', level: 'Critical', color: tk('magenta'), pct: 95 },
                { region: 'China / Taiwan', level: 'High', color: tk('threat'), pct: 78 },
                { region: 'Iran / Israel', level: 'High', color: tk('threat'), pct: 72 },
                { region: 'DPRK / Global', level: 'Elevated', color: tk('amber'), pct: 65 },
              ].map(({ region, level, color, pct }) => (
                <div key={region} className="flex items-center gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between text-[10px] mb-0.5">
                      <span className="text-ink-400 truncate">{region}</span>
                      <span style={{ color }} className="font-medium shrink-0 ml-2">{level}</span>
                    </div>
                    <div className="h-0.5 bg-surface-3 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.8, ease: 'easeOut' }}
                        className="h-full rounded-full"
                        style={{ background: color }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
