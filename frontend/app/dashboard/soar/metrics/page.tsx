'use client'

import { useState, useEffect } from 'react'
import { fetchSoarMetrics, fetchSiemKpis, fetchAttackCoverage,
         fetchSoarAnalysts, fetchPlaybooks, fetchAlertAnalytics,
         type SoarMetrics, type SiemKpis, type AttackCoverage,
         type AnalystStat, type Playbook, type AlertAnalytics, type AlertVolumeDay } from '@/lib/api'
import { motion } from 'framer-motion'
import {
  TrendingDown, TrendingUp, Clock, Zap, AlertTriangle,
  CheckCircle, User, Award, BarChart2, Target,
  Shield, Activity, ChevronUp, ChevronDown, Minus,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { tk, withAlpha } from '@/lib/colors'

/* ── Static data ─────────────────────────────────────────────────── */
const KPI_DATA = [
  {
    label: 'MTTD',
    sublabel: 'Mean Time to Detect',
    value: '4.2 min',
    trend: -18,
    trendLabel: '-18% vs prev period',
    color: 'text-safe',
    borderColor: 'border-safe/25',
    bgColor: 'bg-safe/8',
    icon: Clock,
    good: true,
  },
  {
    label: 'MTTR',
    sublabel: 'Mean Time to Respond',
    value: '18.7 min',
    trend: -34,
    trendLabel: '-34% vs prev period',
    color: 'text-violet',
    borderColor: 'border-violet/25',
    bgColor: 'bg-violet/8',
    icon: Zap,
    good: true,
  },
  {
    label: 'Alert Volume',
    sublabel: 'Per day (rolling avg)',
    value: '1,284',
    trend: 7,
    trendLabel: '+7% vs prev period',
    color: 'text-amber',
    borderColor: 'border-amber/25',
    bgColor: 'bg-amber/8',
    icon: AlertTriangle,
    good: false,
  },
  {
    label: 'Automation Rate',
    sublabel: 'Actions automated',
    value: '73%',
    trend: 5,
    trendLabel: '+5% vs prev period',
    color: 'text-magenta',
    borderColor: 'border-magenta/25',
    bgColor: 'bg-magenta/8',
    icon: Activity,
    good: true,
  },
  {
    label: 'FP Rate',
    sublabel: 'False positive alerts',
    value: '8.3%',
    trend: -2,
    trendLabel: '-2% vs prev period',
    color: 'text-threat',
    borderColor: 'border-threat/25',
    bgColor: 'bg-threat/8',
    icon: Target,
    good: true,
  },
  {
    label: 'SLA Compliance',
    sublabel: 'Alerts within SLA',
    value: '96.4%',
    trend: 1,
    trendLabel: '+1% vs prev period',
    color: 'text-safe',
    borderColor: 'border-safe/25',
    bgColor: 'bg-safe/8',
    icon: CheckCircle,
    good: true,
  },
]

// Bar palette for the (live) analyst-throughput chart.
const ANALYST_COLORS = [tk('magenta'), tk('violet'), tk('safe'), tk('amber'), tk('threat')]
type ThroughputRow = { name: string; closed: number; color: string }

// MITRE ATT&CK tactic → navigator id, for labelling the live coverage derived
// from /siem/attack-coverage (real per-tactic rule coverage, not a mock).
const TACTIC_ID: Record<string, string> = {
  'Reconnaissance': 'TA0043', 'Resource Development': 'TA0042', 'Initial Access': 'TA0001',
  'Execution': 'TA0002', 'Persistence': 'TA0003', 'Privilege Escalation': 'TA0004',
  'Defense Evasion': 'TA0005', 'Credential Access': 'TA0006', 'Discovery': 'TA0007',
  'Lateral Movement': 'TA0008', 'Collection': 'TA0009', 'Command and Control': 'TA0011',
  'Exfiltration': 'TA0010', 'Impact': 'TA0040',
}


/* ── Helpers ──────────────────────────────────────────────────────── */
function coverageColor(pct: number): string {
  if (pct >= 80) return tk('safe')
  if (pct >= 60) return tk('violet')
  if (pct >= 40) return tk('amber')
  return tk('threat')
}

function mitreHeatBg(pct: number): string {
  if (pct >= 80) return withAlpha(tk('safe'), 0.18)
  if (pct >= 60) return withAlpha(tk('violet'), 0.18)
  if (pct >= 40) return withAlpha(tk('amber'), 0.18)
  return withAlpha(tk('threat'), 0.18)
}

/* ── Sub-components ───────────────────────────────────────────────── */

// Stacked bar chart (SVG) — live 7-day alert volume by severity.
function AlertVolumeChart({ data }: { data: AlertVolumeDay[] }) {
  const hasData = data.length > 0 && data.some((d) => d.critical + d.high + d.medium + d.low > 0)
  const maxTotal = Math.max(1, ...data.map((d) => d.critical + d.high + d.medium + d.low))
  const BAR_W = 32
  const GAP = 20
  const HEIGHT = 120
  const COLORS = { critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe') }

  if (!hasData) {
    return <p className="text-xs text-ink-500 py-10 text-center">No alerts recorded in the last 7 days.</p>
  }

  return (
    <div className="w-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        {Object.entries(COLORS).map(([k, c]) => (
          <span key={k} className="flex items-center gap-1.5 text-[10px] text-ink-500">
            <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ background: c }} />
            {k.charAt(0).toUpperCase() + k.slice(1)}
          </span>
        ))}
      </div>
      <svg
        viewBox={`0 0 ${data.length * (BAR_W + GAP)} ${HEIGHT + 28}`}
        className="w-full overflow-visible"
        aria-label="Alert volume stacked bar chart"
      >
        {/* Grid lines */}
        {[0.25, 0.5, 0.75, 1].map((frac) => (
          <line
            key={frac}
            x1={0} y1={HEIGHT - frac * HEIGHT}
            x2={data.length * (BAR_W + GAP) - GAP}
            y2={HEIGHT - frac * HEIGHT}
            stroke="rgba(255,255,255,0.05)"
            strokeDasharray="4 4"
          />
        ))}

        {data.map((d, i) => {
          const total = d.critical + d.high + d.medium + d.low
          const x = i * (BAR_W + GAP)
          let yOff = HEIGHT

          const segments: { key: keyof typeof d; color: string }[] = [
            { key: 'low',      color: COLORS.low },
            { key: 'medium',   color: COLORS.medium },
            { key: 'high',     color: COLORS.high },
            { key: 'critical', color: COLORS.critical },
          ]

          return (
            <g key={d.day}>
              {segments.map(({ key, color }) => {
                if (key === 'day') return null
                const val = d[key as keyof typeof d] as number
                const h = (val / maxTotal) * HEIGHT
                yOff -= h
                return (
                  <motion.rect
                    key={key}
                    initial={{ scaleY: 0, transformOrigin: `0px ${HEIGHT}px` }}
                    animate={{ scaleY: 1 }}
                    transition={{ duration: 0.5, delay: i * 0.06, ease: 'easeOut' }}
                    x={x}
                    y={yOff}
                    width={BAR_W}
                    height={h}
                    fill={color}
                    fillOpacity={0.85}
                    rx={key === 'critical' ? 2 : 0}
                  />
                )
              })}
              <text
                x={x + BAR_W / 2}
                y={HEIGHT + 14}
                textAnchor="middle"
                fontSize={9}
                fill="rgba(255,255,255,0.35)"
              >
                {d.day}
              </text>
              <text
                x={x + BAR_W / 2}
                y={HEIGHT - (total / maxTotal) * HEIGHT - 4}
                textAnchor="middle"
                fontSize={8}
                fill="rgba(255,255,255,0.4)"
              >
                {total}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// Analyst throughput bar chart (live data)
function AnalystThroughputChart({ data }: { data: ThroughputRow[] }) {
  const max = Math.max(1, ...data.map((a) => a.closed))
  if (data.length === 0) {
    return <p className="text-xs text-ink-500">No closed cases yet — throughput appears once analysts resolve cases.</p>
  }

  return (
    <div className="space-y-3">
      {data.map((a, i) => (
        <motion.div
          key={a.name}
          initial={{ opacity: 0, x: -12 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.07, duration: 0.3 }}
          className="flex items-center gap-3"
        >
          <span className="text-[11px] text-ink-400 font-mono w-24 shrink-0">{a.name}</span>
          <div className="flex-1 h-5 bg-white/5 rounded overflow-hidden relative">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(a.closed / max) * 100}%` }}
              transition={{ duration: 0.6, delay: i * 0.07, ease: 'easeOut' }}
              className="absolute inset-y-0 left-0 rounded"
              style={{ background: `linear-gradient(90deg, ${a.color}80, ${a.color})` }}
            />
            <span className="absolute right-2 top-0 bottom-0 flex items-center text-[10px] font-mono text-ink-400">
              {a.closed}
            </span>
          </div>
        </motion.div>
      ))}
    </div>
  )
}

// Donut using CSS conic-gradient
function DonutChart({
  segments,
  label,
  sublabel,
  size = 100,
}: {
  segments: { label: string; value: number; color: string }[]
  label: string
  sublabel?: string
  size?: number
}) {
  let cumulative = 0
  const conicParts = segments.map((s) => {
    const start = cumulative
    cumulative += s.value
    return `${s.color} ${start}% ${cumulative}%`
  })
  const gradient = `conic-gradient(${conicParts.join(', ')})`

  return (
    <div className="flex items-center gap-6">
      {/* Donut */}
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <div
          className="w-full h-full rounded-full"
          style={{ background: gradient }}
        />
        {/* Hole - centred via a single translate technique (no conflicting insets).
            A larger hole keeps the ring slim and elegant rather than a thick wedge. */}
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-surface flex flex-col items-center justify-center"
          style={{ width: size * 0.74, height: size * 0.74 }}
        >
          <p className="text-[10px] font-bold text-white leading-tight text-center px-1">{label}</p>
          {sublabel && <p className="text-[8px] text-ink-600 text-center">{sublabel}</p>}
        </div>
      </div>

      {/* Legend */}
      <div className="space-y-2 flex-1">
        {segments.map((s) => (
          <div key={s.label} className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
              <span className="text-[11px] text-ink-400">{s.label}</span>
            </div>
            <span className="text-[11px] font-mono font-semibold text-ink-300">{s.value}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Main page ────────────────────────────────────────────────────── */
export default function SOCMetricsPage() {
  const [mode] = useExperienceMode()
  const [metrics, setMetrics] = useState<SoarMetrics | null>(null)
  const [siem, setSiem] = useState<SiemKpis | null>(null)
  const [coverage, setCoverage] = useState<AttackCoverage | null>(null)
  const [analysts, setAnalysts] = useState<AnalystStat[]>([])
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [analytics, setAnalytics] = useState<AlertAnalytics | null>(null)

  useEffect(() => {
    fetchSoarMetrics().then(setMetrics).catch(() => {})
    fetchSiemKpis().then(setSiem).catch(() => {})
    fetchAttackCoverage().then(setCoverage).catch(() => {})
    fetchSoarAnalysts().then(setAnalysts).catch(() => {})
    fetchPlaybooks().then(setPlaybooks).catch(() => {})
    fetchAlertAnalytics().then(setAnalytics).catch(() => {})
  }, [])

  // Live analyst throughput (cases closed per analyst, excluding the Unassigned
  // bucket) + the leaderboard rows, from /soar/analysts.
  const realAnalysts = analysts.filter((a) => a.name !== 'Unassigned')
  const throughput: ThroughputRow[] = realAnalysts
    .slice().sort((a, b) => b.closed - a.closed).slice(0, 6)
    .map((a, i) => ({ name: a.name, closed: a.closed, color: ANALYST_COLORS[i % ANALYST_COLORS.length] }))
  const leaderboard = realAnalysts
    .slice().sort((a, b) => b.closed - a.closed || b.handled - a.handled).slice(0, 6)

  // Live playbook effectiveness (top by runs), from /soar/playbooks.
  const topPlaybooks = playbooks.slice().sort((a, b) => b.runs - a.runs).slice(0, 5)
  const totalRuns = playbooks.reduce((s, p) => s + p.runs, 0)
  const avgSuccess = playbooks.length
    ? Math.round(playbooks.reduce((s, p) => s + p.successRate, 0) / playbooks.length) : 0
  // Live automation share (closed cases driven by a playbook).
  const autoPct = Math.round(metrics?.automationRate ?? 0)

  // Live alert disposition split (real `disposition` column; null = untriaged).
  const DISP_COLOR: Record<string, string> = {
    'true-positive': tk('magenta'), 'false-positive': tk('threat'), benign: tk('safe'),
    duplicate: tk('amber'), untriaged: tk('violet'),
  }
  const dispTotal = (analytics?.disposition ?? []).reduce((s, d) => s + d.count, 0)
  const dispSegments = (analytics?.disposition ?? []).map((d) => ({
    label: d.label,
    value: dispTotal ? Math.round((d.count / dispTotal) * 100) : 0,
    color: DISP_COLOR[d.key] ?? tk('violet'),
  }))
  const topDisp = dispSegments[0]

  // Live MITRE coverage: % of each tactic's techniques that have an enabled
  // detection rule (from /siem/attack-coverage), labelled with the tactic id.
  const mitreTactics = (coverage?.tactics ?? []).map((t) => {
    const total = t.techniques.length
    const covered = t.techniques.filter((x) => x.covered).length
    return {
      id: TACTIC_ID[t.tactic] ?? '—',
      name: t.tactic,
      coverage: total ? Math.round((covered / total) * 100) : 0,
    }
  }).sort((a, b) => a.id.localeCompare(b.id))

  // Real KPI values overlaid onto the card styling (by label). Unbacked values
  // fall back to the card's static placeholder.
  const fmtMin = (m?: number) => m == null ? undefined : `${m.toFixed(1)} min`
  const liveValue: Record<string, string | undefined> = {
    'MTTD': fmtMin(siem?.mttd),
    'MTTR': fmtMin(siem?.mttr ?? metrics?.mttr),
    'Alert Volume': siem ? siem.totalAlerts.toLocaleString() : undefined,
    'Automation Rate': metrics ? `${Math.round(metrics.automationRate)}%` : undefined,
    'FP Rate': siem ? `${siem.fpRate}%` : undefined,
    'SLA Compliance': metrics && metrics.openCases > 0
      ? `${Math.round((1 - (metrics.slaBreached ?? 0) / metrics.openCases) * 100)}%`
      : metrics ? '100%' : undefined,
  }

  return (
    <div className="overflow-y-auto h-full">
      <div className="px-6 py-5 space-y-6 max-w-screen-2xl mx-auto pb-12">

        {/* ── Page header ──────────────────────────────────────────── */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="font-display text-xl font-bold text-white">SOC Metrics</h1>
            <p className="text-xs text-ink-500 mt-0.5">
              Operational performance, analyst efficiency, and response trends
            </p>
          </div>
        </div>

        {/* ── KPI strip ────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          {KPI_DATA.map((k, i) => {
            const Icon = k.icon
            const value = liveValue[k.label] ?? k.value

            return (
              <motion.div
                key={k.label}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05, duration: 0.25 }}
                className={cn(
                  'bg-surface-2/50 rounded-xl p-4 border flex flex-col gap-2',
                  k.borderColor,
                )}
              >
                <div className="flex items-center justify-between">
                  <div className={cn('p-1.5 rounded-lg', k.bgColor)}>
                    <Icon className={cn('w-3.5 h-3.5', k.color)} />
                  </div>
                </div>
                <div>
                  <p className={cn('text-xl font-bold', k.color)}>{value}</p>
                  <p className="text-[10px] text-ink-600 leading-snug mt-0.5">{k.sublabel}</p>
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* ── Charts row ───────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* 1. Alert Volume Trend (live) */}
          <div className="lg:col-span-2 bg-surface-2/50 rounded-xl border border-white/6 p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="text-sm font-semibold text-white">Alert Volume Trend</p>
                <p className="text-[10px] text-ink-600 mt-0.5">Last 7 days by severity</p>
              </div>
            </div>
            <AlertVolumeChart data={analytics?.volume ?? []} />
          </div>

          {/* 2. Automation vs Manual Donut (live) */}
          <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5 flex flex-col">
            <div className="mb-4">
              <p className="text-sm font-semibold text-white">Automation vs Manual</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Closed cases driven by a playbook</p>
            </div>
            <div className="flex-1 flex items-center justify-center">
              <DonutChart
                segments={[
                  { label: 'Automated', value: autoPct, color: tk('violet') },
                  { label: 'Manual',    value: 100 - autoPct, color: tk('amber') },
                ]}
                label={`${autoPct}%`}
                sublabel="Automated"
                size={110}
              />
            </div>
            <div className="mt-4 pt-4 border-t border-white/5 grid grid-cols-2 gap-3 text-center">
              <div>
                <p className="text-sm font-bold text-violet">{(metrics?.totalRuns ?? 0).toLocaleString()}</p>
                <p className="text-[10px] text-ink-600">Playbook runs</p>
              </div>
              <div>
                <p className="text-sm font-bold text-amber">{(metrics?.casesClosedWeek ?? 0).toLocaleString()}</p>
                <p className="text-[10px] text-ink-600">Cases closed (wk)</p>
              </div>
            </div>
          </div>
        </div>

        {/* 3. Analyst Throughput (live) */}
        <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-sm font-semibold text-white">Analyst Throughput</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Cases closed per analyst</p>
            </div>
            <span className="text-[10px] text-ink-500 font-mono">
              Total: {throughput.reduce((s, a) => s + a.closed, 0)} closed
            </span>
          </div>
          <AnalystThroughputChart data={throughput} />
        </div>

        {/* ── MITRE ATT&CK Coverage ────────────────────────────────── */}
        <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-sm font-semibold text-white">MITRE ATT&CK Coverage</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Detection rule coverage by tactic</p>
            </div>
            <div className="flex items-center gap-3 text-[10px]">
              {[
                { label: '≥80%',  color: tk('safe') },
                { label: '60-80%',color: tk('violet') },
                { label: '40-60%',color: tk('amber') },
                { label: '<40%',  color: tk('threat') },
              ].map((l) => (
                <span key={l.label} className="flex items-center gap-1 text-ink-500">
                  <span className="w-2 h-2 rounded-sm" style={{ background: l.color }} />
                  {l.label}
                </span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2">
            {mitreTactics.map((t, i) => (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.03, duration: 0.22 }}
                className="rounded-lg p-3 border border-white/5 flex flex-col gap-2"
                style={{ background: mitreHeatBg(t.coverage) }}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[8px] font-mono text-ink-600">{t.id}</span>
                  <span
                    className="text-[10px] font-bold"
                    style={{ color: coverageColor(t.coverage) }}
                  >
                    {t.coverage}%
                  </span>
                </div>
                <p className="text-[9px] text-ink-400 leading-tight font-medium line-clamp-2">{t.name}</p>
                {/* Mini bar */}
                <div className="h-1 bg-white/8 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${t.coverage}%` }}
                    transition={{ duration: 0.5, delay: i * 0.03 }}
                    className="h-full rounded-full"
                    style={{ background: coverageColor(t.coverage) }}
                  />
                </div>
              </motion.div>
            ))}
          </div>

          {/* Summary bar */}
          <div className="mt-4 flex items-center gap-6 pt-4 border-t border-white/5 text-[10px] text-ink-500 flex-wrap">
            <span>
              Avg coverage:{' '}
              <span className="text-amber font-mono font-semibold">
                {mitreTactics.length
                  ? Math.round(mitreTactics.reduce((s, t) => s + t.coverage, 0) / mitreTactics.length)
                  : 0}%
              </span>
            </span>
            <span>
              Fully covered (≥80%):{' '}
              <span className="text-safe font-mono font-semibold">
                {mitreTactics.filter((t) => t.coverage >= 80).length} / {mitreTactics.length} tactics
              </span>
            </span>
            <span>
              Gaps ({'<'}40%):{' '}
              <span className="text-threat font-mono font-semibold">
                {mitreTactics.filter((t) => t.coverage < 40).length} tactics
              </span>
            </span>
          </div>
        </div>

        {/* ── Bottom row: leaderboard + donut + playbook effectiveness ── */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

          {/* Analyst leaderboard */}
          <div className="lg:col-span-3 bg-surface-2/50 rounded-xl border border-white/6 overflow-hidden">
            <div className="px-5 py-3.5 border-b border-white/5 flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-white">Analyst Leaderboard</p>
                <p className="text-[10px] text-ink-600 mt-0.5">Cases handled per analyst</p>
              </div>
              <Award className="w-4 h-4 text-amber opacity-60" />
            </div>

            {/* Table header */}
            <div className="grid grid-cols-[20px_1fr_64px_56px_88px_64px] gap-2 px-5 py-2 text-[9px] text-ink-600 uppercase tracking-widest border-b border-white/4">
              <span>#</span>
              <span>Analyst</span>
              <span className="text-right">Closed</span>
              <span className="text-right">Open</span>
              <span className="text-right">Avg resolve</span>
              <span className="text-right">Crit open</span>
            </div>

            {leaderboard.length === 0 && (
              <div className="px-5 py-8 text-center text-xs text-ink-500">
                No analyst activity yet — assign cases to build the leaderboard.
              </div>
            )}
            {leaderboard.map((a, i) => {
              const rank = i + 1
              return (
              <motion.div
                key={a.name}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.06, duration: 0.22 }}
                className={cn(
                  'grid grid-cols-[20px_1fr_64px_56px_88px_64px] gap-2 items-center px-5 py-2.5 border-b border-white/4 last:border-0',
                  rank === 1 && 'bg-magenta/4',
                )}
              >
                {/* Rank */}
                <span className={cn(
                  'text-[10px] font-bold',
                  rank === 1 ? 'text-magenta' :
                  rank === 2 ? 'text-amber' :
                  rank === 3 ? 'text-safe' : 'text-ink-600',
                )}>
                  {rank}
                </span>

                {/* Name (the case owner identity) */}
                <div className="flex items-center gap-2 min-w-0">
                  <div className="w-5 h-5 rounded-full flex items-center justify-center bg-surface-2 border border-white/8 shrink-0">
                    <User className="w-2.5 h-2.5 text-ink-500" />
                  </div>
                  <p className="text-[11px] text-ink-200 truncate font-mono">{a.name}</p>
                </div>

                {/* Closed */}
                <span className="text-[11px] font-mono font-semibold text-white text-right">{a.closed.toLocaleString()}</span>

                {/* Open */}
                <span className="text-[11px] font-mono text-ink-300 text-right">{a.open.toLocaleString()}</span>

                {/* Avg resolve time */}
                <span className="text-[11px] font-mono text-right text-ink-300">
                  {a.avgResolveMins != null ? `${a.avgResolveMins}m` : '—'}
                </span>

                {/* Critical open */}
                <span className={cn('text-[11px] font-mono text-right', a.critical > 0 ? 'text-threat' : 'text-ink-700')}>
                  {a.critical}
                </span>
              </motion.div>
              )
            })}
          </div>

          {/* Right column: disposition donut + playbook table */}
          <div className="lg:col-span-2 flex flex-col gap-4">

            {/* Alert disposition donut (live — from the alerts' disposition column). */}
            <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5 flex-1">
              <div className="mb-4">
                <p className="text-sm font-semibold text-white">Alert Disposition</p>
                <p className="text-[10px] text-ink-600 mt-0.5">Triage outcomes across all alerts</p>
              </div>
              {dispTotal === 0 ? (
                <p className="text-xs text-ink-500 py-8 text-center">No alerts to disposition yet.</p>
              ) : (
                <DonutChart
                  segments={dispSegments}
                  label={topDisp ? `${topDisp.value}%` : '—'}
                  sublabel={topDisp?.label}
                  size={100}
                />
              )}
              <div className="mt-4 pt-4 border-t border-white/5 grid grid-cols-2 gap-2">
                <div className="bg-white/3 rounded-lg px-3 py-2 text-center">
                  <p className="text-sm font-bold text-magenta">{siem ? siem.totalAlerts.toLocaleString() : '—'}</p>
                  <p className="text-[9px] text-ink-600">Total alerts</p>
                </div>
                <div className="bg-white/3 rounded-lg px-3 py-2 text-center">
                  <p className="text-sm font-bold text-safe">{siem ? `${siem.fpRate}%` : '—'}</p>
                  <p className="text-[9px] text-ink-600">FP rate</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── Playbook effectiveness (live) ─────────────────────────── */}
        <div className="bg-surface-2/50 rounded-xl border border-white/6 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-white/5 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-white">Playbook Effectiveness</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Top playbooks by run volume</p>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] text-safe">
              <Zap className="w-3 h-3" />
              <span>{totalRuns.toLocaleString()} total runs</span>
            </div>
          </div>

          {/* Table header */}
          <div className="grid grid-cols-[24px_1fr_80px_80px_90px_90px] gap-3 px-5 py-2 text-[9px] text-ink-600 uppercase tracking-widest border-b border-white/4">
            <span>#</span>
            <span>Playbook</span>
            <span className="text-right">Runs</span>
            <span className="text-right">Success</span>
            <span className="text-right">Avg time</span>
            <span className="text-right">Run share</span>
          </div>

          {topPlaybooks.length === 0 && (
            <div className="px-5 py-8 text-center text-xs text-ink-500">No playbooks configured yet.</div>
          )}
          {topPlaybooks.map((pb, i) => {
            const maxRuns = topPlaybooks[0]?.runs || 1
            const avg = pb.avgTime < 60 ? `${Math.round(pb.avgTime)}s` : `${(pb.avgTime / 60).toFixed(1)}m`
            return (
              <motion.div
                key={pb.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07, duration: 0.22 }}
                className="grid grid-cols-[24px_1fr_80px_80px_90px_90px] gap-3 items-center px-5 py-3 border-b border-white/4 last:border-0 hover:bg-white/2 transition-colors"
              >
                {/* Rank */}
                <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold bg-surface-2 border border-white/8 text-ink-400">
                  {i + 1}
                </span>

                {/* Name */}
                <div className="min-w-0">
                  <p className="text-[11px] text-ink-200 truncate font-medium">{pb.name}</p>
                </div>

                {/* Runs */}
                <span className="text-[11px] font-mono text-ink-400 text-right">
                  {pb.runs.toLocaleString()}
                </span>

                {/* Success rate */}
                <span className={cn(
                  'text-[11px] font-mono font-semibold text-right',
                  pb.successRate >= 97 ? 'text-safe' :
                  pb.successRate >= 90 ? 'text-amber' : 'text-threat',
                )}>
                  {Math.round(pb.successRate)}%
                </span>

                {/* Avg run time */}
                <span className="text-[11px] font-mono text-violet text-right">{avg}</span>

                {/* Run-share bar */}
                <div className="h-2 bg-white/6 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(pb.runs / maxRuns) * 100}%` }}
                    transition={{ duration: 0.6, delay: i * 0.07, ease: 'easeOut' }}
                    className="h-full rounded-full bg-gradient-to-r from-violet to-magenta"
                  />
                </div>
              </motion.div>
            )
          })}

          {/* Footer total (live) */}
          <div className="px-5 py-3 bg-surface-2/30 flex items-center justify-between text-[10px] border-t border-white/5">
            <span className="text-ink-600">
              Across {playbooks.length} playbook{playbooks.length === 1 ? '' : 's'}
            </span>
            <div className="flex items-center gap-4">
              <span className="text-ink-500">
                Runs: <span className="text-white font-mono font-semibold">{totalRuns.toLocaleString()}</span>
              </span>
              <span className="text-ink-500">
                Avg success: <span className="text-violet font-mono font-semibold">{avgSuccess}%</span>
              </span>
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
