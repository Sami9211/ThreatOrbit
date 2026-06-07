'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  TrendingDown, TrendingUp, Clock, Zap, AlertTriangle,
  CheckCircle, User, Award, Flame, BarChart2, Target,
  Shield, Activity, ChevronUp, ChevronDown, Minus,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'

/* ── Types ────────────────────────────────────────────────────────── */
type TimeRange = '7d' | '30d' | '90d'

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

// 7-day alert volume stacked bar data
const ALERT_VOLUME_7D = [
  { day: 'Mon', critical: 38, high: 142, medium: 387, low: 651 },
  { day: 'Tue', critical: 27, high: 118, medium: 412, low: 594 },
  { day: 'Wed', critical: 54, high: 201, medium: 438, low: 723 },
  { day: 'Thu', critical: 19, high: 88,  medium: 299, low: 510 },
  { day: 'Fri', critical: 41, high: 154, medium: 441, low: 648 },
  { day: 'Sat', critical: 12, high: 44,  medium: 187, low: 391 },
  { day: 'Sun', critical: 8,  high: 31,  medium: 143, low: 308 },
]

// Analyst throughput
const ANALYST_THROUGHPUT = [
  { name: 'j.chen',      closed: 247, color: '#FF2E97' },
  { name: 'a.patel',     closed: 198, color: '#7A3CFF' },
  { name: 'm.rodriguez', closed: 156, color: '#34F5C5' },
  { name: 's.kim',       closed: 89,  color: '#FFB23E' },
  { name: 'r.osei',      closed: 74,  color: '#FF4D6D' },
]

// MITRE ATT&CK coverage
const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access',        coverage: 82 },
  { id: 'TA0002', name: 'Execution',             coverage: 74 },
  { id: 'TA0003', name: 'Persistence',           coverage: 61 },
  { id: 'TA0004', name: 'Privilege Escalation',  coverage: 88 },
  { id: 'TA0005', name: 'Defense Evasion',       coverage: 45 },
  { id: 'TA0006', name: 'Credential Access',     coverage: 79 },
  { id: 'TA0007', name: 'Discovery',             coverage: 38 },
  { id: 'TA0008', name: 'Lateral Movement',      coverage: 67 },
  { id: 'TA0009', name: 'Collection',            coverage: 52 },
  { id: 'TA0010', name: 'Exfiltration',          coverage: 71 },
  { id: 'TA0011', name: 'C2',                    coverage: 93 },
  { id: 'TA0040', name: 'Impact',                coverage: 86 },
  { id: 'TA0042', name: 'Resource Development',  coverage: 29 },
  { id: 'TA0043', name: 'Reconnaissance',        coverage: 41 },
]

// Analyst leaderboard
const ANALYSTS = [
  { name: 'j.chen',      full: 'Jenny Chen',       alerts: 247, mttr: '14.2m', fp: '6.1%',  sla: '98.4%', streak: 12, rank: 1 },
  { name: 'a.patel',     full: 'Aryan Patel',      alerts: 198, mttr: '18.9m', fp: '7.4%',  sla: '96.9%', streak: 8,  rank: 2 },
  { name: 'm.rodriguez', full: 'Maya Rodriguez',   alerts: 156, mttr: '21.4m', fp: '9.2%',  sla: '95.5%', streak: 4,  rank: 3 },
  { name: 's.kim',       full: 'Sam Kim',          alerts: 89,  mttr: '28.1m', fp: '11.8%', sla: '91.0%', streak: 1,  rank: 4 },
  { name: '—',           full: 'Unassigned Queue', alerts: 594, mttr: '—',     fp: '—',     sla: '—',     streak: 0,  rank: 0 },
]

// Playbook effectiveness
const PLAYBOOK_EFFECTIVENESS = [
  { name: 'Threat Intel Enrichment',           runs: 38291, timeSaved: 1274, successRate: 99 },
  { name: 'Brute Force Block',                 runs: 14203, timeSaved: 710,  successRate: 99 },
  { name: 'Phishing Email Response',           runs: 2847,  timeSaved: 341,  successRate: 96 },
  { name: 'Endpoint Ransomware Containment',   runs: 847,   timeSaved: 127,  successRate: 98 },
  { name: 'C2 Beacon Isolation',               runs: 412,   timeSaved: 98,   successRate: 97 },
]

/* ── Helpers ──────────────────────────────────────────────────────── */
function coverageColor(pct: number): string {
  if (pct >= 80) return '#34F5C5'
  if (pct >= 60) return '#7A3CFF'
  if (pct >= 40) return '#FFB23E'
  return '#FF4D6D'
}

function mitreHeatBg(pct: number): string {
  if (pct >= 80) return 'rgba(52,245,197,0.18)'
  if (pct >= 60) return 'rgba(122,60,255,0.18)'
  if (pct >= 40) return 'rgba(255,178,62,0.18)'
  return 'rgba(255,77,109,0.18)'
}

/* ── Sub-components ───────────────────────────────────────────────── */

// Stacked bar chart (SVG)
function AlertVolumeChart() {
  const maxTotal = Math.max(...ALERT_VOLUME_7D.map((d) => d.critical + d.high + d.medium + d.low))
  const BAR_W = 32
  const GAP = 20
  const HEIGHT = 120
  const COLORS = { critical: '#FF2E97', high: '#FF4D6D', medium: '#FFB23E', low: '#34F5C5' }

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
        viewBox={`0 0 ${ALERT_VOLUME_7D.length * (BAR_W + GAP)} ${HEIGHT + 28}`}
        className="w-full overflow-visible"
        aria-label="Alert volume stacked bar chart"
      >
        {/* Grid lines */}
        {[0.25, 0.5, 0.75, 1].map((frac) => (
          <line
            key={frac}
            x1={0} y1={HEIGHT - frac * HEIGHT}
            x2={ALERT_VOLUME_7D.length * (BAR_W + GAP) - GAP}
            y2={HEIGHT - frac * HEIGHT}
            stroke="rgba(255,255,255,0.05)"
            strokeDasharray="4 4"
          />
        ))}

        {ALERT_VOLUME_7D.map((d, i) => {
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

// Analyst throughput bar chart
function AnalystThroughputChart() {
  const max = Math.max(...ANALYST_THROUGHPUT.map((a) => a.closed))

  return (
    <div className="space-y-3">
      {ANALYST_THROUGHPUT.map((a, i) => (
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
        {/* Hole */}
        <div
          className="absolute inset-0 m-auto rounded-full bg-[#0D0920] flex flex-col items-center justify-center"
          style={{ width: size * 0.58, height: size * 0.58, top: '50%', left: '50%', transform: 'translate(-50%,-50%)' }}
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
  const [timeRange, setTimeRange] = useState<TimeRange>('7d')

  const timeRanges: TimeRange[] = ['7d', '30d', '90d']

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

          {/* Time range selector */}
          <div className="flex items-center gap-1 bg-surface-2/60 rounded-lg p-1 border border-white/6 self-start shrink-0">
            {timeRanges.map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={cn(
                  'px-3 py-1 rounded-md text-xs font-medium transition-colors',
                  timeRange === r
                    ? 'bg-magenta/15 border border-magenta/30 text-magenta'
                    : 'text-ink-500 hover:text-ink-300',
                )}
              >
                Last {r}
              </button>
            ))}
          </div>
        </div>

        {/* ── KPI strip ────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          {KPI_DATA.map((k, i) => {
            const Icon = k.icon
            const isImproving = (k.trend < 0 && k.good) || (k.trend > 0 && k.good)
            const TrendIcon = k.trend === 0 ? Minus : isImproving ? TrendingDown : TrendingUp

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
                  <div className={cn(
                    'flex items-center gap-0.5 text-[9px] font-mono px-1.5 py-0.5 rounded',
                    isImproving ? 'bg-safe/10 text-safe' : 'bg-threat/10 text-threat',
                  )}>
                    <TrendIcon className="w-2.5 h-2.5" />
                    {Math.abs(k.trend)}%
                  </div>
                </div>
                <div>
                  <p className={cn('text-xl font-bold', k.color)}>{k.value}</p>
                  <p className="text-[10px] text-ink-600 leading-snug mt-0.5">{k.sublabel}</p>
                </div>
                <p className="text-[9px] text-ink-700">{k.trendLabel}</p>
              </motion.div>
            )
          })}
        </div>

        {/* ── Charts row ───────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* 1. Alert Volume Trend */}
          <div className="lg:col-span-2 bg-surface-2/50 rounded-xl border border-white/6 p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="text-sm font-semibold text-white">Alert Volume Trend</p>
                <p className="text-[10px] text-ink-600 mt-0.5">7-day stacked by severity</p>
              </div>
              <div className="flex items-center gap-1.5 text-[10px] text-safe">
                <TrendingDown className="w-3 h-3" />
                <span>-12% this week</span>
              </div>
            </div>
            <AlertVolumeChart />
          </div>

          {/* 2. Automation vs Manual Donut */}
          <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5 flex flex-col">
            <div className="mb-4">
              <p className="text-sm font-semibold text-white">Automation vs Manual</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Response action distribution</p>
            </div>
            <div className="flex-1 flex items-center justify-center">
              <DonutChart
                segments={[
                  { label: 'Automated', value: 73, color: '#7A3CFF' },
                  { label: 'Manual',    value: 27, color: '#FFB23E' },
                ]}
                label="73%"
                sublabel="Automated"
                size={110}
              />
            </div>
            <div className="mt-4 pt-4 border-t border-white/5 grid grid-cols-2 gap-3 text-center">
              <div>
                <p className="text-sm font-bold text-violet">34,821</p>
                <p className="text-[10px] text-ink-600">Auto actions</p>
              </div>
              <div>
                <p className="text-sm font-bold text-amber">12,894</p>
                <p className="text-[10px] text-ink-600">Manual actions</p>
              </div>
            </div>
          </div>
        </div>

        {/* 3. Analyst Throughput */}
        <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-sm font-semibold text-white">Analyst Throughput</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Alerts closed per analyst (last {timeRange})</p>
            </div>
            <span className="text-[10px] text-ink-500 font-mono">
              Total: {ANALYST_THROUGHPUT.reduce((s, a) => s + a.closed, 0)} closed
            </span>
          </div>
          <AnalystThroughputChart />
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
                { label: '≥80%',  color: '#34F5C5' },
                { label: '60–80%',color: '#7A3CFF' },
                { label: '40–60%',color: '#FFB23E' },
                { label: '<40%',  color: '#FF4D6D' },
              ].map((l) => (
                <span key={l.label} className="flex items-center gap-1 text-ink-500">
                  <span className="w-2 h-2 rounded-sm" style={{ background: l.color }} />
                  {l.label}
                </span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2">
            {MITRE_TACTICS.map((t, i) => (
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
                {Math.round(MITRE_TACTICS.reduce((s, t) => s + t.coverage, 0) / MITRE_TACTICS.length)}%
              </span>
            </span>
            <span>
              Fully covered (≥80%):{' '}
              <span className="text-safe font-mono font-semibold">
                {MITRE_TACTICS.filter((t) => t.coverage >= 80).length} / {MITRE_TACTICS.length} tactics
              </span>
            </span>
            <span>
              Gaps ({'<'}40%):{' '}
              <span className="text-threat font-mono font-semibold">
                {MITRE_TACTICS.filter((t) => t.coverage < 40).length} tactics
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
                <p className="text-[10px] text-ink-600 mt-0.5">Last {timeRange} performance</p>
              </div>
              <Award className="w-4 h-4 text-amber opacity-60" />
            </div>

            {/* Table header */}
            <div className="grid grid-cols-[20px_1fr_70px_70px_60px_65px_50px] gap-2 px-5 py-2 text-[9px] text-ink-600 uppercase tracking-widest border-b border-white/4">
              <span>#</span>
              <span>Analyst</span>
              <span className="text-right">Closed</span>
              <span className="text-right">Avg MTTR</span>
              <span className="text-right">FP Rate</span>
              <span className="text-right">SLA %</span>
              <span className="text-right">Streak</span>
            </div>

            {ANALYSTS.map((a, i) => (
              <motion.div
                key={a.name}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.06, duration: 0.22 }}
                className={cn(
                  'grid grid-cols-[20px_1fr_70px_70px_60px_65px_50px] gap-2 items-center px-5 py-2.5 border-b border-white/4 last:border-0',
                  a.rank === 1 && 'bg-magenta/4',
                  a.rank === 0 && 'opacity-50',
                )}
              >
                {/* Rank */}
                <span className={cn(
                  'text-[10px] font-bold',
                  a.rank === 1 ? 'text-magenta' :
                  a.rank === 2 ? 'text-amber' :
                  a.rank === 3 ? 'text-safe' :
                  'text-ink-600',
                )}>
                  {a.rank > 0 ? a.rank : '—'}
                </span>

                {/* Name */}
                <div className="flex items-center gap-2 min-w-0">
                  <div className="w-5 h-5 rounded-full flex items-center justify-center bg-surface-2 border border-white/8 shrink-0">
                    <User className="w-2.5 h-2.5 text-ink-500" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-[11px] text-ink-200 truncate">{a.full}</p>
                    <p className="text-[9px] text-ink-600 font-mono">{a.name}</p>
                  </div>
                </div>

                {/* Alerts closed */}
                <span className="text-[11px] font-mono font-semibold text-white text-right">{a.alerts.toLocaleString()}</span>

                {/* MTTR */}
                <span className={cn(
                  'text-[11px] font-mono text-right',
                  a.mttr === '—' ? 'text-ink-700' :
                  parseFloat(a.mttr) < 18 ? 'text-safe' :
                  parseFloat(a.mttr) < 25 ? 'text-amber' : 'text-threat',
                )}>
                  {a.mttr}
                </span>

                {/* FP Rate */}
                <span className={cn(
                  'text-[11px] font-mono text-right',
                  a.fp === '—' ? 'text-ink-700' :
                  parseFloat(a.fp) < 8 ? 'text-safe' :
                  parseFloat(a.fp) < 12 ? 'text-amber' : 'text-threat',
                )}>
                  {a.fp}
                </span>

                {/* SLA */}
                <span className={cn(
                  'text-[11px] font-mono text-right',
                  a.sla === '—' ? 'text-ink-700' :
                  parseFloat(a.sla) >= 97 ? 'text-safe' :
                  parseFloat(a.sla) >= 93 ? 'text-amber' : 'text-threat',
                )}>
                  {a.sla}
                </span>

                {/* Streak */}
                <div className="flex items-center justify-end gap-1">
                  {a.streak > 0 ? (
                    <>
                      <Flame className="w-3 h-3 text-amber shrink-0" />
                      <span className="text-[10px] font-mono text-amber">{a.streak}d</span>
                    </>
                  ) : (
                    <span className="text-[10px] text-ink-700">—</span>
                  )}
                </div>
              </motion.div>
            ))}
          </div>

          {/* Right column: disposition donut + playbook table */}
          <div className="lg:col-span-2 flex flex-col gap-4">

            {/* Alert disposition donut */}
            <div className="bg-surface-2/50 rounded-xl border border-white/6 p-5 flex-1">
              <div className="mb-4">
                <p className="text-sm font-semibold text-white">Alert Disposition</p>
                <p className="text-[10px] text-ink-600 mt-0.5">Last {timeRange} breakdown</p>
              </div>
              <DonutChart
                segments={[
                  { label: 'True Positive',  value: 67,  color: '#FF2E97' },
                  { label: 'False Positive', value: 8,   color: '#FF4D6D' },
                  { label: 'Benign',         value: 19,  color: '#34F5C5' },
                  { label: 'Duplicate',      value: 6,   color: '#FFB23E' },
                ]}
                label="67%"
                sublabel="True Pos."
                size={100}
              />
              <div className="mt-4 pt-4 border-t border-white/5 grid grid-cols-2 gap-2">
                <div className="bg-white/3 rounded-lg px-3 py-2 text-center">
                  <p className="text-sm font-bold text-magenta">1,284</p>
                  <p className="text-[9px] text-ink-600">Alerts/day</p>
                </div>
                <div className="bg-white/3 rounded-lg px-3 py-2 text-center">
                  <p className="text-sm font-bold text-safe">860</p>
                  <p className="text-[9px] text-ink-600">Actioned</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── Playbook effectiveness ────────────────────────────────── */}
        <div className="bg-surface-2/50 rounded-xl border border-white/6 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-white/5 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-white">Playbook Effectiveness</p>
              <p className="text-[10px] text-ink-600 mt-0.5">Top 5 by analyst time saved (last {timeRange})</p>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] text-safe">
              <Zap className="w-3 h-3" />
              <span>847h total saved this period</span>
            </div>
          </div>

          {/* Table header */}
          <div className="grid grid-cols-[24px_1fr_80px_80px_100px_100px] gap-3 px-5 py-2 text-[9px] text-ink-600 uppercase tracking-widest border-b border-white/4">
            <span>#</span>
            <span>Playbook</span>
            <span className="text-right">Runs</span>
            <span className="text-right">Success</span>
            <span className="text-right">Time Saved</span>
            <span className="text-right">Time Saved Bar</span>
          </div>

          {PLAYBOOK_EFFECTIVENESS.map((pb, i) => {
            const maxSaved = PLAYBOOK_EFFECTIVENESS[0].timeSaved
            return (
              <motion.div
                key={pb.name}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07, duration: 0.22 }}
                className="grid grid-cols-[24px_1fr_80px_80px_100px_100px] gap-3 items-center px-5 py-3 border-b border-white/4 last:border-0 hover:bg-white/2 transition-colors"
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
                  {pb.successRate}%
                </span>

                {/* Time saved (hours) */}
                <div className="text-right">
                  <span className="text-sm font-bold text-violet">{pb.timeSaved}</span>
                  <span className="text-[9px] text-ink-600 ml-1">hrs</span>
                </div>

                {/* Bar */}
                <div className="h-2 bg-white/6 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(pb.timeSaved / maxSaved) * 100}%` }}
                    transition={{ duration: 0.6, delay: i * 0.07, ease: 'easeOut' }}
                    className="h-full rounded-full bg-gradient-to-r from-violet to-magenta"
                  />
                </div>
              </motion.div>
            )
          })}

          {/* Footer total */}
          <div className="px-5 py-3 bg-surface-2/30 flex items-center justify-between text-[10px] border-t border-white/5">
            <span className="text-ink-600">
              Total across all {18} playbooks
            </span>
            <div className="flex items-center gap-4">
              <span className="text-ink-500">
                Runs: <span className="text-white font-mono font-semibold">55,874</span>
              </span>
              <span className="text-ink-500">
                Time saved: <span className="text-violet font-mono font-semibold">847 hrs</span>
              </span>
              <span className="text-ink-500">
                ≈ <span className="text-magenta font-mono font-semibold">$127K</span> analyst value
              </span>
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
