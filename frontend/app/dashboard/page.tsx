'use client'

import { useState, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertTriangle, Shield, Activity, Zap, Globe, TrendingUp,
  TrendingDown, ArrowUpRight, Clock, Eye, Radio, Filter,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import WorldMap from '@/components/dashboard/WorldMap'

const SEVERITY_COLOR = {
  critical: '#FF2E97',
  high:     '#FF4D6D',
  medium:   '#FFB23E',
  low:      '#2DD4BF',
} as const

/* ── KPI Card ────────────────────────────────────────────────────── */
function KPICard({
  label, value, sub, icon: Icon, color, trend, trendVal,
}: {
  label: string
  value: string
  sub?: string
  icon: React.ElementType
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

/* ── Recent Alerts ───────────────────────────────────────────────── */
const ALERTS = [
  { id: 1, title: 'CVE-2024-6387 OpenSSH RCE attempt',          severity: 'critical', time: '2m ago',  src: '45.95.147.236'  },
  { id: 2, title: 'Lazarus Group C2 beacon detected',            severity: 'critical', time: '7m ago',  src: '185.220.101.42' },
  { id: 3, title: 'SQL Injection on /api/users endpoint',        severity: 'high',     time: '12m ago', src: '192.168.10.44'  },
  { id: 4, title: 'Suspicious PowerShell execution pattern',     severity: 'high',     time: '18m ago', src: '10.0.2.15'      },
  { id: 5, title: 'Large data exfiltration to external host',    severity: 'critical', time: '24m ago', src: '172.16.0.44'    },
  { id: 6, title: 'Brute-force SSH login from 14 IPs',          severity: 'medium',   time: '31m ago', src: 'Multiple'       },
  { id: 7, title: 'Malicious URL in phishing email detected',    severity: 'medium',   time: '45m ago', src: 'Email gateway'  },
]

function RecentAlerts() {
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <h3 className="text-sm font-semibold text-white">Recent Alerts</h3>
        <a href="/dashboard/siem" className="text-xs text-magenta hover:underline">View all</a>
      </div>
      <div className="divide-y divide-white/4">
        {ALERTS.map((a) => (
          <div key={a.id} className="flex items-start gap-3 px-5 py-3 hover:bg-white/2 transition-colors cursor-pointer group">
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
              <span className="text-[10px] text-ink-600">{a.time}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Top Threat Actors ───────────────────────────────────────────── */
const TOP_ACTORS = [
  { name: 'Lazarus Group',    origin: 'DPRK',  score: 9.8, attacks: 247, color: '#FF2E97' },
  { name: 'APT29 Cozy Bear', origin: 'Russia', score: 9.4, attacks: 189, color: '#7A3CFF' },
  { name: 'Volt Typhoon',    origin: 'China',  score: 9.2, attacks: 156, color: '#FFB23E' },
  { name: 'Scattered Spider',origin: 'USA/UK', score: 8.6, attacks: 98,  color: '#2DD4BF' },
  { name: 'FIN7',            origin: 'Russia', score: 8.4, attacks: 84,  color: '#FF4D6D' },
]

function TopActors() {
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <h3 className="text-sm font-semibold text-white">Top Threat Actors</h3>
        <a href="/dashboard/cti" className="text-xs text-magenta hover:underline">CTI →</a>
      </div>
      <div className="p-4 space-y-3">
        {TOP_ACTORS.map((a, i) => (
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
                  style={{ background: a.color }}
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

/* ── Attack Vector Breakdown ─────────────────────────────────────── */
const VECTORS = [
  { label: 'Phishing',      pct: 34, color: '#FF2E97' },
  { label: 'RCE Exploits',  pct: 28, color: '#7A3CFF' },
  { label: 'Credential',    pct: 18, color: '#FFB23E' },
  { label: 'Supply Chain',  pct: 12, color: '#2DD4BF' },
  { label: 'Other',         pct:  8, color: '#665B7D'  },
]

function AttackVectors() {
  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <h3 className="text-sm font-semibold text-white mb-4">Attack Vectors (24h)</h3>
      <div className="space-y-3">
        {VECTORS.map((v) => (
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

/* ── Events per hour mini-chart ──────────────────────────────────── */
const HOURLY = [12, 18, 9, 24, 31, 15, 28, 44, 38, 52, 47, 61, 58, 43, 39, 55, 67, 71, 63, 58, 49, 44, 37, 29]

function EventTimeline() {
  const max = Math.max(...HOURLY)
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
        {HOURLY.map((v, i) => (
          <motion.div
            key={i}
            initial={{ height: 0 }}
            animate={{ height: `${(v / max) * 100}%` }}
            transition={{ delay: i * 0.02, duration: 0.6, ease: 'easeOut' }}
            className="flex-1 rounded-sm min-w-0"
            style={{
              background: v > 50 ? '#FF2E97' : v > 35 ? '#FFB23E' : 'rgba(122,60,255,0.5)',
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

/* ── Live Threat Feed (with filters) ─────────────────────────────── */
type Feed = {
  id: number
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  region: string
  ip: string
  detail: string
}

const FEED_SEED: Omit<Feed, 'id'>[] = [
  { type: 'RCE Exploit',   severity: 'critical', region: 'Europe',   ip: '45.95.147.236',  detail: 'CVE-2024-6387 OpenSSH attempt' },
  { type: 'C2 Beacon',     severity: 'critical', region: 'N. America', ip: '185.220.101.42', detail: 'Lazarus Group callback' },
  { type: 'Ransomware',    severity: 'critical', region: 'Asia',     ip: '103.224.182.0',  detail: 'LockBit encryption pattern' },
  { type: 'Phishing',      severity: 'high',     region: 'N. America', ip: '192.3.45.18',   detail: 'Credential harvest page' },
  { type: 'Brute Force',   severity: 'high',     region: 'Europe',   ip: '91.92.251.103',  detail: 'SSH 4,200 attempts / min' },
  { type: 'SQL Injection', severity: 'medium',   region: 'Asia',     ip: '23.184.48.200',  detail: 'WAF blocked union-based' },
  { type: 'Port Scan',     severity: 'low',      region: 'S. America', ip: '177.54.144.9',  detail: 'Full TCP sweep' },
  { type: 'DDoS',          severity: 'high',     region: 'Africa',   ip: '105.112.20.4',   detail: 'SYN flood 48 Gbps' },
  { type: 'Supply Chain',  severity: 'critical', region: 'Europe',   ip: '195.123.246.0',  detail: 'Malicious npm package' },
  { type: 'BEC',           severity: 'medium',   region: 'Oceania',  ip: '110.232.76.5',   detail: 'CEO impersonation' },
  { type: 'Crypto Miner',  severity: 'low',      region: 'Asia',     ip: '47.241.0.88',    detail: 'XMRig on K8s pod' },
  { type: 'Data Exfil',    severity: 'critical', region: 'N. America', ip: '198.51.100.7', detail: '4.2 GB to external host' },
]

const REGIONS = ['All', 'N. America', 'S. America', 'Europe', 'Africa', 'Asia', 'Oceania']
const SEVS = ['All', 'critical', 'high', 'medium', 'low'] as const

let feedId = 100
function randFeed(): Feed {
  const base = FEED_SEED[Math.floor(Math.random() * FEED_SEED.length)]
  return { ...base, id: ++feedId }
}

function LiveThreatFeed() {
  const [feeds, setFeeds] = useState<Feed[]>(() =>
    FEED_SEED.map((f, i) => ({ ...f, id: i })),
  )
  const [paused, setPaused] = useState(false)
  const [region, setRegion] = useState('All')
  const [sev, setSev] = useState<string>('All')

  useEffect(() => {
    if (paused) return
    const id = setInterval(() => {
      setFeeds((prev) => [randFeed(), ...prev].slice(0, 40))
    }, 2200)
    return () => clearInterval(id)
  }, [paused])

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
              className="flex items-center gap-3 px-4 py-2.5 border-b border-white/4 hover:bg-white/2"
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

/* ── Page ────────────────────────────────────────────────────────── */
export default function DashboardOverview() {
  const [count, setCount] = useState({ threats: 1842, iocs: 14671, sources: 23, score: 8.4 })

  useEffect(() => {
    const id = setInterval(() => {
      setCount((c) => ({
        threats: c.threats + Math.floor(Math.random() * 3),
        iocs: c.iocs + Math.floor(Math.random() * 8),
        sources: c.sources,
        score: c.score,
      }))
    }, 3000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="p-6 space-y-6">
      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          label="Active Threats"
          value={count.threats.toLocaleString()}
          sub="across all sources"
          icon={AlertTriangle}
          color="#FF2E97"
          trend="up"
          trendVal="+12%"
        />
        <KPICard
          label="IOCs Tracked"
          value={count.iocs.toLocaleString()}
          sub="last 24 hours"
          icon={Eye}
          color="#7A3CFF"
          trend="up"
          trendVal="+8%"
        />
        <KPICard
          label="Sources Online"
          value={`${count.sources}/24`}
          sub="1 degraded"
          icon={Globe}
          color="#2DD4BF"
        />
        <KPICard
          label="Avg CVSS Score"
          value={count.score.toFixed(1)}
          sub="weighted mean"
          icon={Shield}
          color="#FFB23E"
          trend="up"
          trendVal="+0.3"
        />
      </div>

      {/* World Map + Live Feed */}
      <div className="grid grid-cols-1 xl:grid-cols-[1.5fr_1fr] gap-4">
        <div className="h-[360px] w-full">
          <WorldMap />
        </div>
        <LiveThreatFeed />
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <RecentAlerts />
        <div className="space-y-4">
          <EventTimeline />
          <AttackVectors />
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TopActors />

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
                  animate={{ strokeDashoffset: 207.3 * (1 - 0.74) }}
                  transition={{ duration: 1.4, ease: 'easeOut', delay: 0.3 }}
                />
                <defs>
                  <linearGradient id="postureGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#7A3CFF" />
                    <stop offset="100%" stopColor="#34F5C5" />
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-display text-xl font-bold text-white">74</span>
                <span className="text-[9px] text-ink-600">/100</span>
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold text-white mb-0.5">Security Posture</p>
              <p className="text-[10px] text-safe font-medium">Good</p>
              <p className="text-[10px] text-ink-500 mt-1">1 integration degraded</p>
            </div>
          </div>

          <div className="border-t border-white/5 pt-4 space-y-2.5">
            <h3 className="text-[10px] uppercase tracking-widest text-ink-600 font-semibold">System Status</h3>
            {[
              { label: 'Threat API',        status: 'Healthy',  color: 'safe'  },
              { label: 'Log Ingestion',     status: 'Healthy',  color: 'safe'  },
              { label: 'OpenCTI Sync',      status: 'Healthy',  color: 'safe'  },
              { label: 'MISP Feed',         status: 'Degraded', color: 'amber' },
              { label: 'Shodan',            status: 'Healthy',  color: 'safe'  },
              { label: 'ML Engine',         status: 'Healthy',  color: 'safe'  },
            ].map(({ label, status, color }) => (
              <div key={label} className="flex items-center justify-between">
                <span className="text-xs text-ink-400">{label}</span>
                <div className="flex items-center gap-1.5">
                  <span className={cn('w-1.5 h-1.5 rounded-full', color === 'safe' ? 'bg-safe' : color === 'amber' ? 'bg-amber animate-pulse' : 'bg-threat')} />
                  <span className={cn('text-xs font-medium', color === 'safe' ? 'text-safe' : color === 'amber' ? 'text-amber' : 'text-threat')}>
                    {status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass border border-white/5 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Quick Actions</h3>
          <div className="space-y-2">
            {[
              { label: 'Run Threat Scan',     href: '/dashboard/scanner', icon: Activity,  color: '#FF2E97' },
              { label: 'View Live Feeds',     href: '/dashboard/feeds',   icon: Zap,        color: '#7A3CFF' },
              { label: 'Open SIEM',           href: '/dashboard/siem',    icon: Eye,        color: '#FFB23E' },
              { label: 'CTI Intelligence',    href: '/dashboard/cti',     icon: Shield,     color: '#2DD4BF' },
              { label: 'SOAR Playbooks',      href: '/dashboard/soar',    icon: ArrowUpRight,color: '#FF4D6D' },
            ].map(({ label, href, icon: Icon, color }) => (
              <a
                key={href}
                href={href}
                className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-white/5 transition-colors group"
              >
                <div className="p-1.5 rounded-md" style={{ background: `${color}18` }}>
                  <Icon className="w-3.5 h-3.5" style={{ color }} />
                </div>
                <span className="text-xs text-ink-300 group-hover:text-white transition-colors">{label}</span>
                <ArrowUpRight className="w-3 h-3 text-ink-600 ml-auto group-hover:text-magenta transition-colors" />
              </a>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
