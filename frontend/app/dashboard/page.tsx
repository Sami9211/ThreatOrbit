'use client'

import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import {
  AlertTriangle, Shield, Activity, Zap, Globe, TrendingUp,
  TrendingDown, ArrowUpRight, Clock, Eye,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Sample attack data for the world map ───────────────────────── */
const ATTACKS = [
  { id: 1, sx: 72, sy: 36, dx: 22, dy: 38, color: '#FF2E97', type: 'RCE',       severity: 'critical' },
  { id: 2, sx: 58, sy: 28, dx: 46, dy: 31, color: '#FF4D6D', type: 'DDoS',      severity: 'high'     },
  { id: 3, sx: 76, sy: 38, dx: 47, dy: 32, color: '#FFB23E', type: 'Phishing',  severity: 'medium'   },
  { id: 4, sx: 60, sy: 27, dx: 22, dy: 37, color: '#FF2E97', type: 'Ransomware',severity: 'critical' },
  { id: 5, sx: 75, sy: 52, dx: 47, dy: 33, color: '#7A3CFF', type: 'C2 Beacon', severity: 'high'     },
  { id: 6, sx: 20, sy: 38, dx: 46, dy: 31, color: '#2DD4BF', type: 'Scan',      severity: 'low'      },
  { id: 7, sx: 65, sy: 44, dx: 22, dy: 38, color: '#FFB23E', type: 'BEC',       severity: 'high'     },
  { id: 8, sx: 49, sy: 53, dx: 46, dy: 31, color: '#FF4D6D', type: 'Exploit',   severity: 'critical' },
  { id: 9, sx: 81, sy: 67, dx: 23, dy: 39, color: '#7A3CFF', type: 'APT',       severity: 'high'     },
  { id: 10, sx: 30, sy: 61, dx: 46, dy: 30, color: '#2DD4BF', type: 'Scan',     severity: 'low'      },
]

const CITY_DOTS = [
  { x: 22, y: 37, label: 'New York',   color: '#FF4D6D', intensity: 1.0 },
  { x: 46, y: 31, label: 'London',     color: '#7A3CFF', intensity: 0.9 },
  { x: 58, y: 27, label: 'Moscow',     color: '#FF2E97', intensity: 1.0 },
  { x: 75, y: 37, label: 'Beijing',    color: '#FF2E97', intensity: 0.95 },
  { x: 82, y: 36, label: 'Tokyo',      color: '#FFB23E', intensity: 0.8 },
  { x: 75, y: 52, label: 'Singapore',  color: '#7A3CFF', intensity: 0.75 },
  { x: 65, y: 44, label: 'Mumbai',     color: '#FFB23E', intensity: 0.7 },
  { x: 50, y: 31, label: 'Berlin',     color: '#2DD4BF', intensity: 0.65 },
  { x: 54, y: 43, label: 'Cairo',      color: '#FFB23E', intensity: 0.6 },
  { x: 30, y: 61, label: 'São Paulo',  color: '#2DD4BF', intensity: 0.55 },
  { x: 80, y: 64, label: 'Sydney',     color: '#7A3CFF', intensity: 0.5  },
  { x: 49, y: 53, label: 'Lagos',      color: '#FF2E97', intensity: 0.6  },
]

const SEVERITY_COLOR = {
  critical: '#FF2E97',
  high:     '#FF4D6D',
  medium:   '#FFB23E',
  low:      '#2DD4BF',
} as const

/* ── World Attack Map ────────────────────────────────────────────── */
function WorldMap() {
  const svgRef = useRef<SVGSVGElement>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 2500)
    return () => clearInterval(id)
  }, [])

  // Compute a quadratic bezier midpoint (arc above the line)
  function arc(sx: number, sy: number, dx: number, dy: number) {
    const mx = (sx + dx) / 2
    const my = Math.min(sy, dy) - Math.abs(dx - sx) * 0.25 - 8
    return `M ${sx} ${sy} Q ${mx} ${my} ${dx} ${dy}`
  }

  return (
    <div className="relative w-full h-full bg-[#080613] rounded-xl overflow-hidden border border-white/5">
      {/* Grid background */}
      <div className="absolute inset-0 opacity-20"
        style={{
          backgroundImage: 'linear-gradient(rgba(122,60,255,0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(122,60,255,0.15) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      {/* Continent silhouettes (simplified blobs) */}
      <svg
        ref={svgRef}
        viewBox="0 0 100 75"
        className="absolute inset-0 w-full h-full"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <filter id="glow-map">
            <feGaussianBlur stdDeviation="0.5" result="coloredBlur" />
            <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <radialGradient id="pulse-grad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.8" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Simplified continent fills */}
        {/* North America */}
        <path d="M 8 24 L 12 20 L 18 22 L 26 22 L 30 28 L 28 36 L 22 42 L 16 40 L 10 34 Z"
          fill="rgba(122,60,255,0.07)" stroke="rgba(122,60,255,0.18)" strokeWidth="0.3" />
        {/* South America */}
        <path d="M 24 45 L 30 44 L 35 48 L 34 62 L 28 68 L 24 65 L 22 55 Z"
          fill="rgba(122,60,255,0.07)" stroke="rgba(122,60,255,0.18)" strokeWidth="0.3" />
        {/* Europe */}
        <path d="M 42 22 L 52 20 L 56 25 L 50 32 L 44 30 Z"
          fill="rgba(122,60,255,0.07)" stroke="rgba(122,60,255,0.18)" strokeWidth="0.3" />
        {/* Africa */}
        <path d="M 44 36 L 56 35 L 60 44 L 58 58 L 50 65 L 43 58 L 42 48 Z"
          fill="rgba(122,60,255,0.07)" stroke="rgba(122,60,255,0.18)" strokeWidth="0.3" />
        {/* Asia */}
        <path d="M 56 18 L 88 20 L 90 38 L 82 45 L 68 48 L 58 40 L 54 30 Z"
          fill="rgba(122,60,255,0.07)" stroke="rgba(122,60,255,0.18)" strokeWidth="0.3" />
        {/* Australia */}
        <path d="M 74 58 L 88 58 L 90 68 L 80 70 L 73 65 Z"
          fill="rgba(122,60,255,0.07)" stroke="rgba(122,60,255,0.18)" strokeWidth="0.3" />

        {/* Attack arcs — drawn with animated dashoffset */}
        {ATTACKS.map((a) => (
          <path
            key={`arc-${a.id}-${tick}`}
            d={arc(a.sx, a.sy, a.dx, a.dy)}
            fill="none"
            stroke={a.color}
            strokeWidth="0.4"
            opacity="0.6"
            strokeDasharray="12"
            strokeDashoffset="12"
            style={{ animation: `drawArc 1.8s ease-in-out ${a.id * 0.15}s forwards` }}
          />
        ))}

        {/* Attack destination markers */}
        {ATTACKS.map((a) => (
          <circle
            key={`dst-${a.id}`}
            cx={a.dx}
            cy={a.dy}
            r="0.8"
            fill={a.color}
            opacity="0.9"
            filter="url(#glow-map)"
          />
        ))}

        {/* City dots with pulse rings */}
        {CITY_DOTS.map((c) => (
          <g key={c.label}>
            {/* outer pulse ring */}
            <circle cx={c.x} cy={c.y} r="2.5" fill="none" stroke={c.color}
              strokeWidth="0.4" opacity="0.3"
              style={{ animation: `pulseRing 2.5s ease-out infinite ${Math.random() * 2}s` }}
            />
            {/* core dot */}
            <circle cx={c.x} cy={c.y} r="0.9" fill={c.color} opacity={c.intensity}
              filter="url(#glow-map)" />
          </g>
        ))}
      </svg>

      {/* CSS keyframes via style tag */}
      <style>{`
        @keyframes drawArc {
          to { stroke-dashoffset: 0; }
        }
        @keyframes pulseRing {
          0%   { r: 1;   opacity: 0.8; }
          100% { r: 4;   opacity: 0; }
        }
      `}</style>

      {/* Legend */}
      <div className="absolute bottom-3 right-3 flex items-center gap-4 text-[10px] text-ink-500">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <div key={s} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLOR[s] }} />
            <span className="capitalize">{s}</span>
          </div>
        ))}
      </div>

      {/* Live indicator */}
      <div className="absolute top-3 left-3 flex items-center gap-1.5 text-[10px] text-safe">
        <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
        Live Attack Feed
      </div>
    </div>
  )
}

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

      {/* World Map */}
      <div className="h-[340px] w-full">
        <WorldMap />
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

        {/* Quick stats */}
        <div className="glass border border-white/5 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white">System Status</h3>
          {[
            { label: 'Threat API',       status: 'Healthy', color: 'safe'   },
            { label: 'Log Ingestion',    status: 'Healthy', color: 'safe'   },
            { label: 'OpenCTI Sync',     status: 'Healthy', color: 'safe'   },
            { label: 'MISP Feed',        status: 'Degraded',color: 'amber'  },
            { label: 'Shodan Integration',status:'Healthy',  color: 'safe'   },
            { label: 'ML Engine',        status: 'Healthy', color: 'safe'   },
          ].map(({ label, status, color }) => (
            <div key={label} className="flex items-center justify-between">
              <span className="text-xs text-ink-400">{label}</span>
              <div className="flex items-center gap-1.5">
                <span className={cn('w-1.5 h-1.5 rounded-full', color === 'safe' ? 'bg-safe' : 'bg-amber')} />
                <span className={cn('text-xs font-medium', color === 'safe' ? 'text-safe' : 'text-amber')}>
                  {status}
                </span>
              </div>
            </div>
          ))}
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
