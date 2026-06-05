'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Activity, Filter, Search, ChevronRight, AlertTriangle,
  Terminal, Clock, Shield, Database, TrendingUp,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Log event pool ─────────────────────────────────────────────── */
type LogLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

type LogEvent = {
  id: string
  ts: string
  level: LogLevel
  source: string
  event: string
  user?: string
  ip?: string
  rule?: string
}

const LOG_POOL: Omit<LogEvent, 'id' | 'ts'>[] = [
  { level: 'CRITICAL', source: 'auth',      event: 'root login via SSH from untrusted IP',       ip: '45.95.147.236', rule: 'SIEM-1042' },
  { level: 'HIGH',     source: 'firewall',  event: 'Outbound connection to known C2 endpoint',   ip: '185.220.101.1', rule: 'FW-9821'   },
  { level: 'HIGH',     source: 'endpoint',  event: 'PowerShell encoded command execution',        user: 'jdoe',        rule: 'EDR-4421'  },
  { level: 'MEDIUM',   source: 'web',       event: 'SQL injection attempt blocked by WAF',        ip: '91.92.251.103', rule: 'WAF-2231'  },
  { level: 'HIGH',     source: 'ad',        event: 'Admin account creation outside business hours',user: 'svc-deploy', rule: 'AD-5510'  },
  { level: 'CRITICAL', source: 'endpoint',  event: 'Ransomware file encryption pattern detected', user: 'msmith',      rule: 'EDR-9001'  },
  { level: 'MEDIUM',   source: 'network',   event: 'Large data transfer to external host (4.2 GB)',ip: '23.184.48.200',rule: 'NET-3312' },
  { level: 'INFO',     source: 'vpn',       event: 'VPN login from new geolocation (Singapore)',  user: 'alice',       rule: 'VPN-0012'  },
  { level: 'HIGH',     source: 'email',     event: 'Phishing email with malicious attachment delivered',                rule: 'MAIL-8812' },
  { level: 'LOW',      source: 'web',       event: 'Directory traversal attempt blocked',         ip: '172.16.20.44',  rule: 'WAF-1104'  },
  { level: 'MEDIUM',   source: 'auth',      event: 'Multiple failed MFA attempts — possible fatigue',user: 'bob',      rule: 'AUTH-6621' },
  { level: 'INFO',     source: 'system',    event: 'Security patch applied: CVE-2024-6387',                            rule: 'SYS-0001'  },
  { level: 'HIGH',     source: 'cloud',     event: 'IAM role privilege escalation detected',      user: 'lambda-svc', rule: 'AWS-3421'  },
  { level: 'MEDIUM',   source: 'dns',       event: 'DNS query for known malware domain blocked',  ip: '10.44.0.15',   rule: 'DNS-2201'  },
  { level: 'CRITICAL', source: 'db',        event: 'Bulk data exfiltration query (500K records)', user: 'app_user',    rule: 'DB-8801'   },
]

let evtId = 2000

function generateEvent(): LogEvent {
  const pool = LOG_POOL[Math.floor(Math.random() * LOG_POOL.length)]
  const now = new Date()
  return {
    ...pool,
    id: `e${++evtId}`,
    ts: now.toISOString(),
  }
}

const INITIAL_EVENTS: LogEvent[] = Array.from({ length: 40 }, (_, i) => {
  const pool = LOG_POOL[i % LOG_POOL.length]
  const d = new Date(Date.now() - (40 - i) * 38000)
  return { ...pool, id: `init-${i}`, ts: d.toISOString() }
})

/* ── Level color ─────────────────────────────────────────────────── */
const LVL: Record<LogLevel, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-magenta/12', text: 'text-magenta',  border: 'border-magenta/25' },
  HIGH:     { bg: 'bg-threat/12',  text: 'text-threat',   border: 'border-threat/25'  },
  MEDIUM:   { bg: 'bg-amber/12',   text: 'text-amber',    border: 'border-amber/25'   },
  LOW:      { bg: 'bg-violet/12',  text: 'text-violet',   border: 'border-violet/25'  },
  INFO:     { bg: 'bg-white/5',    text: 'text-ink-400',  border: 'border-white/8'    },
}

/* ── Alert rules ─────────────────────────────────────────────────── */
const RULES = [
  { id: 'SIEM-1042', name: 'Privileged SSH from External IP', severity: 'CRITICAL', hits: 3,  enabled: true  },
  { id: 'EDR-9001',  name: 'Ransomware Encryption Pattern',   severity: 'CRITICAL', hits: 1,  enabled: true  },
  { id: 'FW-9821',   name: 'Known C2 Outbound Traffic',       severity: 'HIGH',     hits: 8,  enabled: true  },
  { id: 'EDR-4421',  name: 'Obfuscated PowerShell Execution', severity: 'HIGH',     hits: 14, enabled: true  },
  { id: 'AD-5510',   name: 'After-Hours Admin Account Creation',severity:'HIGH',    hits: 2,  enabled: true  },
  { id: 'DB-8801',   name: 'Mass Database Record Exfiltration',severity: 'CRITICAL',hits: 1,  enabled: true  },
  { id: 'NET-3312',  name: 'Large External Data Transfer',     severity: 'MEDIUM',  hits: 5,  enabled: true  },
  { id: 'WAF-2231',  name: 'SQL Injection Attempt',           severity: 'MEDIUM',  hits: 47, enabled: true  },
  { id: 'AWS-3421',  name: 'Cloud IAM Privilege Escalation',  severity: 'HIGH',    hits: 1,  enabled: false  },
]

/* ── Event rate sparkbar heights (stable, not regenerated on render) */
const EVENT_RATE_BARS = Array.from({ length: 48 }, () => Math.random())

/* ── Top sources ─────────────────────────────────────────────────── */
const TOP_SOURCES = [
  { src: 'endpoint', count: 284 },
  { src: 'firewall', count: 241 },
  { src: 'web',      count: 198 },
  { src: 'auth',     count: 156 },
  { src: 'network',  count: 112 },
  { src: 'cloud',    count: 87  },
  { src: 'db',       count: 54  },
]

/* ── Page ────────────────────────────────────────────────────────── */
export default function SIEMPage() {
  const [events, setEvents] = useState<LogEvent[]>(INITIAL_EVENTS)
  const [filterLevel, setFilterLevel] = useState<LogLevel | 'ALL'>('ALL')
  const [search, setSearch] = useState('')
  const [live, setLive] = useState(true)
  const [selected, setSelected] = useState<LogEvent | null>(null)

  useEffect(() => {
    if (!live) return
    const id = setInterval(() => {
      setEvents((prev) => [generateEvent(), ...prev.slice(0, 199)])
    }, 2400)
    return () => clearInterval(id)
  }, [live])

  const filtered = events.filter((e) => {
    if (filterLevel !== 'ALL' && e.level !== filterLevel) return false
    if (search && !e.event.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const critical = events.filter((e) => e.level === 'CRITICAL').length
  const high     = events.filter((e) => e.level === 'HIGH').length
  const total    = events.length

  return (
    <div className="p-6 space-y-5">
      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Events (24h)', value: total.toLocaleString(), icon: Activity,      color: '#7A3CFF' },
          { label: 'Critical Alerts',    value: critical.toString(),    icon: AlertTriangle,  color: '#FF2E97' },
          { label: 'High Alerts',        value: high.toString(),        icon: Shield,         color: '#FF4D6D' },
          { label: 'Active Rules',       value: RULES.filter((r) => r.enabled).length.toString(), icon: Database, color: '#2DD4BF' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="glass border border-white/5 rounded-xl p-4 flex items-center gap-4">
            <div className="p-2.5 rounded-xl" style={{ background: `${color}18` }}>
              <Icon className="w-4 h-4" style={{ color }} />
            </div>
            <div>
              <p className="text-xs text-ink-500">{label}</p>
              <p className="font-display text-xl font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        {/* Event log */}
        <div className="lg:col-span-2 glass border border-white/5 rounded-xl flex flex-col overflow-hidden" style={{ height: '540px' }}>
          {/* Log toolbar */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-white/5 shrink-0 flex-wrap">
            <Terminal className="w-4 h-4 text-ink-500" />
            <span className="text-xs font-semibold text-white">Event Log</span>
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-ink-600" />
              <input
                type="text"
                placeholder="Search events..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-7 pr-3 py-1.5 rounded-lg text-[11px] bg-surface-2 border border-white/8 text-ink-200 placeholder-ink-600 focus:outline-none focus:border-magenta/40 w-40"
              />
            </div>
            <div className="flex items-center gap-1">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((l) => (
                <button
                  key={l}
                  onClick={() => setFilterLevel(l)}
                  className={cn(
                    'px-2 py-1 rounded text-[9px] font-semibold border transition-colors',
                    filterLevel === l
                      ? (l === 'ALL' ? 'bg-white/10 border-white/20 text-white' : `${LVL[l as LogLevel]?.bg ?? 'bg-white/10'} ${LVL[l as LogLevel]?.text ?? 'text-white'} ${LVL[l as LogLevel]?.border ?? 'border-white/20'}`)
                      : 'border-transparent text-ink-600 hover:text-ink-300',
                  )}
                >
                  {l}
                </button>
              ))}
            </div>
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => setLive((l) => !l)}
                aria-label={live ? 'Pause live feed' : 'Resume live feed'}
                className={cn('flex items-center gap-1.5 text-[10px] px-2 py-1 rounded border',
                  live ? 'text-safe border-safe/25 bg-safe/8' : 'text-ink-500 border-white/8')}
              >
                <span className={cn('w-1.5 h-1.5 rounded-full', live && 'animate-pulse bg-safe')} style={!live ? { background: '#665B7D' } : {}} />
                {live ? 'Live' : 'Paused'}
              </button>
            </div>
          </div>

          {/* Event table header */}
          <div className="grid grid-cols-[70px_1fr_80px_80px] gap-2 px-4 py-2 text-[9px] uppercase tracking-widest text-ink-600 border-b border-white/4 shrink-0">
            <span>Level</span><span>Event</span><span>Source</span><span>Time</span>
          </div>

          {/* Events */}
          <div className="overflow-y-auto flex-1 font-mono">
            {filtered.map((e, i) => (
              <motion.div
                key={e.id}
                initial={i === 0 ? { opacity: 0, backgroundColor: 'rgba(255,46,151,0.08)' } : {}}
                animate={{ opacity: 1, backgroundColor: 'rgba(0,0,0,0)' }}
                transition={{ duration: 1 }}
                onClick={() => setSelected(selected?.id === e.id ? null : e)}
                className={cn(
                  'grid grid-cols-[70px_1fr_80px_80px] gap-2 px-4 py-2 border-b border-white/3 cursor-pointer hover:bg-white/3 transition-colors text-[10px]',
                  selected?.id === e.id && 'bg-magenta/5',
                )}
              >
                <span className={cn('font-semibold', LVL[e.level].text)}>
                  {e.level}
                </span>
                <span className="text-ink-300 truncate">{e.event}</span>
                <span className="text-ink-500">{e.source}</span>
                <span className="text-ink-600">
                  {new Date(e.ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              </motion.div>
            ))}
          </div>

          {/* Selected event detail */}
          {selected && (
            <div className="border-t border-white/5 p-4 bg-surface-2 text-xs shrink-0">
              <div className="flex items-center gap-2 mb-2">
                <span className={cn('font-semibold', LVL[selected.level].text)}>{selected.level}</span>
                {selected.rule && <span className="font-mono text-ink-500">{selected.rule}</span>}
                <span className="text-ink-600 ml-auto">{selected.ts}</span>
              </div>
              <p className="text-ink-200 mb-2">{selected.event}</p>
              <div className="flex gap-4 text-ink-500">
                {selected.ip && <span>IP: <span className="text-ink-300 font-mono">{selected.ip}</span></span>}
                {selected.user && <span>User: <span className="text-ink-300 font-mono">{selected.user}</span></span>}
                <span>Source: <span className="text-ink-300">{selected.source}</span></span>
              </div>
            </div>
          )}
        </div>

        {/* Right panel */}
        <div className="space-y-4">
          {/* Top sources */}
          <div className="glass border border-white/5 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4">Top Log Sources</h3>
            <div className="space-y-2.5">
              {TOP_SOURCES.map(({ src, count }) => (
                <div key={src}>
                  <div className="flex justify-between mb-1">
                    <span className="text-xs text-ink-300 capitalize">{src}</span>
                    <span className="text-xs text-ink-500 font-mono">{count}</span>
                  </div>
                  <div className="h-1 bg-surface-3 rounded-full">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(count / TOP_SOURCES[0].count) * 100}%` }}
                      transition={{ duration: 0.8 }}
                      className="h-full rounded-full bg-gradient-to-r from-magenta to-violet"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Alert Rules */}
          <div className="glass border border-white/5 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
              <h3 className="text-sm font-semibold text-white">Alert Rules</h3>
              <span className="text-[10px] text-ink-500">{RULES.filter(r => r.enabled).length}/{RULES.length} active</span>
            </div>
            <div className="divide-y divide-white/4 max-h-64 overflow-y-auto">
              {RULES.map((rule) => (
                <div key={rule.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/2">
                  <div className={cn(
                    'w-1.5 h-1.5 rounded-full shrink-0',
                    rule.enabled ? (rule.severity === 'CRITICAL' ? 'bg-magenta' : rule.severity === 'HIGH' ? 'bg-threat' : 'bg-amber') : 'bg-ink-600',
                  )} />
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] text-ink-200 truncate">{rule.name}</p>
                    <p className="text-[9px] text-ink-600 font-mono">{rule.id} · {rule.hits} hits</p>
                  </div>
                  <div className={cn(
                    'w-6 h-3.5 rounded-full transition-colors cursor-pointer shrink-0',
                    rule.enabled ? 'bg-safe' : 'bg-ink-600',
                  )}>
                    <div className={cn('w-2.5 h-2.5 rounded-full bg-white mt-0.5 transition-transform', rule.enabled ? 'translate-x-3' : 'translate-x-0.5')} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat timeline mini */}
          <div className="glass border border-white/5 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-3">Event Rate</h3>
            <div className="flex items-end gap-0.5 h-16">
              {EVENT_RATE_BARS.map((h, i) => (
                <div
                  key={i}
                  className="flex-1 rounded-sm"
                  style={{
                    height: `${h * 100}%`,
                    background: h > 0.7 ? '#FF2E97' : h > 0.5 ? '#FF4D6D' : 'rgba(122,60,255,0.4)',
                  }}
                />
              ))}
            </div>
            <div className="flex justify-between mt-1 text-[9px] text-ink-600">
              <span>-24h</span><span>-12h</span><span>Now</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
