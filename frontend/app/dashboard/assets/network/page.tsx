'use client'

import { useState, useMemo, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Network, Server, Monitor, Shield, Cloud, Database, Globe,
  Cpu, X, MapPin, Lock, Activity, Layers,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Types ───────────────────────────────────────────────────────── */
type Zone = 'dmz' | 'internal' | 'cloud' | 'ot'
type NodeType = 'internet' | 'firewall' | 'server' | 'workstation' | 'cloud' | 'database' | 'ot'
type Risk = 'critical' | 'warning' | 'healthy'

interface Node {
  id: string
  hostname: string
  type: NodeType
  zone: Zone
  ip: string
  risk: Risk
  riskScore: number
  ports: number[]
  x: number
  y: number
}

interface Link {
  from: string
  to: string
}

/* ── Meta ───────────────────────────────────────────────────────── */
const ZONE_META: Record<Zone, { label: string; color: string }> = {
  dmz:      { label: 'DMZ',      color: '#FFB23E' },
  internal: { label: 'Internal', color: '#7A3CFF' },
  cloud:    { label: 'Cloud',    color: '#34F5C5' },
  ot:       { label: 'OT / ICS', color: '#FF2E97' },
}

const RISK_META: Record<Risk, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#FF4D6D' },
  warning:  { label: 'Warning',  color: '#FFB23E' },
  healthy:  { label: 'Healthy',  color: '#34F5C5' },
}

const TYPE_ICON: Record<NodeType, React.ElementType> = {
  internet: Globe,
  firewall: Shield,
  server: Server,
  workstation: Monitor,
  cloud: Cloud,
  database: Database,
  ot: Cpu,
}

const TYPE_LABEL: Record<NodeType, string> = {
  internet: 'Internet Gateway',
  firewall: 'Firewall',
  server: 'Server',
  workstation: 'Workstation',
  cloud: 'Cloud Resource',
  database: 'Database',
  ot: 'OT / ICS Device',
}

/* ── Seed data (hardcoded force-directed-looking layout) ─────────── */
const VB_W = 1000
const VB_H = 620

const NODES: Node[] = [
  // Internet
  { id: 'inet', hostname: 'internet', type: 'internet', zone: 'dmz', ip: '0.0.0.0/0', risk: 'critical', riskScore: 100, ports: [], x: 500, y: 50 },

  // DMZ
  { id: 'fw-edge-01', hostname: 'fw-edge-01', type: 'firewall', zone: 'dmz', ip: '203.0.113.1', risk: 'warning', riskScore: 58, ports: [443, 500, 4500], x: 360, y: 150 },
  { id: 'fw-edge-02', hostname: 'fw-edge-02', type: 'firewall', zone: 'dmz', ip: '203.0.113.2', risk: 'healthy', riskScore: 22, ports: [443, 500, 4500], x: 640, y: 150 },
  { id: 'web-lb-01', hostname: 'web-lb-01', type: 'server', zone: 'dmz', ip: '10.10.1.10', risk: 'healthy', riskScore: 18, ports: [80, 443], x: 250, y: 250 },
  { id: 'wordpress-mkt', hostname: 'wordpress-mkt', type: 'server', zone: 'dmz', ip: '10.10.1.22', risk: 'critical', riskScore: 88, ports: [80, 443, 22], x: 410, y: 270 },
  { id: 'mail-relay-01', hostname: 'mail-relay-01', type: 'server', zone: 'dmz', ip: '10.10.1.30', risk: 'warning', riskScore: 47, ports: [25, 587, 993], x: 720, y: 255 },

  // Internal
  { id: 'PROD-API-04', hostname: 'PROD-API-04', type: 'server', zone: 'internal', ip: '10.0.4.14', risk: 'critical', riskScore: 82, ports: [443, 8443, 9090], x: 180, y: 400 },
  { id: 'jenkins-ci-01', hostname: 'jenkins-ci-01', type: 'server', zone: 'internal', ip: '10.0.4.31', risk: 'warning', riskScore: 61, ports: [8080, 50000, 22], x: 330, y: 470 },
  { id: 'dc-prod-01', hostname: 'dc-prod-01', type: 'server', zone: 'internal', ip: '10.0.2.5', risk: 'warning', riskScore: 44, ports: [88, 389, 445, 636], x: 480, y: 420 },
  { id: 'DESKTOP-FIN-087', hostname: 'DESKTOP-FIN-087', type: 'workstation', zone: 'internal', ip: '10.0.8.87', risk: 'healthy', riskScore: 15, ports: [], x: 250, y: 540 },
  { id: 'DESKTOP-HR-012', hostname: 'DESKTOP-HR-012', type: 'workstation', zone: 'internal', ip: '10.0.8.12', risk: 'healthy', riskScore: 12, ports: [], x: 420, y: 555 },
  { id: 'LAPTOP-EXEC-03', hostname: 'LAPTOP-EXEC-03', type: 'workstation', zone: 'internal', ip: '10.0.8.103', risk: 'warning', riskScore: 39, ports: [], x: 560, y: 545 },

  // Cloud
  { id: 'k8s-prod-node-1', hostname: 'k8s-prod-node-1', type: 'cloud', zone: 'cloud', ip: '172.31.4.10', risk: 'healthy', riskScore: 24, ports: [6443, 10250], x: 820, y: 380 },
  { id: 'k8s-prod-node-2', hostname: 'k8s-prod-node-2', type: 'cloud', zone: 'cloud', ip: '172.31.4.11', risk: 'healthy', riskScore: 20, ports: [6443, 10250], x: 900, y: 460 },
  { id: 'rds-customers', hostname: 'rds-customers', type: 'database', zone: 'cloud', ip: '172.31.6.20', risk: 'critical', riskScore: 76, ports: [5432], x: 770, y: 500 },
  { id: 's3-data-lake', hostname: 's3-data-lake', type: 'cloud', zone: 'cloud', ip: 's3://data-lake', risk: 'warning', riskScore: 41, ports: [443], x: 910, y: 330 },

  // OT / ICS
  { id: 'plc-line-a', hostname: 'plc-line-a', type: 'ot', zone: 'ot', ip: '192.168.50.10', risk: 'critical', riskScore: 91, ports: [502, 44818], x: 110, y: 250 },
  { id: 'scada-hmi-01', hostname: 'scada-hmi-01', type: 'ot', zone: 'ot', ip: '192.168.50.20', risk: 'warning', riskScore: 53, ports: [502, 102], x: 90, y: 360 },
]

const LINKS: Link[] = [
  { from: 'inet', to: 'fw-edge-01' },
  { from: 'inet', to: 'fw-edge-02' },
  { from: 'fw-edge-01', to: 'web-lb-01' },
  { from: 'fw-edge-01', to: 'wordpress-mkt' },
  { from: 'fw-edge-02', to: 'mail-relay-01' },
  { from: 'web-lb-01', to: 'PROD-API-04' },
  { from: 'wordpress-mkt', to: 'PROD-API-04' },
  { from: 'PROD-API-04', to: 'jenkins-ci-01' },
  { from: 'PROD-API-04', to: 'dc-prod-01' },
  { from: 'PROD-API-04', to: 'rds-customers' },
  { from: 'jenkins-ci-01', to: 'k8s-prod-node-1' },
  { from: 'dc-prod-01', to: 'DESKTOP-FIN-087' },
  { from: 'dc-prod-01', to: 'DESKTOP-HR-012' },
  { from: 'dc-prod-01', to: 'LAPTOP-EXEC-03' },
  { from: 'k8s-prod-node-1', to: 'k8s-prod-node-2' },
  { from: 'k8s-prod-node-1', to: 'rds-customers' },
  { from: 'k8s-prod-node-1', to: 's3-data-lake' },
  { from: 'PROD-API-04', to: 'plc-line-a' },
  { from: 'plc-line-a', to: 'scada-hmi-01' },
  { from: 'web-lb-01', to: 'plc-line-a' },
]

/* ── Main page ─────────────────────────────────────────────────── */
export default function NetworkMapPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [hoverId, setHoverId] = useState<string | null>(null)
  const [zoneVisibility, setZoneVisibility] = useState<Record<Zone, boolean>>({
    dmz: true, internal: true, cloud: true, ot: true,
  })

  const nodeMap = useMemo(() => {
    const m: Record<string, Node> = {}
    NODES.forEach((n) => { m[n.id] = n })
    return m
  }, [])

  const visibleNodes = useMemo(
    () => NODES.filter((n) => n.id === 'inet' || zoneVisibility[n.zone]),
    [zoneVisibility],
  )
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes])
  const visibleLinks = useMemo(
    () => LINKS.filter((l) => visibleIds.has(l.from) && visibleIds.has(l.to)),
    [visibleIds],
  )

  const selected = selectedId ? nodeMap[selectedId] ?? null : null

  const connectedIds = useMemo(() => {
    if (!selected) return new Set<string>()
    const set = new Set<string>()
    LINKS.forEach((l) => {
      if (l.from === selected.id) set.add(l.to)
      if (l.to === selected.id) set.add(l.from)
    })
    return set
  }, [selected])

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') setSelectedId(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  function toggleZone(z: Zone) {
    setZoneVisibility((prev) => ({ ...prev, [z]: !prev[z] }))
  }

  const kpis = [
    { label: 'Total Nodes',         value: '148', color: 'text-white'  },
    { label: 'Subnets',             value: '12',  color: 'text-violet' },
    { label: 'Exposed Services',    value: '34',  color: 'text-amber'  },
    { label: 'External Connections', value: '89', color: 'text-threat' },
  ]

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-violet" />
            <h1 className="text-lg font-display font-semibold text-white">Network Map</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Asset topology and connectivity view</p>
        </div>
        <div className="flex items-center gap-1.5">
          {(Object.keys(ZONE_META) as Zone[]).map((z) => (
            <button key={z} onClick={() => toggleZone(z)}
              className={cn('flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border transition-colors',
                zoneVisibility[z] ? 'bg-white/5 text-ink-200 border-white/10' : 'bg-transparent text-ink-700 border-white/5 opacity-60')}>
              <span className="w-2 h-2 rounded-full" style={{ background: zoneVisibility[z] ? ZONE_META[z].color : '#3a3350' }} />
              {ZONE_META[z].label}
            </button>
          ))}
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {kpis.map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Map + legend */}
      <div className="flex-1 relative overflow-hidden">
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} preserveAspectRatio="xMidYMid meet" className="w-full h-full">
          <defs>
            <radialGradient id="bgGlow" cx="50%" cy="40%" r="70%">
              <stop offset="0%" stopColor="#1a1030" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#0A0612" stopOpacity="0" />
            </radialGradient>
          </defs>
          <rect x="0" y="0" width={VB_W} height={VB_H} fill="url(#bgGlow)" />

          {/* Links */}
          <g>
            {visibleLinks.map((l, i) => {
              const a = nodeMap[l.from]
              const b = nodeMap[l.to]
              const active = !!selected && (l.from === selected.id || l.to === selected.id)
              const dim = !!selected && !active
              return (
                <line key={`${l.from}-${l.to}-${i}`}
                  x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke={active ? '#FF2E97' : '#7A3CFF'}
                  strokeWidth={active ? 2 : 1}
                  strokeOpacity={dim ? 0.08 : active ? 0.8 : 0.28}
                  strokeDasharray="6 8"
                  className="topo-flow" />
              )
            })}
          </g>

          {/* Nodes */}
          <g>
            {visibleNodes.map((n) => {
              const Icon = TYPE_ICON[n.type]
              const color = RISK_META[n.risk].color
              const isSel = selected?.id === n.id
              const isConn = connectedIds.has(n.id)
              const dim = !!selected && !isSel && !isConn
              const r = n.type === 'internet' ? 26 : 20
              return (
                <g key={n.id}
                  transform={`translate(${n.x}, ${n.y})`}
                  className="cursor-pointer"
                  opacity={dim ? 0.3 : 1}
                  onClick={() => setSelectedId(isSel ? null : n.id)}
                  onMouseEnter={() => setHoverId(n.id)}
                  onMouseLeave={() => setHoverId(null)}>
                  {(isSel || n.risk === 'critical') && (
                    <circle r={r + 8} fill="none" stroke={color} strokeWidth={1} opacity={0.4}>
                      <animate attributeName="r" values={`${r + 4};${r + 12};${r + 4}`} dur="2.4s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.4;0;0.4" dur="2.4s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <circle r={r} fill="#0D0920" stroke={color} strokeWidth={isSel ? 2.5 : 1.5} />
                  <circle r={r} fill={color} fillOpacity={0.12} />
                  <foreignObject x={-9} y={-9} width={18} height={18} style={{ pointerEvents: 'none' }}>
                    <div className="w-[18px] h-[18px] flex items-center justify-center">
                      <Icon width={14} height={14} color={color} />
                    </div>
                  </foreignObject>
                  {(hoverId === n.id || isSel) && (
                    <g>
                      <rect x={-n.hostname.length * 3.4 - 6} y={r + 5} width={n.hostname.length * 6.8 + 12} height={16} rx={4}
                        fill="#0D0920" stroke={color} strokeOpacity={0.4} strokeWidth={0.75} />
                      <text x={0} y={r + 16} textAnchor="middle" fontSize={9} fill="#E8E0F5" fontFamily="monospace">{n.hostname}</text>
                    </g>
                  )}
                </g>
              )
            })}
          </g>
        </svg>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 rounded-xl border border-white/8 bg-[#0D0920]/90 backdrop-blur-sm px-3 py-2.5 space-y-2">
          <div>
            <p className="text-[9px] text-ink-600 uppercase tracking-wider mb-1 flex items-center gap-1"><Layers className="w-2.5 h-2.5" /> Zones</p>
            <div className="flex flex-col gap-1">
              {(Object.keys(ZONE_META) as Zone[]).map((z) => (
                <div key={z} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: ZONE_META[z].color }} />
                  <span className="text-[10px] text-ink-400">{ZONE_META[z].label}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="pt-1.5 border-t border-white/5">
            <p className="text-[9px] text-ink-600 uppercase tracking-wider mb-1">Risk</p>
            <div className="flex flex-col gap-1">
              {(Object.keys(RISK_META) as Risk[]).map((rk) => (
                <div key={rk} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: RISK_META[rk].color }} />
                  <span className="text-[10px] text-ink-400">{RISK_META[rk].label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Detail side panel */}
        <AnimatePresence>
          {selected && (
            <motion.div
              initial={{ x: '110%', opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: '110%', opacity: 0 }}
              transition={{ type: 'spring', damping: 30, stiffness: 280 }}
              className="absolute top-4 right-4 bottom-4 w-72 rounded-2xl border border-white/10 bg-[#0D0920]/95 backdrop-blur-md shadow-2xl overflow-y-auto">
              {(() => {
                const n = selected
                const Icon = TYPE_ICON[n.type]
                const color = RISK_META[n.risk].color
                const conns = Array.from(connectedIds).map((id) => nodeMap[id]).filter(Boolean)
                return (
                  <div className="p-4 space-y-4">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="p-2 rounded-lg shrink-0" style={{ background: color + '1a' }}>
                          <Icon className="w-4 h-4" style={{ color }} />
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-white truncate">{n.hostname}</p>
                          <p className="text-[10px] text-ink-500">{TYPE_LABEL[n.type]}</p>
                        </div>
                      </div>
                      <button onClick={() => setSelectedId(null)} className="p-1 rounded text-ink-500 hover:text-white shrink-0">
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="flex items-center justify-between rounded-xl border border-white/8 bg-white/3 px-3 py-2.5">
                      <div>
                        <p className="text-[9px] text-ink-600 uppercase tracking-wider">Risk Score</p>
                        <p className="text-lg font-bold font-mono" style={{ color }}>{n.riskScore}</p>
                      </div>
                      <span className="px-2 py-1 rounded-full text-[10px] font-semibold" style={{ color, background: color + '18' }}>
                        {RISK_META[n.risk].label}
                      </span>
                    </div>

                    <div className="space-y-1.5">
                      {[
                        { label: 'IP Address', value: n.ip, icon: MapPin },
                        { label: 'Zone', value: ZONE_META[n.zone].label, icon: Layers },
                        { label: 'Type', value: TYPE_LABEL[n.type], icon: Activity },
                      ].map(({ label, value, icon: I }) => (
                        <div key={label} className="flex items-center justify-between gap-2 py-1.5 border-b border-white/4 last:border-0">
                          <span className="text-[10px] text-ink-600 flex items-center gap-1.5"><I className="w-3 h-3" />{label}</span>
                          <span className="text-[10px] text-ink-200 font-mono text-right truncate">{value}</span>
                        </div>
                      ))}
                    </div>

                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><Lock className="w-3 h-3" /> Open Ports</p>
                      {n.ports.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {n.ports.map((p) => (
                            <span key={p} className="font-mono text-[10px] px-2 py-0.5 rounded bg-white/5 border border-white/8 text-ink-300">{p}</span>
                          ))}
                        </div>
                      ) : <p className="text-[10px] text-ink-700">No exposed ports</p>}
                    </div>

                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><Network className="w-3 h-3" /> Connected Nodes ({conns.length})</p>
                      <div className="space-y-1">
                        {conns.map((c) => (
                          <button key={c.id} onClick={() => setSelectedId(c.id)}
                            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors text-left">
                            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: RISK_META[c.risk].color }} />
                            <span className="text-[10px] font-mono text-ink-300 truncate flex-1">{c.hostname}</span>
                            <span className="text-[9px] text-ink-600">{ZONE_META[c.zone].label}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )
              })()}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <style jsx>{`
        .topo-flow {
          animation: dashflow 1s linear infinite;
        }
        @keyframes dashflow {
          to { stroke-dashoffset: -14; }
        }
      `}</style>
    </div>
  )
}
