'use client'

import { useState, useMemo, useEffect, useRef, useCallback } from 'react'
import { fetchAssets, type Asset as ApiAsset } from '@/lib/api'
import { motion, AnimatePresence, animate, useReducedMotion } from 'framer-motion'
import { EASE, DUR } from '@/lib/motion'
import {
  Network, Server, Monitor, Shield, Cloud, Database, Globe,
  Cpu, X, MapPin, Lock, Activity, Layers, Search, Plus, Minus,
  Maximize2, Route, MousePointer2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { tk, withAlpha } from '@/lib/colors'

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
  live?: boolean   // came from the live asset inventory, not the seed topology
}

interface Link {
  from: string
  to: string
}

/* ── Meta ───────────────────────────────────────────────────────── */
const ZONE_META: Record<Zone, { label: string; color: string }> = {
  dmz:      { label: 'DMZ',      color: tk('amber') },
  internal: { label: 'Internal', color: tk('violet') },
  cloud:    { label: 'Cloud',    color: tk('teal') },
  ot:       { label: 'OT / ICS', color: tk('magenta') },
}

const RISK_META: Record<Risk, { label: string; color: string }> = {
  critical: { label: 'Critical', color: tk('threat') },
  warning:  { label: 'Warning',  color: tk('amber') },
  healthy:  { label: 'Healthy',  color: tk('safe') },
}

const TYPE_ICON: Record<NodeType, React.ComponentType<any>> = {
  internet: Globe, firewall: Shield, server: Server,
  workstation: Monitor, cloud: Cloud, database: Database, ot: Cpu,
}

const TYPE_LABEL: Record<NodeType, string> = {
  internet: 'Internet Gateway', firewall: 'Firewall', server: 'Server',
  workstation: 'Workstation', cloud: 'Cloud Resource', database: 'Database', ot: 'OT / ICS Device',
}

/* ── Topology coordinate space and zone panels ───────────────────── */
const VB_W = 1000
const VB_H = 640

const ZONE_RECTS: Record<Zone, { x: number; y: number; w: number; h: number }> = {
  dmz:      { x: 215, y: 115, w: 560, h: 195 },
  ot:       { x: 30,  y: 200, w: 165, h: 240 },
  internal: { x: 130, y: 350, w: 510, h: 250 },
  cloud:    { x: 690, y: 320, w: 285, h: 250 },
}

const NODES: Node[] = [
  { id: 'inet', hostname: 'internet', type: 'internet', zone: 'dmz', ip: '0.0.0.0/0', risk: 'critical', riskScore: 100, ports: [], x: 495, y: 52 },

  // DMZ
  { id: 'fw-edge-01', hostname: 'fw-edge-01', type: 'firewall', zone: 'dmz', ip: '203.0.113.1', risk: 'warning', riskScore: 58, ports: [443, 500, 4500], x: 370, y: 168 },
  { id: 'fw-edge-02', hostname: 'fw-edge-02', type: 'firewall', zone: 'dmz', ip: '203.0.113.2', risk: 'healthy', riskScore: 22, ports: [443, 500, 4500], x: 625, y: 168 },
  { id: 'web-lb-01', hostname: 'web-lb-01', type: 'server', zone: 'dmz', ip: '10.10.1.10', risk: 'healthy', riskScore: 18, ports: [80, 443], x: 270, y: 258 },
  { id: 'wordpress-mkt', hostname: 'wordpress-mkt', type: 'server', zone: 'dmz', ip: '10.10.1.22', risk: 'critical', riskScore: 88, ports: [80, 443, 22], x: 460, y: 262 },
  { id: 'mail-relay-01', hostname: 'mail-relay-01', type: 'server', zone: 'dmz', ip: '10.10.1.30', risk: 'warning', riskScore: 47, ports: [25, 587, 993], x: 700, y: 252 },

  // Internal
  { id: 'PROD-API-04', hostname: 'PROD-API-04', type: 'server', zone: 'internal', ip: '10.0.4.14', risk: 'critical', riskScore: 82, ports: [443, 8443, 9090], x: 215, y: 415 },
  { id: 'jenkins-ci-01', hostname: 'jenkins-ci-01', type: 'server', zone: 'internal', ip: '10.0.4.31', risk: 'warning', riskScore: 61, ports: [8080, 50000, 22], x: 360, y: 475 },
  { id: 'dc-prod-01', hostname: 'dc-prod-01', type: 'server', zone: 'internal', ip: '10.0.2.5', risk: 'warning', riskScore: 44, ports: [88, 389, 445, 636], x: 510, y: 425 },
  { id: 'DESKTOP-FIN-087', hostname: 'DESKTOP-FIN-087', type: 'workstation', zone: 'internal', ip: '10.0.8.87', risk: 'healthy', riskScore: 15, ports: [], x: 255, y: 552 },
  { id: 'DESKTOP-HR-012', hostname: 'DESKTOP-HR-012', type: 'workstation', zone: 'internal', ip: '10.0.8.12', risk: 'healthy', riskScore: 12, ports: [], x: 420, y: 562 },
  { id: 'LAPTOP-EXEC-03', hostname: 'LAPTOP-EXEC-03', type: 'workstation', zone: 'internal', ip: '10.0.8.103', risk: 'warning', riskScore: 39, ports: [], x: 565, y: 548 },

  // Cloud
  { id: 'k8s-prod-node-1', hostname: 'k8s-prod-node-1', type: 'cloud', zone: 'cloud', ip: '172.31.4.10', risk: 'healthy', riskScore: 24, ports: [6443, 10250], x: 790, y: 385 },
  { id: 'k8s-prod-node-2', hostname: 'k8s-prod-node-2', type: 'cloud', zone: 'cloud', ip: '172.31.4.11', risk: 'healthy', riskScore: 20, ports: [6443, 10250], x: 905, y: 450 },
  { id: 'rds-customers', hostname: 'rds-customers', type: 'database', zone: 'cloud', ip: '172.31.6.20', risk: 'critical', riskScore: 76, ports: [5432], x: 775, y: 510 },
  { id: 's3-data-lake', hostname: 's3-data-lake', type: 'cloud', zone: 'cloud', ip: 's3://data-lake', risk: 'warning', riskScore: 41, ports: [443], x: 915, y: 358 },

  // OT / ICS
  { id: 'plc-line-a', hostname: 'plc-line-a', type: 'ot', zone: 'ot', ip: '192.168.50.10', risk: 'critical', riskScore: 91, ports: [502, 44818], x: 112, y: 262 },
  { id: 'scada-hmi-01', hostname: 'scada-hmi-01', type: 'ot', zone: 'ot', ip: '192.168.50.20', risk: 'warning', riskScore: 53, ports: [502, 102], x: 100, y: 380 },
]

const BASE_LINKS: Link[] = [
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

/* Live assets that aren't part of the seed topology get auto-placed into
 * their zone on a spiral of free slots, attached to that zone's hub. */
const ZONE_HUB: Record<Zone, string> = {
  dmz: 'fw-edge-01', internal: 'dc-prod-01', cloud: 'k8s-prod-node-1', ot: 'scada-hmi-01',
}

const API_TYPE_TO_NODE: Record<string, { type: NodeType; zone: Zone }> = {
  domain:   { type: 'server',      zone: 'dmz' },
  ip:       { type: 'server',      zone: 'dmz' },
  server:   { type: 'server',      zone: 'internal' },
  endpoint: { type: 'workstation', zone: 'internal' },
  cloud:    { type: 'cloud',       zone: 'cloud' },
  database: { type: 'database',    zone: 'cloud' },
}

const riskFromScore = (score: number): Risk =>
  score >= 70 ? 'critical' : score >= 40 ? 'warning' : 'healthy'

function placeInZone(zone: Zone, index: number): { x: number; y: number } {
  const r = ZONE_RECTS[zone]
  const cols = 3
  const col = index % cols
  const row = Math.floor(index / cols)
  return {
    x: r.x + 42 + col * ((r.w - 84) / (cols - 1 || 1)),
    y: r.y + r.h - 38 - row * 52,
  }
}

/* Curved link path: a gentle quadratic bend perpendicular to the segment. */
function linkPath(a: Node, b: Node): string {
  const mx = (a.x + b.x) / 2
  const my = (a.y + b.y) / 2
  const dx = b.x - a.x
  const dy = b.y - a.y
  const len = Math.hypot(dx, dy) || 1
  const bend = Math.min(26, len * 0.16)
  const cx = mx - (dy / len) * bend
  const cy = my + (dx / len) * bend
  return `M ${a.x} ${a.y} Q ${cx} ${cy} ${b.x} ${b.y}`
}

/* BFS shortest path over the undirected link graph. */
function shortestPath(links: Link[], from: string, to: string): string[] | null {
  const adj = new Map<string, string[]>()
  links.forEach((l) => {
    adj.set(l.from, [...(adj.get(l.from) ?? []), l.to])
    adj.set(l.to, [...(adj.get(l.to) ?? []), l.from])
  })
  const prev = new Map<string, string>()
  const seen = new Set([from])
  const queue = [from]
  while (queue.length) {
    const cur = queue.shift()!
    if (cur === to) {
      const path = [to]
      while (path[0] !== from) path.unshift(prev.get(path[0])!)
      return path
    }
    for (const nxt of adj.get(cur) ?? []) {
      if (!seen.has(nxt)) { seen.add(nxt); prev.set(nxt, cur); queue.push(nxt) }
    }
  }
  return null
}

/* ── Main page ─────────────────────────────────────────────────── */
export default function NetworkMapPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [hoverId, setHoverId] = useState<string | null>(null)
  const [zoneVisibility, setZoneVisibility] = useState<Record<Zone, boolean>>({
    dmz: true, internal: true, cloud: true, ot: true,
  })
  const [nodes, setNodes] = useState<Node[]>(NODES)
  const [links, setLinks] = useState<Link[]>(BASE_LINKS)
  const [search, setSearch] = useState('')
  const [tracePath, setTracePath] = useState(false)

  // Viewport (zoom + pan) expressed as an SVG viewBox.
  const [vb, setVb] = useState({ x: 0, y: 0, w: VB_W, h: VB_H })
  const svgRef = useRef<SVGSVGElement>(null)
  const dragRef = useRef<{ kind: 'node' | 'pan'; id?: string; startX: number; startY: number; startClientX: number; startClientY: number; vb?: typeof vb; moved: boolean } | null>(null)
  // SMIL <animate>/<animateMotion> ignore both the reduce-motion CSS rule and
  // MotionConfig, so the traffic particles / pulse rings gate on this directly.
  const reduced = useReducedMotion()

  /* Merge live inventory: update seed-node risk from matching assets and
   * place unknown assets into their zone as live nodes. */
  useEffect(() => {
    fetchAssets({ limit: '100' }).then(({ items }) => {
      if (items.length === 0) return
      setNodes((prev) => {
        const known = new Set(prev.map((n) => n.id))
        const knownNames = new Set(prev.map((n) => n.hostname.toLowerCase()))
        const updated = prev.map((n) => {
          const api = items.find((a: ApiAsset) => a.name === n.hostname || a.id === n.id)
          if (!api) return n
          const score = api.riskScore ?? n.riskScore
          return { ...n, riskScore: score, risk: riskFromScore(score), ports: api.openPorts ?? n.ports }
        })
        const zoneCounts: Record<Zone, number> = { dmz: 0, internal: 0, cloud: 0, ot: 0 }
        const extras: Node[] = []
        const extraLinks: Link[] = []
        for (const a of items as ApiAsset[]) {
          if (known.has(a.id) || knownNames.has(a.name.toLowerCase())) continue
          const meta = API_TYPE_TO_NODE[a.type] ?? { type: 'server' as NodeType, zone: 'internal' as Zone }
          if (zoneCounts[meta.zone] >= 4) continue   // keep the canvas readable
          const pos = placeInZone(meta.zone, zoneCounts[meta.zone]++)
          extras.push({
            id: a.id, hostname: a.name, type: meta.type, zone: meta.zone,
            ip: a.value, risk: riskFromScore(a.riskScore ?? 0),
            riskScore: a.riskScore ?? 0, ports: a.openPorts ?? [],
            x: pos.x, y: pos.y, live: true,
          })
          extraLinks.push({ from: ZONE_HUB[meta.zone], to: a.id })
        }
        if (extras.length > 0) setLinks([...BASE_LINKS, ...extraLinks])
        return [...updated, ...extras]
      })
    }).catch(() => {})
  }, [])

  const nodeMap = useMemo(() => {
    const m: Record<string, Node> = {}
    nodes.forEach((n) => { m[n.id] = n })
    return m
  }, [nodes])

  const visibleNodes = useMemo(
    () => nodes.filter((n) => n.id === 'inet' || zoneVisibility[n.zone]),
    [nodes, zoneVisibility],
  )
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes])
  const visibleLinks = useMemo(
    () => links.filter((l) => visibleIds.has(l.from) && visibleIds.has(l.to)),
    [links, visibleIds],
  )

  const selected = selectedId ? nodeMap[selectedId] ?? null : null
  const focusId = hoverId ?? selectedId

  const neighborhood = useMemo(() => {
    if (!focusId) return null
    const set = new Set<string>([focusId])
    links.forEach((l) => {
      if (l.from === focusId) set.add(l.to)
      if (l.to === focusId) set.add(l.from)
    })
    return set
  }, [focusId, links])

  const attackPath = useMemo(() => {
    if (!tracePath || !selected || selected.id === 'inet') return null
    return shortestPath(visibleLinks, 'inet', selected.id)
  }, [tracePath, selected, visibleLinks])

  const attackEdges = useMemo(() => {
    if (!attackPath) return new Set<string>()
    const s = new Set<string>()
    for (let i = 0; i < attackPath.length - 1; i++) {
      s.add(`${attackPath[i]}|${attackPath[i + 1]}`)
      s.add(`${attackPath[i + 1]}|${attackPath[i]}`)
    }
    return s
  }, [attackPath])

  const searchMatch = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return null
    return visibleNodes.find((n) => n.hostname.toLowerCase().includes(q) || n.ip.includes(q)) ?? null
  }, [search, visibleNodes])

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') { setSelectedId(null); setTracePath(false) } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  /* ── Pointer interactions: drag nodes, pan canvas, wheel zoom ──── */
  const toSvg = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current
    if (!svg) return { x: 0, y: 0 }
    const rect = svg.getBoundingClientRect()
    return {
      x: vb.x + ((clientX - rect.left) / rect.width) * vb.w,
      y: vb.y + ((clientY - rect.top) / rect.height) * vb.h,
    }
  }, [vb])

  const onNodePointerDown = (id: string) => (e: React.PointerEvent) => {
    e.stopPropagation()
    ;(e.target as Element).setPointerCapture?.(e.pointerId)
    const p = toSvg(e.clientX, e.clientY)
    dragRef.current = { kind: 'node', id, startX: p.x, startY: p.y, startClientX: e.clientX, startClientY: e.clientY, moved: false }
  }

  const onCanvasPointerDown = (e: React.PointerEvent) => {
    svgRef.current?.setPointerCapture?.(e.pointerId)   // keep the pan smooth past the edge
    dragRef.current = { kind: 'pan', startX: 0, startY: 0, startClientX: e.clientX, startClientY: e.clientY, vb: { ...vb }, moved: false }
  }

  const onPointerMove = (e: React.PointerEvent) => {
    const drag = dragRef.current
    if (!drag) return
    const p = toSvg(e.clientX, e.clientY)
    if (drag.kind === 'node' && drag.id) {
      drag.moved = true
      setNodes((prev) => prev.map((n) => (n.id === drag.id
        ? { ...n, x: Math.max(20, Math.min(VB_W - 20, p.x)), y: Math.max(20, Math.min(VB_H - 20, p.y)) }
        : n)))
    } else if (drag.kind === 'pan' && drag.vb) {
      drag.moved = true
      // Pan in SCREEN pixels against the ORIGINAL viewBox so the frame doesn't
      // chase itself (that feedback was the "shake"); 1:1 follow under the cursor.
      const rect = svgRef.current?.getBoundingClientRect()
      if (!rect) return
      const dx = ((e.clientX - drag.startClientX) / rect.width) * drag.vb.w
      const dy = ((e.clientY - drag.startClientY) / rect.height) * drag.vb.h
      setVb({ ...drag.vb, x: drag.vb.x - dx, y: drag.vb.y - dy })
    }
  }

  const onPointerUp = (id?: string) => () => {
    const drag = dragRef.current
    dragRef.current = null
    if (drag && !drag.moved && drag.kind === 'node' && id) {
      setSelectedId((cur) => (cur === id ? null : id))
      setTracePath(false)
    }
    if (drag && !drag.moved && drag.kind === 'pan') {
      setSelectedId(null)
      setTracePath(false)
    }
  }

  // Zoom toward a fractional anchor (fx,fy in 0..1 of the SVG box; default
  // centre). The anchor's user-space point is derived from the LIVE `prev`
  // inside the updater — not a mirrored ref — so a fast/held pinch doesn't
  // drift the centre and wobble. ViewBox values are rounded to kill the
  // sub-pixel shimmer that also reads as "shake".
  const zoomBy = useCallback((factor: number, fx = 0.5, fy = 0.5) => {
    setVb((prev) => {
      const w = Math.max(280, Math.min(VB_W * 1.4, prev.w * factor))
      const h = w * (VB_H / VB_W)
      const ax = prev.x + fx * prev.w
      const ay = prev.y + fy * prev.h
      const round = (n: number) => Math.round(n * 100) / 100
      return { x: round(ax - fx * w), y: round(ay - fy * h), w: round(w), h: round(h) }
    })
  }, [])

  // Button zoom takes one big step, so ease it (wheel/pinch stays instant —
  // it's already incremental and must track the finger). Reduced motion jumps.
  const vbRef = useRef(vb)
  useEffect(() => { vbRef.current = vb }, [vb])
  const smoothZoom = useCallback((factor: number) => {
    const from = { ...vbRef.current }
    const w = Math.max(280, Math.min(VB_W * 1.4, from.w * factor))
    const h = w * (VB_H / VB_W)
    const target = { x: from.x + 0.5 * (from.w - w), y: from.y + 0.5 * (from.h - h), w, h }
    if (reduced) { setVb(target); return }
    animate(0, 1, {
      duration: DUR.base,
      ease: [...EASE],
      onUpdate: (t) => setVb({
        x: from.x + (target.x - from.x) * t,
        y: from.y + (target.y - from.y) * t,
        w: from.w + (target.w - from.w) * t,
        h: from.h + (target.h - from.h) * t,
      }),
    })
  }, [reduced])

  // Wheel: zoom ONLY on a pinch gesture (ctrl+wheel - how trackpads report
  // pinch). A normal scroll passes straight through to the page. Native,
  // non-passive listener so preventDefault can stop the browser's own page
  // pinch-zoom; passes a fractional cursor anchor so it never re-subscribes.
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const onWheelNative = (e: WheelEvent) => {
      if (!e.ctrlKey) return
      e.preventDefault()
      const rect = svg.getBoundingClientRect()
      const fx = (e.clientX - rect.left) / rect.width
      const fy = (e.clientY - rect.top) / rect.height
      zoomBy(e.deltaY > 0 ? 1.08 : 0.92, fx, fy)
    }
    svg.addEventListener('wheel', onWheelNative, { passive: false })
    return () => svg.removeEventListener('wheel', onWheelNative)
  }, [zoomBy])

  function toggleZone(z: Zone) {
    setZoneVisibility((prev) => ({ ...prev, [z]: !prev[z] }))
  }

  /* KPIs computed from the actual graph, not hardcoded. */
  const kpis = useMemo(() => {
    const real = visibleNodes.filter((n) => n.id !== 'inet')
    return [
      { label: 'Nodes',            value: String(real.length),                                          color: 'text-white' },
      { label: 'Connections',      value: String(visibleLinks.length),                                  color: 'text-violet' },
      { label: 'Exposed Services', value: String(real.reduce((s, n) => s + n.ports.length, 0)),         color: 'text-amber' },
      { label: 'Critical Assets',  value: String(real.filter((n) => n.risk === 'critical').length),     color: 'text-threat' },
    ]
  }, [visibleNodes, visibleLinks])

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 px-6 py-4 border-b border-white/5 shrink-0 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-violet" />
            <h1 className="text-lg font-display font-semibold text-white">Network Map</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Asset topology · drag to pan, pinch to zoom, click for detail</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
            <input
              value={search}
              onChange={(e) => { setSearch(e.target.value) }}
              onKeyDown={(e) => { if (e.key === 'Enter' && searchMatch) { setSelectedId(searchMatch.id); setSearch('') } }}
              placeholder="Find host or IP…"
              className="w-44 pl-8 pr-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-[11px] text-ink-100 placeholder-ink-600 focus:outline-none focus:border-magenta/40"
            />
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

      {/* Map */}
      <div className="flex-1 relative overflow-hidden select-none">
        <svg
          ref={svgRef}
          viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
          preserveAspectRatio="xMidYMid meet"
          className="w-full h-full touch-none"
          onPointerDown={onCanvasPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp()}
          style={{ cursor: 'grab' }}
        >
          <defs>
            <radialGradient id="nm-bg" cx="50%" cy="38%" r="75%">
              <stop offset="0%" stopColor="#171030" stopOpacity="0.85" />
              <stop offset="100%" stopColor="#0A0612" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="nm-link" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={tk('violet')} stopOpacity="0.55" />
              <stop offset="100%" stopColor={tk('teal')} stopOpacity="0.4" />
            </linearGradient>
            <filter id="nm-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="3.5" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <pattern id="nm-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke={withAlpha(tk('violet'), 0.07)} strokeWidth="1" />
            </pattern>
          </defs>

          <rect x={-VB_W} y={-VB_H} width={VB_W * 3} height={VB_H * 3} fill="url(#nm-grid)" />
          <rect x="0" y="0" width={VB_W} height={VB_H} fill="url(#nm-bg)" />

          {/* Zone panels */}
          {(Object.keys(ZONE_RECTS) as Zone[]).map((z) => {
            if (!zoneVisibility[z]) return null
            const r = ZONE_RECTS[z]
            const meta = ZONE_META[z]
            return (
              <g key={z} pointerEvents="none">
                <rect x={r.x} y={r.y} width={r.w} height={r.h} rx={18}
                  fill={meta.color} fillOpacity={0.045}
                  stroke={meta.color} strokeOpacity={0.22} strokeWidth={1} strokeDasharray="3 6" />
                <rect x={r.x + 12} y={r.y - 9} width={meta.label.length * 6.4 + 22} height={18} rx={9}
                  fill="#100A1C" stroke={meta.color} strokeOpacity={0.45} strokeWidth={1} />
                <circle cx={r.x + 22} cy={r.y} r={2.6} fill={meta.color} />
                <text x={r.x + 30} y={r.y + 3.2} fontSize={9} fontWeight={600} fill={meta.color}
                  fontFamily="system-ui,sans-serif" letterSpacing="0.08em">{meta.label.toUpperCase()}</text>
              </g>
            )
          })}

          {/* Links */}
          <g pointerEvents="none">
            {visibleLinks.map((l, i) => {
              const a = nodeMap[l.from]
              const b = nodeMap[l.to]
              if (!a || !b) return null
              const onAttackPath = attackEdges.has(`${l.from}|${l.to}`)
              const active = !!focusId && (l.from === focusId || l.to === focusId)
              const dim = (!!focusId && !active && !onAttackPath) || (!!attackPath && !onAttackPath)
              const d = linkPath(a, b)
              const pid = `lk-${i}`
              return (
                <g key={pid}>
                  {/* draw in once on mount; MotionConfig covers reduced motion */}
                  <motion.path id={pid} d={d} fill="none"
                    initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
                    transition={{ duration: DUR.slow, delay: Math.min(i * 0.03, 0.5), ease: [...EASE] }}
                    stroke={onAttackPath ? tk('magenta') : active ? '#B98AFF' : 'url(#nm-link)'}
                    strokeWidth={onAttackPath ? 2.4 : active ? 1.8 : 1.1}
                    strokeOpacity={dim ? 0.07 : onAttackPath ? 0.95 : active ? 0.85 : 0.4} />
                  {/* Traffic particle — SMIL, so gate on reduced motion directly */}
                  {!dim && !reduced && (
                    <circle r={onAttackPath ? 3 : 1.8}
                      fill={onAttackPath ? tk('magenta') : '#B98AFF'}
                      opacity={onAttackPath ? 1 : 0.75}
                      filter={onAttackPath ? 'url(#nm-glow)' : undefined}>
                      <animateMotion dur={`${2.4 + (i % 5) * 0.45}s`} repeatCount="indefinite"
                        begin={`${(i % 7) * 0.35}s`}>
                        <mpath href={`#${pid}`} />
                      </animateMotion>
                    </circle>
                  )}
                </g>
              )
            })}
          </g>

          {/* Nodes */}
          <g>
            {visibleNodes.map((n, nodeIdx) => {
              const Icon = TYPE_ICON[n.type]
              const riskColor = RISK_META[n.risk].color
              const zoneColor = n.id === 'inet' ? tk('magenta') : ZONE_META[n.zone].color
              const isSel = selectedId === n.id
              const isFocus = focusId === n.id
              const inHood = !focusId || neighborhood?.has(n.id)
              const onPath = attackPath?.includes(n.id)
              const dim = (!inHood && !onPath) || (!!attackPath && !onPath)
              const isMatch = searchMatch?.id === n.id
              const r = n.type === 'internet' ? 24 : n.type === 'workstation' ? 15 : 18
              const arc = 2 * Math.PI * (r + 4)
              return (
                <g key={n.id}
                  transform={`translate(${n.x}, ${n.y})`}
                  opacity={dim ? 0.22 : 1}
                  style={{ cursor: 'pointer', transition: 'opacity 0.25s' }}
                  onPointerDown={onNodePointerDown(n.id)}
                  onPointerUp={onPointerUp(n.id)}
                  onMouseEnter={() => setHoverId(n.id)}
                  onMouseLeave={() => setHoverId(null)}>
                  {/* inner group scales in on mount (staggered); the outer g
                     owns the translate so the entrance can't fight the drag */}
                  <motion.g
                    initial={{ scale: 0.5, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ duration: DUR.base, delay: Math.min(nodeIdx * 0.025, 0.45), ease: [...EASE] }}>

                  {/* Critical pulse / selection ring — SMIL, gated on reduced motion */}
                  {(isSel || isMatch || (n.risk === 'critical' && !dim)) && (
                    <circle r={r + 11} fill="none" stroke={isMatch ? tk('safe') : riskColor} strokeWidth={1.2} opacity={0.5}>
                      {!reduced && <>
                        <animate attributeName="r" values={`${r + 7};${r + 15};${r + 7}`} dur="2.2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.5;0;0.5" dur="2.2s" repeatCount="indefinite" />
                      </>}
                    </circle>
                  )}

                  {/* Risk arc: how much of the ring is filled = risk score */}
                  <circle r={r + 4} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={2.4} />
                  <circle r={r + 4} fill="none" stroke={riskColor} strokeWidth={2.4}
                    strokeLinecap="round"
                    strokeDasharray={`${(n.riskScore / 100) * arc} ${arc}`}
                    transform="rotate(-90)" opacity={0.9} />

                  {/* Body */}
                  <circle r={r} fill="#130C24" stroke={zoneColor} strokeWidth={isSel || isFocus ? 2 : 1.2}
                    strokeOpacity={isSel || isFocus ? 1 : 0.65}
                    filter={n.risk === 'critical' && !dim ? 'url(#nm-glow)' : undefined} />
                  <circle r={r} fill={riskColor} fillOpacity={0.1} />
                  {n.live && (
                    <circle cx={r - 3} cy={-r + 3} r={3.4} fill={tk('safe')} stroke="#0A0612" strokeWidth={1.4}>
                      {!reduced && <animate attributeName="opacity" values="1;0.4;1" dur="1.8s" repeatCount="indefinite" />}
                    </circle>
                  )}
                  <foreignObject x={-10} y={-10} width={20} height={20} style={{ pointerEvents: 'none' }}>
                    <div className="w-[20px] h-[20px] flex items-center justify-center">
                      <Icon width={n.type === 'internet' ? 16 : 13} height={n.type === 'internet' ? 16 : 13} color={isFocus ? '#fff' : zoneColor} />
                    </div>
                  </foreignObject>

                  {/* Persistent label */}
                  <text y={r + 14} textAnchor="middle" fontSize={8.5}
                    fill={isFocus ? '#FFFFFF' : '#9C92B8'} fontFamily="ui-monospace,monospace"
                    style={{ pointerEvents: 'none', transition: 'fill 0.2s' }}>
                    {n.hostname.length > 18 ? n.hostname.slice(0, 17) + '…' : n.hostname}
                  </text>
                  {/* Risk score on hover/selection */}
                  {isFocus && (
                    <g pointerEvents="none">
                      <rect x={-17} y={-r - 22} width={34} height={15} rx={7.5}
                        fill="#100A1C" stroke={riskColor} strokeOpacity={0.6} strokeWidth={1} />
                      <text y={-r - 11} textAnchor="middle" fontSize={8.5} fontWeight={700}
                        fill={riskColor} fontFamily="ui-monospace,monospace">{n.riskScore}</text>
                    </g>
                  )}
                  </motion.g>
                </g>
              )
            })}
          </g>
        </svg>

        {/* Zoom controls */}
        <div className="absolute top-4 left-4 flex flex-col gap-1 rounded-xl border border-white/10 bg-surface/90 backdrop-blur-sm p-1">
          <button onClick={() => smoothZoom(0.8)} title="Zoom in"
            className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/8 transition-colors"><Plus className="w-3.5 h-3.5" /></button>
          <button onClick={() => smoothZoom(1.25)} title="Zoom out"
            className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/8 transition-colors"><Minus className="w-3.5 h-3.5" /></button>
          <button onClick={() => setVb({ x: 0, y: 0, w: VB_W, h: VB_H })} title="Reset view"
            className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/8 transition-colors"><Maximize2 className="w-3.5 h-3.5" /></button>
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 rounded-xl border border-white/8 bg-surface/90 backdrop-blur-sm px-3 py-2.5 space-y-2">
          <div>
            <p className="text-[9px] text-ink-500 uppercase tracking-wider mb-1 flex items-center gap-1"><Layers className="w-2.5 h-2.5" /> Ring = zone</p>
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
            <p className="text-[9px] text-ink-500 uppercase tracking-wider mb-1">Arc = risk score</p>
            <div className="flex flex-col gap-1">
              {(Object.keys(RISK_META) as Risk[]).map((rk) => (
                <div key={rk} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: RISK_META[rk].color }} />
                  <span className="text-[10px] text-ink-400">{RISK_META[rk].label}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="pt-1.5 border-t border-white/5 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-safe animate-pulse" />
            <span className="text-[10px] text-ink-400">Live inventory asset</span>
          </div>
        </div>

        {/* Hint */}
        {!selected && (
          <div className="absolute bottom-4 right-4 flex items-center gap-1.5 text-[10px] text-ink-600 pointer-events-none">
            <MousePointer2 className="w-3 h-3" /> drag to pan · pinch to zoom · drag nodes to rearrange
          </div>
        )}

        {/* Detail side panel */}
        <AnimatePresence>
          {selected && (
            <motion.div
              initial={{ x: '110%', opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: '110%', opacity: 0 }}
              transition={{ type: 'spring', damping: 30, stiffness: 280 }}
              className="absolute top-4 right-4 bottom-4 w-72 rounded-2xl border border-white/10 bg-surface/95 backdrop-blur-md shadow-2xl overflow-y-auto">
              {(() => {
                const n = selected
                const Icon = TYPE_ICON[n.type]
                const color = RISK_META[n.risk].color
                const conns = links
                  .filter((l) => l.from === n.id || l.to === n.id)
                  .map((l) => nodeMap[l.from === n.id ? l.to : l.from])
                  .filter(Boolean)
                return (
                  <div className="p-4 space-y-4">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="p-2 rounded-lg shrink-0" style={{ background: color + '1a' }}>
                          <Icon className="w-4 h-4" style={{ color }} />
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-white truncate">{n.hostname}</p>
                          <p className="text-[10px] text-ink-500">{TYPE_LABEL[n.type]}{n.live ? ' · live inventory' : ''}</p>
                        </div>
                      </div>
                      <button onClick={() => { setSelectedId(null); setTracePath(false) }} className="p-1 rounded text-ink-500 hover:text-white shrink-0">
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="flex items-center justify-between rounded-xl border border-white/8 bg-white/3 px-3 py-2.5">
                      <div>
                        <p className="text-[9px] text-ink-500 uppercase tracking-wider">Risk Score</p>
                        <p className="text-lg font-bold font-mono" style={{ color }}>{n.riskScore}</p>
                      </div>
                      <span className="px-2 py-1 rounded-full text-[10px] font-semibold" style={{ color, background: color + '18' }}>
                        {RISK_META[n.risk].label}
                      </span>
                    </div>

                    {n.id !== 'inet' && (
                      <button
                        onClick={() => setTracePath((t) => !t)}
                        className={cn('w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold border transition-all',
                          tracePath
                            ? 'bg-magenta/15 text-magenta border-magenta/40'
                            : 'text-ink-300 border-white/10 hover:text-white hover:border-white/20')}>
                        <Route className="w-3.5 h-3.5" />
                        {tracePath
                          ? (attackPath ? `Attack path: ${attackPath.length - 1} hops from internet` : 'No path from internet')
                          : 'Trace attack path from internet'}
                      </button>
                    )}

                    <div className="space-y-1.5">
                      {[
                        { label: 'IP Address', value: n.ip, icon: MapPin },
                        { label: 'Zone', value: ZONE_META[n.zone].label, icon: Layers },
                        { label: 'Type', value: TYPE_LABEL[n.type], icon: Activity },
                      ].map(({ label, value, icon: I }) => (
                        <div key={label} className="flex items-center justify-between gap-2 py-1.5 border-b border-white/4 last:border-0">
                          <span className="text-[10px] text-ink-500 flex items-center gap-1.5"><I className="w-3 h-3" />{label}</span>
                          <span className="text-[10px] text-ink-200 font-mono text-right truncate">{value}</span>
                        </div>
                      ))}
                    </div>

                    <div>
                      <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><Lock className="w-3 h-3" /> Open Ports</p>
                      {n.ports.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {n.ports.map((p) => (
                            <span key={p} className="font-mono text-[10px] px-2 py-0.5 rounded bg-white/5 border border-white/8 text-ink-300">{p}</span>
                          ))}
                        </div>
                      ) : <p className="text-[10px] text-ink-600">No exposed ports</p>}
                    </div>

                    <div>
                      <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><Network className="w-3 h-3" /> Connected Nodes ({conns.length})</p>
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
    </div>
  )
}
