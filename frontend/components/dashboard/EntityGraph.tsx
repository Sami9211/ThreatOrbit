'use client'

import { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import { tk } from '@/lib/colors'

/* ─────────────────────────────────────────────────────────────────────
   Entity relationship / investigation graph.
   A deterministic radial layout (no randomness → SSR-safe): a central
   entity surrounded by grouped satellite nodes, each group occupying an
   angular sector. Edges connect the center to every satellite. Hovering a
   node highlights it and its edge and surfaces a label tooltip.
   ───────────────────────────────────────────────────────────────────── */

export type GraphGroup = {
  kind: string          // e.g. "Campaign", "IOC", "Sector", "TTP"
  color: string
  nodes: { id: string; label: string; meta?: string }[]
}

export type GraphData = {
  center: { label: string; sub?: string }
  groups: GraphGroup[]
}

const W = 760
const H = 460
const CX = W / 2
const CY = H / 2

type PlacedNode = {
  id: string; label: string; meta?: string
  x: number; y: number; color: string; kind: string
}

export default function EntityGraph({ data }: { data: GraphData }) {
  const [hover, setHover] = useState<string | null>(null)

  const nodes = useMemo<PlacedNode[]>(() => {
    const out: PlacedNode[] = []
    const groupCount = data.groups.length
    // Each group gets an angular sector; nodes fan out within it on a ring.
    const ringR = 168
    data.groups.forEach((group, gi) => {
      const sectorCenter = (gi / groupCount) * Math.PI * 2 - Math.PI / 2
      const n = group.nodes.length
      const spread = Math.min(Math.PI * 2 / groupCount * 0.82, 1.3)
      group.nodes.forEach((node, ni) => {
        const t = n === 1 ? 0 : (ni / (n - 1) - 0.5)
        const angle = sectorCenter + t * spread
        // Stagger radius slightly so labels don't collide
        const r = ringR + (ni % 2) * 34
        out.push({
          ...node,
          kind: group.kind,
          color: group.color,
          x: CX + Math.cos(angle) * r,
          y: CY + Math.sin(angle) * r,
        })
      })
    })
    return out
  }, [data])

  return (
    <div className="relative w-full overflow-hidden">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" style={{ maxHeight: 460 }}>
        <defs>
          <radialGradient id="eg-center" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={tk('magenta')} />
            <stop offset="100%" stopColor={tk('violet')} />
          </radialGradient>
          <filter id="eg-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {nodes.map((n) => {
          const active = hover === null || hover === n.id
          return (
            <line
              key={`e-${n.id}`}
              x1={CX} y1={CY} x2={n.x} y2={n.y}
              stroke={n.color}
              strokeWidth={hover === n.id ? 1.8 : 0.8}
              strokeOpacity={active ? 0.45 : 0.08}
              style={{ transition: 'stroke-opacity 0.2s, stroke-width 0.2s' }}
            />
          )
        })}

        {/* Satellite nodes */}
        {nodes.map((n) => {
          const active = hover === null || hover === n.id
          const isHover = hover === n.id
          return (
            <g key={n.id}
              onMouseEnter={() => setHover(n.id)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: 'pointer', opacity: active ? 1 : 0.25, transition: 'opacity 0.2s' }}>
              <circle cx={n.x} cy={n.y} r={isHover ? 7 : 5}
                fill={n.color} fillOpacity={0.18}
                stroke={n.color} strokeWidth={isHover ? 1.4 : 1}
                filter={isHover ? 'url(#eg-glow)' : undefined}
                style={{ transition: 'r 0.15s' }} />
              <text x={n.x} y={n.y - 11} textAnchor="middle" dominantBaseline="auto"
                fontSize={9} fontWeight={isHover ? 700 : 500}
                fill={isHover ? '#fff' : '#9a90b5'}
                fontFamily="system-ui,sans-serif"
                style={{ transition: 'fill 0.15s', pointerEvents: 'none' }}>
                {n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label}
              </text>
              {isHover && n.meta && (
                <text x={n.x} y={n.y + 16} textAnchor="middle" dominantBaseline="hanging" fontSize={7.5}
                  fill={n.color} fontFamily="system-ui,sans-serif" style={{ pointerEvents: 'none' }}>
                  {n.meta}
                </text>
              )}
            </g>
          )
        })}

        {/* Center node */}
        <g>
          <circle cx={CX} cy={CY} r={34} fill="url(#eg-center)" fillOpacity={0.16} stroke="url(#eg-center)" strokeWidth={1.5} />
          <circle cx={CX} cy={CY} r={9} fill="url(#eg-center)" filter="url(#eg-glow)" />
          <text x={CX} y={CY - 42} textAnchor="middle" fontSize={12} fontWeight={700} fill="#fff" fontFamily="system-ui,sans-serif">
            {data.center.label}
          </text>
          {data.center.sub && (
            <text x={CX} y={CY + 50} textAnchor="middle" fontSize={8} fill="#9a90b5" fontFamily="system-ui,sans-serif">
              {data.center.sub}
            </text>
          )}
        </g>
      </svg>

      {/* Group legend */}
      <div className="flex flex-wrap items-center gap-3 mt-1 px-1">
        {data.groups.map((g) => (
          <div key={g.kind} className="flex items-center gap-1.5 text-[10px] text-ink-500">
            <span className="w-2 h-2 rounded-full" style={{ background: g.color }} />
            {g.kind} <span className="text-ink-700">({g.nodes.length})</span>
          </div>
        ))}
      </div>
    </div>
  )
}
