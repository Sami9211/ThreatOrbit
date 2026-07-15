'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { geoNaturalEarth1, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import type { Feature, Geometry } from 'geojson'
import worldTopo from 'world-atlas/countries-110m.json'
import { NUM_TO_META, ISO2_TO_NUM } from '@/lib/geo/countryMeta'
import { fetchGeo, type GeoCountry } from '@/lib/api'
import { tk, withAlpha } from '@/lib/colors'

/* -- Geometry, computed once at module load (identical for every mount) ------
   The world-atlas TopoJSON ships inside the npm package (no network), keyed by
   ISO-3166 numeric ids - the same ids countryMeta maps to ISO-2 + continent, so
   we can join the API's attack counts (ISO-2) onto the polygons. Antarctica is
   dropped so the populated continents frame larger. */
const W = 1000
const H = 520
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const FC = feature(worldTopo as any, (worldTopo as any).objects.countries) as unknown as {
  features: Feature<Geometry, { name?: string }>[]
}
const FEATURES = FC.features.filter((f) => NUM_TO_META[String(f.id)]?.continent !== 'Antarctic')
const PROJECTION = geoNaturalEarth1().fitExtent([[8, 10], [W - 8, H - 12]],
  { type: 'FeatureCollection', features: FEATURES })
const PATH = geoPath(PROJECTION)
const SHAPES = FEATURES.map((f) => {
  const id = String(f.id)
  const meta = NUM_TO_META[id]
  return { id, d: PATH(f) || '', name: meta?.name || f.properties?.name || 'Unknown', continent: meta?.continent || 'Other' }
}).filter((s) => s.d)

/* -- Colour scale: cold land (no attacks) -> hot magenta (most attacks) -- */
const NODATA = '#1b1830'
// Choropleth ramp: the accent at rising opacity, so it follows the theme.
const SCALE = [0.16, 0.3, 0.48, 0.7, 1].map((a) => withAlpha(tk('magenta'), a))
function colorFor(count: number, max: number): string {
  if (count <= 0) return NODATA
  const t = Math.sqrt(count / Math.max(1, max))            // sqrt spreads the low end
  return SCALE[Math.min(SCALE.length - 1, Math.floor(t * SCALE.length))]
}

const SEV = { critical: tk('magenta'), high: tk('threat'), medium: tk('amber') }

/** ISO-2 -> flag emoji (regional indicator letters). */
function flag(iso2: string | null): string {
  if (!iso2 || iso2.length !== 2) return '🏴'
  return iso2.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)))
}

type Mode = 'country' | 'continent'
type Shape = typeof SHAPES[number]

export default function WorldMap() {
  const [data, setData] = useState<GeoCountry[]>([])
  const [loaded, setLoaded] = useState(false)
  const [mode, setMode] = useState<Mode>('country')
  const [hoverId, setHoverId] = useState<string | null>(null)        // numeric id (country mode)
  const [hoverCont, setHoverCont] = useState<string | null>(null)    // continent name (continent mode)
  const [tip, setTip] = useState<{ x: number; y: number } | null>(null)
  const wrapRef = useRef<HTMLDivElement>(null)

  // Live origins from the platform's own alert store; refresh on a gentle tick.
  useEffect(() => {
    let on = true
    const load = () => fetchGeo(200)
      .then((r) => { if (on) { setData(r.countries); setLoaded(true) } })
      .catch(() => { if (on) setLoaded(true) })
    load()
    const t = setInterval(load, 20000)
    return () => { on = false; clearInterval(t) }
  }, [])

  // numeric-id -> country, and continent -> aggregate.
  const byNum = useMemo(() => {
    const m: Record<string, GeoCountry> = {}
    for (const c of data) {
      const num = c.iso2 ? ISO2_TO_NUM[c.iso2.toUpperCase()] : undefined
      if (num) m[num] = c
    }
    return m
  }, [data])

  const byCont = useMemo(() => {
    const m: Record<string, { observed: number; critical: number; high: number; countries: number }> = {}
    for (const c of data) {
      const num = c.iso2 ? ISO2_TO_NUM[c.iso2.toUpperCase()] : undefined
      const cont = num ? NUM_TO_META[num]?.continent : undefined
      if (!cont) continue
      const g = (m[cont] ??= { observed: 0, critical: 0, high: 0, countries: 0 })
      g.observed += c.observed; g.critical += c.critical; g.high += c.high; g.countries++
    }
    return m
  }, [data])

  const max = useMemo(() => mode === 'continent'
    ? Math.max(1, ...Object.values(byCont).map((g) => g.observed))
    : Math.max(1, ...data.map((c) => c.observed)),
    [mode, data, byCont])

  const top = useMemo(() => [...data].sort((a, b) => b.observed - a.observed).slice(0, 8), [data])

  const onLeave = () => { setHoverId(null); setHoverCont(null); setTip(null) }
  // Tooltip follows the cursor; kept stable so it doesn't re-render the polygons.
  const onMove = useCallback((e: React.MouseEvent) => {
    const r = wrapRef.current?.getBoundingClientRect()
    if (r) setTip({ x: e.clientX - r.left, y: e.clientY - r.top })
  }, [])

  // Memoise the 177 country paths so moving the cursor (tooltip position only)
  // doesn't rebuild them - they recompute only when the data/mode/hover changes.
  const paths = useMemo(() => SHAPES.map((s) => {
    const datum = mode === 'continent' ? byCont[s.continent] : byNum[s.id]
    const fill = datum ? colorFor(datum.observed, max) : NODATA
    const hot = mode === 'continent' ? hoverCont === s.continent : hoverId === s.id
    return (
      <path key={s.id} d={s.d} fill={fill}
        stroke={hot ? '#FFFFFF' : 'rgba(255,255,255,0.10)'} strokeWidth={hot ? 1 : 0.4}
        onMouseEnter={() => { if (mode === 'continent') setHoverCont(s.continent); else setHoverId(s.id) }}
        onMouseMove={onMove}
        style={{ cursor: datum ? 'pointer' : 'default', filter: hot ? 'brightness(1.35)' : undefined,
          transition: 'fill 200ms ease' }} />
    )
  }), [mode, hoverId, hoverCont, byNum, byCont, max, onMove])

  // Tooltip content for the current hover.
  const tipBody = (() => {
    if (mode === 'continent' && hoverCont) {
      const g = byCont[hoverCont]
      return {
        title: hoverCont,
        lines: g
          ? [`${g.observed} attacks · ${g.countries} countr${g.countries === 1 ? 'y' : 'ies'}`, `${g.critical} critical · ${g.high} high`]
          : ['No attacks observed'],
      }
    }
    if (mode === 'country' && hoverId) {
      const c = byNum[hoverId]
      const name = SHAPES.find((s) => s.id === hoverId)?.name ?? 'Unknown'
      return {
        title: name,
        lines: c
          ? [`${c.observed} attacks observed`, `${c.critical} critical · ${c.high} high`,
             c.lastSeen ? `last ${new Date(c.lastSeen).toLocaleString()}` : '']
          : ['No attacks observed'],
      }
    }
    return null
  })()

  return (
    <div className="glass border border-white/8 rounded-2xl overflow-hidden h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-white/8 shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-magenta animate-pulse" />
          <h3 className="text-sm font-semibold text-white">Live Attack Origins</h3>
        </div>
        <span className="text-[10px] text-ink-600">
          {loaded ? `${data.reduce((s, c) => s + c.observed, 0).toLocaleString()} attacks · ${data.length} countries` : 'Loading…'}
        </span>
        {/* Mode toggle */}
        <div className="ml-auto inline-flex p-0.5 rounded-lg bg-surface-2 border border-white/8">
          {(['country', 'continent'] as Mode[]).map((m) => (
            <button key={m} onClick={() => { setMode(m); setHoverId(null); setHoverCont(null) }} aria-pressed={mode === m}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors border ${
                mode === m ? 'bg-magenta/15 text-magenta border-magenta/30' : 'text-ink-400 hover:text-white border-transparent'}`}>
              {m === 'country' ? 'Countries' : 'Continents'}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-[1fr_220px]">
        {/* Map */}
        <div ref={wrapRef} className="relative min-h-0" onMouseLeave={onLeave}>
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full" preserveAspectRatio="xMidYMid meet"
            style={{ background: `radial-gradient(ellipse 80% 80% at 50% 30%, ${withAlpha(tk('violet'), 0.07)}, transparent 70%)` }}>
            {paths}
          </svg>

          {/* Tooltip */}
          {tip && tipBody && (
            <div className="pointer-events-none absolute z-10 px-3 py-2 rounded-lg bg-surface border border-white/15 shadow-xl"
              style={{ left: Math.min(tip.x + 14, (wrapRef.current?.clientWidth ?? 9999) - 170), top: tip.y + 14 }}>
              <p className="text-xs font-semibold text-white whitespace-nowrap">{tipBody.title}</p>
              {tipBody.lines.filter(Boolean).map((l, i) => (
                <p key={i} className="text-[10px] text-ink-400 whitespace-nowrap">{l}</p>
              ))}
            </div>
          )}

          {/* Legend */}
          <div className="absolute left-3 bottom-3 flex items-center gap-1.5 px-2 py-1 rounded-lg bg-surface/70 border border-white/8 backdrop-blur-xs">
            <span className="text-[9px] text-ink-500">fewer</span>
            {SCALE.map((c) => <span key={c} className="w-3.5 h-2.5 rounded-xs" style={{ background: c }} />)}
            <span className="text-[9px] text-ink-500">more</span>
          </div>
        </div>

        {/* Top origins panel */}
        <div className="border-t lg:border-t-0 lg:border-l border-white/8 p-3 overflow-y-auto min-h-0">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-ink-500 mb-2">Top origins</p>
          {!loaded && <p className="text-[11px] text-ink-600 animate-pulse">Loading…</p>}
          {loaded && top.length === 0 && <p className="text-[11px] text-ink-600">No geolocated attacks yet.</p>}
          <div className="space-y-1">
            {top.map((c) => {
              const num = c.iso2 ? ISO2_TO_NUM[c.iso2.toUpperCase()] : undefined
              const hot = mode === 'country' ? hoverId === num : hoverCont === (num ? NUM_TO_META[num]?.continent : '')
              return (
                <button key={c.country}
                  onMouseEnter={() => { if (num) { if (mode === 'country') setHoverId(num); else setHoverCont(NUM_TO_META[num]?.continent ?? null) } }}
                  onMouseLeave={onLeave}
                  className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-left transition-colors ${
                    hot ? 'bg-magenta/10' : 'hover:bg-white/5'}`}>
                  <span className="text-sm shrink-0">{flag(c.iso2)}</span>
                  <span className="flex-1 min-w-0">
                    <span className="block text-[11px] text-ink-200 truncate">{c.country}</span>
                    <span className="block text-[9px] text-ink-600">{c.critical} crit · {c.high} high</span>
                  </span>
                  <span className="text-[11px] font-mono font-semibold shrink-0"
                    style={{ color: c.critical ? SEV.critical : c.high ? SEV.high : SEV.medium }}>
                    {c.observed}
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
