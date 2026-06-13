'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'
import { fetchGeo, type GeoCountry } from '@/lib/api'

/* Equirectangular projection onto a 360x180 viewBox (1 unit = 1 degree). */
const W = 360
const H = 180
const project = (lon: number, lat: number): [number, number] => [lon + 180, 90 - lat]

/* Hand-drawn coastline (subtle land fill). Kept from the original map. */
const LAND: number[][][] = [
  [[-168,65],[-162,70],[-156,71],[-140,70],[-125,72],[-110,74],[-95,72],[-80,68],[-64,60],[-56,50],[-67,45],[-70,44],[-74,40],[-75,38],[-81,31],[-80,25],[-82,28],[-90,29],[-97,26],[-97,21],[-95,19],[-91,19],[-90,21],[-87,21],[-88,16],[-92,15],[-97,16],[-105,20],[-110,23],[-112,26],[-117,33],[-120,34],[-124,40],[-125,49],[-130,54],[-135,58],[-140,60],[-148,60],[-153,57],[-158,57],[-166,60],[-168,65]],
  [[-45,60],[-30,60],[-20,64],[-18,70],[-22,76],[-32,82],[-45,83],[-58,82],[-55,76],[-58,70],[-53,66],[-45,60]],
  [[-81,7],[-77,8],[-77,1],[-80,-3],[-81,-6],[-77,-12],[-70,-18],[-71,-24],[-71,-30],[-73,-38],[-75,-46],[-69,-52],[-66,-55],[-64,-53],[-65,-48],[-62,-40],[-57,-34],[-48,-25],[-40,-22],[-35,-8],[-35,-5],[-44,-2],[-50,0],[-52,4],[-60,8],[-66,11],[-72,12],[-77,8],[-81,7]],
  [[-17,15],[-16,21],[-10,27],[-6,32],[-2,36],[10,37],[11,33],[20,32],[25,32],[32,31],[34,28],[35,23],[37,18],[39,15],[43,11],[51,12],[51,8],[48,5],[42,-1],[40,-4],[40,-11],[35,-17],[35,-24],[32,-26],[26,-34],[20,-35],[18,-34],[15,-27],[12,-17],[13,-9],[9,-1],[9,4],[4,6],[-4,5],[-8,5],[-13,8],[-16,12],[-17,15]],
  [[-10,37],[-9,43],[-2,43],[-2,48],[2,51],[4,52],[7,53],[8,57],[5,58],[8,62],[11,64],[14,68],[20,70],[26,71],[30,68],[28,60],[24,60],[24,57],[20,55],[14,54],[12,55],[8,54],[3,51],[-2,49],[-5,48],[-9,44],[-10,37]],
  [[26,41],[35,42],[40,44],[48,46],[55,50],[60,55],[68,55],[68,40],[57,42],[53,37],[57,25],[60,25],[57,20],[52,16],[48,24],[44,39],[40,40],[35,37],[28,41],[26,41]],
  [[60,55],[66,55],[68,68],[80,73],[105,78],[140,73],[160,70],[170,66],[165,62],[160,60],[155,52],[142,46],[140,36],[135,35],[130,43],[127,34],[122,40],[122,30],[117,24],[109,18],[105,10],[103,1],[97,8],[100,14],[92,21],[88,22],[80,13],[77,8],[73,16],[70,21],[67,25],[62,25],[58,30],[55,40],[55,50],[60,55]],
  [[130,31],[136,35],[141,40],[142,45],[140,42],[137,37],[132,33],[130,31]],
  [[95,5],[105,1],[110,-3],[117,-4],[119,0],[125,1],[131,-1],[141,-2],[150,-6],[141,-9],[131,-4],[120,-9],[110,-8],[100,0],[95,5]],
  [[114,-22],[122,-18],[130,-12],[137,-12],[142,-11],[146,-19],[150,-25],[153,-28],[150,-38],[143,-39],[137,-36],[129,-32],[122,-34],[115,-34],[114,-22]],
]

const LAND_PATHS = LAND.map((poly) =>
  poly.map(([lon, lat], i) => `${i ? 'L' : 'M'}${project(lon, lat).join(' ')}`).join(' ') + 'Z')

/* Country centroid (lat, lon) + flag, for every name /overview/geo can emit
   (its _CC ISO->name normalization). Markers are placed here. */
const COUNTRY: Record<string, { lat: number; lon: number; flag: string }> = {
  'Russia': { lat: 55, lon: 50, flag: '🇷🇺' }, 'China': { lat: 35, lon: 105, flag: '🇨🇳' },
  'North Korea': { lat: 40, lon: 127, flag: '🇰🇵' }, 'Iran': { lat: 32, lon: 53, flag: '🇮🇷' },
  'United States': { lat: 39, lon: -98, flag: '🇺🇸' }, 'Brazil': { lat: -10, lon: -52, flag: '🇧🇷' },
  'Netherlands': { lat: 52, lon: 5, flag: '🇳🇱' }, 'Romania': { lat: 46, lon: 25, flag: '🇷🇴' },
  'Vietnam': { lat: 16, lon: 106, flag: '🇻🇳' }, 'Nigeria': { lat: 9, lon: 8, flag: '🇳🇬' },
  'India': { lat: 22, lon: 79, flag: '🇮🇳' }, 'United Kingdom': { lat: 54, lon: -2, flag: '🇬🇧' },
  'Germany': { lat: 51, lon: 10, flag: '🇩🇪' }, 'Ukraine': { lat: 49, lon: 32, flag: '🇺🇦' },
  'Egypt': { lat: 27, lon: 30, flag: '🇪🇬' }, 'Australia': { lat: -25, lon: 133, flag: '🇦🇺' },
  'Japan': { lat: 36, lon: 138, flag: '🇯🇵' }, 'South Korea': { lat: 36, lon: 128, flag: '🇰🇷' },
  'Singapore': { lat: 1.3, lon: 103.8, flag: '🇸🇬' }, 'UAE': { lat: 24, lon: 54, flag: '🇦🇪' },
  'France': { lat: 47, lon: 2, flag: '🇫🇷' }, 'Italy': { lat: 42, lon: 12, flag: '🇮🇹' },
  'Spain': { lat: 40, lon: -4, flag: '🇪🇸' }, 'Turkey': { lat: 39, lon: 35, flag: '🇹🇷' },
  'Pakistan': { lat: 30, lon: 70, flag: '🇵🇰' }, 'Indonesia': { lat: -2, lon: 118, flag: '🇮🇩' },
  'Mexico': { lat: 23, lon: -102, flag: '🇲🇽' }, 'Canada': { lat: 56, lon: -106, flag: '🇨🇦' },
  'Poland': { lat: 52, lon: 19, flag: '🇵🇱' }, 'Belarus': { lat: 53, lon: 28, flag: '🇧🇾' },
}

/* A point representing the monitored environment - arcs converge here so the
   map reads as "origins -> what we observed", not a claim about geography. */
const HOME = project(15, 30)

type Origin = GeoCountry & { x: number; y: number; flag: string; sev: 'critical' | 'high' | 'medium' }

const SEV_COLOR = { critical: '#FF2E97', high: '#FF4D6D', medium: '#FFB23E' } as const

function severityOf(c: GeoCountry): 'critical' | 'high' | 'medium' {
  if (c.critical > 0) return 'critical'
  if (c.high > 0) return 'high'
  return 'medium'
}

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

function arcPath(x1: number, y1: number, x2: number, y2: number): string {
  const mx = (x1 + x2) / 2
  const my = (y1 + y2) / 2 - Math.hypot(x2 - x1, y2 - y1) * 0.32
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`
}

/**
 * Live attack origins map. Every marker is a country the platform has REALLY
 * observed attacks from (/overview/geo, derived from alerts.src_country) -
 * sized by observed volume, coloured by its worst severity. Hovering a marker
 * or a row in the ranked panel highlights both and shows the detail. No
 * hardcoded "attack" numbers; an honest empty state when nothing is observed.
 */
export default function WorldMap() {
  const [geo, setGeo] = useState<{ countries: GeoCountry[]; totalGeolocated: number } | null>(null)
  const [hover, setHover] = useState<string | null>(null)
  const wrapRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const load = () => fetchGeo(20).then(setGeo).catch(() => {})
    load()
    const t = setInterval(load, 20000) // live refresh
    return () => clearInterval(t)
  }, [])

  const origins = useMemo<Origin[]>(() => {
    if (!geo) return []
    return geo.countries
      .filter((c) => COUNTRY[c.country])
      .map((c) => {
        const { lat, lon, flag } = COUNTRY[c.country]
        const [x, y] = project(lon, lat)
        return { ...c, x, y, flag, sev: severityOf(c) }
      })
  }, [geo])

  const maxObs = Math.max(1, ...origins.map((o) => o.observed))
  const topArcs = origins.slice(0, 6)
  const active = hover ? origins.find((o) => o.country === hover) ?? null : null
  const totalObserved = geo?.totalGeolocated ?? 0

  /* radius scales with sqrt(volume) so large origins don't swamp the map */
  const radius = (obs: number) => 1.6 + Math.sqrt(obs / maxObs) * 3.6

  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-magenta/60" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-magenta" />
          </span>
          <h3 className="text-sm font-semibold text-white">Live Attack Origins</h3>
        </div>
        <span className="text-[10px] text-ink-500">
          <span className="font-mono text-ink-300">{totalObserved.toLocaleString()}</span> observed
          {origins.length > 0 && <> · {origins.length} countries</>}
        </span>
      </div>

      <div className="grid lg:grid-cols-[1.55fr_1fr]">
        {/* ── Map ── */}
        <div ref={wrapRef} className="relative border-b lg:border-b-0 lg:border-r border-white/5">
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full block" style={{ aspectRatio: '2 / 1' }}>
            <defs>
              <radialGradient id="wm-glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#FF2E97" stopOpacity="0.18" />
                <stop offset="100%" stopColor="#FF2E97" stopOpacity="0" />
              </radialGradient>
            </defs>

            {/* subtle grid */}
            {[30, 60, 90, 120, 150].map((x) => (
              <line key={`v${x}`} x1={x} y1={0} x2={x} y2={H} stroke="rgba(255,255,255,0.03)" strokeWidth={0.3} />
            ))}
            {[45, 90, 135].map((y) => (
              <line key={`h${y}`} x1={0} y1={y} x2={W} y2={y} stroke="rgba(255,255,255,0.03)" strokeWidth={0.3} />
            ))}

            {/* land */}
            {LAND_PATHS.map((d, i) => (
              <path key={i} d={d} fill="rgba(122,60,255,0.06)" stroke="rgba(255,255,255,0.10)" strokeWidth={0.4} />
            ))}

            {/* converge node */}
            <circle cx={HOME[0]} cy={HOME[1]} r={1.4} fill="#34F5C5" opacity={0.7} />
            <circle cx={HOME[0]} cy={HOME[1]} r={3} fill="none" stroke="#34F5C5" strokeWidth={0.3} opacity={0.4}>
              <animate attributeName="r" values="2;6;2" dur="3s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.5;0;0.5" dur="3s" repeatCount="indefinite" />
            </circle>

            {/* live arcs from top origins -> converge node */}
            {topArcs.map((o) => {
              const isActive = active?.country === o.country
              const c = SEV_COLOR[o.sev]
              return (
                <path
                  key={`arc-${o.country}`}
                  d={arcPath(o.x, o.y, HOME[0], HOME[1])}
                  fill="none"
                  stroke={c}
                  strokeWidth={isActive ? 0.8 : 0.45}
                  strokeOpacity={hover && !isActive ? 0.12 : 0.4}
                  strokeDasharray="2 4"
                  style={{ transition: 'stroke-opacity .25s, stroke-width .25s' }}
                >
                  <animate attributeName="stroke-dashoffset" from="6" to="0" dur="1.1s" repeatCount="indefinite" />
                </path>
              )
            })}

            {/* origin markers */}
            {origins.map((o) => {
              const r = radius(o.observed)
              const c = SEV_COLOR[o.sev]
              const isActive = active?.country === o.country
              const dim = hover && !isActive
              return (
                <g
                  key={o.country}
                  style={{ cursor: 'pointer', transition: 'opacity .25s' }}
                  opacity={dim ? 0.35 : 1}
                  onMouseEnter={() => setHover(o.country)}
                  onMouseLeave={() => setHover((h) => (h === o.country ? null : h))}
                >
                  <circle cx={o.x} cy={o.y} r={r * 3} fill="url(#wm-glow)" />
                  {/* pulse ring */}
                  <circle cx={o.x} cy={o.y} r={r} fill="none" stroke={c} strokeWidth={0.5} opacity={0.6}>
                    <animate attributeName="r" values={`${r};${r * 2.4};${r}`} dur="2.4s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.6;0;0.6" dur="2.4s" repeatCount="indefinite" />
                  </circle>
                  <circle
                    cx={o.x} cy={o.y}
                    r={isActive ? r * 1.5 : r}
                    fill={c}
                    style={{ transition: 'r .2s ease' }}
                  />
                  {isActive && <circle cx={o.x} cy={o.y} r={r * 2.2} fill="none" stroke={c} strokeWidth={0.6} />}
                </g>
              )
            })}
          </svg>

          {/* empty state */}
          {geo && origins.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center">
              <p className="text-[11px] text-ink-600 max-w-[260px] text-center px-4">
                No attack origins observed yet. Countries light up here as the engine
                records the source of real alerts.
              </p>
            </div>
          )}

          {/* tooltip */}
          <AnimatePresence>
            {active && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 4 }}
                transition={{ duration: 0.14 }}
                className="absolute z-20 pointer-events-none rounded-lg border border-white/10 bg-[#0B0712]/95 backdrop-blur px-3 py-2 shadow-xl"
                style={{
                  left: `${Math.min(70, (active.x / W) * 100)}%`,
                  top: `${Math.max(4, (active.y / H) * 100 - 4)}%`,
                }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm">{active.flag}</span>
                  <span className="text-xs font-semibold text-white">{active.country}</span>
                </div>
                <p className="text-[11px] text-ink-300">
                  <span className="font-mono" style={{ color: SEV_COLOR[active.sev] }}>
                    {active.observed.toLocaleString()}
                  </span>{' '}
                  observed {active.observed === 1 ? 'alert' : 'alerts'}
                </p>
                <p className="text-[10px] text-ink-600 mt-0.5">
                  {active.critical > 0 && <span className="text-magenta">{active.critical} critical</span>}
                  {active.critical > 0 && active.high > 0 && ' · '}
                  {active.high > 0 && <span className="text-threat">{active.high} high</span>}
                  {(active.critical > 0 || active.high > 0) && ' · '}
                  last {relTime(active.lastSeen)}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* ── Top countries panel ── */}
        <div className="p-3">
          <p className="text-[10px] font-semibold text-ink-400 uppercase tracking-wide px-2 mb-1.5">
            Top origin countries
          </p>
          {(!geo || origins.length === 0) ? (
            <p className="text-[11px] text-ink-600 px-2 py-6 text-center">
              {geo ? 'No observed origins yet.' : 'Loading observed origins…'}
            </p>
          ) : (
            <div className="space-y-0.5 max-h-[280px] overflow-y-auto">
              {origins.slice(0, 8).map((o, i) => {
                const isActive = hover === o.country
                return (
                  <button
                    key={o.country}
                    onMouseEnter={() => setHover(o.country)}
                    onMouseLeave={() => setHover((h) => (h === o.country ? null : h))}
                    className={cn(
                      'w-full flex items-center gap-2.5 px-2 py-1.5 rounded-lg text-left transition-colors',
                      isActive ? 'bg-white/8' : 'hover:bg-white/4',
                    )}
                  >
                    <span className="text-[10px] text-ink-600 w-3">{i + 1}</span>
                    <span className="text-sm leading-none">{o.flag}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-ink-200 truncate">{o.country}</span>
                        <span className="text-[10px] font-mono text-ink-400">{o.observed.toLocaleString()}</span>
                      </div>
                      <div className="h-1 bg-surface-3 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${(o.observed / maxObs) * 100}%` }}
                          transition={{ duration: 0.6, ease: 'easeOut', delay: i * 0.04 }}
                          className="h-full rounded-full"
                          style={{ background: SEV_COLOR[o.sev] }}
                        />
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          )}
          <p className="text-[9px] text-ink-700 px-2 pt-2">
            Observed source countries of real alerts - not global statistics.
          </p>
        </div>
      </div>
    </div>
  )
}
