'use client'

import { useMemo, useState, useRef, useCallback } from 'react'

const W = 360
const H = 180
const project = (lon: number, lat: number): [number, number] => [lon + 180, 90 - lat]

const LAND: number[][][] = [
  [[-168,65],[-162,70],[-156,71],[-140,70],[-125,72],[-110,74],[-95,72],[-80,68],[-64,60],[-56,50],[-67,45],[-70,44],[-74,40],[-75,38],[-81,31],[-80,25],[-82,28],[-90,29],[-97,26],[-97,21],[-95,19],[-91,19],[-90,21],[-87,21],[-88,16],[-92,15],[-97,16],[-105,20],[-110,23],[-112,26],[-117,33],[-120,34],[-124,40],[-125,49],[-130,54],[-135,58],[-140,60],[-148,60],[-153,57],[-158,57],[-166,60],[-168,65]],
  [[-45,60],[-30,60],[-20,64],[-18,70],[-22,76],[-32,82],[-45,83],[-58,82],[-55,76],[-58,70],[-53,66],[-45,60]],
  [[-81,7],[-77,8],[-77,1],[-80,-3],[-81,-6],[-77,-12],[-70,-18],[-71,-24],[-71,-30],[-73,-38],[-75,-46],[-69,-52],[-66,-55],[-64,-53],[-65,-48],[-62,-40],[-57,-34],[-48,-25],[-40,-22],[-35,-8],[-35,-5],[-44,-2],[-50,0],[-52,4],[-60,8],[-66,11],[-72,12],[-77,8],[-81,7]],
  [[-17,15],[-16,21],[-10,27],[-6,32],[-2,36],[10,37],[11,33],[20,32],[25,32],[32,31],[34,28],[35,23],[37,18],[39,15],[43,11],[51,12],[51,8],[48,5],[42,-1],[40,-4],[40,-11],[35,-17],[35,-24],[32,-26],[26,-34],[20,-35],[18,-34],[15,-27],[12,-17],[13,-9],[9,-1],[9,4],[4,6],[-4,5],[-8,5],[-13,8],[-16,12],[-17,15]],
  [[-10,37],[-9,43],[-2,43],[-2,48],[2,51],[4,52],[7,53],[8,57],[5,58],[8,62],[11,64],[14,68],[20,70],[26,71],[30,68],[28,60],[24,60],[24,57],[20,55],[14,54],[12,55],[8,54],[3,51],[-2,49],[-5,48],[-9,44],[-10,37]],
  [[-6,50],[-2,51],[0,53],[-2,56],[-5,58],[-7,57],[-6,53],[-6,50]],
  [[26,41],[35,42],[40,44],[48,46],[55,50],[60,55],[68,55],[68,40],[57,42],[53,37],[57,25],[60,25],[57,20],[52,16],[48,24],[44,39],[40,40],[35,37],[28,41],[26,41]],
  [[60,55],[66,55],[68,68],[80,73],[105,78],[140,73],[160,70],[170,66],[165,62],[160,60],[155,52],[142,46],[140,36],[135,35],[130,43],[127,34],[122,40],[122,30],[117,24],[109,18],[105,10],[103,1],[97,8],[100,14],[92,21],[88,22],[80,13],[77,8],[73,16],[70,21],[67,25],[62,25],[58,30],[55,40],[55,50],[60,55]],
  [[35,30],[40,30],[48,30],[57,25],[52,16],[45,13],[43,17],[38,22],[35,28],[35,30]],
  [[130,31],[136,35],[141,40],[142,45],[140,42],[137,37],[132,33],[130,31]],
  [[95,5],[105,1],[110,-3],[117,-4],[119,0],[125,1],[131,-1],[141,-2],[150,-6],[141,-9],[131,-4],[120,-9],[110,-8],[100,0],[95,5]],
  [[120,6],[126,7],[126,16],[122,18],[120,13],[120,6]],
  [[114,-22],[122,-18],[130,-12],[137,-12],[142,-11],[146,-19],[150,-25],[153,-28],[150,-38],[143,-39],[137,-36],[129,-32],[122,-34],[115,-34],[114,-22]],
  [[167,-46],[171,-44],[174,-41],[178,-38],[176,-41],[172,-44],[167,-46]],
  [[43,-12],[50,-15],[50,-25],[45,-25],[43,-18],[43,-12]],
]

function pointInPoly(lon: number, lat: number, poly: number[][]): boolean {
  let inside = false
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1]
    const xj = poly[j][0], yj = poly[j][1]
    const intersect = yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi
    if (intersect) inside = !inside
  }
  return inside
}

const isLand = (lon: number, lat: number) => LAND.some((p) => pointInPoly(lon, lat, p))

type RegionStat = {
  id: string; name: string; count: number
  lonRange: [number, number]; latRange: [number, number]
  color: string; dotOpacity: number
}

const REGION_STATS: RegionStat[] = [
  { id: 'as', name: 'Asia',          count: 94318, lonRange: [65,  170], latRange: [0,   77], color: '#FF2E97', dotOpacity: 0.75 },
  { id: 'eu', name: 'Europe',        count: 61429, lonRange: [-12, 40],  latRange: [36,  72], color: '#7A3CFF', dotOpacity: 0.65 },
  { id: 'na', name: 'North America', count: 48231, lonRange: [-170,-50], latRange: [15,  80], color: '#FF4D6D', dotOpacity: 0.55 },
  { id: 'me', name: 'Middle East',   count: 19872, lonRange: [30,  65],  latRange: [10,  40], color: '#FFB23E', dotOpacity: 0.45 },
  { id: 'sa', name: 'South America', count: 12847, lonRange: [-82, -34], latRange: [-56, 15], color: '#FF9B2E', dotOpacity: 0.35 },
  { id: 'af', name: 'Africa',        count: 8394,  lonRange: [-18, 52],  latRange: [-36, 36], color: '#2DD4BF', dotOpacity: 0.30 },
  { id: 'oc', name: 'Oceania',       count: 6127,  lonRange: [110, 180], latRange: [-50, 0],  color: '#34F5C5', dotOpacity: 0.25 },
]

const MAX_COUNT = Math.max(...REGION_STATS.map((r) => r.count))
const REGION_PRIORITY = ['me', 'eu', 'na', 'sa', 'af', 'as', 'oc']
const regionById = Object.fromEntries(REGION_STATS.map((r) => [r.id, r]))
const HOVER_DRAW_ORDER = [...REGION_PRIORITY].reverse()

function getRegion(lon: number, lat: number): RegionStat | null {
  for (const id of REGION_PRIORITY) {
    const r = regionById[id]
    if (lon >= r.lonRange[0] && lon <= r.lonRange[1] && lat >= r.latRange[0] && lat <= r.latRange[1]) return r
  }
  return null
}

/* ── Per-country stats ───────────────────────────────────────────── */
type CountryStat = {
  country: string
  flag: string
  attacks: number
  topTypes: string[]
  topTargets: string[]
  knownActors: string[]
  color: string
}

const COUNTRY_STATS: Record<string, CountryStat> = {
  'Russia':       { country: 'Russia',        flag: '🇷🇺', attacks: 42817, topTypes: ['Ransomware', 'APT', 'Phishing', 'C2'], topTargets: ['Finance', 'Government', 'Energy'], knownActors: ['Sandworm', 'APT29', 'LockBit'], color: '#FF2E97' },
  'China':        { country: 'China',         flag: '🇨🇳', attacks: 38924, topTypes: ['APT', 'Espionage', 'Supply Chain'], topTargets: ['Defense', 'Technology', 'IP Theft'], knownActors: ['APT41', 'Volt Typhoon', 'Salt Typhoon'], color: '#FF4D6D' },
  'North Korea':  { country: 'North Korea',   flag: '🇰🇵', attacks: 18472, topTypes: ['Cryptocurrency', 'Supply Chain', 'APT'], topTargets: ['Finance', 'Crypto', 'Defense'], knownActors: ['Lazarus', 'Kimsuky', 'UNC4736'], color: '#FF2E97' },
  'Iran':         { country: 'Iran',          flag: '🇮🇷', attacks: 15834, topTypes: ['Wiper', 'DoS', 'Espionage'], topTargets: ['Israel', 'US Gov', 'Critical Infra'], knownActors: ['APT33', 'OilRig', 'Charming Kitten'], color: '#FFB23E' },
  'United States':{ country: 'United States', flag: '🇺🇸', attacks: 12847, topTypes: ['Ransomware', 'BEC', 'Phishing'], topTargets: ['Healthcare', 'Finance', 'Education'], knownActors: ['FIN7', 'Scattered Spider', 'TA505'], color: '#FF4D6D' },
  'Brazil':       { country: 'Brazil',        flag: '🇧🇷', attacks: 7241,  topTypes: ['Banking Trojan', 'Phishing', 'Credential'], topTargets: ['Banking', 'Retail', 'Telecom'], knownActors: ['Guildma', 'Prilex', 'BrasDex'], color: '#2DD4BF' },
  'United Kingdom': { country: 'United Kingdom', flag: '🇬🇧', attacks: 9832, topTypes: ['Phishing', 'Ransomware', 'BEC'], topTargets: ['Finance', 'NHS', 'Government'], knownActors: ['Clop', 'LockBit', 'BlackBasta'], color: '#7A3CFF' },
  'Germany':      { country: 'Germany',       flag: '🇩🇪', attacks: 6918,  topTypes: ['Espionage', 'Ransomware', 'Phishing'], topTargets: ['Auto', 'Pharma', 'Government'], knownActors: ['APT28', 'Fancy Bear'], color: '#2DD4BF' },
  'India':        { country: 'India',         flag: '🇮🇳', attacks: 8441,  topTypes: ['Phishing', 'Credential', 'Mobile Malware'], topTargets: ['BFSI', 'Telecom', 'Government'], knownActors: ['SideWinder', 'APT-C-35'], color: '#FFB23E' },
  'Japan':        { country: 'Japan',         flag: '🇯🇵', attacks: 5234,  topTypes: ['Supply Chain', 'Espionage', 'APT'], topTargets: ['Defense', 'Technology', 'Manufacturing'], knownActors: ['APT10', 'Tick'], color: '#FFB23E' },
  'South Korea':  { country: 'South Korea',   flag: '🇰🇷', attacks: 4891,  topTypes: ['APT', 'Ransomware', 'Phishing'], topTargets: ['Defense', 'Crypto', 'Government'], knownActors: ['Lazarus', 'Kimsuky'], color: '#2DD4BF' },
  'Singapore':    { country: 'Singapore',     flag: '🇸🇬', attacks: 3127,  topTypes: ['Phishing', 'BEC', 'Credential'], topTargets: ['Finance', 'Shipping', 'Technology'], knownActors: ['APT40', 'UNC1945'], color: '#7A3CFF' },
  'Australia':    { country: 'Australia',     flag: '🇦🇺', attacks: 4218,  topTypes: ['Ransomware', 'Phishing', 'Credential'], topTargets: ['Healthcare', 'Education', 'Government'], knownActors: ['LockBit', 'BlackCat'], color: '#7A3CFF' },
  'Dubai':        { country: 'UAE',           flag: '🇦🇪', attacks: 3847,  topTypes: ['BEC', 'Phishing', 'Spyware'], topTargets: ['Finance', 'Government', 'Energy'], knownActors: ['APT-C-37', 'Dark River'], color: '#7A3CFF' },
  'Cairo':        { country: 'Egypt',         flag: '🇪🇬', attacks: 2891,  topTypes: ['Phishing', 'Mobile Malware', 'RAT'], topTargets: ['Government', 'Telecom', 'Banking'], knownActors: ['APT-C-37', 'Charming Kitten'], color: '#FFB23E' },
  'Lagos':        { country: 'Nigeria',       flag: '🇳🇬', attacks: 5124,  topTypes: ['BEC', 'Advance Fee', 'Phishing'], topTargets: ['Finance', 'HR', 'Executives'], knownActors: ['SilverTerrier', 'BEC crews'], color: '#FFB23E' },
  'Tehran':       { country: 'Iran',          flag: '🇮🇷', attacks: 15834, topTypes: ['Wiper', 'DoS', 'Espionage'], topTargets: ['Israel', 'US Gov', 'Critical Infra'], knownActors: ['APT33', 'OilRig'], color: '#FFB23E' },
  'Beijing':      { country: 'China',         flag: '🇨🇳', attacks: 38924, topTypes: ['APT', 'Espionage', 'Supply Chain'], topTargets: ['Defense', 'Technology', 'IP Theft'], knownActors: ['APT41', 'Volt Typhoon'], color: '#FF4D6D' },
  'Moscow':       { country: 'Russia',        flag: '🇷🇺', attacks: 42817, topTypes: ['Ransomware', 'APT', 'Phishing'], topTargets: ['Finance', 'Government', 'Energy'], knownActors: ['Sandworm', 'APT29'], color: '#FF2E97' },
  'Kyiv':         { country: 'Ukraine',       flag: '🇺🇦', attacks: 8244,  topTypes: ['Wiper', 'DDoS', 'Espionage'], topTargets: ['Government', 'Military', 'Critical Infra'], knownActors: ['UAC-0056', 'Sandworm targets'], color: '#FF4D6D' },
  'New York':     { country: 'United States', flag: '🇺🇸', attacks: 12847, topTypes: ['Ransomware', 'BEC', 'Phishing'], topTargets: ['Finance', 'Healthcare', 'Education'], knownActors: ['FIN7', 'Scattered Spider'], color: '#FF4D6D' },
  'Washington':   { country: 'United States', flag: '🇺🇸', attacks: 12847, topTypes: ['APT', 'Espionage', 'Phishing'], topTargets: ['Government', 'Defense', 'Think Tanks'], knownActors: ['APT29', 'APT28', 'Lazarus'], color: '#FF4D6D' },
  'Los Angeles':  { country: 'United States', flag: '🇺🇸', attacks: 12847, topTypes: ['Ransomware', 'BEC', 'Credential'], topTargets: ['Entertainment', 'Healthcare', 'Tech'], knownActors: ['Scattered Spider', 'LockBit'], color: '#FF4D6D' },
  'São Paulo':    { country: 'Brazil',        flag: '🇧🇷', attacks: 7241,  topTypes: ['Banking Trojan', 'Phishing', 'Credential'], topTargets: ['Banking', 'Retail', 'Telecom'], knownActors: ['Guildma', 'BrasDex'], color: '#2DD4BF' },
  'Mumbai':       { country: 'India',         flag: '🇮🇳', attacks: 8441,  topTypes: ['Phishing', 'Mobile Malware', 'BEC'], topTargets: ['Banking', 'IT Sector', 'Telecom'], knownActors: ['SideWinder', 'APT-C-35'], color: '#FFB23E' },
  'London':       { country: 'United Kingdom', flag: '🇬🇧', attacks: 9832, topTypes: ['Phishing', 'Ransomware', 'BEC'], topTargets: ['Finance', 'NHS', 'Government'], knownActors: ['Clop', 'LockBit'], color: '#7A3CFF' },
  'Berlin':       { country: 'Germany',       flag: '🇩🇪', attacks: 6918,  topTypes: ['Espionage', 'Ransomware', 'APT'], topTargets: ['Auto Industry', 'Gov', 'Pharma'], knownActors: ['APT28', 'Wizard Spider'], color: '#2DD4BF' },
  'Seoul':        { country: 'South Korea',   flag: '🇰🇷', attacks: 4891,  topTypes: ['APT', 'Ransomware', 'Phishing'], topTargets: ['Defense', 'Crypto', 'Telco'], knownActors: ['Lazarus', 'Kimsuky'], color: '#2DD4BF' },
  'Tokyo':        { country: 'Japan',         flag: '🇯🇵', attacks: 5234,  topTypes: ['Supply Chain', 'APT', 'Espionage'], topTargets: ['Defense', 'Manufacturing', 'Finance'], knownActors: ['APT10', 'Bronze Butler'], color: '#FFB23E' },
  'Sydney':       { country: 'Australia',     flag: '🇦🇺', attacks: 4218,  topTypes: ['Ransomware', 'Phishing', 'Credential'], topTargets: ['Healthcare', 'Education', 'Gov'], knownActors: ['LockBit', 'BlackCat'], color: '#7A3CFF' },
}

type City = { name: string; lat: number; lon: number; color: string; intensity: number }
const CITIES: City[] = [
  { name: 'New York',    lat: 40.7,  lon: -74.0,  color: '#FF4D6D', intensity: 1.0  },
  { name: 'Washington',  lat: 38.9,  lon: -77.0,  color: '#FF2E97', intensity: 0.9  },
  { name: 'Los Angeles', lat: 34.0,  lon: -118.2, color: '#FFB23E', intensity: 0.8  },
  { name: 'São Paulo',   lat: -23.5, lon: -46.6,  color: '#2DD4BF', intensity: 0.6  },
  { name: 'London',      lat: 51.5,  lon: -0.1,   color: '#7A3CFF', intensity: 0.95 },
  { name: 'Berlin',      lat: 52.5,  lon: 13.4,   color: '#2DD4BF', intensity: 0.7  },
  { name: 'Kyiv',        lat: 50.5,  lon: 30.5,   color: '#FF4D6D', intensity: 0.75 },
  { name: 'Moscow',      lat: 55.75, lon: 37.6,   color: '#FF2E97', intensity: 1.0  },
  { name: 'Lagos',       lat: 6.5,   lon: 3.4,    color: '#FFB23E', intensity: 0.65 },
  { name: 'Cairo',       lat: 30.0,  lon: 31.2,   color: '#FFB23E', intensity: 0.7  },
  { name: 'Tehran',      lat: 35.7,  lon: 51.4,   color: '#FF4D6D', intensity: 0.8  },
  { name: 'Dubai',       lat: 25.2,  lon: 55.3,   color: '#7A3CFF', intensity: 0.7  },
  { name: 'Mumbai',      lat: 19.0,  lon: 72.8,   color: '#FFB23E', intensity: 0.75 },
  { name: 'Singapore',   lat: 1.35,  lon: 103.8,  color: '#7A3CFF', intensity: 0.7  },
  { name: 'Beijing',     lat: 39.9,  lon: 116.4,  color: '#FF2E97', intensity: 0.95 },
  { name: 'Seoul',       lat: 37.6,  lon: 126.9,  color: '#2DD4BF', intensity: 0.7  },
  { name: 'Tokyo',       lat: 35.7,  lon: 139.7,  color: '#FFB23E', intensity: 0.85 },
  { name: 'Sydney',      lat: -33.9, lon: 151.2,  color: '#7A3CFF', intensity: 0.55 },
]

type Attack = { from: string; to: string; color: string }
const ATTACKS: Attack[] = [
  { from: 'Moscow',    to: 'New York',    color: '#FF2E97' },
  { from: 'Beijing',   to: 'Washington',  color: '#FF4D6D' },
  { from: 'Tehran',    to: 'London',      color: '#FFB23E' },
  { from: 'Moscow',    to: 'Berlin',      color: '#FF2E97' },
  { from: 'Beijing',   to: 'Tokyo',       color: '#7A3CFF' },
  { from: 'Singapore', to: 'Sydney',      color: '#2DD4BF' },
  { from: 'Lagos',     to: 'London',      color: '#FFB23E' },
  { from: 'Tehran',    to: 'Dubai',       color: '#FF4D6D' },
  { from: 'Beijing',   to: 'Mumbai',      color: '#7A3CFF' },
  { from: 'Moscow',    to: 'Kyiv',        color: '#FF2E97' },
  { from: 'São Paulo', to: 'New York',    color: '#2DD4BF' },
  { from: 'Seoul',     to: 'Los Angeles', color: '#FFB23E' },
]

const cityMap = Object.fromEntries(CITIES.map((c) => [c.name, c]))

function arcPath(x1: number, y1: number, x2: number, y2: number): string {
  const mx = (x1 + x2) / 2
  const my = (y1 + y2) / 2 - Math.hypot(x2 - x1, y2 - y1) * 0.28
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`
}

const SORTED_BY_COUNT = [...REGION_STATS].sort((a, b) => b.count - a.count)

/* ── Tooltip component (rendered in HTML overlay, not SVG) ─────── */
function CountryTooltip({
  city,
  screenX,
  screenY,
  containerW,
  containerH,
}: {
  city: string
  screenX: number
  screenY: number
  containerW: number
  containerH: number
}) {
  const data = COUNTRY_STATS[city]
  if (!data) return null

  // Keep tooltip inside container
  const tooltipW = 220
  const tooltipH = 160
  let left = screenX + 12
  let top = screenY - tooltipH / 2
  if (left + tooltipW > containerW - 8) left = screenX - tooltipW - 12
  if (top < 8) top = 8
  if (top + tooltipH > containerH - 8) top = containerH - tooltipH - 8

  return (
    <div
      className="absolute pointer-events-none z-50"
      style={{ left, top, width: tooltipW }}
    >
      <div
        className="rounded-xl border p-3 text-xs shadow-2xl"
        style={{
          background: '#0D0920F5',
          borderColor: data.color + '44',
          backdropFilter: 'blur(12px)',
        }}
      >
        {/* Header */}
        <div className="flex items-center gap-2 mb-2">
          <span className="text-base">{data.flag}</span>
          <div>
            <p className="font-semibold text-white">{data.country}</p>
            <p style={{ color: data.color }} className="text-[10px] font-mono font-bold">
              {data.attacks.toLocaleString()} attacks · origin
            </p>
          </div>
        </div>

        {/* Top attack types */}
        <div className="mb-2">
          <p className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">Top Attack Types</p>
          <div className="flex flex-wrap gap-1">
            {data.topTypes.slice(0, 3).map(t => (
              <span key={t} className="text-[9px] px-1.5 py-0.5 rounded"
                style={{ background: data.color + '22', color: data.color, border: `1px solid ${data.color}33` }}>
                {t}
              </span>
            ))}
          </div>
        </div>

        {/* Primary targets */}
        <div className="mb-2">
          <p className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">Primary Targets</p>
          <p className="text-[10px] text-slate-300">{data.topTargets.join(', ')}</p>
        </div>

        {/* Known actors */}
        <div>
          <p className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">Known Actors</p>
          <p className="text-[10px] text-slate-300">{data.knownActors.join(' · ')}</p>
        </div>
      </div>
    </div>
  )
}

export default function WorldMap() {
  const [hoveredRegion, setHoveredRegion] = useState<RegionStat | null>(null)
  const [hoveredCity, setHoveredCity] = useState<string | null>(null)
  const [cityTooltipPos, setCityTooltipPos] = useState({ x: 0, y: 0 })
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const clearRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const cityLeaveRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function enterRegion(r: RegionStat) {
    if (clearRef.current) clearTimeout(clearRef.current)
    setHoveredRegion(r)
  }
  function scheduleLeave() {
    clearRef.current = setTimeout(() => setHoveredRegion(null), 80)
  }

  // Convert SVG coords to container-relative pixels
  function svgToScreen(svgX: number, svgY: number): { x: number; y: number } {
    const svg = svgRef.current
    const container = containerRef.current
    if (!svg || !container) return { x: svgX, y: svgY }
    const vb = svg.viewBox.baseVal
    const rect = svg.getBoundingClientRect()
    const cRect = container.getBoundingClientRect()
    const scaleX = rect.width / vb.width
    const scaleY = rect.height / vb.height
    return {
      x: (svgX - vb.x) * scaleX + (rect.left - cRect.left),
      y: (svgY - vb.y) * scaleY + (rect.top - cRect.top),
    }
  }

  function enterCity(name: string, cx: number, cy: number) {
    if (cityLeaveRef.current) clearTimeout(cityLeaveRef.current)
    const pos = svgToScreen(cx, cy)
    setCityTooltipPos(pos)
    setHoveredCity(name)
  }

  function leaveCitySchedule() {
    cityLeaveRef.current = setTimeout(() => setHoveredCity(null), 120)
  }

  // Touch handler for mobile
  const handleTouchCity = useCallback((name: string, cx: number, cy: number, e: React.TouchEvent) => {
    e.preventDefault()
    if (hoveredCity === name) {
      setHoveredCity(null)
    } else {
      const pos = svgToScreen(cx, cy)
      setCityTooltipPos(pos)
      setHoveredCity(name)
    }
  }, [hoveredCity])

  const dots = useMemo(() => {
    const out: { x: number; y: number; regionId: string | null; color: string; baseOpacity: number }[] = []
    for (let lat = 78; lat >= -56; lat -= 3) {
      for (let lon = -178; lon <= 180; lon += 2.5) {
        if (isLand(lon, lat)) {
          const [x, y] = project(lon, lat)
          const region = getRegion(lon, lat)
          out.push({
            x, y,
            regionId: region?.id ?? null,
            color: region?.color ?? '#3A2E63',
            baseOpacity: region?.dotOpacity ?? 0.18,
          })
        }
      }
    }
    return out
  }, [])

  const containerW = containerRef.current?.getBoundingClientRect().width ?? 400
  const containerH = containerRef.current?.getBoundingClientRect().height ?? 220

  return (
    <div ref={containerRef} className="relative w-full h-full bg-[#070512] rounded-xl overflow-hidden border border-white/5">
      {/* Grid */}
      <div
        className="absolute inset-0 opacity-[0.12]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(122,60,255,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(122,60,255,0.4) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="absolute inset-0 w-full h-full"
        preserveAspectRatio="xMidYMid meet"
        onMouseLeave={scheduleLeave}
      >
        <defs>
          <filter id="wm-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="0.6" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="city-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="1.5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Land dots */}
        {dots.map((d, i) => {
          const isHov = hoveredRegion !== null && d.regionId === hoveredRegion.id
          return <circle key={i} cx={d.x} cy={d.y} r={0.62} fill={d.color} opacity={isHov ? Math.min(d.baseOpacity + 0.22, 0.97) : d.baseOpacity} />
        })}

        {/* Attack arcs */}
        {ATTACKS.map((a, i) => {
          const s = cityMap[a.from]; const t = cityMap[a.to]
          if (!s || !t) return null
          const [x1, y1] = project(s.lon, s.lat)
          const [x2, y2] = project(t.lon, t.lat)
          return (
            <path
              key={`arc-${i}`}
              d={arcPath(x1, y1, x2, y2)}
              fill="none" stroke={a.color} strokeWidth={0.45} strokeLinecap="round"
              strokeDasharray="14" strokeDashoffset="14"
              style={{ animation: `wmArc 3s ease-in-out ${i * 0.28}s infinite`, filter: 'url(#wm-glow)' }}
            />
          )
        })}

        {/* City nodes — larger tap targets for mobile */}
        {CITIES.map((c) => {
          const [cx, cy] = project(c.lon, c.lat)
          const isHov = hoveredCity === c.name
          const hasData = !!COUNTRY_STATS[c.name]
          return (
            <g
              key={c.name}
              style={{ cursor: hasData ? 'pointer' : 'default' }}
              onMouseEnter={() => hasData && enterCity(c.name, cx, cy)}
              onMouseLeave={leaveCitySchedule}
              onTouchStart={(e) => hasData && handleTouchCity(c.name, cx, cy, e)}
            >
              {/* Invisible tap target (larger area for mobile) */}
              <circle cx={cx} cy={cy} r={5} fill="rgba(0,0,0,0)" />
              {/* Pulse ring */}
              <circle cx={cx} cy={cy} r={isHov ? 3.5 : 2.2} fill="none" stroke={c.color}
                strokeWidth={isHov ? 0.6 : 0.35} opacity={isHov ? 0.8 : 0.4}
                style={{ animation: `wmPulse 2.6s ease-out infinite ${(c.lon + 180) / 90}s`, transition: 'r 0.2s, opacity 0.2s' }}
              />
              {/* City dot */}
              <circle
                cx={cx} cy={cy}
                r={isHov ? 1.6 : 0.95}
                fill={c.color}
                opacity={isHov ? 1 : c.intensity}
                filter={isHov ? 'url(#city-glow)' : 'url(#wm-glow)'}
                style={{ transition: 'r 0.15s' }}
              />
              {/* City name on hover */}
              {isHov && (
                <text
                  x={cx} y={cy - 4}
                  textAnchor="middle" fill="white"
                  fontSize={4.5} fontWeight="600" fontFamily="system-ui,sans-serif"
                  style={{ pointerEvents: 'none' }}
                >
                  {c.name}
                </text>
              )}
            </g>
          )
        })}

        {/* Region hover rects */}
        {HOVER_DRAW_ORDER.map((id) => {
          const r = regionById[id]
          const [x1, y1] = project(r.lonRange[0], r.latRange[1])
          const [x2, y2] = project(r.lonRange[1], r.latRange[0])
          return (
            <rect
              key={id}
              x={x1} y={y1} width={x2 - x1} height={y2 - y1}
              fill="rgba(0,0,0,0)"
              style={{ pointerEvents: 'all', cursor: 'crosshair' }}
              onMouseEnter={() => enterRegion(r)}
              onMouseLeave={scheduleLeave}
            />
          )
        })}

        {/* Region tooltip (SVG) */}
        {hoveredRegion && !hoveredCity && (() => {
          const cx = (hoveredRegion.lonRange[0] + hoveredRegion.lonRange[1]) / 2 + 180
          const cy = 90 - (hoveredRegion.latRange[0] + hoveredRegion.latRange[1]) / 2
          const tx = Math.max(60, Math.min(W - 60, cx))
          const ty = Math.max(24, Math.min(H - 22, cy - 18))
          const barW = 92 * (hoveredRegion.count / MAX_COUNT)
          const rank = SORTED_BY_COUNT.findIndex((r) => r.id === hoveredRegion.id) + 1
          return (
            <g style={{ pointerEvents: 'none' }}>
              <rect x={tx - 59} y={ty - 19} width={118} height={44} rx={5} fill="#000" opacity={0.4} />
              <rect x={tx - 58} y={ty - 20} width={116} height={44} rx={4.5}
                fill="#100A1C" fillOpacity={0.97} stroke={hoveredRegion.color} strokeOpacity={0.45} strokeWidth={0.65} />
              <text x={tx} y={ty - 7} textAnchor="middle" fill="white"
                fontSize={7} fontWeight="700" fontFamily="system-ui,sans-serif">
                {hoveredRegion.name}
              </text>
              <text x={tx} y={ty + 4} textAnchor="middle" fill={hoveredRegion.color}
                fontSize={5.5} fontFamily="system-ui,sans-serif">
                {hoveredRegion.count.toLocaleString()} attacks · #{rank} most targeted
              </text>
              <rect x={tx - 46} y={ty + 9.5} width={92} height={2.5} rx={1.25} fill="rgba(255,255,255,0.1)" />
              <rect x={tx - 46} y={ty + 9.5} width={barW} height={2.5} rx={1.25}
                fill={hoveredRegion.color} opacity={0.85} />
            </g>
          )
        })()}
      </svg>

      {/* Country tooltip (HTML overlay — richer, supports flex layout) */}
      {hoveredCity && COUNTRY_STATS[hoveredCity] && (
        <CountryTooltip
          city={hoveredCity}
          screenX={cityTooltipPos.x}
          screenY={cityTooltipPos.y}
          containerW={containerRef.current?.clientWidth ?? 400}
          containerH={containerRef.current?.clientHeight ?? 220}
        />
      )}

      <style>{`
        @keyframes wmArc {
          0%   { stroke-dashoffset: 14; opacity: 0; }
          15%  { opacity: 0.85; }
          85%  { stroke-dashoffset: 0; opacity: 0.55; }
          100% { stroke-dashoffset: 0; opacity: 0; }
        }
        @keyframes wmPulse {
          0%   { r: 1; opacity: 0.7; }
          100% { r: 4.5; opacity: 0; }
        }
      `}</style>

      <div className="absolute top-3 left-3 flex items-center gap-1.5 text-[10px] text-safe pointer-events-none">
        <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
        Live Attack Map
      </div>

      {!hoveredRegion && !hoveredCity && (
        <div className="absolute top-3 right-3 text-[9px] text-slate-600 pointer-events-none hidden md:block">
          Hover cities · tap on mobile
        </div>
      )}

      <div className="absolute bottom-3 right-3 flex items-center gap-3 text-[10px] text-slate-500 pointer-events-none">
        {([['Critical','#FF2E97'],['High','#FF4D6D'],['Medium','#FFB23E'],['Low','#2DD4BF']] as const).map(([l, c]) => (
          <div key={l} className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />
            {l}
          </div>
        ))}
      </div>
    </div>
  )
}
