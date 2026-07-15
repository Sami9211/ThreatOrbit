'use client'

import { useState, useMemo, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plus, Server, Globe, Database, Cloud, Smartphone, Shield,
  Search, Trash2, RefreshCw, AlertTriangle, CheckCircle, Clock,
  X, Activity, Wifi, LayoutGrid, List, ChevronRight,
  Lock, Cpu, GitBranch, Tag, User, TrendingUp, TrendingDown,
  ExternalLink, Eye, FileText,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import ReportButton from '@/components/dashboard/ReportButton'
import SavedViewsButton from '@/components/dashboard/SavedViewsButton'
import AttackSurfacePanel from '@/components/dashboard/AttackSurfacePanel'
import { SkeletonRows } from '@/components/dashboard/Skeleton'
import { fetchAssets, fetchAsset, createAsset, deleteAsset, recomputeAssetRisk, scanAssetVulns, fetchAssetActivity, type RiskBreakdown, type AssetActivity } from '@/lib/api'
import { tk, withAlpha } from '@/lib/colors'

/* -- Types --------------------------------------------------------- */
type AssetType = 'domain' | 'ip' | 'server' | 'cloud' | 'database' | 'endpoint'
type ScanStatus = 'clean' | 'scanning' | 'at-risk' | 'critical' | 'unscanned'
type Criticality = 'critical' | 'high' | 'medium' | 'low'

type Asset = {
  id: string
  name: string
  type: AssetType
  value: string
  criticality: Criticality
  status: ScanStatus
  riskScore: number
  lastScan: string
  alerts: number
  cves: { critical: number; high: number; medium: number; low: number }
  openPorts: number[]
  os?: string
  owner?: string
  patchAge?: number
  tags: string[]
  uptime?: number
}

/* -- Meta --------------------------------------------------------- */
const TYPE_META: Record<AssetType, { icon: React.ComponentType<any>; label: string; color: string }> = {
  domain:   { icon: Globe,      label: 'Domain',     color: tk('violet') },
  ip:       { icon: Wifi,       label: 'IP / Host',  color: tk('teal') },
  server:   { icon: Server,     label: 'Server',     color: tk('magenta') },
  cloud:    { icon: Cloud,      label: 'Cloud',      color: tk('amber') },
  database: { icon: Database,   label: 'Database',   color: tk('threat') },
  endpoint: { icon: Smartphone, label: 'Endpoint',   color: tk('safe') },
}

const STATUS_META: Record<ScanStatus, { label: string; color: string; bg: string }> = {
  clean:     { label: 'Clean',     color: tk('safe'), bg: 'bg-safe/10'    },
  scanning:  { label: 'Scanning',  color: tk('violet'), bg: 'bg-violet/10'  },
  'at-risk': { label: 'At Risk',   color: tk('amber'), bg: 'bg-amber/10'   },
  critical:  { label: 'Critical',  color: tk('magenta'), bg: 'bg-magenta/10' },
  unscanned: { label: 'Unscanned', color: '#665B7D', bg: 'bg-white/5'    },
}

const CRIT_COLOR: Record<Criticality, string> = {
  critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe'),
}

/* -- Seed data ---------------------------------------------------- */
const SEED: Asset[] = [
  {
    id: 'a1', name: 'Corporate Website', type: 'domain', value: 'acme-corp.com',
    criticality: 'high', status: 'critical', riskScore: 82, lastScan: '4m ago', alerts: 3,
    cves: { critical: 2, high: 5, medium: 11, low: 4 }, openPorts: [80, 443, 8080],
    os: 'Nginx 1.24', owner: 'j.chen', patchAge: 28, tags: ['production', 'public'], uptime: 99.7,
  },
  {
    id: 'a2', name: 'API Gateway', type: 'server', value: 'api.acme-corp.com',
    criticality: 'critical', status: 'at-risk', riskScore: 54, lastScan: '12m ago', alerts: 1,
    cves: { critical: 0, high: 3, medium: 8, low: 6 }, openPorts: [443, 8443, 9090],
    os: 'Ubuntu 22.04', owner: 'a.patel', patchAge: 7, tags: ['production', 'api'], uptime: 99.9,
  },
  {
    id: 'a3', name: 'Primary DB', type: 'database', value: '10.0.4.12:5432',
    criticality: 'critical', status: 'clean', riskScore: 12, lastScan: '8m ago', alerts: 0,
    cves: { critical: 0, high: 0, medium: 2, low: 3 }, openPorts: [5432],
    os: 'PostgreSQL 15', owner: 'r.osei', patchAge: 3, tags: ['internal', 'postgres'], uptime: 99.99,
  },
  {
    id: 'a4', name: 'AWS Prod Account', type: 'cloud', value: 'aws:944xxxx21027',
    criticality: 'critical', status: 'at-risk', riskScore: 47, lastScan: '1h ago', alerts: 2,
    cves: { critical: 1, high: 2, medium: 6, low: 9 }, openPorts: [],
    os: 'AWS IAM', owner: 'j.chen', patchAge: 0, tags: ['cloud', 'iam'], uptime: 100,
  },
  {
    id: 'a5', name: 'Edge Node EU-W', type: 'ip', value: '185.12.44.9',
    criticality: 'medium', status: 'clean', riskScore: 9, lastScan: '15m ago', alerts: 0,
    cves: { critical: 0, high: 0, medium: 1, low: 2 }, openPorts: [80, 443],
    os: 'Debian 12', owner: undefined, patchAge: 1, tags: ['cdn', 'edge'], uptime: 99.95,
  },
  {
    id: 'a6', name: 'CFO Laptop', type: 'endpoint', value: 'WIN-CFO-04',
    criticality: 'high', status: 'clean', riskScore: 18, lastScan: '30m ago', alerts: 0,
    cves: { critical: 0, high: 1, medium: 3, low: 7 }, openPorts: [],
    os: 'Windows 11 22H2', owner: 'alice', patchAge: 14, tags: ['exec', 'managed'], uptime: 97.2,
  },
  {
    id: 'a7', name: 'CI/CD Pipeline', type: 'server', value: 'jenkins.acme-corp.internal',
    criticality: 'high', status: 'at-risk', riskScore: 61, lastScan: '2h ago', alerts: 1,
    cves: { critical: 1, high: 4, medium: 9, low: 5 }, openPorts: [8080, 50000, 22],
    os: 'Jenkins 2.426', owner: 'a.patel', patchAge: 45, tags: ['internal', 'devops'], uptime: 98.1,
  },
  {
    id: 'a8', name: 'Redis Cache', type: 'database', value: '10.0.4.22:6379',
    criticality: 'medium', status: 'clean', riskScore: 22, lastScan: '20m ago', alerts: 0,
    cves: { critical: 0, high: 0, medium: 3, low: 4 }, openPorts: [6379],
    os: 'Redis 7.2', owner: 'r.osei', patchAge: 5, tags: ['cache', 'internal'], uptime: 99.98,
  },
]

let nextId = 200

/* Responsive grid template for the asset table. The CVEs and Ports columns are
   hidden below md/lg, so the template must drop their tracks at those breakpoints
   too - otherwise the empty tracks keep consuming width and squash the remaining
   columns (making the risk rings overlap badges on mobile). Track count always
   matches the number of *visible* cells at each breakpoint. */
const ROW_GRID =
  'grid gap-2 md:gap-3 items-center ' +
  'grid-cols-[minmax(0,1fr)_auto_auto_auto_auto] ' +          // mobile: Asset Risk Alerts Status Actions
  'md:grid-cols-[1.4fr_70px_90px_80px_100px_80px] ' +          // +CVEs
  'lg:grid-cols-[1.4fr_70px_90px_110px_80px_100px_80px]'       // +Ports/OS

/* -- Sub-components ----------------------------------------------- */
function RiskRing({ score, size = 52 }: { score: number; size?: number }) {
  const r = size / 2 - 7
  const circ = 2 * Math.PI * r
  const fill = (score / 100) * circ
  const color = score >= 70 ? 'rgb(var(--magenta))' : score >= 40 ? 'rgb(var(--amber))' : 'rgb(var(--safe))'
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={5} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={5}
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-[11px] font-bold" style={{ color }}>{score}</span>
      </div>
    </div>
  )
}

function CveBadges({ cves }: { cves: Asset['cves'] }) {
  const items = [
    { label: 'C', count: cves.critical, color: tk('magenta') },
    { label: 'H', count: cves.high,     color: tk('threat') },
    { label: 'M', count: cves.medium,   color: tk('amber') },
    { label: 'L', count: cves.low,      color: tk('safe') },
  ]
  return (
    <div className="flex items-center gap-1">
      {items.map(({ label, count, color }) => count > 0 ? (
        <span key={label} className="text-[9px] font-bold px-1.5 py-0.5 rounded"
          style={{ color, background: color + '20', border: `1px solid ${color}35` }}>
          {label}:{count}
        </span>
      ) : null)}
      {Object.values(cves).every(v => v === 0) && (
        <span className="text-[10px] text-ink-600">No CVEs</span>
      )}
    </div>
  )
}

/* -- Main page --------------------------------------------------- */
export default function AssetsPage() {
  // Empty by default - the API is the source of truth. On a real deployment an
  // empty inventory is honest ("no assets yet"), never a cue to show demo hosts.
  // SEED is used only if the API is unreachable (offline/marketing preview).
  const [assets, setAssets] = useState<Asset[]>([])
  // First answer pending → skeleton rows, not "No assets match your filters"
  const [assetsPending, setAssetsPending] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<AssetType | 'all'>('all')
  const [critFilter, setCritFilter] = useState<Criticality | 'all'>('all')
  const [view, setView] = useState<'table' | 'cards'>('table')
  const [sortBy, setSortBy] = useState<'risk' | 'name' | 'alerts' | 'cves'>('risk')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  // Load from API
  const loadAssets = () => {
    fetchAssets({ limit: '200' })
      // The API answered → show its inventory, even when empty (real deployment).
      .then(({ items }) => setAssets(items as unknown as Asset[]))
      // Unreachable → offline preview with the demo inventory.
      .catch(() => setAssets(SEED))
      .finally(() => setAssetsPending(false))
  }
  useEffect(() => { loadAssets() }, [])

  // Add-asset form
  const [name, setName] = useState('')
  const [formValue, setFormValue] = useState('')
  const [formType, setFormType] = useState<AssetType>('domain')
  const [formCrit, setFormCrit] = useState<Criticality>('medium')

  // Real vulnerability scan: matches the asset's software inventory against
  // the CVE catalogue server-side, then reloads the refreshed risk/findings.
  function scanAsset(id: string) {
    setAssets((prev) => prev.map((a) => (a.id === id ? { ...a, status: 'scanning' } : a)))
    scanAssetVulns(id)
      .then(async () => {
        const { items } = await fetchAssets({ limit: '200' })
        setAssets(items as unknown as Asset[])
      })
      .catch(() => {
        // API unreachable - restore status rather than fabricate results.
        setAssets((prev) => prev.map((a) => (a.id === id ? { ...a, status: 'unscanned' as ScanStatus } : a)))
      })
  }

  function scanAll() { assets.forEach((a, i) => setTimeout(() => scanAsset(a.id), i * 250)) }

  function removeAsset(id: string) {
    const asset = assets.find((a) => a.id === id)
    if (!window.confirm(`Remove "${asset?.name ?? 'this asset'}"? This permanently deletes the asset and its findings.`)) return
    setAssets((p) => p.filter((a) => a.id !== id))   // optimistic
    if (selectedId === id) setSelectedId(null)
    deleteAsset(id).catch(() => {
      // Delete failed (offline / permission) - restore so the UI matches the server.
      if (asset) setAssets((p) => [asset, ...p])
    })
  }

  const selectedAsset = assets.find((a) => a.id === selectedId) ?? null

  // Fetch the per-axis risk explanation + linked activity for the open asset.
  const [breakdown, setBreakdown] = useState<RiskBreakdown | null>(null)
  const [activity, setActivity] = useState<AssetActivity | null>(null)
  useEffect(() => {
    if (!selectedId) { setBreakdown(null); setActivity(null); return }
    let live = true
    fetchAsset(selectedId)
      .then((d) => { if (live) setBreakdown(d.riskBreakdown ?? null) })
      .catch(() => { if (live) setBreakdown(null) })
    fetchAssetActivity(selectedId)
      .then((d) => { if (live) setActivity(d) })
      .catch(() => { if (live) setActivity(null) })
    return () => { live = false }
  }, [selectedId])

  // Recompute every asset's risk from current CVEs + live alert pressure.
  const [recomputing, setRecomputing] = useState(false)
  async function recomputeRisk() {
    if (recomputing) return
    setRecomputing(true)
    try {
      await recomputeAssetRisk()
      const { items } = await fetchAssets({ limit: '200' })
      setAssets(items as unknown as Asset[])
    } catch { /* leave current data in place */ }
    finally { setRecomputing(false) }
  }

  // Escape closes the add-asset modal first, otherwise the detail panel.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== 'Escape') return
      if (showAdd) setShowAdd(false)
      else if (selectedId) setSelectedId(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [showAdd, selectedId])

  function addAsset() {
    if (!name.trim() || !formValue.trim()) return
    const local: Asset = {
      id: `a${++nextId}`, name: name.trim(), type: formType, value: formValue.trim(),
      criticality: formCrit, status: 'unscanned', riskScore: 0, lastScan: 'never',
      alerts: 0, cves: { critical: 0, high: 0, medium: 0, low: 0 }, openPorts: [], tags: ['new'],
    }
    // Persist to the inventory; keep the local row as offline fallback.
    createAsset({ name: local.name, type: local.type, value: local.value, criticality: local.criticality })
      .then((created) => {
        setAssets((p) => [created as unknown as Asset, ...p])
        setTimeout(() => scanAsset((created as unknown as Asset).id), 400)
      })
      .catch(() => {
        setAssets((p) => [local, ...p])
        setTimeout(() => scanAsset(local.id), 400)
      })
    setName(''); setFormValue(''); setFormType('domain'); setFormCrit('medium'); setShowAdd(false)
  }

  const filtered = useMemo(() => {
    let list = assets.filter((a) =>
      (typeFilter === 'all' || a.type === typeFilter) &&
      (critFilter === 'all' || a.criticality === critFilter) &&
      (!search || a.name.toLowerCase().includes(search.toLowerCase()) || a.value.toLowerCase().includes(search.toLowerCase()))
    )
    if (sortBy === 'risk')   list = [...list].sort((a, b) => b.riskScore - a.riskScore)
    if (sortBy === 'alerts') list = [...list].sort((a, b) => b.alerts - a.alerts)
    if (sortBy === 'name')   list = [...list].sort((a, b) => a.name.localeCompare(b.name))
    if (sortBy === 'cves')   list = [...list].sort((a, b) =>
      (b.cves.critical * 10 + b.cves.high * 3 + b.cves.medium) - (a.cves.critical * 10 + a.cves.high * 3 + a.cves.medium))
    return list
  }, [assets, typeFilter, critFilter, search, sortBy])

  // Stats
  const totalCves = assets.reduce((s, a) => s + a.cves.critical + a.cves.high + a.cves.medium + a.cves.low, 0)
  const criticalCves = assets.reduce((s, a) => s + a.cves.critical, 0)
  const atRisk = assets.filter((a) => a.status === 'critical' || a.status === 'at-risk').length
  const avgRisk = Math.round(assets.reduce((s, a) => s + a.riskScore, 0) / (assets.length || 1))

  return (
    <div className="flex h-full overflow-hidden">
      {/* -- Main column ------------------------------------------- */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-white/5 flex flex-wrap gap-3 items-center justify-between shrink-0">
          <div>
            <h1 className="font-display text-xl font-bold text-white">Attack Surface</h1>
            <p className="text-xs text-ink-500 mt-0.5">
              <span className="text-magenta">{atRisk} assets at risk</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span className="text-threat">{criticalCves} critical CVEs</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span>Avg risk score {avgRisk}/100</span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <SavedViewsButton
              section="assets"
              filters={{ q: search, type: typeFilter, criticality: critFilter }}
              onApply={(f) => {
                setSearch(f.q ?? '')
                setTypeFilter((f.type as AssetType) ?? 'all')
                setCritFilter((f.criticality as Criticality) ?? 'all')
              }}
            />
            <ReportButton kind="assets" label="Asset Risk & Exposure" />
            <button onClick={scanAll}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-white/10 text-ink-400 hover:text-white hover:border-violet/40 transition-colors">
              <RefreshCw className="w-3.5 h-3.5" /> Scan All
            </button>
            <button onClick={recomputeRisk} disabled={recomputing}
              title="Recalculate risk from current CVEs and live alert pressure"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-white/10 text-ink-400 hover:text-white hover:border-safe/40 transition-colors disabled:opacity-50 disabled:cursor-wait">
              <RefreshCw className={cn('w-3.5 h-3.5', recomputing && 'animate-spin')} /> {recomputing ? 'Recomputing…' : 'Recompute Risk'}
            </button>
            <button onClick={() => setShowAdd(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-plasma text-white shadow-magenta-sm hover:shadow-magenta transition-all">
              <Plus className="w-3.5 h-3.5" /> Add Asset
            </button>
          </div>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 border-b border-white/5 shrink-0">
          {[
            { label: 'Total Assets',   value: assets.length,                   color: 'text-white',   sub: `${assets.filter(a => a.criticality === 'critical').length} critical infra` },
            { label: 'At Risk',        value: atRisk,                          color: 'text-magenta', sub: `${assets.filter(a => a.status === 'critical').length} critical status` },
            { label: 'Open Alerts',    value: assets.reduce((s,a)=>s+a.alerts,0), color: 'text-threat',  sub: 'across all assets' },
            { label: 'Total CVEs',     value: totalCves,                       color: 'text-amber',   sub: `${criticalCves} critical severity` },
            { label: 'Avg Risk Score', value: `${avgRisk}/100`,                color: avgRisk > 50 ? 'text-threat' : 'text-safe', sub: 'exposure index' },
            { label: 'Clean Assets',   value: assets.filter(a=>a.status==='clean').length, color: 'text-safe', sub: 'last 24h scan pass' },
          ].map((k) => (
            <div key={k.label} className="px-4 py-3 border-r border-white/5 last:border-r-0">
              <p className="text-[10px] text-ink-600 uppercase tracking-wide">{k.label}</p>
              <p className={cn('text-lg font-bold mt-0.5', k.color)}>{k.value}</p>
              <p className="text-[10px] text-ink-500 mt-0.5">{k.sub}</p>
            </div>
          ))}
        </div>

        {/* Toolbar */}
        <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 border-b border-white/5 shrink-0">
          {/* Search */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/8 flex-1 min-w-[160px] max-w-xs">
            <Search className="w-3 h-3 text-ink-500 shrink-0" />
            <input value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets…"
              className="flex-1 bg-transparent text-xs text-ink-200 placeholder-ink-600 focus:outline-none" />
            {search && <button onClick={() => setSearch('')}><X className="w-3 h-3 text-ink-500" /></button>}
          </div>

          {/* Type filter */}
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as AssetType | 'all')}
            className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/8 bg-surface-2 text-ink-400 focus:outline-none cursor-pointer">
            <option value="all">All Types</option>
            {(Object.keys(TYPE_META) as AssetType[]).map((t) => (
              <option key={t} value={t} className="bg-[#100A1C]">{TYPE_META[t].label}</option>
            ))}
          </select>

          {/* Criticality filter */}
          <select value={critFilter} onChange={(e) => setCritFilter(e.target.value as Criticality | 'all')}
            className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/8 bg-surface-2 text-ink-400 focus:outline-none cursor-pointer">
            <option value="all">All Criticality</option>
            {(['critical', 'high', 'medium', 'low'] as Criticality[]).map((c) => (
              <option key={c} value={c} className="bg-[#100A1C] capitalize">{c.charAt(0).toUpperCase() + c.slice(1)}</option>
            ))}
          </select>

          {/* Sort */}
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
            className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/8 bg-surface-2 text-ink-400 focus:outline-none cursor-pointer">
            <option value="risk">Sort: Risk Score</option>
            <option value="alerts">Sort: Alerts</option>
            <option value="cves">Sort: CVE Count</option>
            <option value="name">Sort: Name</option>
          </select>

          <span className="text-[10px] text-ink-600">{filtered.length} assets</span>

          {/* View toggle */}
          <div className="ml-auto flex items-center gap-1 bg-surface-2 border border-white/8 rounded-lg p-0.5">
            <button onClick={() => setView('table')}
              className={cn('p-1.5 rounded-md transition-colors', view === 'table' ? 'bg-white/10 text-white' : 'text-ink-500 hover:text-ink-200')}>
              <List className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setView('cards')}
              className={cn('p-1.5 rounded-md transition-colors', view === 'cards' ? 'bg-white/10 text-white' : 'text-ink-500 hover:text-ink-200')}>
              <LayoutGrid className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          {/* -- TABLE VIEW ----------------------------------------- */}
          {view === 'table' && (
            <>
              <div className={cn(ROW_GRID, 'px-4 py-2 border-b border-white/5 text-[10px] text-ink-600 uppercase tracking-wide')}>
                <span>Asset</span>
                <span>Risk</span>
                <span className="hidden md:block">CVEs</span>
                <span className="hidden lg:block">Ports / OS</span>
                <span>Alerts</span>
                <span>Status</span>
                <span className="text-right">Actions</span>
              </div>
              <AnimatePresence initial={false}>
                {filtered.map((a, i) => {
                  const TM = TYPE_META[a.type]
                  const SM = STATUS_META[a.status]
                  const isSelected = selectedId === a.id
                  return (
                    <motion.div key={a.id}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ delay: i * 0.02 }}
                      onClick={() => setSelectedId(isSelected ? null : a.id)}
                      className={cn(
                        ROW_GRID, 'px-4 py-2.5 border-b border-white/4 cursor-pointer transition-colors',
                        isSelected ? 'bg-magenta/6 border-l-2 border-l-magenta' : 'hover:bg-white/2',
                      )}
                    >
                      {/* Asset name */}
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-1.5 rounded-lg shrink-0" style={{ background: TM.color + '1a' }}>
                          <TM.icon className="w-3.5 h-3.5" style={{ color: TM.color }} />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <p className="text-xs font-medium text-ink-100 truncate">{a.name}</p>
                            <span className="text-[9px] px-1 py-0.5 rounded font-semibold shrink-0"
                              style={{ color: CRIT_COLOR[a.criticality], background: CRIT_COLOR[a.criticality] + '18' }}>
                              {a.criticality.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-[10px] font-mono text-ink-600 truncate">{a.value}</p>
                        </div>
                      </div>

                      {/* Risk */}
                      <div className="flex items-center gap-2">
                        <RiskRing score={a.riskScore} size={36} />
                      </div>

                      {/* CVEs */}
                      <div className="hidden md:block">
                        <CveBadges cves={a.cves} />
                      </div>

                      {/* Ports / OS */}
                      <div className="hidden lg:block min-w-0">
                        {a.openPorts.length > 0 ? (
                          <p className="text-[10px] font-mono text-ink-400 truncate">
                            {a.openPorts.slice(0, 3).join(', ')}{a.openPorts.length > 3 ? ` +${a.openPorts.length - 3}` : ''}
                          </p>
                        ) : (
                          <p className="text-[10px] text-ink-700">No open ports</p>
                        )}
                        {a.os && <p className="text-[10px] text-ink-600 truncate mt-0.5">{a.os}</p>}
                      </div>

                      {/* Alerts */}
                      <div>
                        {a.alerts > 0 ? (
                          <span className="flex items-center gap-1 text-[11px] font-semibold text-threat">
                            <AlertTriangle className="w-3 h-3" /> {a.alerts}
                          </span>
                        ) : (
                          <span className="text-[11px] text-ink-600">-</span>
                        )}
                      </div>

                      {/* Status */}
                      <div>
                        <span className={cn('inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full font-semibold', SM.bg)}
                          style={{ color: SM.color }}>
                          {a.status === 'scanning'
                            ? <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                            : <span className="w-1.5 h-1.5 rounded-full" style={{ background: SM.color }} />}
                          {SM.label}
                        </span>
                        <p className="text-[9px] text-ink-700 mt-0.5 flex items-center gap-0.5">
                          <Clock className="w-2 h-2" />{a.lastScan}
                        </p>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                        <button onClick={() => scanAsset(a.id)} disabled={a.status === 'scanning'}
                          className="p-1.5 rounded-md text-ink-500 hover:text-violet hover:bg-white/5 transition-colors disabled:opacity-40">
                          <RefreshCw className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => removeAsset(a.id)}
                          className="p-1.5 rounded-md text-ink-500 hover:text-threat hover:bg-white/5 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </motion.div>
                  )
                })}
              </AnimatePresence>
              {filtered.length === 0 && assetsPending && <SkeletonRows rows={8} />}
              {filtered.length === 0 && !assetsPending && (
                <div className="py-14 text-center">
                  <Server className="w-7 h-7 text-ink-700 mx-auto mb-2" />
                  <p className="text-sm text-ink-500">No assets match your filters</p>
                  <button onClick={() => { setSearch(''); setTypeFilter('all'); setCritFilter('all') }}
                    className="mt-3 text-xs text-magenta hover:underline">Clear filters</button>
                </div>
              )}
            </>
          )}

          {/* -- CARD VIEW ------------------------------------------ */}
          {view === 'cards' && (
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {filtered.length === 0 && (assetsPending
                ? <SkeletonRows rows={6} className="col-span-full" />
                : (
                  <p className="col-span-full py-14 text-center text-sm text-ink-500">
                    No assets match your filters
                  </p>
                ))}
              {filtered.map((a, i) => {
                const TM = TYPE_META[a.type]
                const SM = STATUS_META[a.status]
                return (
                  <motion.div key={a.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className={cn(
                      'bg-surface-2/40 rounded-xl border p-4 cursor-pointer hover:border-white/15 transition-colors',
                      selectedId === a.id ? 'border-magenta/40 bg-magenta/5' : 'border-white/5',
                    )}
                    onClick={() => setSelectedId(selectedId === a.id ? null : a.id)}
                  >
                    {/* Card header */}
                    <div className="flex items-start justify-between gap-3 mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-lg shrink-0" style={{ background: TM.color + '1a' }}>
                          <TM.icon className="w-4 h-4" style={{ color: TM.color }} />
                        </div>
                        <div>
                          <p className="text-xs font-semibold text-white">{a.name}</p>
                          <p className="text-[10px] font-mono text-ink-600">{a.value}</p>
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-1 shrink-0">
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase"
                          style={{ color: CRIT_COLOR[a.criticality], background: CRIT_COLOR[a.criticality] + '18' }}>
                          {a.criticality}
                        </span>
                        <span className={cn('inline-flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full font-semibold', SM.bg)}
                          style={{ color: SM.color }}>
                          {a.status === 'scanning' ? <RefreshCw className="w-2 h-2 animate-spin" /> : null}
                          {SM.label}
                        </span>
                      </div>
                    </div>

                    {/* Risk score + CVEs */}
                    <div className="flex items-center gap-4 mb-3">
                      <div className="flex items-center gap-2">
                        <RiskRing score={a.riskScore} size={48} />
                        <div>
                          <p className="text-[9px] text-ink-600">Risk Score</p>
                          <p className="text-[10px] text-ink-400">{a.riskScore >= 70 ? 'High exposure' : a.riskScore >= 40 ? 'Moderate' : 'Low exposure'}</p>
                        </div>
                      </div>
                      <div className="flex-1">
                        <p className="text-[9px] text-ink-600 mb-1">CVEs</p>
                        <CveBadges cves={a.cves} />
                      </div>
                    </div>

                    {/* Details grid */}
                    <div className="space-y-1.5 mb-3">
                      {a.os && (
                        <div className="flex items-center gap-2 text-[10px]">
                          <Cpu className="w-3 h-3 text-ink-600 shrink-0" />
                          <span className="text-ink-400">{a.os}</span>
                          {a.patchAge !== undefined && (
                            <span className={cn('ml-auto font-mono', a.patchAge > 30 ? 'text-threat' : a.patchAge > 7 ? 'text-amber' : 'text-safe')}>
                              patch {a.patchAge}d ago
                            </span>
                          )}
                        </div>
                      )}
                      {a.openPorts.length > 0 && (
                        <div className="flex items-center gap-2 text-[10px]">
                          <Lock className="w-3 h-3 text-ink-600 shrink-0" />
                          <span className="font-mono text-ink-400">
                            {a.openPorts.slice(0, 4).join(', ')}{a.openPorts.length > 4 ? ` +${a.openPorts.length - 4}` : ''}
                          </span>
                          <span className="text-ink-700 ml-auto">{a.openPorts.length} open port{a.openPorts.length !== 1 ? 's' : ''}</span>
                        </div>
                      )}
                      {a.owner && (
                        <div className="flex items-center gap-2 text-[10px]">
                          <User className="w-3 h-3 text-ink-600 shrink-0" />
                          <span className="text-ink-400">{a.owner}</span>
                          {a.alerts > 0 && (
                            <span className="ml-auto flex items-center gap-0.5 text-threat font-semibold">
                              <AlertTriangle className="w-3 h-3" />{a.alerts} alert{a.alerts !== 1 ? 's' : ''}
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Tags */}
                    <div className="flex flex-wrap gap-1 mb-3">
                      {a.tags.map((t) => (
                        <span key={t} className="text-[9px] px-1.5 py-0.5 rounded-full bg-white/5 border border-white/8 text-ink-500">
                          {t}
                        </span>
                      ))}
                    </div>

                    {/* Card actions */}
                    <div className="flex items-center gap-2 pt-2.5 border-t border-white/5" onClick={(e) => e.stopPropagation()}>
                      <button onClick={() => scanAsset(a.id)} disabled={a.status === 'scanning'}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] bg-violet/10 border border-violet/25 text-violet hover:bg-violet/20 transition-colors disabled:opacity-40">
                        <RefreshCw className={cn('w-3 h-3', a.status === 'scanning' && 'animate-spin')} /> Scan
                      </button>
                      <button className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] bg-surface-2 border border-white/8 text-ink-400 hover:text-white transition-colors">
                        <Eye className="w-3 h-3" /> Details
                      </button>
                      <button onClick={() => removeAsset(a.id)}
                        className="ml-auto p-1.5 rounded-lg text-ink-600 hover:text-threat hover:bg-white/5 transition-colors">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          )}

          {/* Attack surface: exposure inventory + discovered-host promotion */}
          <div className="p-4">
            <AttackSurfacePanel onPromoted={loadAssets} />
          </div>
        </div>
      </div>

      {/* Backdrop for the detail drawer on < xl screens */}
      <AnimatePresence>
        {selectedAsset && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={() => setSelectedId(null)}
            className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm xl:hidden"
          />
        )}
      </AnimatePresence>

      {/* -- Right panel ---------------------------------------------
          xl+: static column in normal flow.
          below xl: fixed slide-over drawer, visible only when an asset
          is selected (the inline column would otherwise be unreachable). */}
      <div
        className={cn(
          'border-l border-white/5 flex flex-col overflow-hidden bg-surface',
          'xl:static xl:z-auto xl:w-72 xl:max-w-none xl:translate-x-0 xl:shadow-none',
          'fixed right-0 top-0 bottom-0 z-[60] w-full max-w-sm shadow-2xl transition-transform duration-300 ease-in-out',
          selectedAsset ? 'translate-x-0' : 'translate-x-full',
        )}
      >
        {selectedAsset ? (
          /* Asset detail panel */
          <div className="flex-1 overflow-y-auto p-4">
            <div className="flex items-center justify-between mb-4">
              <p className="text-xs font-semibold text-white">Asset Detail</p>
              <button onClick={() => setSelectedId(null)} className="p-1 text-ink-500 hover:text-white">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            {(() => {
              const a = selectedAsset
              const TM = TYPE_META[a.type]
              const SM = STATUS_META[a.status]
              return (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="p-3 rounded-xl" style={{ background: TM.color + '1a' }}>
                      <TM.icon className="w-5 h-5" style={{ color: TM.color }} />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-white">{a.name}</p>
                      <p className="text-[10px] font-mono text-ink-500">{a.value}</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <RiskRing score={a.riskScore} size={64} />
                    <div className="text-right space-y-1">
                      <div>
                        <p className="text-[10px] text-ink-600">Status</p>
                        <p className="text-xs font-semibold" style={{ color: SM.color }}>{SM.label}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-ink-600">Criticality</p>
                        <p className="text-xs font-semibold capitalize" style={{ color: CRIT_COLOR[a.criticality] }}>{a.criticality}</p>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <p className="text-[10px] text-ink-600 uppercase tracking-wide">CVE Breakdown</p>
                    {[
                      { label: 'Critical', count: a.cves.critical, color: tk('magenta') },
                      { label: 'High',     count: a.cves.high,     color: tk('threat') },
                      { label: 'Medium',   count: a.cves.medium,   color: tk('amber') },
                      { label: 'Low',      count: a.cves.low,      color: tk('safe') },
                    ].map(({ label, count, color }) => (
                      <div key={label} className="flex items-center gap-2">
                        <span className="text-[10px] text-ink-400 w-14">{label}</span>
                        <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${Math.min(100, count * 8)}%`, background: color }} />
                        </div>
                        <span className="text-[10px] font-mono w-4 text-right" style={{ color }}>{count}</span>
                      </div>
                    ))}
                  </div>

                  {breakdown && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <p className="text-[10px] text-ink-600 uppercase tracking-wide">Risk Breakdown</p>
                        <span className="text-[9px] text-ink-600">×{breakdown.criticalityMultiplier} criticality</span>
                      </div>
                      {breakdown.components.map(({ axis, value, contribution }) => {
                        const meta: Record<string, { label: string; color: string }> = {
                          vulnerability: { label: 'Vulnerabilities', color: tk('magenta') },
                          exposure:      { label: 'Exposure',        color: tk('amber') },
                          patch:         { label: 'Patch Hygiene',   color: tk('violet') },
                          alerts:        { label: 'Alert Pressure',  color: tk('threat') },
                        }
                        const m = meta[axis] ?? { label: axis, color: tk('safe') }
                        return (
                          <div key={axis} className="flex items-center gap-2">
                            <span className="text-[10px] text-ink-400 w-24 shrink-0">{m.label}</span>
                            <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                              <div className="h-full rounded-full" style={{ width: `${value}%`, background: m.color }} />
                            </div>
                            <span className="text-[10px] font-mono w-10 text-right text-ink-400">+{contribution}</span>
                          </div>
                        )
                      })}
                      <p className="text-[9px] text-ink-700 leading-relaxed pt-0.5">
                        Bars show each axis (0-100); the figure is points added to the score after criticality scaling.
                      </p>
                    </div>
                  )}

                  <div className="space-y-1.5">
                    <p className="text-[10px] text-ink-600 uppercase tracking-wide">Details</p>
                    {[
                      { label: 'Owner',       value: a.owner ?? 'Unassigned' },
                      { label: 'OS / Stack',  value: a.os ?? '-' },
                      { label: 'Open Ports',  value: a.openPorts.join(', ') || 'None' },
                      { label: 'Patch Age',   value: a.patchAge !== undefined ? `${a.patchAge} days` : '-' },
                      { label: 'Last Scan',   value: a.lastScan },
                      { label: 'Uptime',      value: a.uptime !== undefined ? `${a.uptime}%` : '-' },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex items-start justify-between gap-2 py-1.5 border-b border-white/4 last:border-0">
                        <span className="text-[10px] text-ink-600 shrink-0">{label}</span>
                        <span className="text-[10px] text-ink-300 text-right font-mono truncate">{value}</span>
                      </div>
                    ))}
                  </div>

                  <div>
                    <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5">Tags</p>
                    <div className="flex flex-wrap gap-1">
                      {a.tags.map((t) => (
                        <span key={t} className="text-[9px] px-2 py-1 rounded-full bg-white/5 border border-white/8 text-ink-400">{t}</span>
                      ))}
                    </div>
                  </div>

                  {/* Linked activity: asset ↔ alert ↔ case, one click away */}
                  {activity && (activity.summary.alerts > 0 || activity.summary.cases > 0 || activity.summary.openVulns > 0) && (
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5">
                        Linked activity
                        <span className="ml-2 normal-case tracking-normal text-ink-500">
                          {activity.summary.openAlerts} open alerts · {activity.summary.cases} cases · {activity.summary.openVulns} CVEs
                        </span>
                      </p>
                      <div className="space-y-1">
                        {activity.vulnFindings.slice(0, 3).map((v) => (
                          <div key={v.cve} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-surface-2/50 border border-white/5">
                            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0"
                              style={{ color: v.severity === 'critical' ? tk('magenta') : tk('threat'),
                                       background: v.severity === 'critical' ? withAlpha(tk('magenta'), 0.09) : withAlpha(tk('threat'), 0.09) }}>
                              {v.cvss.toFixed(1)}
                            </span>
                            <span className="text-[10px] font-mono text-ink-200 truncate">{v.cve}</span>
                            <span className="text-[9px] text-ink-600 truncate">{v.product} {v.version}</span>
                          </div>
                        ))}
                        {activity.alerts.slice(0, 4).map((al) => (
                          <a key={al.id} href={`/dashboard/siem?q=${encodeURIComponent(al.srcIp ?? a.name)}`}
                            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-surface-2/50 border border-white/5 hover:border-white/15 transition-colors">
                            <span className="w-1.5 h-1.5 rounded-full shrink-0"
                              style={{ background: { critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe') }[al.severity] ?? tk('violet') }} />
                            <span className="text-[10px] text-ink-300 truncate flex-1">{al.title}</span>
                            <span className="text-[9px] text-ink-600 capitalize shrink-0">{al.status}</span>
                          </a>
                        ))}
                        {activity.cases.slice(0, 2).map((c) => (
                          <a key={c.id} href="/dashboard/soar"
                            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-surface-2/50 border border-white/5 hover:border-white/15 transition-colors">
                            <span className="text-[9px] font-mono text-violet shrink-0">{c.id}</span>
                            <span className="text-[10px] text-ink-300 truncate flex-1">{c.title}</span>
                            <span className="text-[9px] text-ink-600 capitalize shrink-0">{c.status}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex flex-col gap-2 pt-2">
                    <button onClick={() => scanAsset(a.id)} disabled={a.status === 'scanning'}
                      className="flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs bg-violet/10 border border-violet/25 text-violet hover:bg-violet/20 transition-colors disabled:opacity-40">
                      <RefreshCw className={cn('w-3.5 h-3.5', a.status === 'scanning' && 'animate-spin')} />
                      {a.status === 'scanning' ? 'Scanning…' : 'Re-scan Asset'}
                    </button>
                    <button onClick={() => removeAsset(a.id)}
                      className="flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs border border-threat/25 text-threat hover:bg-threat/10 transition-colors">
                      <Trash2 className="w-3.5 h-3.5" /> Remove Asset
                    </button>
                  </div>
                </div>
              )
            })()}
          </div>
        ) : (
          /* Summary panel */
          <div className="flex-1 overflow-y-auto p-4 space-y-5">
            <p className="text-xs font-semibold text-white">Attack Surface Summary</p>

            {/* Asset type breakdown */}
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">By Type</p>
              {(Object.keys(TYPE_META) as AssetType[]).map((t) => {
                const count = assets.filter((a) => a.type === t).length
                if (count === 0) return null
                const TM = TYPE_META[t]
                return (
                  <div key={t} className="flex items-center gap-2 mb-2">
                    <TM.icon className="w-3 h-3 shrink-0" style={{ color: TM.color }} />
                    <span className="text-[10px] text-ink-400 flex-1">{TM.label}</span>
                    <div className="w-16 h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${(count / assets.length) * 100}%`, background: TM.color }} />
                    </div>
                    <span className="text-[10px] font-mono text-ink-500 w-4 text-right">{count}</span>
                  </div>
                )
              })}
            </div>

            {/* CVE breakdown */}
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Total CVEs</p>
              {[
                { label: 'Critical', value: assets.reduce((s,a)=>s+a.cves.critical,0), color: tk('magenta') },
                { label: 'High',     value: assets.reduce((s,a)=>s+a.cves.high,0),     color: tk('threat') },
                { label: 'Medium',   value: assets.reduce((s,a)=>s+a.cves.medium,0),   color: tk('amber') },
                { label: 'Low',      value: assets.reduce((s,a)=>s+a.cves.low,0),      color: tk('safe') },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center gap-2 mb-1.5">
                  <span className="text-[10px] text-ink-400 w-12">{label}</span>
                  <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${Math.min(100, value * 3)}%`, background: color }} />
                  </div>
                  <span className="text-[10px] font-bold w-6 text-right" style={{ color }}>{value}</span>
                </div>
              ))}
            </div>

            {/* Top risk assets */}
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Highest Risk</p>
              {[...assets].sort((a, b) => b.riskScore - a.riskScore).slice(0, 4).map((a) => (
                <button key={a.id} onClick={() => setSelectedId(a.id)}
                  className="w-full flex items-center gap-2 py-1.5 hover:bg-white/3 rounded-lg px-1 transition-colors group text-left">
                  <RiskRing score={a.riskScore} size={30} />
                  <div className="flex-1 min-w-0">
                    <p className="text-[10px] text-ink-300 truncate">{a.name}</p>
                    <CveBadges cves={a.cves} />
                  </div>
                  <ChevronRight className="w-3 h-3 text-ink-700 group-hover:text-ink-400" />
                </button>
              ))}
            </div>

            {/* Patch health */}
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Patch Health</p>
              {[
                { label: 'Up to date (≤7d)',   count: assets.filter(a => (a.patchAge ?? 0) <= 7).length,  color: tk('safe') },
                { label: 'Needs update (8-30d)', count: assets.filter(a => (a.patchAge ?? 0) > 7 && (a.patchAge ?? 0) <= 30).length, color: tk('amber') },
                { label: 'Overdue (>30d)',       count: assets.filter(a => (a.patchAge ?? 0) > 30).length, color: tk('magenta') },
              ].map(({ label, count, color }) => (
                <div key={label} className="flex items-center gap-2 mb-1.5">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
                  <span className="text-[10px] text-ink-500 flex-1 truncate">{label}</span>
                  <span className="text-[10px] font-bold" style={{ color }}>{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* -- Add asset modal ---------------------------------------- */}
      <AnimatePresence>
        {showAdd && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
            onClick={() => setShowAdd(false)}
          >
            <motion.div
              initial={{ scale: 0.94, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.94, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-md bg-surface border border-white/10 rounded-2xl p-6"
            >
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Plus className="w-4 h-4 text-magenta" /> Add Asset to Monitor
                </h3>
                <button onClick={() => setShowAdd(false)} className="p-1 rounded text-ink-500 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">Asset Type</label>
              <div className="grid grid-cols-3 gap-2 mb-4">
                {(Object.keys(TYPE_META) as AssetType[]).map((t) => {
                  const M = TYPE_META[t]
                  return (
                    <button key={t} onClick={() => setFormType(t)}
                      className={cn('flex flex-col items-center gap-1.5 py-2.5 rounded-xl border text-[10px] transition-colors',
                        formType === t ? 'border-magenta/40 bg-magenta/8 text-white' : 'border-white/8 text-ink-400 hover:border-white/20')}>
                      <M.icon className="w-4 h-4" style={{ color: M.color }} />
                      {M.label}
                    </button>
                  )
                })}
              </div>

              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">Criticality</label>
              <div className="grid grid-cols-4 gap-2 mb-4">
                {(['critical', 'high', 'medium', 'low'] as Criticality[]).map((c) => (
                  <button key={c} onClick={() => setFormCrit(c)}
                    className={cn('py-2 rounded-lg border text-[10px] font-semibold capitalize transition-colors',
                      formCrit === c ? 'text-white' : 'border-white/8 text-ink-500 hover:border-white/20')}
                    style={formCrit === c ? { borderColor: CRIT_COLOR[c] + '60', background: CRIT_COLOR[c] + '18', color: CRIT_COLOR[c] } : undefined}>
                    {c}
                  </button>
                ))}
              </div>

              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">Display Name</label>
              <input value={name} onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Corporate Website"
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 mb-3 focus:outline-none focus:border-magenta/40" />

              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">
                {formType === 'domain' ? 'Domain' : formType === 'ip' ? 'IP Address' : formType === 'cloud' ? 'Cloud ID' : 'Hostname / Address'}
              </label>
              <input value={formValue} onChange={(e) => setFormValue(e.target.value)}
                placeholder={formType === 'domain' ? 'example.com' : formType === 'ip' ? '203.0.113.10' : 'hostname'}
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 font-mono mb-5 focus:outline-none focus:border-magenta/40" />

              <div className="flex items-center gap-2">
                <button onClick={addAsset} disabled={!name.trim() || !formValue.trim()}
                  className="flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-sm font-semibold bg-plasma text-white shadow-magenta-sm hover:shadow-magenta transition-all disabled:opacity-40">
                  <Activity className="w-4 h-4" /> Add &amp; Scan
                </button>
                <button onClick={() => setShowAdd(false)}
                  className="px-4 py-2.5 rounded-xl text-sm text-ink-400 border border-white/8 hover:text-white transition-colors">
                  Cancel
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
