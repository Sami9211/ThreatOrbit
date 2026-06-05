'use client'

import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plus, Server, Globe, Database, Cloud, Smartphone, Shield,
  Search, Trash2, RefreshCw, AlertTriangle, CheckCircle, Clock,
  X, Activity, Wifi,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Types ───────────────────────────────────────────────────────── */
type AssetType = 'domain' | 'ip' | 'server' | 'cloud' | 'database' | 'endpoint'
type ScanStatus = 'clean' | 'scanning' | 'at-risk' | 'critical' | 'unscanned'

type Asset = {
  id: string
  name: string
  type: AssetType
  value: string
  status: ScanStatus
  lastScan: string
  alerts: number
  exposure: number // 0-100
  tags: string[]
}

const TYPE_META: Record<AssetType, { icon: React.ElementType; label: string; color: string }> = {
  domain:   { icon: Globe,      label: 'Domain',      color: '#7A3CFF' },
  ip:       { icon: Wifi,       label: 'IP Address',  color: '#2DD4BF' },
  server:   { icon: Server,     label: 'Server',      color: '#FF2E97' },
  cloud:    { icon: Cloud,      label: 'Cloud',       color: '#FFB23E' },
  database: { icon: Database,   label: 'Database',    color: '#FF4D6D' },
  endpoint: { icon: Smartphone, label: 'Endpoint',    color: '#34F5C5' },
}

const STATUS_META: Record<ScanStatus, { label: string; color: string; bg: string }> = {
  clean:      { label: 'Clean',     color: '#34F5C5', bg: 'bg-safe/10' },
  scanning:   { label: 'Scanning',  color: '#7A3CFF', bg: 'bg-violet/10' },
  'at-risk':  { label: 'At Risk',   color: '#FFB23E', bg: 'bg-amber/10' },
  critical:   { label: 'Critical',  color: '#FF2E97', bg: 'bg-magenta/10' },
  unscanned:  { label: 'Unscanned', color: '#665B7D', bg: 'bg-white/5' },
}

const SEED_ASSETS: Asset[] = [
  { id: 'a1', name: 'Corporate Website',  type: 'domain',   value: 'acme-corp.com',          status: 'critical', lastScan: '4m ago',  alerts: 3, exposure: 82, tags: ['production', 'public'] },
  { id: 'a2', name: 'API Gateway',        type: 'server',   value: 'api.acme-corp.com',      status: 'at-risk',  lastScan: '12m ago', alerts: 1, exposure: 54, tags: ['production', 'api'] },
  { id: 'a3', name: 'Primary DB',         type: 'database', value: '10.0.4.12:5432',         status: 'clean',    lastScan: '8m ago',  alerts: 0, exposure: 12, tags: ['internal', 'postgres'] },
  { id: 'a4', name: 'AWS Prod Account',   type: 'cloud',    value: 'aws:944xxxx21027',       status: 'at-risk',  lastScan: '1h ago',  alerts: 2, exposure: 47, tags: ['cloud', 'iam'] },
  { id: 'a5', name: 'Edge Node EU-W',     type: 'ip',       value: '185.12.44.9',            status: 'clean',    lastScan: '15m ago', alerts: 0, exposure: 9,  tags: ['cdn', 'edge'] },
  { id: 'a6', name: 'CFO Laptop',         type: 'endpoint', value: 'WIN-CFO-04',             status: 'clean',    lastScan: '30m ago', alerts: 0, exposure: 18, tags: ['exec', 'managed'] },
]

let nextId = 100

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>(SEED_ASSETS)
  const [showAdd, setShowAdd] = useState(false)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<AssetType | 'all'>('all')

  // add-asset form state
  const [name, setName] = useState('')
  const [value, setValue] = useState('')
  const [type, setType] = useState<AssetType>('domain')

  function addAsset() {
    if (!name.trim() || !value.trim()) return
    const a: Asset = {
      id: `a${++nextId}`,
      name: name.trim(),
      type,
      value: value.trim(),
      status: 'unscanned',
      lastScan: 'never',
      alerts: 0,
      exposure: 0,
      tags: ['new'],
    }
    setAssets((prev) => [a, ...prev])
    setName(''); setValue(''); setType('domain'); setShowAdd(false)
    // kick off a simulated scan
    setTimeout(() => scanAsset(a.id), 400)
  }

  function scanAsset(id: string) {
    setAssets((prev) => prev.map((a) => (a.id === id ? { ...a, status: 'scanning' } : a)))
    setTimeout(() => {
      setAssets((prev) =>
        prev.map((a) => {
          if (a.id !== id) return a
          const exposure = Math.floor(Math.random() * 100)
          const alerts = exposure > 70 ? Math.ceil(Math.random() * 4) : exposure > 40 ? Math.ceil(Math.random() * 2) : 0
          const status: ScanStatus = exposure > 70 ? 'critical' : exposure > 40 ? 'at-risk' : 'clean'
          return { ...a, status, exposure, alerts, lastScan: 'just now' }
        }),
      )
    }, 2200)
  }

  function scanAll() {
    assets.forEach((a, i) => setTimeout(() => scanAsset(a.id), i * 250))
  }

  function removeAsset(id: string) {
    setAssets((prev) => prev.filter((a) => a.id !== id))
  }

  const filtered = useMemo(
    () =>
      assets.filter(
        (a) =>
          (typeFilter === 'all' || a.type === typeFilter) &&
          (search === '' ||
            a.name.toLowerCase().includes(search.toLowerCase()) ||
            a.value.toLowerCase().includes(search.toLowerCase())),
      ),
    [assets, typeFilter, search],
  )

  const totalAlerts = assets.reduce((s, a) => s + a.alerts, 0)
  const atRisk = assets.filter((a) => a.status === 'critical' || a.status === 'at-risk').length
  const clean = assets.filter((a) => a.status === 'clean').length

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Asset Surface</h1>
          <p className="text-xs text-ink-500 mt-0.5">Add your assets, run continuous scans, and track alerts per asset.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={scanAll}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border border-white/10 text-ink-200 hover:text-white hover:border-violet/40 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Scan All
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-plasma text-white shadow-magenta-sm hover:shadow-magenta transition-all"
          >
            <Plus className="w-3.5 h-3.5" /> Add Asset
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Assets',  value: assets.length, icon: Server,        color: '#7A3CFF' },
          { label: 'Open Alerts',   value: totalAlerts,   icon: AlertTriangle, color: '#FF2E97' },
          { label: 'At Risk',       value: atRisk,        icon: Shield,        color: '#FFB23E' },
          { label: 'Clean',         value: clean,         icon: CheckCircle,   color: '#34F5C5' },
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

      {/* Toolbar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search assets..."
            className="pl-8 pr-3 py-2 rounded-lg text-xs bg-surface-2 border border-white/8 text-ink-200 placeholder-ink-600 focus:outline-none focus:border-magenta/40 w-52"
          />
        </div>
        <div className="flex items-center gap-1 flex-wrap">
          <button
            onClick={() => setTypeFilter('all')}
            className={cn('px-2.5 py-1.5 rounded-lg text-[11px] border transition-colors',
              typeFilter === 'all' ? 'bg-white/10 border-white/20 text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}
          >
            All
          </button>
          {(Object.keys(TYPE_META) as AssetType[]).map((t) => {
            const M = TYPE_META[t]
            return (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={cn('flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] border transition-colors',
                  typeFilter === t ? 'border-white/20 text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}
                style={typeFilter === t ? { background: `${M.color}1a` } : undefined}
              >
                <M.icon className="w-3 h-3" style={{ color: M.color }} />
                {M.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Asset table */}
      <div className="glass border border-white/5 rounded-xl overflow-hidden">
        <div className="grid grid-cols-[1.4fr_1fr_auto_auto_auto] gap-4 px-4 py-2.5 text-[9px] uppercase tracking-widest text-ink-600 border-b border-white/5">
          <span>Asset</span>
          <span className="hidden md:block">Exposure</span>
          <span>Alerts</span>
          <span>Status</span>
          <span className="text-right">Actions</span>
        </div>
        <AnimatePresence initial={false}>
          {filtered.map((a) => {
            const TM = TYPE_META[a.type]
            const SM = STATUS_META[a.status]
            return (
              <motion.div
                key={a.id}
                initial={{ opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, height: 0 }}
                className="grid grid-cols-[1.4fr_1fr_auto_auto_auto] gap-4 px-4 py-3 items-center border-b border-white/4 hover:bg-white/2 transition-colors"
              >
                {/* name + value */}
                <div className="flex items-center gap-3 min-w-0">
                  <div className="p-2 rounded-lg shrink-0" style={{ background: `${TM.color}18` }}>
                    <TM.icon className="w-4 h-4" style={{ color: TM.color }} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-ink-100 truncate">{a.name}</p>
                    <p className="text-[10px] font-mono text-ink-600 truncate">{a.value}</p>
                  </div>
                </div>

                {/* exposure */}
                <div className="hidden md:flex items-center gap-2">
                  <div className="h-1.5 flex-1 bg-surface-3 rounded-full overflow-hidden max-w-[120px]">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${a.exposure}%`,
                        background: a.exposure > 70 ? '#FF2E97' : a.exposure > 40 ? '#FFB23E' : '#34F5C5',
                      }}
                    />
                  </div>
                  <span className="text-[10px] font-mono text-ink-500 w-7">{a.exposure}</span>
                </div>

                {/* alerts */}
                <div className="flex items-center justify-center w-12">
                  {a.alerts > 0 ? (
                    <span className="flex items-center gap-1 text-[11px] font-semibold text-threat">
                      <AlertTriangle className="w-3 h-3" /> {a.alerts}
                    </span>
                  ) : (
                    <span className="text-[11px] text-ink-600">—</span>
                  )}
                </div>

                {/* status */}
                <div className="w-24">
                  <span
                    className={cn('inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full font-semibold', SM.bg)}
                    style={{ color: SM.color }}
                  >
                    {a.status === 'scanning' ? (
                      <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                    ) : (
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: SM.color }} />
                    )}
                    {SM.label}
                  </span>
                  <p className="text-[9px] text-ink-700 mt-0.5 flex items-center gap-1"><Clock className="w-2 h-2" />{a.lastScan}</p>
                </div>

                {/* actions */}
                <div className="flex items-center justify-end gap-1">
                  <button
                    onClick={() => scanAsset(a.id)}
                    disabled={a.status === 'scanning'}
                    aria-label="Scan asset"
                    className="p-1.5 rounded-md text-ink-500 hover:text-violet hover:bg-white/5 transition-colors disabled:opacity-40"
                  >
                    <Search className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => removeAsset(a.id)}
                    aria-label="Remove asset"
                    className="p-1.5 rounded-md text-ink-500 hover:text-threat hover:bg-white/5 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </motion.div>
            )
          })}
        </AnimatePresence>
        {filtered.length === 0 && (
          <div className="py-14 text-center">
            <Server className="w-7 h-7 text-ink-700 mx-auto mb-2" />
            <p className="text-sm text-ink-500">No assets yet</p>
            <button onClick={() => setShowAdd(true)} className="mt-3 text-xs text-magenta hover:underline">+ Add your first asset</button>
          </div>
        )}
      </div>

      {/* Add asset modal */}
      <AnimatePresence>
        {showAdd && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
            onClick={() => setShowAdd(false)}
          >
            <motion.div
              initial={{ scale: 0.94, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.94, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-md glass border border-white/10 rounded-2xl p-6"
            >
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Plus className="w-4 h-4 text-magenta" /> Add Asset to Monitor
                </h3>
                <button onClick={() => setShowAdd(false)} aria-label="Close" className="p-1 rounded text-ink-500 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* type picker */}
              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">Asset Type</label>
              <div className="grid grid-cols-3 gap-2 mb-4">
                {(Object.keys(TYPE_META) as AssetType[]).map((t) => {
                  const M = TYPE_META[t]
                  return (
                    <button
                      key={t}
                      onClick={() => setType(t)}
                      className={cn('flex flex-col items-center gap-1.5 py-2.5 rounded-xl border text-[10px] transition-colors',
                        type === t ? 'border-magenta/40 bg-magenta/8 text-white' : 'border-white/8 text-ink-400 hover:border-white/20')}
                    >
                      <M.icon className="w-4 h-4" style={{ color: M.color }} />
                      {M.label}
                    </button>
                  )
                })}
              </div>

              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Corporate Website"
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 mb-3 focus:outline-none focus:border-magenta/40"
              />

              <label className="block text-[11px] font-medium text-ink-400 mb-1.5">
                {type === 'domain' ? 'Domain' : type === 'ip' ? 'IP Address' : type === 'cloud' ? 'Cloud Identifier' : 'Address / Host'}
              </label>
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={type === 'domain' ? 'example.com' : type === 'ip' ? '203.0.113.10' : '10.0.0.5:443'}
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 font-mono mb-5 focus:outline-none focus:border-magenta/40"
              />

              <div className="flex items-center gap-2">
                <button
                  onClick={addAsset}
                  disabled={!name.trim() || !value.trim()}
                  className="flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-sm font-semibold bg-plasma text-white shadow-magenta-sm hover:shadow-magenta transition-all disabled:opacity-40"
                >
                  <Activity className="w-4 h-4" /> Add &amp; Scan
                </button>
                <button
                  onClick={() => setShowAdd(false)}
                  className="px-4 py-2.5 rounded-xl text-sm text-ink-400 border border-white/8 hover:text-white transition-colors"
                >
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
