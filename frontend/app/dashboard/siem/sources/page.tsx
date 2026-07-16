'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Database, Plus, RefreshCw, CheckCircle, AlertTriangle,
  XCircle, Settings, 
  Activity, Clock, 
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchSiemSources, createLogSource } from '@/lib/api'
import CreateModal from '@/components/dashboard/CreateModal'
import LogAnalysisPanel from '@/components/dashboard/LogAnalysisPanel'
import LogCollectorPanel from '@/components/dashboard/LogCollectorPanel'
import { tk } from '@/lib/colors'

type SourceStatus = 'healthy' | 'degraded' | 'offline' | 'paused'
type SourceType = 'Syslog' | 'Windows Event' | 'CEF/ArcSight' | 'API Pull' | 'Kafka' | 'S3 Bucket' | 'Splunk Forwarder'

interface LogSource {
  id: string
  name: string
  type: SourceType
  host: string
  status: SourceStatus
  epsAvg: number
  epsPeak: number
  lastEvent: string
  totalEvents24h: string
  latencyMs: number
  parseSuccess: number
  format: string
  tags: string[]
}

const SOURCES: LogSource[] = [
  { id: 's01', name: 'Windows Domain Controllers (6 hosts)', type: 'Windows Event', host: 'dc-prod-01..06', status: 'healthy',  epsAvg: 1240, epsPeak: 4800, lastEvent: '2s ago',   totalEvents24h: '107M', latencyMs: 140,  parseSuccess: 99.8, format: 'WEF/WinRM',      tags: ['AD', 'Identity', 'Critical'] },
  { id: 's02', name: 'Linux Fleet - Endpoint Syslog',        type: 'Syslog',        host: '10.0.0.0/16',  status: 'healthy',  epsAvg: 2840, epsPeak: 6200, lastEvent: '1s ago',   totalEvents24h: '245M', latencyMs: 88,   parseSuccess: 98.4, format: 'RFC 5424',       tags: ['Linux', 'Endpoint'] },
  { id: 's03', name: 'AWS CloudTrail (us-east-1)',            type: 'S3 Bucket',     host: 's3://ct-logs', status: 'healthy',  epsAvg: 380,  epsPeak: 1100, lastEvent: '12s ago',  totalEvents24h: '33M',  latencyMs: 2800, parseSuccess: 100,  format: 'JSON CloudTrail', tags: ['Cloud', 'AWS', 'IAM'] },
  { id: 's04', name: 'Palo Alto NGFW',                       type: 'Syslog',        host: '10.0.1.254',   status: 'healthy',  epsAvg: 3200, epsPeak: 8400, lastEvent: '<1s ago',  totalEvents24h: '277M', latencyMs: 55,   parseSuccess: 99.6, format: 'PAN-OS Syslog',   tags: ['Network', 'Firewall', 'Critical'] },
  { id: 's05', name: 'CrowdStrike EDR',                      type: 'API Pull',      host: 'api.crowdstrike.com', status: 'healthy', epsAvg: 920, epsPeak: 2400, lastEvent: '4s ago', totalEvents24h: '80M', latencyMs: 320, parseSuccess: 100, format: 'CS JSON',         tags: ['EDR', 'Endpoint', 'Critical'] },
  { id: 's06', name: 'Office 365 Unified Audit Log',         type: 'API Pull',      host: 'graph.microsoft.com', status: 'degraded', epsAvg: 88, epsPeak: 340, lastEvent: '4m ago', totalEvents24h: '7.6M', latencyMs: 8400, parseSuccess: 97.1, format: 'O365 JSON',      tags: ['SaaS', 'Identity', 'Email'] },
  { id: 's07', name: 'Kubernetes Audit Logs (k8s-prod)',     type: 'Kafka',         host: 'kafka:9092',   status: 'healthy',  epsAvg: 660,  epsPeak: 1800, lastEvent: '2s ago',   totalEvents24h: '57M',  latencyMs: 195,  parseSuccess: 99.2, format: 'K8s JSON',        tags: ['Cloud', 'Kubernetes', 'API'] },
  { id: 's08', name: 'MySQL Slow Query Log',                 type: 'Syslog',        host: '10.0.5.22',   status: 'paused',   epsAvg: 0,    epsPeak: 120,  lastEvent: '2h ago',   totalEvents24h: '0',    latencyMs: 0,    parseSuccess: 94.2, format: 'MySQL Text',      tags: ['Database'] },
  { id: 's09', name: 'Cisco ASA Firewall',                   type: 'Syslog',        host: '10.8.0.1',    status: 'offline',  epsAvg: 0,    epsPeak: 2200, lastEvent: '4h ago',   totalEvents24h: '0',    latencyMs: 0,    parseSuccess: 0,    format: 'Cisco ASA',       tags: ['Network', 'Critical'] },
  { id: 's10', name: 'GitHub Enterprise Audit',              type: 'API Pull',      host: 'github.corp', status: 'healthy',  epsAvg: 14,   epsPeak: 88,   lastEvent: '18s ago',  totalEvents24h: '1.2M', latencyMs: 1200, parseSuccess: 100,  format: 'GitHub JSON',     tags: ['DevOps', 'SCM'] },
]

const STATUS_CONFIG: Record<SourceStatus, { label: string; color: string; dot: string; icon: React.ComponentType<any> }> = {
  healthy:  { label: 'Healthy',  color: 'text-safe  bg-safe/10  border-safe/20',  dot: 'bg-safe',    icon: CheckCircle  },
  degraded: { label: 'Degraded', color: 'text-amber bg-amber/10 border-amber/20', dot: 'bg-amber',   icon: AlertTriangle },
  offline:  { label: 'Offline',  color: 'text-threat bg-threat/10 border-threat/20', dot: 'bg-threat', icon: XCircle    },
  paused:   { label: 'Paused',   color: 'text-ink-400 bg-white/5 border-white/10', dot: 'bg-ink-500', icon: Clock      },
}

export default function SiemSourcesPage() {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const [sourcesData, setSourcesData] = useState(SOURCES)
  const [showAdd, setShowAdd] = useState(false)

  useEffect(() => {
    fetchSiemSources()
      .then((data) => { if (data.length > 0) setSourcesData(data as unknown as typeof SOURCES) })
      .catch(() => {})
  }, [])

  async function handleAddSource(values: Record<string, string>) {
    const created = await createLogSource({
      name: values.name, type: values.type, host: values.host || undefined,
      format: values.format || undefined,
    })
    setSourcesData((prev) => [created as unknown as LogSource, ...prev])
  }

  const SOURCES_ACTIVE = sourcesData

  const filtered = SOURCES_ACTIVE.filter(s => {
    if (statusFilter !== 'all' && s.status !== statusFilter) return false
    if (search && !s.name.toLowerCase().includes(search.toLowerCase()) && !s.host.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const selectedSource = SOURCES_ACTIVE.find(s => s.id === selected) ?? null

  const totalEps = SOURCES_ACTIVE.filter(s => s.status === 'healthy' || s.status === 'degraded').reduce((acc, s) => acc + s.epsAvg, 0)
  const healthyCount = SOURCES_ACTIVE.filter(s => s.status === 'healthy').length
  const offlineCount = SOURCES_ACTIVE.filter(s => s.status === 'offline').length
  const degradedCount = SOURCES_ACTIVE.filter(s => s.status === 'degraded').length

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-violet" />
            <h1 className="text-lg font-display font-semibold text-white">Log Sources</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Data ingestion pipeline - {SOURCES_ACTIVE.length} sources configured</p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
          <Plus className="w-3.5 h-3.5" />
          Add Source
        </button>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Total EPS',    value: `${(totalEps / 1000).toFixed(1)}k`, color: 'text-violet'  },
          { label: 'Healthy',      value: healthyCount,                         color: 'text-safe'    },
          { label: 'Degraded',     value: degradedCount,                        color: 'text-amber'   },
          { label: 'Offline',      value: offlineCount,                         color: 'text-threat'  },
        ].map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Native log collector + deep-analysis bridge */}
      <div className="px-6 pt-4 shrink-0 space-y-4">
        <LogCollectorPanel />
        <LogAnalysisPanel />
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-white/4 shrink-0">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search sources..."
          className="flex-1 max-w-xs bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-ink-600 outline-hidden focus:border-magenta/30"
        />
        {(['all', 'healthy', 'degraded', 'offline', 'paused'] as const).map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={cn(
              'px-3 py-1 rounded-full text-[11px] font-medium capitalize transition-colors',
              statusFilter === s
                ? 'bg-magenta/20 text-magenta border border-magenta/30'
                : 'bg-white/4 text-ink-500 border border-white/8 hover:text-ink-200',
            )}
          >
            {s === 'all' ? 'All' : s}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-[#0A0612] border-b border-white/8">
            <tr>
              {['Source Name', 'Type', 'Host', 'Status', 'EPS avg', 'Latency', 'Parse Rate', 'Last Event', 'Tags'].map(h => (
                <th key={h} className="text-left px-4 py-2.5 text-[10px] text-ink-500 font-semibold uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((src, i) => {
              const st = STATUS_CONFIG[src.status]
              return (
                <motion.tr
                  key={src.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  onClick={() => setSelected(selected === src.id ? null : src.id)}
                  className={cn(
                    'border-b border-white/4 cursor-pointer transition-colors',
                    selected === src.id ? 'bg-magenta/5 border-l-2 border-l-magenta/50' : 'hover:bg-white/3',
                    i % 2 !== 0 && selected !== src.id && 'bg-white/1',
                  )}
                >
                  <td className="px-4 py-3 font-medium text-ink-100">{src.name}</td>
                  <td className="px-4 py-3 text-ink-400">{src.type}</td>
                  <td className="px-4 py-3 font-mono text-ink-500 text-[10px]">{src.host}</td>
                  <td className="px-4 py-3">
                    <span className={cn('flex items-center gap-1.5 w-fit px-2 py-0.5 rounded-full border text-[10px] font-semibold', st.color)}>
                      <span className={cn('w-1.5 h-1.5 rounded-full', st.dot, src.status === 'healthy' && 'animate-pulse')} />
                      {st.label}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-violet text-right">
                    {src.epsAvg > 0 ? src.epsAvg.toLocaleString() : '-'}
                  </td>
                  <td className={cn('px-4 py-3 font-mono text-right', src.latencyMs > 5000 ? 'text-amber' : src.latencyMs > 0 ? 'text-safe' : 'text-ink-600')}>
                    {src.latencyMs > 0 ? `${src.latencyMs}ms` : '-'}
                  </td>
                  <td className={cn('px-4 py-3 font-mono text-right', src.parseSuccess >= 99 ? 'text-safe' : src.parseSuccess >= 95 ? 'text-amber' : 'text-threat')}>
                    {src.parseSuccess > 0 ? `${src.parseSuccess}%` : '-'}
                  </td>
                  <td className="px-4 py-3 text-ink-500 whitespace-nowrap">{src.lastEvent}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {src.tags.slice(0, 2).map(t => (
                        <span key={t} className="text-[9px] px-1.5 py-0.5 rounded-sm bg-white/5 text-ink-500 border border-white/8">{t}</span>
                      ))}
                    </div>
                  </td>
                </motion.tr>
              )
            })}
          </tbody>
        </table>

        {/* Detail panel */}
        <AnimatePresence>
          {selectedSource && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              className="mx-4 my-4 p-5 rounded-2xl border border-magenta/20 bg-magenta/3 glass"
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="font-semibold text-white">{selectedSource.name}</h3>
                  <p className="text-xs text-ink-500">{selectedSource.type} · {selectedSource.format}</p>
                </div>
                <button onClick={() => setSelected(null)} className="p-1.5 rounded-lg hover:bg-white/8 text-ink-500">
                  <XCircle className="w-4 h-4" />
                </button>
              </div>
              <div className="grid sm:grid-cols-3 gap-4">
                {[
                  { label: 'Peak EPS',       value: selectedSource.epsPeak.toLocaleString()        },
                  { label: 'Events (24h)',   value: selectedSource.totalEvents24h                   },
                  { label: 'Avg Latency',   value: selectedSource.latencyMs > 0 ? `${selectedSource.latencyMs}ms` : 'N/A' },
                  { label: 'Parse Success', value: selectedSource.parseSuccess > 0 ? `${selectedSource.parseSuccess}%` : 'N/A' },
                  { label: 'Host / Endpoint', value: selectedSource.host                           },
                  { label: 'Tags',           value: selectedSource.tags.join(', ')                 },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-0.5">{label}</p>
                    <p className="text-sm font-mono text-ink-200">{value}</p>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-2 mt-4">
                <button className="px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white flex items-center gap-1.5">
                  <Settings className="w-3.5 h-3.5" />
                  Configure
                </button>
                <button className="px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white flex items-center gap-1.5">
                  <RefreshCw className="w-3.5 h-3.5" />
                  Reconnect
                </button>
                <button className="px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Test Parse
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <AnimatePresence>
        {showAdd && (
          <CreateModal
            title="Add Log Source"
            icon={Database}
            accent={tk('violet')}
            submitLabel="Add Source"
            onClose={() => setShowAdd(false)}
            onSubmit={handleAddSource}
            fields={[
              { key: 'name', label: 'Source name', required: true, placeholder: 'e.g. Kubernetes Audit Logs' },
              { key: 'type', label: 'Type', type: 'select', options: [
                { value: 'Syslog', label: 'Syslog' }, { value: 'Windows Event', label: 'Windows Event' },
                { value: 'CEF/ArcSight', label: 'CEF/ArcSight' }, { value: 'API Pull', label: 'API Pull' },
                { value: 'Kafka', label: 'Kafka' }, { value: 'S3 Bucket', label: 'S3 Bucket' },
                { value: 'Splunk Forwarder', label: 'Splunk Forwarder' },
              ] },
              { key: 'host', label: 'Host / endpoint', placeholder: 'e.g. 10.0.1.254 or kafka:9092' },
              { key: 'format', label: 'Log format', placeholder: 'e.g. RFC 5424, JSON' },
            ]}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
