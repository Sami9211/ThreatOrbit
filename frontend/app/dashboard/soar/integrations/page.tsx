'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Link, Plus, CheckCircle, AlertTriangle, XCircle, Settings,
  RefreshCw, Activity, Zap, Shield, Globe, Database, Clock,
  ChevronRight, ToggleLeft, ToggleRight, X, Code,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type IntStatus = 'connected' | 'degraded' | 'disconnected' | 'pending'
type IntCategory = 'EDR' | 'Firewall' | 'SIEM' | 'Ticketing' | 'Communication' | 'Threat Intel' | 'Identity' | 'Cloud'

interface Integration {
  id: string
  name: string
  vendor: string
  category: IntCategory
  status: IntStatus
  lastSync: string
  actionsRun: number
  avgResponseMs: number
  description: string
  actions: string[]
  enabled: boolean
}

const INTEGRATIONS: Integration[] = [
  { id: 'i01', name: 'CrowdStrike Falcon',  vendor: 'CrowdStrike',  category: 'EDR',          status: 'connected',    lastSync: '8s ago',   actionsRun: 1847, avgResponseMs: 220,  description: 'Endpoint isolation, process kill, containment via RTR', actions: ['Contain Host', 'Kill Process', 'Get Process Tree', 'Network Quarantine'], enabled: true },
  { id: 'i02', name: 'Palo Alto NGFW',      vendor: 'Palo Alto',    category: 'Firewall',     status: 'connected',    lastSync: '3m ago',   actionsRun: 924,  avgResponseMs: 540,  description: 'Block IPs, add to DAGs, update security policy', actions: ['Block IP', 'Block URL', 'Add to DAG', 'Get Traffic Logs'], enabled: true },
  { id: 'i03', name: 'Splunk ES',           vendor: 'Splunk',       category: 'SIEM',         status: 'connected',    lastSync: '1m ago',   actionsRun: 3241, avgResponseMs: 180,  description: 'Create notable events, run SPL searches, update risk scores', actions: ['Create Notable', 'Run Search', 'Add Risk Score', 'Correlate Events'], enabled: true },
  { id: 'i04', name: 'Jira Service Mgmt',   vendor: 'Atlassian',    category: 'Ticketing',    status: 'connected',    lastSync: '2m ago',   actionsRun: 548,  avgResponseMs: 1200, description: 'Auto-create incidents, assign tickets, update SLA fields', actions: ['Create Issue', 'Update Issue', 'Assign Issue', 'Add Comment'], enabled: true },
  { id: 'i05', name: 'PagerDuty',           vendor: 'PagerDuty',    category: 'Communication', status: 'connected',   lastSync: '45s ago',  actionsRun: 287,  avgResponseMs: 340,  description: 'Page on-call engineers, trigger incidents, resolve alerts', actions: ['Create Incident', 'Trigger Alert', 'Resolve Incident', 'Send Notification'], enabled: true },
  { id: 'i06', name: 'Slack',               vendor: 'Slack',        category: 'Communication', status: 'connected',   lastSync: '12s ago',  actionsRun: 2140, avgResponseMs: 290,  description: 'War room notifications, analyst alerts, status updates', actions: ['Send Message', 'Create Channel', 'Post File', 'Add Reaction'], enabled: true },
  { id: 'i07', name: 'VirusTotal',          vendor: 'Google',       category: 'Threat Intel', status: 'connected',    lastSync: '5m ago',   actionsRun: 7824, avgResponseMs: 680,  description: 'Enrich IOCs — IPs, domains, hashes, URLs against 90+ engines', actions: ['Scan IP', 'Scan URL', 'Scan Hash', 'Get File Report'], enabled: true },
  { id: 'i08', name: 'Recorded Future',     vendor: 'Recorded Future', category: 'Threat Intel', status: 'connected', lastSync: '11m ago',  actionsRun: 1203, avgResponseMs: 820,  description: 'Threat actor enrichment, risk scoring, C2 infrastructure lookup', actions: ['Enrich IP', 'Actor Lookup', 'Risk Score', 'IOC Context'], enabled: true },
  { id: 'i09', name: 'Okta',               vendor: 'Okta',          category: 'Identity',     status: 'degraded',    lastSync: '18m ago',  actionsRun: 344,  avgResponseMs: 4800, description: 'Suspend user, reset MFA, revoke sessions, get user activity', actions: ['Suspend User', 'Reset MFA', 'Revoke Sessions', 'Get User Logs'], enabled: true },
  { id: 'i10', name: 'AWS Security Hub',   vendor: 'Amazon',         category: 'Cloud',        status: 'connected',   lastSync: '2m ago',   actionsRun: 892,  avgResponseMs: 450,  description: 'Update findings, isolate EC2, revoke IAM keys, S3 lockdown', actions: ['Update Finding', 'Isolate EC2', 'Revoke IAM Key', 'Block S3 Access'], enabled: true },
  { id: 'i11', name: 'Microsoft Sentinel', vendor: 'Microsoft',      category: 'SIEM',         status: 'pending',     lastSync: 'Never',    actionsRun: 0,    avgResponseMs: 0,    description: 'Pending API configuration — requires Azure app registration', actions: ['Create Incident', 'Run Logic App', 'Update Alert'], enabled: false },
  { id: 'i12', name: 'ServiceNow ITSM',   vendor: 'ServiceNow',      category: 'Ticketing',   status: 'disconnected', lastSync: '3d ago',   actionsRun: 0,    avgResponseMs: 0,    description: 'Disconnected — credential rotation required', actions: ['Create Incident', 'Update Incident', 'Assign CI'], enabled: false },
]

const CAT_COLORS: Record<IntCategory, string> = {
  EDR: 'bg-magenta/15 text-magenta border-magenta/20',
  Firewall: 'bg-threat/15 text-[#FF4D6D] border-threat/20',
  SIEM: 'bg-violet/15 text-violet border-violet/20',
  Ticketing: 'bg-amber/15 text-amber border-amber/20',
  Communication: 'bg-safe/15 text-safe border-safe/20',
  'Threat Intel': 'bg-violet/15 text-violet border-violet/20',
  Identity: 'bg-amber/15 text-amber border-amber/20',
  Cloud: 'bg-safe/15 text-safe border-safe/20',
}

const STATUS_CFG: Record<IntStatus, { label: string; cls: string; dot: string }> = {
  connected:    { label: 'Connected',    cls: 'text-safe  border-safe/20  bg-safe/10',  dot: 'bg-safe animate-pulse'  },
  degraded:     { label: 'Degraded',     cls: 'text-amber border-amber/20 bg-amber/10', dot: 'bg-amber'               },
  disconnected: { label: 'Disconnected', cls: 'text-threat border-threat/20 bg-threat/10', dot: 'bg-threat'           },
  pending:      { label: 'Pending',      cls: 'text-ink-400 border-white/10 bg-white/5',  dot: 'bg-ink-500'            },
}

export default function SoarIntegrationsPage() {
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>(
    Object.fromEntries(INTEGRATIONS.map(i => [i.id, i.enabled]))
  )
  const [selected, setSelected] = useState<string | null>(null)
  const [catFilter, setCatFilter] = useState<string>('All')

  const categories = ['All', ...Array.from(new Set(INTEGRATIONS.map(i => i.category)))]
  const filtered = catFilter === 'All' ? INTEGRATIONS : INTEGRATIONS.filter(i => i.category === catFilter)
  const selectedInt = INTEGRATIONS.find(i => i.id === selected) ?? null

  const connected = INTEGRATIONS.filter(i => i.status === 'connected').length
  const totalActions = INTEGRATIONS.reduce((a, i) => a + i.actionsRun, 0)

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Link className="w-4 h-4 text-safe" />
            <h1 className="text-lg font-display font-semibold text-white">Integrations</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Connect security tools for automated response actions</p>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold">
          <Plus className="w-3.5 h-3.5" />
          Connect Tool
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Connected',     value: connected,                        color: 'text-safe'   },
          { label: 'Total Actions', value: `${(totalActions/1000).toFixed(1)}k`, color: 'text-violet' },
          { label: 'Degraded',      value: INTEGRATIONS.filter(i => i.status === 'degraded').length, color: 'text-amber' },
          { label: 'Offline',       value: INTEGRATIONS.filter(i => i.status === 'disconnected').length, color: 'text-threat' },
        ].map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Category filter */}
      <div className="flex items-center gap-2 px-6 py-2.5 border-b border-white/4 shrink-0 overflow-x-auto">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setCatFilter(cat)}
            className={cn(
              'px-3 py-1 rounded-full text-[11px] font-medium whitespace-nowrap transition-colors',
              catFilter === cat
                ? 'bg-magenta/20 text-magenta border border-magenta/30'
                : 'bg-white/4 text-ink-500 border border-white/8 hover:text-ink-200',
            )}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Integration cards */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((int, i) => {
            const st = STATUS_CFG[int.status]
            const isEnabled = enabledMap[int.id] ?? int.enabled
            const isSelected = selected === int.id
            return (
              <motion.div
                key={int.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                onClick={() => setSelected(isSelected ? null : int.id)}
                className={cn(
                  'rounded-xl border p-4 cursor-pointer transition-all',
                  isSelected
                    ? 'border-magenta/30 bg-magenta/5 ring-1 ring-magenta/20'
                    : 'border-white/8 bg-[#0D0920] hover:border-white/15',
                  !isEnabled && 'opacity-50',
                )}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white truncate">{int.name}</p>
                    <p className="text-[10px] text-ink-600">{int.vendor}</p>
                  </div>
                  <div className="flex items-center gap-2 ml-2">
                    <button
                      onClick={e => { e.stopPropagation(); setEnabledMap(prev => ({ ...prev, [int.id]: !prev[int.id] })) }}
                    >
                      {isEnabled
                        ? <ToggleRight className="w-5 h-5 text-safe" />
                        : <ToggleLeft className="w-5 h-5 text-ink-600" />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center gap-2 mb-3">
                  <span className={cn('text-[9px] font-semibold px-1.5 py-0.5 rounded-full border', CAT_COLORS[int.category])}>
                    {int.category}
                  </span>
                  <span className={cn('flex items-center gap-1 text-[9px] font-medium px-1.5 py-0.5 rounded-full border', st.cls)}>
                    <span className={cn('w-1.5 h-1.5 rounded-full', st.dot)} />
                    {st.label}
                  </span>
                </div>

                <p className="text-[10px] text-ink-500 leading-snug line-clamp-2 mb-3">{int.description}</p>

                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-ink-600">
                    <Activity className="w-3 h-3 inline mr-1 text-violet" />
                    {int.actionsRun.toLocaleString()} actions
                  </span>
                  <span className="text-ink-600">
                    <Clock className="w-3 h-3 inline mr-1" />
                    {int.lastSync}
                  </span>
                  {int.avgResponseMs > 0 && (
                    <span className={cn('font-mono', int.avgResponseMs > 2000 ? 'text-amber' : 'text-safe')}>
                      {int.avgResponseMs}ms
                    </span>
                  )}
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* Detail expansion */}
        <AnimatePresence>
          {selectedInt && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 overflow-hidden"
            >
              <div className="p-5 rounded-2xl border border-magenta/20 bg-magenta/3 glass">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold text-white">{selectedInt.name} — Available Actions</h3>
                  <button onClick={() => setSelected(null)} className="p-1.5 rounded-lg hover:bg-white/8 text-ink-500">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="grid sm:grid-cols-2 gap-3">
                  {selectedInt.actions.map(action => (
                    <div key={action} className="flex items-center justify-between p-3 rounded-xl bg-white/4 border border-white/8">
                      <div className="flex items-center gap-2">
                        <Zap className="w-3.5 h-3.5 text-violet" />
                        <span className="text-xs text-ink-200">{action}</span>
                      </div>
                      <button className="text-[10px] text-magenta hover:underline">Run</button>
                    </div>
                  ))}
                </div>
                <div className="flex items-center gap-2 mt-4">
                  <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white">
                    <Settings className="w-3.5 h-3.5" />
                    Configure
                  </button>
                  <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white">
                    <RefreshCw className="w-3.5 h-3.5" />
                    Test Connection
                  </button>
                  <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white">
                    <Code className="w-3.5 h-3.5" />
                    View API Docs
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
