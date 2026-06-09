'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Database, Plus, CheckCircle, X, Save, Cloud, Fingerprint,
  MonitorSmartphone, Network, AppWindow, Settings, Radio,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchSiemSources, type LogSource } from '@/lib/api'

/* Keywords that link a connector to a live SIEM log source by name. A connector
 * shows "Connected" when a matching source is ingesting (not offline). */
const CONNECTOR_MATCH: Record<string, string[]> = {
  aws: ['aws', 'cloudtrail'], azure: ['azure'], gcp: ['gcp', 'google cloud'],
  okta: ['okta'], aad: ['azure ad', 'entra', 'sentinel'], gws: ['workspace', 'google'],
  crwd: ['crowdstrike', 'falcon'], s1: ['sentinelone'], mde: ['defender'],
  palo: ['palo alto'], cisco: ['cisco', 'firepower', 'ftd'], forti: ['fortinet', 'fortigate'],
  o365: ['office 365', 'o365', 'microsoft 365', 'exchange'], slack: ['slack'], github: ['github'],
}

/* ── Types ───────────────────────────────────────────────────────── */
type ConnCategory = 'Cloud' | 'Identity' | 'Endpoint' | 'Network' | 'SaaS'
type ConnStatus = 'connected' | 'unconfigured'

interface Connector {
  id: string
  name: string
  vendor: string
  category: ConnCategory
  status: ConnStatus
  color: string
  dataTypes: string[]
  endpoint: string
}

interface CustomSourceType {
  id: string
  name: string
  description: string
  icon: React.ElementType
}

/* ── Seed data ───────────────────────────────────────────────────── */
const CONNECTORS: Connector[] = [
  // Cloud
  { id: 'aws',    name: 'Amazon Web Services', vendor: 'AWS',              category: 'Cloud',    status: 'connected',    color: '#FFB23E', dataTypes: ['CloudTrail', 'GuardDuty', 'VPC Flow Logs'],     endpoint: 'https://cloudtrail.us-east-1.amazonaws.com' },
  { id: 'azure',  name: 'Microsoft Azure',     vendor: 'Azure',           category: 'Cloud',    status: 'connected',    color: '#7A3CFF', dataTypes: ['Activity Logs', 'Defender for Cloud', 'NSG Flow'], endpoint: 'https://management.azure.com' },
  { id: 'gcp',    name: 'Google Cloud',        vendor: 'GCP',             category: 'Cloud',    status: 'unconfigured', color: '#34F5C5', dataTypes: ['Cloud Audit Logs', 'SCC Findings'],            endpoint: '' },
  // Identity
  { id: 'okta',   name: 'Okta',                vendor: 'Okta',            category: 'Identity', status: 'connected',    color: '#7A3CFF', dataTypes: ['System Log', 'MFA Events', 'Session Events'],   endpoint: 'https://acme.okta.com/api/v1/logs' },
  { id: 'aad',    name: 'Azure AD / Entra ID', vendor: 'Microsoft',       category: 'Identity', status: 'connected',    color: '#FF2E97', dataTypes: ['Sign-in Logs', 'Audit Logs', 'Risk Detections'], endpoint: 'https://graph.microsoft.com/v1.0/auditLogs' },
  { id: 'gws',    name: 'Google Workspace',    vendor: 'Google',          category: 'Identity', status: 'unconfigured', color: '#34F5C5', dataTypes: ['Admin Audit', 'Login Audit', 'Drive Audit'],   endpoint: '' },
  // Endpoint
  { id: 'crwd',   name: 'CrowdStrike Falcon',  vendor: 'CrowdStrike',     category: 'Endpoint', status: 'connected',    color: '#FF4D6D', dataTypes: ['Detections', 'Process Events', 'Network Conn'], endpoint: 'https://api.crowdstrike.com/sensors/queries/detects' },
  { id: 's1',     name: 'SentinelOne',         vendor: 'SentinelOne',     category: 'Endpoint', status: 'connected',    color: '#7A3CFF', dataTypes: ['Threats', 'Deep Visibility', 'Agent Events'],   endpoint: 'https://acme.sentinelone.net/web/api/v2.1' },
  { id: 'mde',    name: 'Microsoft Defender',  vendor: 'Microsoft',       category: 'Endpoint', status: 'unconfigured', color: '#FF2E97', dataTypes: ['Alerts', 'Device Events', 'Advanced Hunting'], endpoint: '' },
  // Network
  { id: 'palo',   name: 'Palo Alto NGFW',      vendor: 'Palo Alto',       category: 'Network',  status: 'connected',    color: '#FFB23E', dataTypes: ['Traffic', 'Threat', 'URL Filtering'],          endpoint: 'https://panorama.acme.com/api' },
  { id: 'cisco',  name: 'Cisco Firepower',     vendor: 'Cisco',           category: 'Network',  status: 'unconfigured', color: '#34F5C5', dataTypes: ['Intrusion Events', 'Connection Events'],       endpoint: '' },
  { id: 'forti',  name: 'Fortinet FortiGate',  vendor: 'Fortinet',        category: 'Network',  status: 'connected',    color: '#FF4D6D', dataTypes: ['Traffic Logs', 'IPS Events', 'Web Filter'],    endpoint: 'https://fortigate.acme.com/api/v2' },
  // SaaS
  { id: 'o365',   name: 'Microsoft 365',       vendor: 'Microsoft',       category: 'SaaS',     status: 'connected',    color: '#FF2E97', dataTypes: ['Unified Audit', 'Exchange', 'SharePoint'],     endpoint: 'https://manage.office.com/api/v1.0' },
  { id: 'slack',  name: 'Slack',               vendor: 'Slack',           category: 'SaaS',     status: 'connected',    color: '#7A3CFF', dataTypes: ['Audit Logs', 'Access Logs'],                   endpoint: 'https://api.slack.com/audit/v1/logs' },
  { id: 'github', name: 'GitHub',              vendor: 'GitHub',          category: 'SaaS',     status: 'unconfigured', color: '#34F5C5', dataTypes: ['Audit Log', 'Secret Scanning', 'Code Scan'],   endpoint: '' },
]

const CUSTOM_SOURCES: CustomSourceType[] = [
  { id: 'syslog',  name: 'Syslog',   description: 'RFC 5424 / 3164 over UDP, TCP or TLS', icon: Radio },
  { id: 'webhook', name: 'Webhook',  description: 'Inbound HTTP POST with JSON payloads',  icon: AppWindow },
  { id: 's3',      name: 'Amazon S3', description: 'Pull log files from an S3 bucket',     icon: Cloud },
  { id: 'kafka',   name: 'Kafka',    description: 'Consume events from a Kafka topic',      icon: Network },
]

const CATEGORIES: { id: ConnCategory; icon: React.ElementType; color: string }[] = [
  { id: 'Cloud',    icon: Cloud,             color: '#FFB23E' },
  { id: 'Identity', icon: Fingerprint,       color: '#7A3CFF' },
  { id: 'Endpoint', icon: MonitorSmartphone, color: '#FF4D6D' },
  { id: 'Network',  icon: Network,           color: '#34F5C5' },
  { id: 'SaaS',     icon: AppWindow,         color: '#FF2E97' },
]

/* ── Config form panel ───────────────────────────────────────────── */
function ConfigPanel({ connector, onClose }: { connector: Connector; onClose: () => void }) {
  const [saved, setSaved] = useState(false)
  const save = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ x: 420 }}
        animate={{ x: 0 }}
        exit={{ x: 420 }}
        transition={{ type: 'tween', duration: 0.2 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto"
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/8 sticky top-0 bg-surface z-10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: `${connector.color}18` }}>
              <Database className="w-4 h-4" style={{ color: connector.color }} />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">{connector.name}</h2>
              <p className="text-[10px] text-ink-500">{connector.vendor} connector</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Endpoint URL</label>
            <input
              defaultValue={connector.endpoint}
              placeholder="https://api.vendor.com/v1/logs"
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-ink-100 focus:outline-none focus:border-magenta/40 focus:ring-1 focus:ring-magenta/15 transition-colors placeholder-ink-600 font-mono text-xs"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Authentication Method</label>
            <select className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
              <option>API Key</option>
              <option>OAuth 2.0 (Client Credentials)</option>
              <option>Bearer Token</option>
              <option>IAM Role / Assume Role</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Polling Interval</label>
            <select className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
              <option>Every 1 minute</option>
              <option>Every 5 minutes</option>
              <option>Every 15 minutes</option>
              <option>Every hour</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-ink-300 mb-2">Field Mapping</label>
            <div className="space-y-2">
              {[
                { src: 'eventTime', dst: '@timestamp' },
                { src: 'srcIp',     dst: 'source.ip' },
                { src: 'userName',  dst: 'user.name' },
                { src: 'action',    dst: 'event.action' },
              ].map((m) => (
                <div key={m.src} className="flex items-center gap-2">
                  <input
                    defaultValue={m.src}
                    className="flex-1 px-2.5 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 font-mono focus:outline-none focus:border-magenta/40"
                  />
                  <span className="text-ink-600 text-xs">&rarr;</span>
                  <input
                    defaultValue={m.dst}
                    className="flex-1 px-2.5 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-safe font-mono focus:outline-none focus:border-magenta/40"
                  />
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={save}
            className={cn(
              'w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all',
              saved ? 'bg-safe/15 text-safe border border-safe/25' : 'bg-plasma text-white hover:shadow-magenta-sm',
            )}
          >
            {saved ? <><CheckCircle className="w-4 h-4" /> Saved!</> : <><Save className="w-4 h-4" /> Save Connector</>}
          </button>
        </div>
      </motion.div>
    </motion.div>
  )
}

/* ── Connector card ──────────────────────────────────────────────── */
function ConnectorCard({ connector, onConfigure }: { connector: Connector; onConfigure: () => void }) {
  const connected = connector.status === 'connected'
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-white/8 bg-surface p-4 hover:border-white/15 transition-colors"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" style={{ background: `${connector.color}18` }}>
            <Database className="w-4 h-4" style={{ color: connector.color }} />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white truncate">{connector.name}</p>
            <p className="text-[10px] text-ink-600">{connector.vendor}</p>
          </div>
        </div>
        <span className={cn(
          'flex items-center gap-1 text-[9px] font-medium px-1.5 py-0.5 rounded-full border whitespace-nowrap',
          connected ? 'text-safe border-safe/20 bg-safe/10' : 'text-ink-400 border-white/10 bg-white/5',
        )}>
          <span className={cn('w-1.5 h-1.5 rounded-full', connected ? 'bg-safe animate-pulse' : 'bg-ink-500')} />
          {connected ? 'Connected' : 'Not configured'}
        </span>
      </div>

      <div className="flex flex-wrap gap-1 mb-3">
        {connector.dataTypes.map((dt) => (
          <span key={dt} className="text-[9px] px-1.5 py-0.5 rounded-full bg-violet/10 text-violet border border-violet/20">{dt}</span>
        ))}
      </div>

      <button
        onClick={onConfigure}
        className={cn(
          'w-full flex items-center justify-center gap-1.5 text-xs px-3 py-2 rounded-lg border transition-colors',
          connected
            ? 'border-white/10 text-ink-300 hover:text-white hover:border-white/20'
            : 'border-magenta/25 text-magenta hover:bg-magenta/5',
        )}
      >
        <Settings className="w-3.5 h-3.5" />
        {connected ? 'Configure' : 'Connect'}
      </button>
    </motion.div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function DataSourcesPage() {
  const [selected, setSelected] = useState<string | null>(null)
  const [connectors, setConnectors] = useState<Connector[]>(CONNECTORS)
  const selectedConnector = connectors.find((c) => c.id === selected) ?? null

  // Derive each connector's status from live log sources: connected when a
  // matching source is actively ingesting (anything but offline).
  useEffect(() => {
    fetchSiemSources().then((sources: LogSource[]) => {
      if (sources.length === 0) return
      const liveNames = sources
        .filter((s) => s.status !== 'offline')
        .map((s) => s.name.toLowerCase())
      setConnectors(CONNECTORS.map((c) => {
        const kws = CONNECTOR_MATCH[c.id] ?? [c.vendor.toLowerCase()]
        const connected = liveNames.some((n) => kws.some((kw) => n.includes(kw)))
        return connected ? { ...c, status: 'connected' } : { ...c, status: 'unconfigured' }
      }))
    }).catch(() => {})
  }, [])

  const connectedCount = connectors.filter((c) => c.status === 'connected').length

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Data Sources</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Configure data ingestion connectors</p>
        </div>
        <div className="text-right">
          <span className="text-sm font-bold font-mono text-safe">{connectedCount}</span>
          <span className="text-xs text-ink-500"> / {connectors.length} connected</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-8">
        {CATEGORIES.map(({ id, icon: Icon, color }) => {
          const items = connectors.filter((c) => c.category === id)
          return (
            <section key={id}>
              <div className="flex items-center gap-2 mb-3">
                <div className="p-1.5 rounded-lg" style={{ background: `${color}18` }}>
                  <Icon className="w-3.5 h-3.5" style={{ color }} />
                </div>
                <h2 className="text-sm font-semibold text-white">{id}</h2>
                <span className="text-[10px] text-ink-600">({items.length})</span>
              </div>
              <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
                {items.map((c) => (
                  <ConnectorCard key={c.id} connector={c} onConfigure={() => setSelected(c.id)} />
                ))}
              </div>
            </section>
          )
        })}

        {/* Add custom source */}
        <section>
          <div className="flex items-center gap-2 mb-3">
            <div className="p-1.5 rounded-lg bg-white/5">
              <Plus className="w-3.5 h-3.5 text-ink-300" />
            </div>
            <h2 className="text-sm font-semibold text-white">Add Custom Source</h2>
          </div>
          <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-4">
            {CUSTOM_SOURCES.map(({ id, name, description, icon: Icon }) => (
              <button
                key={id}
                className="flex flex-col items-start gap-2 p-4 rounded-xl border border-dashed border-white/12 bg-surface hover:border-magenta/30 hover:bg-magenta/5 transition-colors text-left"
              >
                <div className="flex items-center gap-2">
                  <Icon className="w-4 h-4 text-violet" />
                  <span className="text-sm font-semibold text-white">{name}</span>
                </div>
                <p className="text-[10px] text-ink-500 leading-snug">{description}</p>
                <span className="mt-1 inline-flex items-center gap-1 text-[10px] text-magenta">
                  <Plus className="w-3 h-3" /> Add source
                </span>
              </button>
            ))}
          </div>
        </section>
      </div>

      <AnimatePresence>
        {selectedConnector && (
          <ConfigPanel connector={selectedConnector} onClose={() => setSelected(null)} />
        )}
      </AnimatePresence>
    </div>
  )
}
