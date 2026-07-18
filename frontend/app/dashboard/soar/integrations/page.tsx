'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchSoarIntegrations, createIntegration, testIntegration, runIntegrationAction, updateIntegration, type Integration as ApiIntegration } from '@/lib/api'
import CreateModal from '@/components/dashboard/CreateModal'
import {
  Link, Plus, 
  RefreshCw, Activity, Zap, Shield, Clock,
  ToggleLeft, ToggleRight, X, Code,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { tk } from '@/lib/colors'

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
  /** Whether a vendor base URL + API key are stored (the key itself is write-only). */
  credentialed: boolean
  baseUrl: string | null
}



const CAT_COLORS: Record<IntCategory, string> = {
  EDR: 'bg-magenta/15 text-magenta border-magenta/20',
  Firewall: `bg-threat/15 text-[${tk('threat')}] border-threat/20`,
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

// Backend rows carry the full connector record; map it faithfully.
const apiToIntegration = (d: ApiIntegration & {
  vendor?: string; category?: string; actionsRun?: number
  avgResponseMs?: number; actions?: string[]; enabled?: number
  credentialed?: boolean; baseUrl?: string | null
}): Integration => ({
  id: d.id,
  name: d.name,
  vendor: d.vendor ?? d.name,
  category: (d.category ?? 'SIEM') as IntCategory,
  status: (['connected', 'degraded', 'disconnected', 'pending'].includes(d.status)
    ? d.status : 'disconnected') as IntStatus,
  lastSync: d.lastSync ?? 'Never',
  actionsRun: d.actionsRun ?? 0,
  avgResponseMs: d.avgResponseMs ?? 0,
  description: d.description ?? '',
  actions: d.actions ?? [],
  enabled: Boolean(d.enabled ?? (d.status === 'connected')),
  credentialed: Boolean(d.credentialed),
  baseUrl: d.baseUrl ?? null,
})

/* Credential entry for an action integration. The API key is write-only:
   we never display a stored key, only whether one exists (`credentialed`). */
function CredentialsForm({ integration, onSaved }: {
  integration: Integration
  onSaved: (updated: Integration) => void
}) {
  const [baseUrl, setBaseUrl] = useState(integration.baseUrl ?? '')
  const [apiKey, setApiKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => { setBaseUrl(integration.baseUrl ?? ''); setApiKey(''); setErr(null) }, [integration.id, integration.baseUrl])

  function save(clear = false) {
    if (busy) return
    setBusy(true); setErr(null)
    updateIntegration(integration.id, clear
      ? { baseUrl: '', apiKey: '' }
      : { baseUrl, ...(apiKey.trim() ? { apiKey: apiKey.trim() } : {}) })
      .then((u) => { setApiKey(''); onSaved(apiToIntegration(u as Parameters<typeof apiToIntegration>[0])) })
      .catch(() => setErr('Could not save credentials.'))
      .finally(() => setBusy(false))
  }

  return (
    <div className="mt-4 p-4 rounded-xl border border-white/10 bg-white/3">
      <div className="flex items-center gap-2 mb-1">
        <Shield className="w-3.5 h-3.5 text-safe" />
        <p className="text-xs font-semibold text-white">API credentials</p>
        <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-medium',
          integration.credentialed ? 'text-safe bg-safe/12' : 'text-ink-500 bg-white/6')}>
          {integration.credentialed ? 'configured' : 'not configured'}
        </span>
      </div>
      <p className="text-[10px] text-ink-600 mb-3">
        With a base URL + API key, response actions call the live vendor API; without them,
        attempts are honestly recorded as not-configured. The key is write-only - it is never shown again.
      </p>
      <div className="grid sm:grid-cols-[1fr_1fr_auto_auto] gap-2 items-center">
        <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
          placeholder="https://api.vendor.example"
          className="px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-100 focus:outline-hidden focus:border-safe/40 placeholder-ink-600" />
        <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} type="password"
          placeholder={integration.credentialed ? 'API key (leave blank to keep current)' : 'API key'}
          className="px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-100 focus:outline-hidden focus:border-safe/40 placeholder-ink-600" />
        <button onClick={() => save(false)} disabled={busy || !baseUrl.trim()}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-safe/15 border border-safe/30 text-safe hover:bg-safe/20 disabled:opacity-50 transition-colors">
          Save
        </button>
        <button onClick={() => save(true)} disabled={busy || !integration.credentialed}
          title="Remove the stored base URL and API key"
          className="px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-threat disabled:opacity-40 transition-colors">
          Clear
        </button>
      </div>
      {err && <p className="text-[10px] text-threat mt-2">{err}</p>}
    </div>
  )
}

export default function SoarIntegrationsPage() {
  // Empty until the API answers - integrations are NOT seeded in live mode, so
  // an empty list is the honest truth on a real deployment. Demo vendors would
  // misrepresent what SOAR can actually act on, so they're offline-only.
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [unreachable, setUnreachable] = useState(false)
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [catFilter, setCatFilter] = useState<string>('All')
  const [showConnect, setShowConnect] = useState(false)
  const [actionMsg, setActionMsg] = useState<string | null>(null)

  useEffect(() => {
    fetchSoarIntegrations().then((data) => {
      const mapped = data.map(apiToIntegration)   // applied even when empty
      setIntegrations(mapped)
      setEnabledMap(Object.fromEntries(mapped.map(i => [i.id, i.enabled])))
    }).catch(() => {
      // API unreachable: say so - a fabricated "connected" vendor list would
      // misrepresent what this deployment can actually act on.
      setUnreachable(true)
    })
  }, [])

  function note(msg: string) {
    setActionMsg(msg)
    setTimeout(() => setActionMsg(null), 4000)
  }

  async function handleConnect(values: Record<string, string>) {
    const created = await createIntegration({
      name: values.name,
      vendor: values.vendor || undefined,
      category: values.category || undefined,
      description: values.description || undefined,
      actions: [],
      base_url: values.baseUrl || undefined,
      api_key: values.apiKey || undefined,
    })
    const mapped = apiToIntegration(created as Parameters<typeof apiToIntegration>[0])
    setIntegrations((prev) => [mapped, ...prev])
    setEnabledMap((prev) => ({ ...prev, [mapped.id]: mapped.enabled }))
  }

  function handleTest(id: string) {
    testIntegration(id)
      .then((updated) => {
        const mapped = apiToIntegration(updated as Parameters<typeof apiToIntegration>[0])
        setIntegrations((prev) => prev.map((i) => (i.id === id ? mapped : i)))
        note(`Connection OK - ${mapped.name} synced just now`)
      })
      .catch(() => note('Connection test failed - is the dashboard API running?'))
  }

  function handleRunAction(id: string, action: string) {
    runIntegrationAction(id, action)
      .then((updated) => {
        setIntegrations((prev) => prev.map((i) => (i.id === id
          ? { ...i, actionsRun: updated.actionsRun ?? i.actionsRun + 1, lastSync: 'just now' }
          : i)))
        note(`"${action}" executed`)
      })
      .catch((e) => note(e instanceof Error && e.message.includes('not connected')
        ? 'Tool is not connected - run Test Connection first.'
        : 'Action failed - is the dashboard API running?'))
  }

  const categories = ['All', ...Array.from(new Set(integrations.map(i => i.category)))]
  const filtered = catFilter === 'All' ? integrations : integrations.filter(i => i.category === catFilter)
  const selectedInt = integrations.find(i => i.id === selected) ?? null

  const connected = integrations.filter(i => i.status === 'connected').length
  const totalActions = integrations.reduce((a, i) => a + i.actionsRun, 0)

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
        <button
          onClick={() => setShowConnect(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
          <Plus className="w-3.5 h-3.5" />
          Connect Tool
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Connected',     value: connected,                        color: 'text-safe'   },
          { label: 'Total Actions', value: `${(totalActions/1000).toFixed(1)}k`, color: 'text-violet' },
          { label: 'Degraded',      value: integrations.filter(i => i.status === 'degraded').length, color: 'text-amber' },
          { label: 'Offline',       value: integrations.filter(i => i.status === 'disconnected').length, color: 'text-threat' },
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
        {unreachable && (
          <div className="mb-4 px-4 py-3 rounded-xl border border-amber/30 bg-amber/10 text-xs text-amber">
            The dashboard API is unreachable - integration status cannot be shown.
            Nothing here is simulated: this page only ever lists integrations the
            backend actually knows about.
          </div>
        )}
        {!unreachable && integrations.length === 0 && (
          <div className="mb-4 px-4 py-8 rounded-xl border border-white/8 text-center text-xs text-ink-500">
            No integrations connected yet. Use &quot;Connect Integration&quot; to add your
            SIEM, EDR, ticketing or threat-intel tooling - status here always
            reflects a real configured connection, never a demo vendor list.
          </div>
        )}
        <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {(filtered as Integration[]).map((int, i) => {
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
                    : 'border-white/8 bg-surface hover:border-white/15',
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
                      title={isEnabled ? 'Disable integration' : 'Enable integration'}
                      onClick={e => {
                        e.stopPropagation()
                        const next = !isEnabled
                        setEnabledMap(prev => ({ ...prev, [int.id]: next }))  // optimistic
                        updateIntegration(int.id, { enabled: next })
                          .catch(() => setEnabledMap(prev => ({ ...prev, [int.id]: !next })))  // roll back
                      }}
                    >
                      {isEnabled
                        ? <ToggleRight className="w-5 h-5 text-safe" />
                        : <ToggleLeft className="w-5 h-5 text-ink-600" />}
                    </button>
                  </div>
                </div>

                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <span className={cn('text-[9px] font-semibold px-1.5 py-0.5 rounded-full border', CAT_COLORS[int.category])}>
                    {int.category}
                  </span>
                  <span className={cn('flex items-center gap-1 text-[9px] font-medium px-1.5 py-0.5 rounded-full border', st.cls)}>
                    <span className={cn('w-1.5 h-1.5 rounded-full', st.dot)} />
                    {st.label}
                  </span>
                  <span className={cn('text-[9px] font-medium px-1.5 py-0.5 rounded-full border',
                    int.credentialed
                      ? 'text-safe border-safe/20 bg-safe/10'
                      : 'text-ink-500 border-white/10 bg-white/5')}
                    title={int.credentialed
                      ? 'API credentials configured - actions call the live vendor API'
                      : 'No credentials - actions are recorded as not-configured until a base URL + API key are set'}>
                    {int.credentialed ? 'live API' : 'no credentials'}
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
                  <h3 className="font-semibold text-white">{selectedInt.name} - Available Actions</h3>
                  <button onClick={() => setSelected(null)} className="p-1.5 rounded-lg hover:bg-white/8 text-ink-500">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                {selectedInt.actions.length === 0 ? (
                  <p className="text-xs text-ink-600 py-3">No response actions registered for this tool yet.</p>
                ) : (
                  <div className="grid sm:grid-cols-2 gap-3">
                    {selectedInt.actions.map(action => (
                      <div key={action} className="flex items-center justify-between p-3 rounded-xl bg-white/4 border border-white/8">
                        <div className="flex items-center gap-2">
                          <Zap className="w-3.5 h-3.5 text-violet" />
                          <span className="text-xs text-ink-200">{action}</span>
                        </div>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleRunAction(selectedInt.id, action) }}
                          className="text-[10px] text-magenta hover:underline">Run</button>
                      </div>
                    ))}
                  </div>
                )}
                {/* Credential entry - set the vendor base URL + API key so
                    actions call the live API instead of recording not-configured */}
                <CredentialsForm
                  integration={selectedInt}
                  onSaved={(updated) => {
                    setIntegrations((prev) => prev.map((i) => (i.id === updated.id ? updated : i)))
                    note(updated.credentialed
                      ? `Credentials saved - ${updated.name} actions now call the live API`
                      : 'Credentials cleared - actions will record as not-configured')
                  }}
                />
                <div className="flex items-center gap-2 mt-4 flex-wrap">
                  <button
                    onClick={(e) => { e.stopPropagation(); handleTest(selectedInt.id) }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white">
                    <RefreshCw className="w-3.5 h-3.5" />
                    Test Connection
                  </button>
                  <a href="/docs/rest-api"
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white">
                    <Code className="w-3.5 h-3.5" />
                    View API Docs
                  </a>
                  {actionMsg && <span className="text-[10px] text-safe" role="status">{actionMsg}</span>}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <AnimatePresence>
        {showConnect && (
          <CreateModal
            title="Connect Tool"
            icon={Link}
            accent={tk('safe')}
            submitLabel="Connect"
            onClose={() => setShowConnect(false)}
            onSubmit={handleConnect}
            fields={[
              { key: 'name', label: 'Tool name', required: true, placeholder: 'e.g. TheHive' },
              { key: 'vendor', label: 'Vendor', placeholder: 'e.g. StrangeBee' },
              { key: 'category', label: 'Category', type: 'select', default: 'Ticketing', options: [
                'EDR', 'Firewall', 'SIEM', 'Ticketing', 'Communication', 'Threat Intel', 'Identity', 'Cloud',
              ].map((c) => ({ value: c, label: c })) },
              { key: 'description', label: 'Description', type: 'textarea', placeholder: 'What this connector is used for' },
              { key: 'baseUrl', label: 'API base URL (optional)', placeholder: 'https://api.vendor.example' },
              { key: 'apiKey', label: 'API key (optional, write-only)', placeholder: 'Set now or later via the card' },
            ]}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
