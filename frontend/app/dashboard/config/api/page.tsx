'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  fetchApiKeys, createApiKey, revokeApiKey,
  fetchWebhooks, createWebhook, patchWebhook, deleteWebhook, testWebhook,
  type ApiKey as RemoteApiKey, type Webhook as RemoteWebhook,
} from '@/lib/api'
import {
  Key, Plus, Copy, CheckCircle, Trash2, X, AlertTriangle, Webhook,
  Activity, Clock, Terminal, Pause, Play,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Types ───────────────────────────────────────────────────────── */
type Scope = 'read' | 'write' | 'admin'
type KeyStatus = 'active' | 'revoked'

interface ApiKey {
  id: string
  label: string
  masked: string
  scopes: Scope[]
  created: string
  lastUsed: string
  requests: number
  status: KeyStatus
}

type WebhookStatus = 'active' | 'failing' | 'paused'

interface WebhookEndpoint {
  id: string
  url: string
  events: string[]
  status: WebhookStatus
  lastDelivery: string
}

/* ── Seed data ───────────────────────────────────────────────────── */
const API_KEYS: ApiKey[] = [
  { id: 'k1', label: 'Production Backend',  masked: 'to_sk_live_••••4f2a', scopes: ['read', 'write'],        created: 'Jan 12, 2026', lastUsed: '8s ago',  requests: 84213, status: 'active'  },
  { id: 'k2', label: 'SIEM Integration',    masked: 'to_sk_live_••••9b71', scopes: ['read'],                 created: 'Nov 03, 2025', lastUsed: '2m ago',  requests: 41902, status: 'active'  },
  { id: 'k3', label: 'CI/CD Pipeline',      masked: 'to_sk_live_••••1c08', scopes: ['read', 'write'],        created: 'Feb 28, 2026', lastUsed: '1h ago',  requests: 8841,  status: 'active'  },
  { id: 'k4', label: 'Mobile App',          masked: 'to_sk_live_••••7e34', scopes: ['read'],                 created: 'Mar 15, 2026', lastUsed: '40m ago', requests: 6210,  status: 'active'  },
  { id: 'k5', label: 'Partner: Acme Corp',  masked: 'to_sk_live_••••a55d', scopes: ['read', 'write', 'admin'], created: 'Dec 01, 2025', lastUsed: '5h ago', requests: 1024,  status: 'active'  },
  { id: 'k6', label: 'Dev Sandbox',         masked: 'to_sk_test_••••0f9e', scopes: ['read', 'write'],        created: 'Apr 02, 2026', lastUsed: '3d ago',  requests: 312,   status: 'revoked' },
]

const WEBHOOKS: WebhookEndpoint[] = [
  { id: 'w1', url: 'https://hooks.acme.io/threatorbit/alerts',   events: ['alert.created'],                       status: 'active',  lastDelivery: '12s ago' },
  { id: 'w2', url: 'https://soar.acme.io/api/incidents/resolve', events: ['incident.resolved'],                   status: 'active',  lastDelivery: '4m ago'  },
  { id: 'w3', url: 'https://intel.acme.io/ingest/ioc',           events: ['ioc.confirmed', 'alert.created'],      status: 'failing', lastDelivery: '1h ago'  },
  { id: 'w4', url: 'https://slack.acme.io/webhooks/sec-ops',     events: ['alert.created', 'incident.resolved'],  status: 'paused',  lastDelivery: '2d ago'  },
]

const SCOPE_CFG: Record<Scope, string> = {
  read:  'text-safe border-safe/20 bg-safe/10',
  write: 'text-amber border-amber/20 bg-amber/10',
  admin: 'text-threat border-threat/20 bg-threat/10',
}

const KEY_STATUS_CFG: Record<KeyStatus, { label: string; cls: string }> = {
  active:  { label: 'Active',  cls: 'text-safe border-safe/20 bg-safe/10'       },
  revoked: { label: 'Revoked', cls: 'text-ink-400 border-white/10 bg-white/5'   },
}

const WH_STATUS_CFG: Record<WebhookStatus, { label: string; cls: string; dot: string }> = {
  active:  { label: 'Active',  cls: 'text-safe border-safe/20 bg-safe/10',       dot: 'bg-safe animate-pulse' },
  failing: { label: 'Failing', cls: 'text-threat border-threat/20 bg-threat/10', dot: 'bg-threat'             },
  paused:  { label: 'Paused',  cls: 'text-ink-400 border-white/10 bg-white/5',   dot: 'bg-ink-500'            },
}

const SCOPE_PREFIX: Record<string, string> = {
  admin: 'to_ak_live_', write: 'to_sk_live_', read: 'to_rk_live_',
}

const maskKey = (scope: string, fragment: string) =>
  `${SCOPE_PREFIX[scope] ?? 'to_sk_live_'}••••${fragment}`

const CURL_SNIPPET = `curl https://api.threatorbit.space/v2/alerts \\
  -H "Authorization: Bearer to_sk_live_••••4f2a" \\
  -H "Content-Type: application/json"`

/* ── KPI tile ────────────────────────────────────────────────────── */
function Kpi({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="px-5 py-3">
      <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
      <div className="text-[10px] text-ink-600">{label}</div>
    </div>
  )
}

/* ── Copy button ─────────────────────────────────────────────────── */
function CopyBtn({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1800)
  }
  return (
    <button onClick={copy} className={cn('p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors', className)}>
      {copied ? <CheckCircle className="w-3.5 h-3.5 text-safe" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

/* ── Generate key modal: name+scope form, then the one-time secret ── */
function GenerateModal({ onCreate, onClose }: {
  onCreate: (name: string, scope: Scope) => Promise<string>
  onClose: () => void
}) {
  const [name, setName] = useState('')
  const [scope, setScope] = useState<Scope>('read')
  const [secret, setSecret] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim() || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      setSecret(await onCreate(name.trim(), scope))
    } catch {
      setError('Could not create the key. Check the API is running and you have admin access.')
      setSubmitting(false)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-6"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-2xl border border-white/10 bg-surface p-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-magenta/15">
              <Key className="w-4 h-4 text-magenta" />
            </div>
            <h2 className="text-sm font-semibold text-white">{secret ? 'New API Key Generated' : 'Generate New Key'}</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        {secret === null ? (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Key name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. CI pipeline"
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 placeholder-ink-600" />
            </div>
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Scope</label>
              <select value={scope} onChange={(e) => setScope(e.target.value as Scope)}
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                <option value="read">Read only</option>
                <option value="write">Read + write</option>
                <option value="admin">Full admin</option>
              </select>
            </div>
            {error && <p className="px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert">{error}</p>}
            <button type="submit" disabled={!name.trim() || submitting}
              className={cn('w-full px-4 py-2.5 rounded-xl text-sm font-semibold transition-all',
                name.trim() && !submitting ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
              {submitting ? 'Generating…' : 'Generate Key'}
            </button>
          </form>
        ) : (
          <>
            <div className="flex items-start gap-2 p-3 rounded-xl bg-amber/10 border border-amber/20 mb-4">
              <AlertTriangle className="w-4 h-4 text-amber shrink-0 mt-0.5" />
              <p className="text-[11px] text-amber leading-snug">
                Save this key now &mdash; it is shown only once. You will not be able to retrieve it again after closing this dialog.
              </p>
            </div>

            <label className="block text-xs font-medium text-ink-300 mb-1.5">Your API Key</label>
            <div className="flex items-center gap-2 p-3 rounded-xl bg-surface-3 border border-white/8 mb-4">
              <code className="flex-1 font-mono text-xs text-safe break-all">{secret}</code>
              <CopyBtn value={secret} />
            </div>

            <button
              onClick={onClose}
              className="w-full px-4 py-2.5 rounded-xl bg-plasma text-white text-sm font-semibold hover:shadow-magenta-sm transition-all"
            >
              I&apos;ve saved my key
            </button>
          </>
        )}
      </motion.div>
    </motion.div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
const remoteToRow = (k: RemoteApiKey): ApiKey => ({
  id: k.id,
  label: k.name,
  masked: maskKey(k.scope, k.prefix),
  scopes: [k.scope as Scope],
  created: new Date(k.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
  lastUsed: k.lastUsed ? new Date(k.lastUsed).toLocaleDateString() : 'Never',
  requests: 0,
  status: k.revoked ? 'revoked' : 'active',
})

const remoteWebhookToRow = (w: RemoteWebhook): WebhookEndpoint => ({
  id: w.id,
  url: w.url,
  events: w.events,
  status: w.status,
  lastDelivery: w.lastDelivery ? new Date(w.lastDelivery).toLocaleString() : 'never',
})

export default function ApiKeysPage() {
  const [showModal, setShowModal] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [keys, setKeys] = useState<ApiKey[]>(API_KEYS)
  const [webhooks, setWebhooks] = useState<WebhookEndpoint[]>(WEBHOOKS)
  const [webhooksLive, setWebhooksLive] = useState(false)
  const [newHookUrl, setNewHookUrl] = useState('')
  const [newHookEvent, setNewHookEvent] = useState('alert.created')
  const [hookError, setHookError] = useState<string | null>(null)

  useEffect(() => {
    fetchApiKeys().then((data) => setKeys(data.map(remoteToRow))).catch(() => {})
    fetchWebhooks().then((data) => {
      setWebhooks(data.map(remoteWebhookToRow))
      setWebhooksLive(true)
    }).catch(() => {})
  }, [])

  function addWebhook() {
    const url = newHookUrl.trim()
    if (!url) return
    setHookError(null)
    createWebhook(url, [newHookEvent])
      .then((created) => {
        setWebhooks((prev) => [remoteWebhookToRow(created), ...prev])
        setNewHookUrl('')
      })
      .catch((err) => setHookError(err instanceof Error && err.message.includes('http')
        ? 'URL must start with http:// or https://'
        : 'Could not add webhook — check the API is running and you have admin access.'))
  }

  function toggleWebhook(w: WebhookEndpoint) {
    const next = w.status === 'paused' ? 'active' : 'paused'
    setWebhooks((prev) => prev.map((x) => (x.id === w.id ? { ...x, status: next as WebhookStatus } : x)))
    patchWebhook(w.id, { status: next }).catch(() => {
      setWebhooks((prev) => prev.map((x) => (x.id === w.id ? { ...x, status: w.status } : x)))
    })
  }

  function removeWebhook(id: string) {
    const prev = webhooks
    setWebhooks((w) => w.filter((x) => x.id !== id))
    deleteWebhook(id).catch(() => setWebhooks(prev))
  }

  const [testing, setTesting] = useState<string | null>(null)
  function runTest(id: string) {
    if (testing) return
    setTesting(id)
    testWebhook(id)
      .then((out) => {
        setWebhooks((prev) => prev.map((x) => x.id === id
          ? { ...x, status: out.status as WebhookStatus, lastDelivery: out.lastDelivery ? new Date(out.lastDelivery).toLocaleString() : x.lastDelivery }
          : x))
      })
      .catch(() => {})
      .finally(() => setTesting(null))
  }

  async function handleGenerate(name: string, scope: Scope): Promise<string> {
    const result = await createApiKey(name, scope)
    setKeys((prev) => [remoteToRow(result), ...prev])
    return result.secret
  }

  async function handleRevoke(id: string) {
    try {
      await revokeApiKey(id)
      setKeys((prev) => prev.map((k) => k.id === id ? { ...k, status: 'revoked' as KeyStatus } : k))
    } catch { /* ignore */ }
  }

  const copyKey = (k: ApiKey) => {
    navigator.clipboard?.writeText(k.masked)
    setCopiedKey(k.id)
    setTimeout(() => setCopiedKey(null), 1800)
  }

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-amber" />
            <h1 className="text-lg font-display font-semibold text-white">API Keys</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Manage API access tokens and webhooks</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all"
        >
          <Plus className="w-3.5 h-3.5" />
          Generate New Key
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-3 divide-x divide-white/5 border-b border-white/5 shrink-0">
        <Kpi label="Active Keys"    value={String(keys.filter(k => k.status === 'active').length)}    color="text-safe"   />
        <Kpi label="Requests Today" value={`${(keys.reduce((a, k) => a + k.requests, 0) / 1000).toFixed(0)}k`} color="text-violet" />
        <Kpi label="Rate Limit"     value="1M/mo" color="text-amber"  />
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-8">
        {/* API keys table */}
        <section>
          <h2 className="text-sm font-semibold text-white mb-3">API Keys</h2>
          <div className="rounded-xl border border-white/8 overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/8 text-[10px] uppercase tracking-wide text-ink-600">
                  <th className="px-4 py-3 font-medium">Name</th>
                  <th className="px-4 py-3 font-medium">Key</th>
                  <th className="px-4 py-3 font-medium">Scopes</th>
                  <th className="px-4 py-3 font-medium">Created</th>
                  <th className="px-4 py-3 font-medium">Last Used</th>
                  <th className="px-4 py-3 font-medium text-right">Requests</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-xs text-ink-600">
                      No API keys yet — generate one to integrate with the ThreatOrbit API.
                    </td>
                  </tr>
                )}
                {keys.map((k) => (
                  <tr key={k.id} className="border-b border-white/4 last:border-0 hover:bg-white/4 transition-colors">
                    <td className="px-4 py-3 text-xs font-medium text-white">{k.label}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => copyKey(k)}
                        className="flex items-center gap-1.5 font-mono text-[11px] text-ink-300 hover:text-white transition-colors"
                        title="Click to copy"
                      >
                        {k.masked}
                        {copiedKey === k.id
                          ? <CheckCircle className="w-3 h-3 text-safe" />
                          : <Copy className="w-3 h-3 text-ink-600" />}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        {k.scopes.map((s) => (
                          <span key={s} className={cn('text-[9px] px-1.5 py-0.5 rounded-full border capitalize', SCOPE_CFG[s])}>{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[11px] text-ink-500">{k.created}</td>
                    <td className="px-4 py-3 text-[11px] text-ink-500">{k.lastUsed}</td>
                    <td className="px-4 py-3 text-[11px] text-ink-300 font-mono text-right">{k.requests.toLocaleString()}</td>
                    <td className="px-4 py-3">
                      <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border', KEY_STATUS_CFG[k.status].cls)}>
                        {KEY_STATUS_CFG[k.status].label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button className="text-[10px] text-ink-400 hover:text-white px-2 py-1 rounded-lg hover:bg-white/5 transition-colors">
                          View scopes
                        </button>
                        <button
                          disabled={k.status === 'revoked'}
                          onClick={() => handleRevoke(k.id)}
                          className={cn(
                            'p-1.5 rounded-lg transition-colors',
                            k.status === 'revoked'
                              ? 'text-ink-600 cursor-not-allowed'
                              : 'text-ink-500 hover:text-threat hover:bg-threat/5',
                          )}
                          title="Revoke key"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Webhooks */}
        <section>
          <div className="flex items-center gap-2 mb-3">
            <Webhook className="w-4 h-4 text-violet" />
            <h2 className="text-sm font-semibold text-white">Webhooks</h2>
            {webhooksLive && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-safe/10 text-safe border border-safe/20">live</span>}
          </div>

          {/* Add webhook */}
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <input
              value={newHookUrl}
              onChange={(e) => setNewHookUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addWebhook()}
              placeholder="https://hooks.yourcompany.com/threatorbit"
              className="flex-1 min-w-[240px] px-3 py-2 rounded-xl bg-surface-2 border border-white/8 text-xs font-mono text-ink-100 placeholder-ink-600 focus:outline-none focus:border-magenta/40"
            />
            <select
              value={newHookEvent}
              onChange={(e) => setNewHookEvent(e.target.value)}
              className="px-3 py-2 rounded-xl bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-none focus:border-magenta/40"
            >
              {['alert.created', 'incident.resolved', 'ioc.confirmed', 'case.created', 'playbook.failed'].map((e) => (
                <option key={e} value={e}>{e}</option>
              ))}
            </select>
            <button
              onClick={addWebhook}
              disabled={!newHookUrl.trim()}
              className={cn('flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold transition-all',
                newHookUrl.trim() ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}
            >
              <Plus className="w-3.5 h-3.5" /> Add
            </button>
          </div>
          {hookError && <p className="text-[11px] text-threat mb-3" role="alert">{hookError}</p>}

          <div className="space-y-2">
            {webhooks.length === 0 && (
              <p className="text-xs text-ink-600 py-4 text-center rounded-xl border border-white/8 bg-surface">
                No webhooks configured — add one above to push events to your stack.
              </p>
            )}
            {webhooks.map((w) => {
              const st = WH_STATUS_CFG[w.status]
              return (
                <div key={w.id} className="flex items-center gap-4 p-4 rounded-xl border border-white/8 bg-surface">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-ink-200 truncate">{w.url}</p>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {w.events.map((e) => (
                        <span key={e} className="text-[9px] px-1.5 py-0.5 rounded-full bg-violet/10 text-violet border border-violet/20 font-mono">{e}</span>
                      ))}
                    </div>
                  </div>
                  <div className="text-[10px] text-ink-500 flex items-center gap-1 whitespace-nowrap">
                    <Clock className="w-3 h-3" /> {w.lastDelivery}
                  </div>
                  <span className={cn('flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full border whitespace-nowrap', st.cls)}>
                    <span className={cn('w-1.5 h-1.5 rounded-full', st.dot)} />
                    {st.label}
                  </span>
                  {webhooksLive && (
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => runTest(w.id)}
                        disabled={testing === w.id}
                        title="Send a test event"
                        className="text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors disabled:opacity-50"
                      >
                        {testing === w.id ? 'Testing…' : 'Test'}
                      </button>
                      <button
                        onClick={() => toggleWebhook(w)}
                        title={w.status === 'paused' ? 'Resume deliveries' : 'Pause deliveries'}
                        className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors"
                      >
                        {w.status === 'paused' ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => removeWebhook(w.id)}
                        title="Delete webhook"
                        className="p-1.5 rounded-lg text-ink-500 hover:text-threat hover:bg-threat/5 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </section>

        {/* Auth example */}
        <section>
          <div className="flex items-center gap-2 mb-3">
            <Terminal className="w-4 h-4 text-safe" />
            <h2 className="text-sm font-semibold text-white">Authentication Example</h2>
          </div>
          <p className="text-[11px] text-ink-500 mb-2">
            Authenticate requests by passing your secret key in the <code className="font-mono text-ink-300">Authorization</code> header.
          </p>
          <div className="relative rounded-xl border border-white/8 bg-surface-3 overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 border-b border-white/8">
              <span className="flex items-center gap-1.5 text-[10px] text-ink-500">
                <Activity className="w-3 h-3 text-safe" /> Shell
              </span>
              <CopyBtn value={CURL_SNIPPET} />
            </div>
            <pre className="px-4 py-3 text-[11px] font-mono text-ink-200 overflow-x-auto leading-relaxed">
              <code>{CURL_SNIPPET}</code>
            </pre>
          </div>
        </section>
      </div>

      <AnimatePresence>
        {showModal && <GenerateModal onCreate={handleGenerate} onClose={() => setShowModal(false)} />}
      </AnimatePresence>
    </div>
  )
}
