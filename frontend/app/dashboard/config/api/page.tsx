'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchApiKeys, createApiKey, revokeApiKey, type ApiKey as RemoteApiKey } from '@/lib/api'
import {
  Key, Plus, Copy, CheckCircle, Trash2, X, AlertTriangle, Webhook,
  Activity, Clock, Terminal,
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

const NEW_KEY_FALLBACK = 'to_sk_live_a7f8e92b1d47c61e83dd2a9f7c4b5e01abcd1234'

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

/* ── Generate key modal ──────────────────────────────────────────── */
function GenerateModal({ keySecret, onClose }: { keySecret: string; onClose: () => void }) {
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
            <h2 className="text-sm font-semibold text-white">New API Key Generated</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-start gap-2 p-3 rounded-xl bg-amber/10 border border-amber/20 mb-4">
          <AlertTriangle className="w-4 h-4 text-amber shrink-0 mt-0.5" />
          <p className="text-[11px] text-amber leading-snug">
            Save this key now &mdash; it is shown only once. You will not be able to retrieve it again after closing this dialog.
          </p>
        </div>

        <label className="block text-xs font-medium text-ink-300 mb-1.5">Your API Key</label>
        <div className="flex items-center gap-2 p-3 rounded-xl bg-surface-3 border border-white/8 mb-4">
          <code className="flex-1 font-mono text-xs text-safe break-all">{keySecret}</code>
          <CopyBtn value={keySecret} />
        </div>

        <button
          onClick={onClose}
          className="w-full px-4 py-2.5 rounded-xl bg-plasma text-white text-sm font-semibold hover:shadow-magenta-sm transition-all"
        >
          I&apos;ve saved my key
        </button>
      </motion.div>
    </motion.div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function ApiKeysPage() {
  const [showModal, setShowModal] = useState(false)
  const [newKeySecret, setNewKeySecret] = useState(NEW_KEY_FALLBACK)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [keys, setKeys] = useState<ApiKey[]>(API_KEYS)

  useEffect(() => {
    fetchApiKeys().then((data) => {
      if (data.length > 0) {
        setKeys(data.map((k: RemoteApiKey) => ({
          id: k.id,
          label: k.name,
          masked: `to_sk_live_••••${k.prefix}`,
          scopes: [k.scope as Scope],
          created: new Date(k.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          lastUsed: k.lastUsed ? new Date(k.lastUsed).toLocaleDateString() : 'Never',
          requests: 0,
          status: k.revoked ? 'revoked' : 'active' as KeyStatus,
        })))
      }
    }).catch(() => {})
  }, [])

  async function handleGenerate() {
    try {
      const result = await createApiKey('New Key')
      setNewKeySecret(result.secret ?? NEW_KEY_FALLBACK)
      const newEntry: ApiKey = {
        id: result.id,
        label: result.name,
        masked: `to_sk_live_••••${result.prefix}`,
        scopes: [result.scope as Scope],
        created: new Date(result.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
        lastUsed: 'Never',
        requests: 0,
        status: 'active',
      }
      setKeys((prev) => [newEntry, ...prev])
    } catch {
      setNewKeySecret(NEW_KEY_FALLBACK)
    }
    setShowModal(true)
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
          onClick={handleGenerate}
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
          </div>
          <div className="space-y-2">
            {WEBHOOKS.map((w) => {
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
        {showModal && <GenerateModal keySecret={newKeySecret} onClose={() => setShowModal(false)} />}
      </AnimatePresence>
    </div>
  )
}
