'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Settings, Key, Bell, Shield, Globe, Plug,
  Eye, Copy, CheckCircle, Save,
  Zap, User, BarChart2, ChevronRight, Palette, Check,
  PanelLeftOpen, PanelLeftClose, ScrollText,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchAuditLog, fetchSettings, updateSettings, authChangePassword,
  fetchApiKeys, createApiKey, revokeApiKey,
  fetchFeeds, toggleFeed, fetchSoarIntegrations, fetchJobs,
  type AuditEntry, type ApiKey as RemoteApiKey, type Feed, type Integration, type JobEntry,
} from '@/lib/api'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { useDashboardTheme, THEMES } from '@/lib/useDashboardTheme'
import { useCursorEffect } from '@/lib/useCursorEffect'

/* ── Shared input ────────────────────────────────────────────────── */
function Field({ label, value, type = 'text', hint, onChange, placeholder }: {
  label: string; value: string; type?: string; hint?: string
  onChange?: (v: string) => void; placeholder?: string
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-ink-300 mb-1.5">{label}</label>
      <input
        type={type}
        placeholder={placeholder}
        {...(onChange ? { value, onChange: (e) => onChange(e.target.value) } : { defaultValue: value })}
        className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 focus:ring-1 focus:ring-magenta/15 transition-colors placeholder-ink-600"
      />
      {hint && <p className="text-[10px] text-ink-600 mt-1">{hint}</p>}
    </div>
  )
}

function Toggle({ label, description, checked, value, onChange }: {
  label: string; description: string; checked?: boolean
  value?: boolean; onChange?: (v: boolean) => void
}) {
  const [on, setOn] = useState(checked ?? true)
  const controlled = value !== undefined
  const isOn = controlled ? value! : on
  const toggle = () => {
    if (controlled) onChange?.(!value)
    else setOn((o) => { const n = !o; onChange?.(n); return n })
  }
  return (
    <div className="flex items-center justify-between py-2.5 sm:py-3 border-b border-white/4 last:border-0">
      <div className="mr-4">
        <p className="text-xs font-medium text-ink-200">{label}</p>
        <p className="text-[10px] text-ink-600 mt-0.5">{description}</p>
      </div>
      <button
        onClick={toggle}
        role="switch"
        aria-checked={isOn}
        aria-label={label}
        className={cn('relative w-9 h-5 rounded-full transition-colors shrink-0', isOn ? 'bg-safe' : 'bg-ink-600')}
      >
        <span className={cn('absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all', isOn ? 'left-[18px]' : 'left-0.5')} />
      </button>
    </div>
  )
}

/* ── Live API keys panel (backed by /config/api-keys) ────────────── */
const SCOPE_PREFIX: Record<string, string> = {
  admin: 'to_ak_live_', write: 'to_sk_live_', read: 'to_rk_live_',
}
const SCOPE_LABEL: Record<string, string> = {
  admin: 'Full Admin', write: 'Read + Write', read: 'Read Only',
}

function LiveApiKeys() {
  const [keys, setKeys] = useState<RemoteApiKey[] | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const [name, setName] = useState('')
  const [scope, setScope] = useState('read')
  const [generated, setGenerated] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    fetchApiKeys().then(setKeys).catch(() => setUnavailable(true))
  }, [])

  async function generate() {
    if (!name.trim() || creating) return
    setCreating(true)
    try {
      const created = await createApiKey(name.trim(), scope)
      setGenerated(created.secret)
      setCopied(false)
      setName('')
      setKeys((prev) => [created, ...(prev ?? [])])
    } catch {
      setUnavailable(true)
    }
    setCreating(false)
  }

  async function revoke(id: string) {
    try {
      await revokeApiKey(id)
      setKeys((prev) => prev?.map((k) => (k.id === id ? { ...k, revoked: true } : k)) ?? prev)
    } catch { /* leave row as-is when the API is unreachable */ }
  }

  return (
    <>
      {unavailable && (
        <p className="text-xs text-ink-600 py-4 text-center">
          API key store unavailable. Start the dashboard API to manage keys.
        </p>
      )}
      {!unavailable && keys !== null && keys.length === 0 && (
        <p className="text-xs text-ink-600 py-4 text-center">No API keys yet — create the first one below.</p>
      )}
      {!unavailable && keys !== null && keys.length > 0 && (
        <div className="space-y-3 mb-6">
          {keys.map((k) => (
            <div key={k.id} className="glass border border-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="min-w-0">
                  <span className={cn('text-xs font-semibold', k.revoked ? 'text-ink-500 line-through' : 'text-white')}>{k.name}</span>
                  <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded-full bg-violet/15 text-violet border border-violet/20">
                    {SCOPE_LABEL[k.scope] ?? k.scope}
                  </span>
                  {Boolean(k.revoked) && (
                    <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded-full bg-white/5 text-ink-500 border border-white/10">Revoked</span>
                  )}
                </div>
                {!k.revoked && (
                  <button
                    onClick={() => revoke(k.id)}
                    className="text-[10px] px-2 py-1 rounded-lg border border-threat/25 text-threat hover:bg-threat/5 transition-colors shrink-0"
                  >
                    Revoke
                  </button>
                )}
              </div>
              <div className="font-mono text-xs text-ink-400 bg-surface-3 px-3 py-2 rounded-lg tracking-wider">
                {(SCOPE_PREFIX[k.scope] ?? 'to_sk_live_') + '•'.repeat(28) + k.prefix}
              </div>
              <p className="text-[9px] text-ink-700 mt-1.5">
                Created {new Date(k.createdAt).toLocaleDateString()} by {k.createdBy ?? 'system'} ·
                last used {k.lastUsed ? new Date(k.lastUsed).toLocaleDateString() : 'never'}
              </p>
            </div>
          ))}
        </div>
      )}

      <div className="glass border border-white/5 rounded-xl p-4">
        <h3 className="text-xs font-semibold text-white mb-3">Create New API Key</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
          <Field label="Key Name" value={name} onChange={setName} placeholder="e.g. CI pipeline" />
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Scope</label>
            <select
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40"
            >
              <option value="read">Read Only</option>
              <option value="write">Read + Write</option>
              <option value="admin">Full Admin</option>
            </select>
          </div>
        </div>
        <button
          onClick={generate}
          disabled={!name.trim() || creating}
          className={cn('px-4 py-2 rounded-xl text-xs font-semibold transition-all',
            name.trim() && !creating ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}
        >
          {creating ? 'Generating…' : 'Generate Key'}
        </button>

        {generated && (
          <motion.div
            initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
            className="mt-3 overflow-hidden"
          >
            <div className="flex items-center gap-2 rounded-lg bg-surface-3 border border-safe/20 px-3 py-2">
              <span className="font-mono text-[11px] text-safe flex-1 truncate">{generated}</span>
              <button
                onClick={() => { navigator.clipboard?.writeText(generated); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
                className="p-1 rounded text-ink-400 hover:text-white transition-colors shrink-0"
                aria-label="Copy key"
              >
                {copied ? <CheckCircle className="w-3.5 h-3.5 text-safe" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <p className="text-[10px] text-amber mt-1.5">Copy this key now — for security it won&apos;t be shown again.</p>
          </motion.div>
        )}
      </div>
    </>
  )
}

/* ── Live feed sources (backed by /feeds) ────────────────────────── */
const FEED_ICONS: Record<string, string> = {
  commercial: '🛡️', opensource: '🛸', community: '🌐', internal: '🏠',
}

function LiveFeedSources() {
  const [feeds, setFeeds] = useState<Feed[] | null>(null)
  const [unavailable, setUnavailable] = useState(false)

  useEffect(() => {
    fetchFeeds().then(setFeeds).catch(() => setUnavailable(true))
  }, [])

  function toggle(feed: Feed) {
    const next = !feed.enabled
    setFeeds((prev) => prev?.map((f) => (f.id === feed.id ? { ...f, enabled: next } : f)) ?? prev)
    toggleFeed(feed.id, next).catch(() => {
      setFeeds((prev) => prev?.map((f) => (f.id === feed.id ? { ...f, enabled: feed.enabled } : f)) ?? prev)
    })
  }

  if (unavailable) {
    return <p className="text-xs text-ink-600 py-6 text-center">Feed store unavailable. Start the dashboard API to manage sources.</p>
  }
  if (feeds === null) {
    return <p className="text-xs text-ink-600 py-6 text-center animate-pulse">Loading feeds…</p>
  }
  return (
    <div>
      {feeds.map((f) => (
        <div key={f.id} className="flex items-center gap-4 py-3 border-b border-white/4 last:border-0">
          <span className="text-lg shrink-0">{FEED_ICONS[f.type] ?? '📡'}</span>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-ink-200">{f.name}</p>
            <p className="text-[10px] text-ink-600 font-mono truncate">{f.url ?? f.type}</p>
            <p className="text-[9px] text-ink-700 mt-0.5">
              {f.indicators.toLocaleString()} indicators · last sync {f.lastSync ? new Date(f.lastSync).toLocaleString() : 'never'}
            </p>
          </div>
          <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border shrink-0',
            f.status === 'active' ? 'bg-safe/10 text-safe border-safe/20'
            : f.status === 'error' ? 'bg-threat/10 text-threat border-threat/20'
            : 'bg-white/5 text-ink-400 border-white/10')}>
            {f.status}
          </span>
          <button
            onClick={() => toggle(f)}
            role="switch"
            aria-checked={f.enabled}
            aria-label={`Toggle ${f.name}`}
            className={cn('relative w-9 h-5 rounded-full transition-colors shrink-0', f.enabled ? 'bg-safe' : 'bg-ink-600')}
          >
            <span className={cn('absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all', f.enabled ? 'left-[18px]' : 'left-0.5')} />
          </button>
        </div>
      ))}
    </div>
  )
}

/* ── Live integrations (backed by /soar/integrations) ────────────── */
function LiveIntegrations() {
  const [items, setItems] = useState<Integration[] | null>(null)
  const [unavailable, setUnavailable] = useState(false)

  useEffect(() => {
    fetchSoarIntegrations().then(setItems).catch(() => setUnavailable(true))
  }, [])

  if (unavailable) {
    return <p className="text-xs text-ink-600 py-6 text-center">Integration store unavailable. Start the dashboard API to see connector state.</p>
  }
  if (items === null) {
    return <p className="text-xs text-ink-600 py-6 text-center animate-pulse">Loading integrations…</p>
  }
  return (
    <div className="space-y-3">
      {items.map((it) => {
        const ok = it.status === 'connected'
        return (
          <div key={it.id} className="flex items-center gap-4 py-3 border-b border-white/4 last:border-0">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-ink-200">{it.name}</span>
                <span className={cn(
                  'text-[9px] px-1.5 py-0.5 rounded-full border font-semibold capitalize',
                  ok ? 'bg-safe/10 text-safe border-safe/20'
                  : it.status === 'degraded' ? 'bg-amber/10 text-amber border-amber/20'
                  : 'bg-threat/10 text-threat border-threat/20',
                )}>
                  {it.status}
                </span>
              </div>
              <p className="text-[10px] text-ink-600 mt-0.5">
                {it.description ?? ''}
                {it.lastSync ? ` · last sync ${new Date(it.lastSync).toLocaleString()}` : ''}
              </p>
            </div>
          </div>
        )
      })}
      <p className="text-[10px] text-ink-700 pt-1">
        Full connector detail — actions, response times, sync history — lives in{' '}
        <a href="/dashboard/soar/integrations" className="text-magenta hover:underline">SOAR → Integrations</a>.
      </p>
    </div>
  )
}

/* ── Experience mode ─────────────────────────────────────────────── */
function ExperienceModeCard() {
  const [mode, setMode] = useExperienceMode()

  const MODES = [
    {
      id: 'normal' as const,
      label: 'Normal',
      icon: User,
      color: '#2DD4BF',
      tagline: 'Simplified, analyst-first view',
      features: [
        'Top-5 most critical alerts, pre-triaged',
        'At-a-glance KPI tiles (MTTD, open cases, risk score)',
        'Visual heatmap and executive summaries',
        'Simplified filter controls and guided workflows',
        'Best for: L1 analysts, on-call, SOC managers',
      ],
    },
    {
      id: 'power' as const,
      label: 'Power User',
      icon: Zap,
      color: '#FF2E97',
      tagline: 'Full access — dense data, raw controls',
      features: [
        'Full alert queue with all 15+ fields',
        'SIEM raw log view and KQL/SPL query interface',
        'Correlation rule editor + suppression tuning',
        'Entity risk drill-down and UEBA timeline',
        'Best for: L2/L3 analysts, threat hunters, IR leads',
      ],
    },
  ]

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-violet/25 overflow-hidden"
      style={{ background: 'linear-gradient(135deg, rgba(122,60,255,0.08), rgba(255,46,151,0.05))' }}>
      <div className="flex items-center gap-3 px-4 py-3 sm:px-5 sm:py-4 border-b border-white/8">
        <div className="p-2 rounded-lg bg-violet/15 shrink-0">
          <BarChart2 className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white">Experience Mode</h2>
          <p className="text-[11px] text-ink-500 mt-0.5">Switch between simplified and power-user dashboard layouts</p>
        </div>
        <div className="ml-auto shrink-0 px-2.5 py-1 rounded-full text-[10px] font-semibold border border-violet/30 bg-violet/10 text-violet">
          <span className="hidden sm:inline">Active: </span>{mode === 'normal' ? 'Normal' : 'Power'}
        </div>
      </div>

      <div className="p-3 sm:p-5 grid grid-cols-2 gap-2.5 sm:gap-4">
        {MODES.map((m) => {
          const Icon = m.icon
          const active = mode === m.id
          return (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={cn(
                'text-left p-2.5 sm:p-4 rounded-xl border transition-all',
                active
                  ? 'border-opacity-60 shadow-lg'
                  : 'border-white/8 hover:border-white/15 bg-surface-2/40',
              )}
              style={active ? {
                borderColor: m.color + '60',
                background: m.color + '0c',
                boxShadow: `0 0 24px ${m.color}18`,
              } : undefined}
            >
              <div className="flex items-center gap-2 sm:gap-3 mb-0 sm:mb-3">
                <div className="p-1.5 sm:p-2 rounded-lg shrink-0" style={{ background: m.color + '18' }}>
                  <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4" style={{ color: m.color }} />
                </div>
                <div className="min-w-0">
                  <p className="text-xs sm:text-sm font-semibold text-white leading-tight">{m.label}</p>
                  <p className="text-[9px] sm:text-[10px] leading-tight" style={{ color: m.color }}>{m.tagline}</p>
                </div>
                {active && (
                  <div className="ml-auto w-4 h-4 sm:w-5 sm:h-5 rounded-full flex items-center justify-center shrink-0"
                    style={{ background: m.color + '20', border: `1px solid ${m.color}50` }}>
                    <CheckCircle className="w-2.5 h-2.5 sm:w-3 sm:h-3" style={{ color: m.color }} />
                  </div>
                )}
              </div>
              {/* Feature list — hidden on mobile to keep cards compact */}
              <ul className="hidden sm:block space-y-1.5 mt-3">
                {m.features.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] text-ink-400">
                    <ChevronRight className="w-3 h-3 mt-0.5 shrink-0" style={{ color: active ? m.color : '#4a4463' }} />
                    {f}
                  </li>
                ))}
              </ul>
            </button>
          )
        })}
      </div>

      <div className="px-4 pb-3 sm:px-5 sm:pb-4">
        <p className="text-[10px] text-ink-700">
          Mode applies across all dashboard pages. Power User mode reveals advanced panels, raw data views, and analyst tools not shown in Normal mode.
        </p>
      </div>
    </motion.div>
  )
}

/* ── Theme picker ────────────────────────────────────────────────── */
function ThemeCard() {
  const [theme, setTheme] = useDashboardTheme()
  const active = THEMES.find((t) => t.id === theme) ?? THEMES[0]

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-5 sm:py-4 border-b border-white/5">
        <div className="p-2 rounded-lg shrink-0" style={{ background: `${active.swatch[1]}22` }}>
          <Palette className="w-4 h-4" style={{ color: active.swatch[1] }} />
        </div>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white">Dashboard Theme</h2>
          <p className="text-[11px] text-ink-500 mt-0.5">Recolour the entire dashboard — applies instantly, only here (not the public site)</p>
        </div>
        <div className="ml-auto shrink-0 px-2.5 py-1 rounded-full text-[10px] font-semibold border border-white/12 bg-white/5 text-ink-200">
          {active.label}
        </div>
      </div>

      <div className="p-3 sm:p-5 grid grid-cols-2 sm:grid-cols-3 gap-2 sm:gap-3">
        {THEMES.map((t) => {
          const isActive = t.id === theme
          return (
            <button
              key={t.id}
              onClick={() => setTheme(t.id)}
              className={cn(
                'group relative text-left rounded-xl border p-2 sm:p-3 transition-all',
                isActive
                  ? 'border-white/25 shadow-lg'
                  : 'border-white/8 hover:border-white/18 hover:bg-white/3',
              )}
              style={isActive ? { boxShadow: `0 0 22px ${t.swatch[1]}33`, borderColor: `${t.swatch[1]}66` } : undefined}
            >
              <div
                className="relative h-10 sm:h-14 rounded-lg overflow-hidden mb-2 border border-white/8"
                style={{ background: t.swatch[0] }}
              >
                <div className="absolute inset-0 flex items-end gap-1 sm:gap-1.5 p-1.5 sm:p-2">
                  <span className="w-4 h-4 sm:w-6 sm:h-6 rounded-md" style={{ background: t.swatch[1] }} />
                  <span className="w-3 h-3.5 sm:w-4 sm:h-5 rounded-md" style={{ background: t.swatch[2] }} />
                  <span className="w-2 h-3 sm:w-3 sm:h-4 rounded-md" style={{ background: t.swatch[3] }} />
                  <span className="ml-auto w-6 h-1.5 sm:w-8 sm:h-2 rounded-full self-center" style={{ background: `${t.swatch[1]}55` }} />
                </div>
                {isActive && (
                  <div className="absolute top-1 right-1 sm:top-1.5 sm:right-1.5 w-4 h-4 sm:w-5 sm:h-5 rounded-full flex items-center justify-center"
                    style={{ background: t.swatch[1] }}>
                    <Check className="w-2.5 h-2.5 sm:w-3 sm:h-3" style={{ color: t.swatch[0] }} strokeWidth={3} />
                  </div>
                )}
              </div>
              <p className="text-[11px] sm:text-xs font-semibold text-white">{t.label}</p>
              <p className="text-[9px] sm:text-[10px] text-ink-500 mt-0.5 hidden sm:block">{t.desc}</p>
            </button>
          )
        })}
      </div>

      <div className="px-4 pb-3 sm:px-5 sm:pb-4">
        <p className="text-[10px] text-ink-700">
          Your choice is saved to this browser and syncs across open dashboard tabs. The marketing site keeps its signature Plasma Noir look.
        </p>
      </div>
    </motion.div>
  )
}

/* ── Section wrapper ─────────────────────────────────────────────── */
function Section({ title, icon: Icon, color, children }: {
  title: string; icon: React.ElementType; color: string; children: React.ReactNode
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/5 rounded-xl overflow-hidden"
    >
      <div className="flex items-center gap-3 px-4 py-3 sm:px-5 sm:py-4 border-b border-white/5">
        <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}18` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      <div className="p-4 sm:p-5">{children}</div>
    </motion.div>
  )
}

/* ── Tabs ────────────────────────────────────────────────────────── */
const TABS = [
  { id: 'general',     label: 'General',         icon: Settings },
  { id: 'api',         label: 'API Keys',         icon: Key      },
  { id: 'sources',     label: 'Feed Sources',     icon: Globe    },
  { id: 'alerts',      label: 'Notifications',    icon: Bell     },
  { id: 'security',    label: 'Security',         icon: Shield   },
  { id: 'integrations',label: 'Integrations',     icon: Plug     },
]

/* ── Settings navigation ─────────────────────────────────────────────
   Mobile  (< sm): horizontal scrollable icon+label strip above the content
   Desktop (sm+) : vertical collapsible icon rail with hover-to-expand      */
function SettingsNav({ tab, setTab }: { tab: string; setTab: (id: string) => void }) {
  const [pinned, setPinned] = useState(false)
  const [hovered, setHovered] = useState(false)
  const expanded = pinned || hovered

  return (
    <>
      {/* ── Mobile horizontal strip ── */}
      <nav className="sm:hidden overflow-x-auto flex gap-1 pb-2 -mx-4 px-4 scrollbar-none">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              'flex flex-col items-center gap-1 px-3 py-2 rounded-xl shrink-0 transition-colors',
              tab === id
                ? 'bg-magenta/12 text-magenta'
                : 'text-ink-400 hover:text-white hover:bg-white/5',
            )}
          >
            <Icon className="w-4 h-4" />
            <span className="text-[10px] font-medium whitespace-nowrap">{label}</span>
          </button>
        ))}
      </nav>

      {/* ── Desktop vertical rail ── */}
      <nav
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        className={cn(
          'hidden sm:block shrink-0 transition-[width] duration-300 ease-out',
          expanded ? 'w-48' : 'w-12',
        )}
      >
        <div className="sticky top-4 glass border border-white/8 rounded-2xl p-2 overflow-hidden">
          <button
            onClick={() => setPinned((p) => !p)}
            aria-label={pinned ? 'Unpin settings menu' : 'Pin settings menu open'}
            aria-pressed={pinned}
            className="w-full flex items-center py-2 rounded-xl text-ink-400 hover:text-white hover:bg-white/5 transition-colors mb-1"
          >
            <span className="w-8 flex justify-center shrink-0">
              {pinned ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />}
            </span>
            {expanded && (
              <span className="text-[10px] uppercase tracking-widest font-semibold whitespace-nowrap pr-2">
                {pinned ? 'Collapse' : 'Settings'}
              </span>
            )}
          </button>

          <div className="h-px bg-white/6 mx-1 mb-1" />

          <div className="space-y-0.5">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                title={!expanded ? label : undefined}
                className={cn(
                  'w-full flex items-center py-2.5 rounded-xl text-xs font-medium transition-colors',
                  tab === id
                    ? 'bg-magenta/10 text-magenta'
                    : 'text-ink-400 hover:text-white hover:bg-white/5',
                )}
              >
                <span className="w-8 flex justify-center shrink-0"><Icon className="w-4 h-4" /></span>
                {expanded && <span className="whitespace-nowrap pr-2">{label}</span>}
              </button>
            ))}
          </div>
        </div>
      </nav>
    </>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
/* ── Audit trail ─────────────────────────────────────────────────── */
const ACTION_COLOR: Record<string, string> = {
  create: '#34F5C5', update: '#FFB23E', delete: '#FF4D6D',
  revoke: '#FF4D6D', toggle: '#7A3CFF', run: '#FF2E97',
}

function actionTint(action: string): string {
  const verb = action.split('.')[1] ?? action
  return ACTION_COLOR[verb] ?? '#7A3CFF'
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

/* ── Change password ─────────────────────────────────────────────── */
function ChangePassword() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [state, setState] = useState<'idle' | 'saving' | 'done' | 'error'>('idle')
  const [message, setMessage] = useState('')

  const canSubmit = current && next.length >= 8 && next === confirm

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit || state === 'saving') return
    setState('saving')
    try {
      await authChangePassword(current, next)
      setState('done')
      setMessage('Password updated.')
      setCurrent(''); setNext(''); setConfirm('')
    } catch (err) {
      setState('error')
      setMessage(err instanceof Error && err.message.includes('incorrect')
        ? 'Current password is incorrect.'
        : 'Could not update the password. Is the dashboard API running?')
    }
  }

  return (
    <Section title="Change Password" icon={Key} color="#FFB23E">
      <form onSubmit={submit} className="space-y-4 max-w-sm">
        <Field label="Current password" type="password" value={current} onChange={setCurrent} />
        <Field label="New password" type="password" value={next} onChange={setNext}
          hint="At least 8 characters" />
        <Field label="Confirm new password" type="password" value={confirm} onChange={setConfirm}
          hint={confirm && next !== confirm ? 'Passwords do not match' : undefined} />
        {state === 'done' && <p className="text-[11px] text-safe">{message}</p>}
        {state === 'error' && <p className="text-[11px] text-threat" role="alert">{message}</p>}
        <button type="submit" disabled={!canSubmit || state === 'saving'}
          className={cn('px-4 py-2 rounded-xl text-xs font-semibold transition-all',
            canSubmit && state !== 'saving' ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
          {state === 'saving' ? 'Updating…' : 'Update Password'}
        </button>
      </form>
    </Section>
  )
}

function AuditTrail() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    fetchAuditLog(25)
      .then(setEntries)
      .catch(() => setError(true))
  }, [])

  return (
    <Section title="Audit Trail" icon={ScrollText} color="#7A3CFF">
      <p className="text-[11px] text-ink-500 mb-4">
        Most recent mutations recorded server-side. Every state change — alerts, cases,
        rules, users, keys, feeds — is captured with actor and target.
      </p>
      {error && (
        <p className="text-xs text-ink-600 py-6 text-center">
          Audit log unavailable. Start the dashboard API to see live activity.
        </p>
      )}
      {!error && entries === null && (
        <p className="text-xs text-ink-600 py-6 text-center animate-pulse">Loading audit trail…</p>
      )}
      {!error && entries !== null && entries.length === 0 && (
        <p className="text-xs text-ink-600 py-6 text-center">No activity recorded yet.</p>
      )}
      {!error && entries !== null && entries.length > 0 && (
        <div className="space-y-0.5 max-h-80 overflow-y-auto">
          {entries.map((e) => (
            <div key={e.id} className="flex items-center gap-3 py-2 border-b border-white/4 last:border-0 text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: actionTint(e.action) }} />
              <span className="font-mono text-ink-200 shrink-0 w-32 truncate">{e.action}</span>
              <span className="text-ink-500 flex-1 min-w-0 truncate">
                {e.actor ?? 'system'}
                {e.target && <span className="text-ink-600"> → {e.target}</span>}
                {e.detail && <span className="text-ink-700"> · {e.detail}</span>}
              </span>
              <span className="text-ink-600 shrink-0 tabular-nums">{relativeTime(e.ts)}</span>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

/* ── Background jobs ─────────────────────────────────────────────── */
const JOB_LABEL: Record<string, string> = {
  'threat.sync_iocs': 'IOC sync from Threat API',
  'logs.analyse': 'Log anomaly analysis',
  'assets.recompute_risk': 'Asset risk recompute',
}

function jobSummary(j: JobEntry): string {
  const m = j.meta ?? {}
  if (j.kind === 'threat.sync_iocs') return `${m.imported ?? 0} imported · ${m.duplicates ?? 0} known`
  if (j.kind === 'logs.analyse') return `${m.file ?? 'file'} · ${m.findings ?? 0} findings`
  if (j.kind === 'assets.recompute_risk') return `${m.updated ?? 0} assets rescored`
  return ''
}

function BackgroundJobs() {
  const [jobs, setJobs] = useState<JobEntry[] | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    fetchJobs(25).then(setJobs).catch(() => setError(true))
  }, [])

  return (
    <Section title="Background Jobs" icon={Zap} color="#FFB23E">
      <p className="text-[11px] text-ink-500 mb-4">
        Heavy operations — Threat-API IOC syncs, log analyses, fleet risk recomputes —
        are recorded here with their outcome.
      </p>
      {error && (
        <p className="text-xs text-ink-600 py-6 text-center">Job history unavailable. Start the dashboard API to see runs.</p>
      )}
      {!error && jobs !== null && jobs.length === 0 && (
        <p className="text-xs text-ink-600 py-6 text-center">No background jobs recorded yet — trigger a sync, analysis or recompute.</p>
      )}
      {!error && jobs === null && (
        <p className="text-xs text-ink-600 py-6 text-center animate-pulse">Loading jobs…</p>
      )}
      {!error && jobs !== null && jobs.length > 0 && (
        <div className="space-y-0.5 max-h-72 overflow-y-auto">
          {jobs.map((j) => (
            <div key={j.id} className="flex items-center gap-3 py-2 border-b border-white/4 last:border-0 text-[11px]">
              <span className={cn('w-1.5 h-1.5 rounded-full shrink-0',
                j.status === 'completed' ? 'bg-safe' : j.status === 'failed' ? 'bg-threat' : 'bg-amber')} />
              <span className="text-ink-200 shrink-0 w-44 truncate">{JOB_LABEL[j.kind] ?? j.kind}</span>
              <span className="text-ink-500 flex-1 min-w-0 truncate">{jobSummary(j)}</span>
              <span className="text-ink-600 shrink-0 tabular-nums">{relativeTime(j.createdAt)}</span>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

export default function ConfigPage() {
  const [tab, setTab] = useState('general')
  const [saved, setSaved] = useState(false)
  const [cursorFx, setCursorFx] = useCursorEffect()

  // Platform settings, loaded from and persisted to the backend settings store.
  const [settings, setSettings] = useState<Record<string, string>>({
    platform_name: 'ThreatOrbit Production',
    organization: 'Acme Security Corp',
    timezone: 'UTC',
    feed_update_interval: '3',
    data_retention_days: '90',
  })
  const setSetting = (key: string) => (v: string) => setSettings((s) => ({ ...s, [key]: v }))
  // Boolean settings are stored as 'true'/'false' strings in the settings table.
  const boolSetting = (key: string, fallback: boolean) =>
    settings[key] === undefined ? fallback : settings[key] === 'true'
  const setBoolSetting = (key: string) => (v: boolean) => setSettings((s) => ({ ...s, [key]: String(v) }))

  useEffect(() => {
    fetchSettings()
      .then((remote) => setSettings((s) => ({ ...s, ...remote })))
      .catch(() => {})
  }, [])

  const save = () => {
    updateSettings(settings).catch(() => {})  // persists when API is up; UI state is source of truth otherwise
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  return (
    <div className="p-4 sm:p-6 overflow-x-clip">
      <div className="flex items-center justify-between mb-6 gap-3">
        <div className="min-w-0">
          <h1 className="font-display text-xl font-bold text-white">Configuration</h1>
          <p className="text-xs text-ink-500 mt-0.5">Platform settings, API keys, integrations, and notifications</p>
        </div>
        <button
          onClick={save}
          className={cn(
            'flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all',
            saved ? 'bg-safe/15 text-safe border border-safe/25' : 'bg-plasma text-white hover:shadow-magenta-sm',
          )}
        >
          {saved ? <><CheckCircle className="w-4 h-4" /> <span className="hidden sm:inline">Saved!</span></> : <><Save className="w-4 h-4" /> <span className="hidden sm:inline">Save Changes</span></>}
        </button>
      </div>

      <div className="flex flex-col sm:flex-row gap-3 sm:gap-6">
        {/* Nav: horizontal strip on mobile, vertical rail on sm+ */}
        <SettingsNav tab={tab} setTab={setTab} />

        {/* Content */}
        <div className="flex-1 min-w-0 space-y-5">
          {tab === 'general' && (
            <>
              {/* ── Experience Mode ─────────────────────────────────── */}
              <ExperienceModeCard />

              {/* ── Dashboard Theme ─────────────────────────────────── */}
              <ThemeCard />

              <Section title="Platform Settings" icon={Settings} color="#7A3CFF">
                <div className="space-y-4">
                  <Field label="Platform Name" value={settings.platform_name ?? ''} onChange={setSetting('platform_name')} />
                  <Field label="Organization" value={settings.organization ?? ''} onChange={setSetting('organization')} />
                  <Field label="API Base URL" value="https://api.threatorbit.space" hint="The base URL for all API endpoints" />
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <Field label="Timezone" value={settings.timezone ?? 'UTC'} onChange={setSetting('timezone')} />
                    <Field label="Feed Update Interval (seconds)" value={settings.feed_update_interval ?? '3'} type="number" hint="Minimum: 1 second" onChange={setSetting('feed_update_interval')} />
                  </div>
                  <Field label="Data Retention (days)" value={settings.data_retention_days ?? '90'} type="number" hint="Older events are automatically purged" onChange={setSetting('data_retention_days')} />
                </div>
              </Section>

              <Section title="Display Preferences" icon={Eye} color="#2DD4BF">
                <div className="space-y-0">
                  <Toggle label="Dark Mode" description="Use dark Plasma Noir theme (default)" checked={true} />
                  <Toggle label="Compact View" description="Show more rows in event tables" checked={false} />
                  <Toggle label="Animated Effects" description="Enable canvas animations and transitions" checked={true} />
                  <Toggle label="Cursor Particle Effect" description="Liquid particle trail that follows your mouse / finger" value={cursorFx} onChange={setCursorFx} />
                  <Toggle label="Auto-refresh Dashboard" description="Refresh overview widgets every 30s" checked={true} />
                </div>
              </Section>
            </>
          )}

          {tab === 'api' && (
            <Section title="API Keys" icon={Key} color="#FFB23E">
              <LiveApiKeys />
            </Section>
          )}

          {tab === 'sources' && (
            <Section title="Threat Feed Sources" icon={Globe} color="#FF2E97">
              <div className="mb-4 text-xs text-ink-400">Enable or disable threat intelligence feeds. Changes persist immediately and take effect on the next scheduled sync.</div>
              <LiveFeedSources />
            </Section>
          )}

          {tab === 'alerts' && (
            <Section title="Notification Settings" icon={Bell} color="#FF4D6D">
              <div className="space-y-4 mb-5">
                <Field label="Alert Email" type="email" value={settings.alert_email ?? ''} onChange={setSetting('alert_email')} placeholder="soc-team@yourcompany.com" />
                <Field label="Slack Webhook URL" value={settings.slack_webhook_url ?? ''} onChange={setSetting('slack_webhook_url')} placeholder="https://hooks.slack.com/services/…" hint="Receives critical and high severity alerts" />
                <Field label="PagerDuty Integration Key" value={settings.pagerduty_key ?? ''} onChange={setSetting('pagerduty_key')} placeholder="your-integration-key" hint="Used for P0 escalations" />
              </div>
              <div>
                <p className="text-xs font-semibold text-white mb-1">Notification Rules</p>
                <p className="text-[10px] text-ink-600 mb-3">Saved with the Save Changes button above.</p>
                <Toggle label="Critical Severity Alerts"    description="Email + Slack + PagerDuty immediately"        value={boolSetting('notify_critical', true)}  onChange={setBoolSetting('notify_critical')} />
                <Toggle label="High Severity Alerts"        description="Email + Slack within 5 minutes"               value={boolSetting('notify_high', true)}      onChange={setBoolSetting('notify_high')} />
                <Toggle label="Medium Severity Alerts"      description="Daily digest email"                           value={boolSetting('notify_medium', false)}   onChange={setBoolSetting('notify_medium')} />
                <Toggle label="New IOC Matches"             description="Slack notification for new IOC hits"          value={boolSetting('notify_ioc_matches', true)} onChange={setBoolSetting('notify_ioc_matches')} />
                <Toggle label="Feed Source Failures"        description="Alert when a feed source goes offline"        value={boolSetting('notify_feed_failures', true)} onChange={setBoolSetting('notify_feed_failures')} />
                <Toggle label="Playbook Failures"           description="Notify SOC lead when a SOAR playbook fails"   value={boolSetting('notify_playbook_failures', true)} onChange={setBoolSetting('notify_playbook_failures')} />
              </div>
            </Section>
          )}

          {tab === 'security' && (
            <Section title="Security Settings" icon={Shield} color="#34F5C5">
              <div className="space-y-4 mb-5">
                <div>
                  <label className="block text-xs font-medium text-ink-300 mb-1.5">Authentication Method</label>
                  <select
                    value={settings.auth_method ?? 'jwt'}
                    onChange={(e) => setSetting('auth_method')(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                    <option value="jwt">Email + Password (JWT, default)</option>
                    <option value="oidc">OAuth 2.0 (OIDC)</option>
                    <option value="saml">SAML 2.0 SSO</option>
                  </select>
                </div>
                <Field label="Session Timeout (minutes)" type="number" value={settings.session_timeout_minutes ?? '720'} onChange={setSetting('session_timeout_minutes')} />
                <Field label="Allowed IP Ranges" value={settings.allowed_ip_ranges ?? '0.0.0.0/0'} onChange={setSetting('allowed_ip_ranges')} hint="Comma-separated CIDR blocks. Use 0.0.0.0/0 to allow all." />
              </div>
              <p className="text-[10px] text-ink-600 mb-2">Saved with the Save Changes button above.</p>
              <Toggle label="Enforce MFA"                  description="Require TOTP for all dashboard logins"        value={boolSetting('enforce_mfa', false)}      onChange={setBoolSetting('enforce_mfa')} />
              <Toggle label="Audit Logging"                description="Log all API calls and user actions"           value={boolSetting('audit_logging', true)}     onChange={setBoolSetting('audit_logging')} />
              <Toggle label="Rate Limiting"                description="Throttle repeated failed logins per client"   value={boolSetting('rate_limiting', true)}     onChange={setBoolSetting('rate_limiting')} />
              <Toggle label="Automated Threat Blocking"    description="Auto-block IPs with confidence score > 90%"  value={boolSetting('auto_threat_blocking', false)} onChange={setBoolSetting('auto_threat_blocking')} />
            </Section>
          )}

          {tab === 'security' && <ChangePassword />}

          {tab === 'security' && <BackgroundJobs />}

          {tab === 'security' && <AuditTrail />}

          {tab === 'integrations' && (
            <Section title="Integrations" icon={Plug} color="#FFB23E">
              <LiveIntegrations />
            </Section>
          )}
        </div>
      </div>
    </div>
  )
}
