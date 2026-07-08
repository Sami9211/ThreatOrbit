'use client'

import { useState, useEffect, useRef, useId } from 'react'
import { motion } from 'framer-motion'
import {
  Settings, Key, Bell, Shield, Globe, Plug, Database,
  Eye, Copy, CheckCircle,
  Zap, User, BarChart2, ChevronRight, Palette, Check,
  PanelLeftOpen, PanelLeftClose, ScrollText, Plus, RotateCcw, CreditCard, ExternalLink,
  Monitor, LogOut,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import FloatingSave from '@/components/dashboard/FloatingSave'
import {
  fetchAuditLog, fetchSettings, updateSettings, authChangePassword,
  fetchApiKeys, createApiKey, revokeApiKey,
  fetchFeeds, toggleFeed, fetchSoarIntegrations, fetchJobs,
  fetchEngineStatus, controlEngine, enforceRetention,
  fetchCurrentOrg, type Org,
  fetchLicense, activateLicense, type LicenseStatus,
  fetchBillingStatus, startCheckout, openBillingPortal, type BillingStatus,
  fetchDatabaseInfo, type DatabaseInfo,
  fetchMySlackRouting, setMySlackRouting, testMySlackRouting,
  fetchMfaStatus, mfaEnroll, mfaVerify, mfaDisable, mfaRegenerateRecoveryCodes,
  fetchSessions, revokeSession, type SessionInfo,
  type AuditEntry, type ApiKey as RemoteApiKey, type Feed, type Integration, type JobEntry,
  type EngineStatus,
} from '@/lib/api'
import { useExperienceMode } from '@/lib/useExperienceMode'
import {
  useDashboardTheme, THEMES,
  useDashboardPrefs, ACCENT_PRESETS,
} from '@/lib/useDashboardTheme'
import { useCursorEffect } from '@/lib/useCursorEffect'
import { tk, withAlpha } from '@/lib/colors'

/* ── Two-factor authentication (real TOTP, per-user) ─────────────── */
function MyMfaPanel() {
  const [status, setStatus] = useState<{ enabled: boolean; pending: boolean; recoveryCodesRemaining: number } | null>(null)
  const [enrolment, setEnrolment] = useState<{ secret: string; otpauthUri: string } | null>(null)
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [code, setCode] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = () => fetchMfaStatus().then(setStatus).catch(() => {})
  useEffect(() => { load() }, [])

  function start() {
    setBusy(true); setMsg(null)
    mfaEnroll()
      .then((e) => { setEnrolment(e); load() })
      .catch((e) => setMsg(e instanceof Error ? e.message : 'Could not start enrolment.'))
      .finally(() => setBusy(false))
  }

  function verify() {
    if (code.length < 6 || busy) return
    setBusy(true); setMsg(null)
    mfaVerify(code)
      .then((r) => { setEnrolment(null); setCode(''); setRecoveryCodes(r.recoveryCodes ?? null); setMsg('Two-factor authentication is ON - your next login will ask for a code.'); load() })
      .catch(() => setMsg('That code did not verify - check your authenticator and try again.'))
      .finally(() => setBusy(false))
  }

  function regenerate() {
    if (code.length < 6 || busy) return
    setBusy(true); setMsg(null)
    mfaRegenerateRecoveryCodes(code)
      .then((r) => { setCode(''); setRecoveryCodes(r.recoveryCodes); setMsg('New recovery codes generated - your old ones no longer work.'); load() })
      .catch(() => setMsg('That code did not verify - codes unchanged.'))
      .finally(() => setBusy(false))
  }

  function disable() {
    if (code.length < 6 || busy) return
    setBusy(true); setMsg(null)
    mfaDisable(code)
      .then(() => { setCode(''); setMsg('Two-factor authentication is OFF.'); load() })
      .catch(() => setMsg('That code did not verify - MFA stays on.'))
      .finally(() => setBusy(false))
  }

  return (
    <div className="mb-5 p-4 rounded-xl border border-safe/20 bg-safe/5">
      <div className="flex items-center gap-2 mb-1">
        <Shield className="w-3.5 h-3.5 text-safe" />
        <p className="text-xs font-semibold text-white">Two-factor authentication (TOTP)</p>
        {status && (
          <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold',
            status.enabled ? 'text-safe bg-safe/12' : 'text-ink-500 bg-white/6')}>
            {status.enabled ? 'enabled' : status.pending ? 'pending verification' : 'off'}
          </span>
        )}
      </div>
      <p className="text-[10px] text-ink-600 mb-3">
        Personal to your account. Once verified, every sign-in requires a 6-digit code from your
        authenticator app (Google Authenticator, Authy, 1Password, …).
      </p>

      {!status?.enabled && !enrolment && (
        <button onClick={start} disabled={busy}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-safe/15 border border-safe/30 text-safe hover:bg-safe/20 disabled:opacity-50 transition-colors">
          {status?.pending ? 'Restart enrolment' : 'Set up two-factor authentication'}
        </button>
      )}

      {enrolment && (
        <div className="space-y-2.5">
          <p className="text-[11px] text-ink-300">
            1. Add this secret to your authenticator app (or paste the otpauth URI into a QR generator):
          </p>
          <div className="px-3 py-2 rounded-lg bg-surface-2 border border-white/8">
            <p className="text-sm font-mono tracking-wider text-white break-all">{enrolment.secret}</p>
            <p className="text-[10px] font-mono text-ink-600 mt-1 break-all">{enrolment.otpauthUri}</p>
          </div>
          <p className="text-[10px] text-amber">
            Shown once - it is stored encrypted server-side and cannot be displayed again.
          </p>
          <p className="text-[11px] text-ink-300">2. Enter the current code to verify and switch MFA on:</p>
        </div>
      )}

      {(enrolment || status?.enabled) && (
        <div className="flex items-center gap-2 mt-2.5">
          <input value={code} inputMode="numeric" maxLength={6}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            placeholder="6-digit code"
            className="w-32 px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs font-mono tracking-[0.25em] text-ink-100 focus:outline-none focus:border-safe/40 placeholder-ink-600" />
          {enrolment ? (
            <button onClick={verify} disabled={busy || code.length < 6}
              className="px-3 py-2 rounded-lg text-xs font-medium bg-safe/15 border border-safe/30 text-safe hover:bg-safe/20 disabled:opacity-50 transition-colors">
              Verify &amp; enable
            </button>
          ) : (
            <button onClick={disable} disabled={busy || code.length < 6}
              title="Requires a valid current code (possession proof)"
              className="px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-threat disabled:opacity-40 transition-colors">
              Disable MFA
            </button>
          )}
        </div>
      )}
      {recoveryCodes && (
        <div className="mt-3 p-3 rounded-lg border border-amber/30 bg-amber/8">
          <p className="text-[11px] font-semibold text-amber mb-1">Save your recovery codes</p>
          <p className="text-[10px] text-ink-400 mb-2">
            Each works once if you lose your authenticator. They&apos;re stored hashed and can&apos;t be shown again.
          </p>
          <div className="grid grid-cols-2 gap-1.5 mb-2">
            {recoveryCodes.map((c) => (
              <code key={c} className="text-[11px] font-mono text-ink-100 bg-surface-2 border border-white/8 rounded px-2 py-1 text-center tracking-wider">{c}</code>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => navigator.clipboard?.writeText(recoveryCodes.join('\n'))}
              className="px-2.5 py-1.5 rounded-lg text-[11px] bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">Copy all</button>
            <button onClick={() => setRecoveryCodes(null)}
              className="px-2.5 py-1.5 rounded-lg text-[11px] bg-safe/15 border border-safe/30 text-safe hover:bg-safe/20 transition-colors">I&apos;ve saved them</button>
          </div>
        </div>
      )}
      {status?.enabled && !recoveryCodes && (
        <div className="flex items-center gap-2 mt-2 text-[10px] text-ink-500">
          <span>{status.recoveryCodesRemaining} recovery code{status.recoveryCodesRemaining !== 1 ? 's' : ''} left</span>
          <button onClick={regenerate} disabled={busy || code.length < 6}
            title="Enter a current authenticator code above, then regenerate"
            className="text-magenta hover:underline disabled:opacity-40 disabled:no-underline">Regenerate</button>
        </div>
      )}
      {msg && <p className="text-[11px] text-ink-400 mt-2" role="status">{msg}</p>}
    </div>
  )
}

/* ── Personal Slack routing (per-user, backed by /auth/me/slack) ── */
function MySlackRouting() {
  const [url, setUrl] = useState('')
  const [minSev, setMinSev] = useState('high')
  const [configured, setConfigured] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    fetchMySlackRouting()
      .then((r) => { setUrl(r.webhookUrl ?? ''); setMinSev(r.minSeverity); setConfigured(r.configured) })
      .catch(() => {})
  }, [])

  function save() {
    setBusy(true); setMsg(null)
    setMySlackRouting(url.trim() || null, minSev)
      .then((r) => { setConfigured(r.configured); setMsg(r.configured ? 'Saved - notifications will be mirrored to your Slack.' : 'Cleared - no Slack routing for your account.') })
      .catch(() => setMsg('Could not save (is the URL a valid http(s) webhook?).'))
      .finally(() => setBusy(false))
  }

  function testSend() {
    setBusy(true); setMsg(null)
    testMySlackRouting()
      .then((r) => setMsg(r.delivered ? 'Test message delivered ✓' : 'Delivery failed - check the webhook URL.'))
      .catch(() => setMsg('No webhook configured yet - save one first.'))
      .finally(() => setBusy(false))
  }

  return (
    <div className="mb-5 p-4 rounded-xl border border-violet/20 bg-violet/5">
      <p className="text-xs font-semibold text-white">My Slack routing</p>
      <p className="text-[10px] text-ink-600 mt-0.5 mb-3">
        Personal to your account: platform notifications at or above your severity floor are
        mirrored to this incoming-webhook URL. Other users configure their own.
      </p>
      <div className="grid sm:grid-cols-[1fr_140px_auto_auto] gap-2 items-end">
        <div>
          <label className="block text-[10px] font-medium text-ink-400 mb-1">Incoming webhook URL</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/…"
            className="w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-none focus:border-violet/40 placeholder-ink-600" />
        </div>
        <div>
          <label className="block text-[10px] font-medium text-ink-400 mb-1">Minimum severity</label>
          <select value={minSev} onChange={(e) => setMinSev(e.target.value)}
            className="w-full px-2 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-none focus:border-violet/40">
            {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <button onClick={save} disabled={busy}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-violet/15 border border-violet/30 text-violet hover:bg-violet/20 disabled:opacity-50 transition-colors">
          Save
        </button>
        <button onClick={testSend} disabled={busy || !configured}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white disabled:opacity-40 transition-colors">
          Send test
        </button>
      </div>
      {msg && <p className="text-[11px] text-ink-400 mt-2">{msg}</p>}
    </div>
  )
}

/* ── Shared input ────────────────────────────────────────────────── */
function Field({ label, value, type = 'text', hint, onChange, placeholder }: {
  label: string; value: string; type?: string; hint?: string
  onChange?: (v: string) => void; placeholder?: string
}) {
  const id = useId()
  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium text-ink-300 mb-1.5">{label}</label>
      <input
        id={id}
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
        <p className="text-xs text-ink-600 py-4 text-center">No API keys yet - create the first one below.</p>
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
            <p className="text-[10px] text-amber mt-1.5">Copy this key now - for security it won&apos;t be shown again.</p>
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
        Full connector detail - actions, response times, sync history - lives in{' '}
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
      color: tk('teal'),
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
      color: tk('magenta'),
      tagline: 'Full access - dense data, raw controls',
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
      style={{ background: `linear-gradient(135deg, ${withAlpha(tk('violet'), 0.08)}, ${withAlpha(tk('magenta'), 0.05)})` }}>
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
              {/* Feature list - hidden on mobile to keep cards compact */}
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

/* ── Two-option segmented control ────────────────────────────────── */
function Segmented<T extends string>({ label, desc, value, options, onChange }: {
  label: string; desc: string; value: T
  options: { v: T; l: string }[]; onChange: (v: T) => void
}) {
  return (
    <div>
      <p className="text-xs font-semibold text-white">{label}</p>
      <p className="text-[10px] text-ink-600 mb-2">{desc}</p>
      <div className="inline-flex p-0.5 rounded-lg bg-surface-2 border border-white/8">
        {options.map((o) => {
          const on = o.v === value
          return (
            <button key={o.v} onClick={() => onChange(o.v)} aria-pressed={on}
              className={cn('px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors border',
                on ? 'bg-magenta/15 text-magenta border-magenta/30' : 'text-ink-400 hover:text-white border-transparent')}>
              {o.l}
            </button>
          )
        })}
      </div>
    </div>
  )
}

/* ── Appearance: theme + accent + scale + motion + density ───────────
   The theme recolours the dashboard; the accent overrides the theme's
   primary; scale and density rescale the rem baseline (real zoom / density);
   reduced motion stops animations. All persist per-browser and sync across
   open dashboard tabs (see lib/useDashboardTheme.ts). The public marketing
   site is never affected. */
function ThemeCard({ saveTick }: { saveTick: number }) {
  const [theme, setTheme] = useDashboardTheme()
  const [prefs, setPrefs] = useDashboardPrefs()

  // Apply-on-save: edits update a local draft (the card reflects them), and are
  // only committed to the live theme/prefs - and the rest of the dashboard -
  // when the page Save button is clicked (which bumps `saveTick`).
  const [dTheme, setDTheme] = useState(theme)
  const [dPrefs, setDPrefs] = useState(prefs)
  const [dirty, setDirty] = useState(false)

  // Follow the persisted values (localStorage hydration after mount, or a change
  // from another tab) only while the user has not started an unsaved edit.
  useEffect(() => { if (!dirty) setDTheme(theme) }, [theme, dirty])
  useEffect(() => { if (!dirty) setDPrefs(prefs) }, [prefs, dirty])

  // Commit the draft when Save is clicked (skip the initial mount).
  const firstSave = useRef(true)
  useEffect(() => {
    if (firstSave.current) { firstSave.current = false; return }
    setTheme(dTheme)
    setPrefs(dPrefs)
    setDirty(false)
  }, [saveTick]) // eslint-disable-line react-hooks/exhaustive-deps

  const editTheme = (t: typeof theme) => { setDTheme(t); setDirty(true) }
  const editPrefs = (patch: Partial<typeof prefs>) => { setDPrefs((p) => ({ ...p, ...patch })); setDirty(true) }
  const revert = () => { setDTheme(theme); setDPrefs(prefs); setDirty(false) }

  const active = THEMES.find((t) => t.id === dTheme) ?? THEMES[0]
  const accentColor = (dPrefs.accent ?? active.swatch[1]).toLowerCase()
  const isCustomAccent = !!dPrefs.accent && !ACCENT_PRESETS.some((p) => p.toLowerCase() === dPrefs.accent!.toLowerCase())

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-5 sm:py-4 border-b border-white/5">
        <div className="p-2 rounded-lg shrink-0" style={{ background: `${accentColor}22` }}>
          <Palette className="w-4 h-4" style={{ color: accentColor }} />
        </div>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white">Appearance</h2>
          <p className="text-[11px] text-ink-500 mt-0.5">Theme, accent, scale, motion and density - applied when you click Save Changes, only here (not the public site)</p>
        </div>
        {dirty ? (
          <div className="ml-auto shrink-0 flex items-center gap-1.5">
            <span className="px-2 py-1 rounded-full text-[10px] font-semibold border border-amber/30 bg-amber/10 text-amber whitespace-nowrap">Pending - click Save</span>
            <button onClick={revert} title="Discard appearance changes"
              className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors">
              <RotateCcw className="w-3 h-3" /> Revert
            </button>
          </div>
        ) : (
          <div className="ml-auto shrink-0 px-2.5 py-1 rounded-full text-[10px] font-semibold border border-white/12 bg-white/5 text-ink-200">
            {active.label}
          </div>
        )}
      </div>

      {/* ── Theme presets ── */}
      <div className="p-3 sm:p-5 grid grid-cols-2 sm:grid-cols-3 gap-2 sm:gap-3">
        {THEMES.map((t) => {
          const isActive = t.id === dTheme
          return (
            <button
              key={t.id}
              onClick={() => editTheme(t.id)}
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

      {/* ── Detailed customization ── */}
      <div className="px-4 pb-4 sm:px-5 sm:pb-5 pt-4 border-t border-white/5 space-y-5">
        {/* Accent colour */}
        <div>
          <div className="flex items-start justify-between gap-3 mb-2.5">
            <div>
              <p className="text-xs font-semibold text-white">Accent colour</p>
              <p className="text-[10px] text-ink-600">Overrides the theme&apos;s primary across charts, buttons and highlights</p>
            </div>
            {dPrefs.accent && (
              <button onClick={() => editPrefs({ accent: null })}
                className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors shrink-0">
                <RotateCcw className="w-3 h-3" /> Theme default
              </button>
            )}
          </div>
          <div className="flex items-center flex-wrap gap-2">
            {ACCENT_PRESETS.map((hex) => {
              const on = dPrefs.accent?.toLowerCase() === hex.toLowerCase()
              return (
                <button key={hex} onClick={() => editPrefs({ accent: hex })}
                  aria-label={`Accent ${hex}`} aria-pressed={on} title={hex}
                  className={cn('w-7 h-7 rounded-full border-2 grid place-items-center transition-transform hover:scale-110',
                    on ? 'border-white' : 'border-white/15')}
                  style={{ background: hex }}>
                  {on && <Check className="w-3.5 h-3.5 text-black/75" strokeWidth={3} />}
                </button>
              )
            })}
            {/* native colour picker for any custom hex */}
            <label
              className={cn('relative w-7 h-7 rounded-full border-2 grid place-items-center cursor-pointer transition-transform hover:scale-110',
                isCustomAccent ? 'border-white' : 'border-dashed border-white/30')}
              style={isCustomAccent ? { background: dPrefs.accent! } : undefined}
              title="Custom colour">
              {isCustomAccent
                ? <Check className="w-3.5 h-3.5 text-black/75" strokeWidth={3} />
                : <Plus className="w-3.5 h-3.5 text-ink-400" />}
              <input type="color" value={accentColor}
                onChange={(e) => editPrefs({ accent: e.target.value })}
                className="absolute inset-0 opacity-0 cursor-pointer"
                aria-label="Custom accent colour" />
            </label>
          </div>
        </div>

        {/* UI scale */}
        <div>
          <div className="flex items-center justify-between gap-3 mb-2">
            <div>
              <p className="text-xs font-semibold text-white">UI scale</p>
              <p className="text-[10px] text-ink-600">Zoom the whole dashboard in or out</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="text-[11px] font-mono text-ink-300 tabular-nums">{Math.round(dPrefs.scale * 100)}%</span>
              {dPrefs.scale !== 1 && (
                <button onClick={() => editPrefs({ scale: 1 })} title="Reset to 100%"
                  className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors">
                  <RotateCcw className="w-3 h-3" /> Reset
                </button>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-ink-600 select-none">A</span>
            <input type="range" min={0.9} max={1.4} step={0.1} value={dPrefs.scale}
              onChange={(e) => editPrefs({ scale: parseFloat(e.target.value) })}
              aria-label="UI scale"
              className="flex-1 h-1.5 accent-magenta cursor-pointer" />
            <span className="text-sm text-ink-400 select-none">A</span>
          </div>
        </div>

        {/* Motion + density */}
        <div className="grid sm:grid-cols-2 gap-4">
          <Segmented<'full' | 'reduced'>
            label="Motion" desc="Reduce animations and transitions"
            value={dPrefs.motion}
            options={[{ v: 'full', l: 'Full' }, { v: 'reduced', l: 'Reduced' }]}
            onChange={(v) => editPrefs({ motion: v })} />
          <Segmented<'comfortable' | 'compact'>
            label="Density" desc="Tighten spacing to fit more on screen"
            value={dPrefs.density}
            options={[{ v: 'comfortable', l: 'Comfortable' }, { v: 'compact', l: 'Compact' }]}
            onChange={(v) => editPrefs({ density: v })} />
        </div>
      </div>

      <div className="px-4 pb-3 sm:px-5 sm:pb-4">
        <p className="text-[10px] text-ink-700">
          Appearance applies when you click <b className="text-ink-500">Save Changes</b> (top right). Choices are saved to this browser and sync across open dashboard tabs; the marketing site keeps its signature Plasma Noir look.
        </p>
      </div>
    </motion.div>
  )
}

/* ── Section wrapper ─────────────────────────────────────────────── */
function Section({ title, icon: Icon, color, children }: {
  title: string; icon: React.ComponentType<any>; color: string; children: React.ReactNode
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
      <nav aria-label="Settings sections" className="sm:hidden overflow-x-auto flex gap-1 pb-2 -mx-4 px-4 scrollbar-none">
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
        aria-label="Settings sections"
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
  create: tk('safe'), update: tk('amber'), delete: tk('threat'),
  revoke: tk('threat'), toggle: tk('violet'), run: tk('magenta'),
}

function actionTint(action: string): string {
  const verb = action.split('.')[1] ?? action
  return ACTION_COLOR[verb] ?? tk('violet')
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
      // Surface the API's specific reason (wrong current password, too common,
      // too short, …); fall back only for opaque network/HTTP failures.
      const m = err instanceof Error ? err.message : ''
      setMessage(m && !m.startsWith('HTTP')
        ? m
        : 'Could not update the password. Is the dashboard API running?')
    }
  }

  return (
    <Section title="Change Password" icon={Key} color={tk('amber')}>
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

/* ── Active sessions (per-device): list & individually revoke ─────── */
function describeAgent(ua: string | null): string {
  if (!ua) return 'Unknown device'
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS'
    : /Android/.test(ua) ? 'Android' : /iPhone|iPad|iOS/.test(ua) ? 'iOS'
    : /Linux/.test(ua) ? 'Linux' : ''
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera'
    : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari' : 'Browser'
  return os ? `${browser} on ${os}` : browser
}

function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function MySessions() {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null)
  const [error, setError] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)

  const load = () => fetchSessions().then(setSessions).catch(() => setError(true))
  useEffect(() => { load() }, [])

  async function revoke(id: string) {
    setBusy(id)
    try { await revokeSession(id); setSessions((p) => p?.filter((s) => s.id !== id) ?? p) }
    catch { /* leave the row; a reload reflects truth */ }
    finally { setBusy(null) }
  }

  async function revokeOthers() {
    const others = (sessions ?? []).filter((s) => !s.current)
    if (!others.length || !window.confirm(`Sign out ${others.length} other device${others.length > 1 ? 's' : ''}? This device stays signed in.`)) return
    setBusy('others')
    try {
      await Promise.all(others.map((s) => revokeSession(s.id).catch(() => {})))
      setSessions((p) => p?.filter((s) => s.current) ?? p)
    } finally { setBusy(null) }
  }

  const others = (sessions ?? []).filter((s) => !s.current)

  return (
    <Section title="Active Sessions" icon={Monitor} color="#3EE6C4">
      <div className="flex items-center justify-between gap-2 mb-4 flex-wrap">
        <p className="text-[11px] text-ink-500">
          Every device signed in to your account. Sign out any you don&apos;t recognise - it takes effect on that device&apos;s next request.
        </p>
        {others.length > 0 && (
          <button onClick={revokeOthers} disabled={busy === 'others'}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-threat hover:border-threat/30 disabled:opacity-50 transition-colors shrink-0">
            <LogOut className="w-3 h-3" /> Sign out other devices
          </button>
        )}
      </div>
      {error && <p className="text-[11px] text-threat">Could not load sessions. Is the dashboard API running?</p>}
      {sessions && sessions.length === 0 && <p className="text-[11px] text-ink-600">No active sessions.</p>}
      <div className="space-y-2">
        {sessions?.map((s) => (
          <div key={s.id} className="flex items-center gap-3 p-3 rounded-xl border border-white/8 bg-surface-2">
            <Monitor className="w-4 h-4 text-ink-500 shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-medium text-white truncate">{describeAgent(s.userAgent)}</span>
                {s.current && <span className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold text-safe bg-safe/12">this device</span>}
              </div>
              <p className="text-[10px] text-ink-600 truncate">
                {s.ip || 'unknown IP'} · started {new Date(s.createdAt).toLocaleDateString()} · active {timeAgo(s.lastSeen)}
              </p>
            </div>
            {!s.current && (
              <button onClick={() => revoke(s.id)} disabled={busy === s.id}
                className="px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-surface-3 border border-white/10 text-ink-400 hover:text-threat hover:border-threat/30 disabled:opacity-50 transition-colors shrink-0">
                {busy === s.id ? '…' : 'Sign out'}
              </button>
            )}
          </div>
        ))}
      </div>
    </Section>
  )
}

function AuditTrail() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  const [error, setError] = useState(false)
  const [retentionMsg, setRetentionMsg] = useState<string | null>(null)

  useEffect(() => {
    fetchAuditLog(25)
      .then(setEntries)
      .catch(() => setError(true))
  }, [])

  return (
    <Section title="Audit Trail" icon={ScrollText} color={tk('violet')}>
      <div className="flex items-center justify-between gap-2 mb-4 flex-wrap">
        <p className="text-[11px] text-ink-500">
          Every state change - alerts, cases, rules, users, keys, feeds - captured with actor and target.
        </p>
        <div className="flex items-center gap-2 shrink-0">
          <a href={`${(typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) || 'http://localhost:8002'}/config/audit-export`}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
            <Copy className="w-3 h-3" /> Export CSV
          </a>
          <button onClick={() => { enforceRetention().then((r) => { const n = Object.values(r.purged).reduce((a, b) => a + b, 0); setRetentionMsg(`Purged ${n} records older than ${r.retentionDays} days.${r.archiveDir ? ` Archived to cold storage first (${r.archiveDir}).` : ''}`) }).catch(() => {}) }}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
            Enforce retention
          </button>
        </div>
      </div>
      {retentionMsg && <p className="text-[11px] text-safe mb-3">{retentionMsg}</p>}
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

/* ── Live engine control ─────────────────────────────────────────── */
function WorkspaceCard() {
  const [org, setOrg] = useState<Org | null>(null)
  useEffect(() => { fetchCurrentOrg().then(setOrg).catch(() => {}) }, [])
  return (
    <Section title="Workspace" icon={Globe} color={tk('safe')}>
      {!org ? (
        <p className="text-xs text-ink-600">Loading workspace…</p>
      ) : (
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex-1 min-w-[180px]">
            <p className="text-sm font-semibold text-white">{org.name}</p>
            <p className="text-[11px] text-ink-500 mt-0.5 font-mono">
              {org.slug} · {org.plan} plan · {org.users ?? 0} member{org.users === 1 ? '' : 's'}
            </p>
          </div>
          <div className="text-right">
            <span className={cn('text-[10px] px-2 py-1 rounded-full border font-medium',
              org.isolationEnforced
                ? 'text-safe border-safe/30 bg-safe/10'
                : 'text-ink-400 border-white/10 bg-white/5')}>
              {org.isolationEnforced ? 'Tenant isolation: enforced' : 'Single-tenant'}
            </span>
            <p className="text-[10px] text-ink-700 mt-1">Per-tenant data isolation rolls out next</p>
          </div>
        </div>
      )}
    </Section>
  )
}

function StorageCard() {
  const [db, setDb] = useState<DatabaseInfo | null>(null)
  useEffect(() => { fetchDatabaseInfo().then(setDb).catch(() => {}) }, [])
  if (!db) return null
  return (
    <Section title="Storage" icon={Database} color={tk('safe')}>
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex-1 min-w-[180px]">
          <p className="text-sm font-semibold text-white capitalize">{db.backend}
            <span className={cn('ml-2 text-[9px] px-1.5 py-0.5 rounded-full uppercase',
              db.backend === 'postgres' ? 'bg-safe/12 text-safe' : 'bg-white/8 text-ink-400')}>
              {db.backend === 'postgres' ? (db.configured ? 'configured' : 'selected') : 'single-node'}
            </span>
          </p>
          <p className="text-[10px] text-ink-500 mt-0.5">{db.note}</p>
        </div>
        <span className="text-[10px] text-ink-600">
          psycopg driver: <b className={db.driverReady ? 'text-safe' : 'text-ink-400'}>{db.driverReady ? 'ready' : 'not installed'}</b>
        </span>
      </div>
    </Section>
  )
}

function LicenseCard() {
  const [lic, setLic] = useState<LicenseStatus | null>(null)
  const [key, setKey] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const load = () => fetchLicense().then(setLic).catch(() => {})
  useEffect(() => { load() }, [])

  function activate() {
    const k = key.trim()
    if (!k) return
    activateLicense(k)
      .then((r) => { setMsg(`Activated: ${r.plan} plan`); setKey(''); load() })
      .catch((e) => setMsg(e?.message || 'Invalid license key'))
  }

  const bar = (used: number, limit: number | null) => limit === null ? 0 : Math.min(100, (used / limit) * 100)
  return (
    <Section title="License" icon={Key} color={tk('amber')}>
      {!lic ? <p className="text-xs text-ink-600">Loading license…</p> : (
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex-1 min-w-[160px]">
              <p className="text-sm font-semibold text-white">{lic.label} plan
                {lic.builtin && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded-full bg-white/8 text-ink-400 uppercase">built-in</span>}
              </p>
              <p className="text-[10px] text-ink-500 mt-0.5">
                {lic.org ? `Licensed to ${lic.org}` : 'No activated key'}
                {lic.expires ? ` · expires ${lic.expires.slice(0, 10)}` : ''}
              </p>
              {lic.warning && <p className="text-[10px] text-threat mt-0.5">{lic.warning}</p>}
            </div>
            <div className="grid grid-cols-2 gap-3 min-w-[220px]">
              {([['Seats', lic.usage.seats, lic.limits.seats],
                 ['Connectors', lic.usage.connectors, lic.limits.connectors]] as const).map(([label, used, limit]) => (
                <div key={label}>
                  <div className="flex items-center justify-between text-[10px] mb-1">
                    <span className="text-ink-600">{label}</span>
                    <span className="font-mono text-ink-300">{used}{limit !== null ? ` / ${limit}` : ' · unlimited'}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
                    <div className={cn('h-full rounded-full', limit !== null && used >= limit ? 'bg-threat' : 'bg-amber')}
                      style={{ width: `${limit === null ? 100 : bar(used, limit)}%`, opacity: limit === null ? 0.25 : 1 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input value={key} onChange={(e) => setKey(e.target.value)}
              placeholder="Paste a license key (TOL-…)"
              className="flex-1 px-3 py-2 rounded-lg bg-surface-2 border border-white/10 text-[11px] font-mono text-ink-200 focus:outline-none focus:border-amber/40 placeholder-ink-700" />
            <button onClick={activate} disabled={!key.trim()}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-amber/15 border border-amber/30 text-amber hover:bg-amber/25 transition-colors disabled:opacity-40">
              Activate
            </button>
          </div>
          {msg && <p className="text-[10px] text-ink-400">{msg}</p>}
        </div>
      )}
    </Section>
  )
}

/* ── Billing (Stripe self-serve; honest "not configured" fallback) ── */
function BillingCard() {
  const [bs, setBs] = useState<BillingStatus | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  useEffect(() => {
    fetchBillingStatus().then(setBs).catch(() => {})
    // surface the post-Stripe redirect outcome (?billing=success|cancel|portal)
    const p = new URLSearchParams(window.location.search).get('billing')
    if (p === 'success') setMsg('Subscription active - your plan is now updated.')
    else if (p === 'cancel') setMsg('Checkout cancelled - no changes were made.')
  }, [])

  function upgrade(plan: string) {
    setBusy(plan); setMsg(null)
    startCheckout(plan)
      .then((r) => { window.location.href = r.url })
      .catch(() => { setMsg('Could not start checkout. Is billing configured on the server?'); setBusy(null) })
  }
  function manage() {
    setBusy('portal'); setMsg(null)
    openBillingPortal()
      .then((r) => { window.location.href = r.url })
      .catch(() => { setMsg('Could not open the billing portal.'); setBusy(null) })
  }

  if (!bs) return null

  // Honest degrade: billing not enabled on this deployment.
  if (!bs.configured) {
    return (
      <Section title="Billing" icon={CreditCard} color={tk('violet')}>
        <p className="text-xs text-ink-400 leading-relaxed">
          Self-serve billing (Stripe) is not configured on this deployment. Activate a
          <b className="text-ink-200"> license key</b> above to change plan, or contact sales for
          Enterprise. Operators can enable self-serve checkout by setting <code className="font-mono text-ink-300">STRIPE_SECRET_KEY</code> and the plan price IDs.
        </p>
      </Section>
    )
  }

  const others = bs.plans.filter((p) => p.plan !== bs.currentPlan)
  return (
    <Section title="Billing" icon={CreditCard} color={tk('violet')}>
      <div className="flex items-center gap-3 flex-wrap mb-4">
        <div className="flex-1 min-w-[160px]">
          <p className="text-sm font-semibold text-white capitalize">
            {bs.currentPlan ?? 'free'} plan
            {bs.currentPlanBuiltin && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded-full bg-white/8 text-ink-400 uppercase">built-in</span>}
          </p>
          <p className="text-[10px] text-ink-500 mt-0.5">
            {bs.hasSubscription ? 'Billed monthly via Stripe' : 'No active subscription'}
          </p>
        </div>
        {bs.portalAvailable && (
          <button onClick={manage} disabled={!!busy}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-200 hover:text-white hover:border-white/20 transition-colors disabled:opacity-50">
            {busy === 'portal' ? 'Opening…' : <>Manage billing <ExternalLink className="w-3 h-3" /></>}
          </button>
        )}
      </div>
      {others.length > 0 && (
        <div className="grid sm:grid-cols-2 gap-2.5">
          {others.map((p) => (
            <button key={p.plan} onClick={() => upgrade(p.plan)} disabled={!!busy}
              className="text-left p-3 rounded-xl border border-violet/25 bg-violet/5 hover:bg-violet/10 hover:border-violet/40 transition-colors disabled:opacity-50">
              <p className="text-xs font-semibold text-white capitalize">{p.label}</p>
              <p className="text-[10px] text-ink-500 mt-0.5">
                {p.seats === null ? 'Unlimited seats' : `${p.seats} seats`} ·{' '}
                {p.connectors === null ? 'unlimited connectors' : `${p.connectors} connectors`}
              </p>
              <p className="text-[11px] text-violet font-medium mt-1.5">{busy === p.plan ? 'Redirecting…' : 'Switch to this plan →'}</p>
            </button>
          ))}
        </div>
      )}
      {msg && <p className="text-[11px] text-ink-400 mt-3" role="status">{msg}</p>}
      <p className="text-[10px] text-ink-700 mt-3">
        Checkout and plan management are handled securely by Stripe; a completed subscription mints
        this workspace&apos;s license key automatically.
      </p>
    </Section>
  )
}

function LiveEngineCard() {
  const [status, setStatus] = useState<EngineStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)

  const load = () => fetchEngineStatus().then(setStatus).catch(() => setStatus(null))
  useEffect(() => {
    load()
    const t = setInterval(load, 8000)
    return () => clearInterval(t)
  }, [])

  function toggle() {
    if (!status) return
    setBusy(true)
    controlEngine({ enabled: !status.enabled })
      .then(() => load())
      .finally(() => setBusy(false))
  }

  function generate() {
    setBusy(true)
    setMsg(null)
    controlEngine({ generate: 8 })
      .then((r) => {
        const g = r.generated
        setMsg(g ? `Generated ${g.alerts} alerts, ${g.iocs} IOCs, ${g.darkWeb} dark-web findings, ${g.casesEscalated} cases.` : 'Done.')
        load()
      })
      .catch(() => setMsg('Could not generate - is the dashboard API running in live mode?'))
      .finally(() => { setBusy(false); setTimeout(() => setMsg(null), 8000) })
  }

  if (status && status.mode !== 'live') {
    return (
      <Section title="Live Processing Engine" icon={Zap} color={tk('magenta')}>
        <p className="text-xs text-ink-400">
          Running in <b className="text-ink-200">demo mode</b> - showing seeded sample data. To run the
          live engine (continuous telemetry → real SIEM alerts, CTI indicators, SOAR cases & dark-web
          findings), start the API with <code className="font-mono text-ink-300">DASHBOARD_DATA_MODE=live</code>.
        </p>
      </Section>
    )
  }

  return (
    <Section title="Live Processing Engine" icon={Zap} color={tk('magenta')}>
      <div className="flex items-center gap-3 mb-4">
        <span className={cn('flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-full border font-semibold',
          status?.running ? 'border-safe/25 bg-safe/10 text-safe' : 'border-amber/25 bg-amber/10 text-amber')}>
          <span className={cn('w-1.5 h-1.5 rounded-full', status?.running ? 'bg-safe animate-pulse' : 'bg-amber')} />
          {status?.running ? 'Running' : 'Paused'}
        </span>
        {status && <span className="text-[11px] text-ink-500">telemetry every {status.tickSeconds}s</span>}
      </div>
      <p className="text-[11px] text-ink-500 mb-4 leading-relaxed">
        The engine continuously generates environment telemetry and runs it through the real
        detect → correlate → escalate pipeline. It has produced{' '}
        <b className="text-ink-200">{status?.totalAlerts ?? 0}</b> SIEM alerts and{' '}
        <b className="text-ink-200">{status?.darkWebFindings ?? 0}</b> dark-web findings so far.
      </p>
      {msg && <p className="text-[11px] text-safe mb-3">{msg}</p>}
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={toggle} disabled={busy || !status}
          className="px-3 py-2 rounded-xl text-xs font-semibold bg-surface-2 border border-white/10 text-ink-200 hover:text-white hover:border-white/20 transition-colors disabled:opacity-50">
          {status?.enabled ? 'Pause engine' : 'Resume engine'}
        </button>
        <button onClick={generate} disabled={busy}
          className="px-3 py-2 rounded-xl text-xs font-semibold bg-plasma text-white hover:shadow-magenta-sm transition-all disabled:opacity-50">
          {busy ? 'Generating…' : 'Generate burst now'}
        </button>
      </div>
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
    <Section title="Background Jobs" icon={Zap} color={tk('amber')}>
      <p className="text-[11px] text-ink-500 mb-4">
        Heavy operations - Threat-API IOC syncs, log analyses, fleet risk recomputes -
        are recorded here with their outcome.
      </p>
      {error && (
        <p className="text-xs text-ink-600 py-6 text-center">Job history unavailable. Start the dashboard API to see runs.</p>
      )}
      {!error && jobs !== null && jobs.length === 0 && (
        <p className="text-xs text-ink-600 py-6 text-center">No background jobs recorded yet - trigger a sync, analysis or recompute.</p>
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
  // Bumped on every Save - the Appearance card commits its draft on the change.
  const [saveTick, setSaveTick] = useState(0)
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
    setSaveTick((t) => t + 1)                  // commit pending Appearance draft
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
      </div>

      {/* Always-reachable Save — pinned top-right so it stays clickable from
          any scroll position (no scrolling back up to the header). */}
      <FloatingSave onSave={save} saved={saved} />

      <div className="flex flex-col sm:flex-row gap-3 sm:gap-6">
        {/* Nav: horizontal strip on mobile, vertical rail on sm+ */}
        <SettingsNav tab={tab} setTab={setTab} />

        {/* Content */}
        <div className="flex-1 min-w-0 space-y-5">
          {tab === 'general' && (
            <>
              {/* ── Workspace (multi-tenancy) ───────────────────────── */}
              <WorkspaceCard />

              {/* ── License & plan limits ───────────────────────────── */}
              <LicenseCard />

              {/* ── Billing (Stripe self-serve) ─────────────────────── */}
              <BillingCard />

              {/* ── Storage backend (Postgres staged) ───────────────── */}
              <StorageCard />

              {/* ── Live Processing Engine ──────────────────────────── */}
              <LiveEngineCard />

              {/* ── Experience Mode ─────────────────────────────────── */}
              <ExperienceModeCard />

              {/* ── Dashboard Theme ─────────────────────────────────── */}
              <ThemeCard saveTick={saveTick} />

              <Section title="Platform Settings" icon={Settings} color={tk('violet')}>
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

              <Section title="Display Preferences" icon={Eye} color={tk('teal')}>
                <p className="text-[11px] text-ink-500 mb-3">
                  Theme, accent colour, UI scale, motion and density now live in <b className="text-ink-300">Appearance</b> above.
                </p>
                <div className="space-y-0">
                  <Toggle label="Cursor Particle Effect" description="Liquid particle trail that follows your mouse / finger" value={cursorFx} onChange={setCursorFx} />
                </div>
              </Section>
            </>
          )}

          {tab === 'api' && (
            <Section title="API Keys" icon={Key} color={tk('amber')}>
              <LiveApiKeys />
            </Section>
          )}

          {tab === 'sources' && (
            <Section title="Threat Feed Sources" icon={Globe} color={tk('magenta')}>
              <div className="mb-4 text-xs text-ink-400">Enable or disable threat intelligence feeds. Changes persist immediately and take effect on the next scheduled sync.</div>
              <LiveFeedSources />
            </Section>
          )}

          {tab === 'alerts' && (
            <Section title="Notification Settings" icon={Bell} color={tk('threat')}>
              <MySlackRouting />
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
            <Section title="Security Settings" icon={Shield} color={tk('safe')}>
              <div className="space-y-4 mb-5">
                <div>
                  <label className="block text-xs font-medium text-ink-300 mb-1.5">Authentication Method</label>
                  <select
                    value={settings.auth_method ?? 'jwt'}
                    onChange={(e) => setSetting('auth_method')(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                    <option value="jwt">Email + Password (JWT, default)</option>
                    {/* SSO (OIDC/SAML) is on the roadmap (Tier 2) - options appear here when implemented */}
                  </select>
                </div>
                <Field label="Idle Timeout (minutes)" type="number" value={settings.session_timeout_minutes ?? '720'} onChange={setSetting('session_timeout_minutes')} hint="Sign out sessions left inactive this long. 0 disables it; the token's 12h hard expiry still applies." />
                <Field label="Allowed IP Ranges" value={settings.allowed_ip_ranges ?? '0.0.0.0/0'} onChange={setSetting('allowed_ip_ranges')} hint="Comma-separated CIDR blocks. Use 0.0.0.0/0 to allow all." />
              </div>
              <MyMfaPanel />
              <p className="text-[10px] text-ink-600 mb-2">Saved with the Save Changes button above.</p>
              <Toggle label="Audit Logging"                description="Log all API calls and user actions"           value={boolSetting('audit_logging', true)}     onChange={setBoolSetting('audit_logging')} />
              <Toggle label="Rate Limiting"                description="Throttle repeated failed logins per client"   value={boolSetting('rate_limiting', true)}     onChange={setBoolSetting('rate_limiting')} />
              <Toggle label="Automated Threat Blocking"    description="Auto-block IPs with confidence score > 90%"  value={boolSetting('auto_threat_blocking', false)} onChange={setBoolSetting('auto_threat_blocking')} />
            </Section>
          )}

          {tab === 'security' && <ChangePassword />}

          {tab === 'security' && <MySessions />}

          {tab === 'security' && <BackgroundJobs />}

          {tab === 'security' && <AuditTrail />}

          {tab === 'integrations' && (
            <Section title="Integrations" icon={Plug} color={tk('amber')}>
              <LiveIntegrations />
            </Section>
          )}
        </div>
      </div>
    </div>
  )
}
