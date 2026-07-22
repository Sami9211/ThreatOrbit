'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  User as UserIcon, Shield, KeyRound, Monitor, Bell, Sliders, Key,
  LogOut, Trash2, Copy, Check, ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import { useAuth } from '@/lib/auth-context'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { Toggle as Switch } from '@/components/dashboard/Toggle'
import {
  authChangePassword,
  fetchMfaStatus, mfaEnroll, mfaVerify, mfaDisable, mfaRegenerateRecoveryCodes,
  fetchSessions, revokeSession, authRevokeAllSessions, type SessionInfo,
  fetchApiKeys, createApiKey, revokeApiKey, type ApiKey,
  fetchMySlackRouting, setMySlackRouting, testMySlackRouting,
} from '@/lib/api'

/* A settings section shell so every card reads the same. */
function Section({ icon: Icon, title, description, children }: {
  icon: React.ComponentType<{ className?: string }>
  title: string; description: string; children: React.ReactNode
}) {
  return (
    <motion.section variants={fadeInUp} initial="hidden" animate="show"
      className="rounded-2xl border border-white/8 bg-surface/60 p-5 sm:p-6">
      <div className="flex items-start gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center shrink-0">
          <Icon className="w-4 h-4 text-ink-300" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          <p className="text-[11px] text-ink-500 mt-0.5">{description}</p>
        </div>
      </div>
      {children}
    </motion.section>
  )
}

/* -- Profile summary (read-only; identity is directory-managed) ---- */
function ProfileCard() {
  const { user } = useAuth()
  if (!user) return null
  const initial = (user.name?.[0] ?? user.email?.[0] ?? 'U').toUpperCase()
  const since = user.createdAt ? new Date(user.createdAt).toLocaleDateString() : '—'
  return (
    <div className="flex items-center gap-4">
      <div className="w-14 h-14 rounded-2xl bg-plasma flex items-center justify-center shrink-0">
        <span className="text-xl font-bold text-white">{initial}</span>
      </div>
      <div className="min-w-0">
        <p className="text-base font-semibold text-white truncate">{user.name}</p>
        <p className="text-xs text-ink-400 truncate">{user.email}</p>
        <div className="flex flex-wrap items-center gap-2 mt-1.5">
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-plasma/15 text-plasma capitalize font-semibold">{user.role}</span>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/5 text-ink-400 capitalize">{user.status}</span>
          <span className="text-[10px] text-ink-600">Member since {since}</span>
        </div>
      </div>
    </div>
  )
}

/* -- Change password ---------------------------------------------- */
function PasswordPanel() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  // Client-side complexity hint (backend password_policy is authoritative).
  const strong = next.length >= 12 && /[a-z]/.test(next) && /[A-Z]/.test(next) && /\d/.test(next)
  const canSubmit = current.length > 0 && strong && next === confirm && !busy

  async function submit() {
    if (!canSubmit) return
    setBusy(true); setMsg(null)
    try {
      await authChangePassword(current, next)
      setCurrent(''); setNext(''); setConfirm('')
      setMsg({ ok: true, text: 'Password changed. Use it the next time you sign in.' })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Could not change password.' })
    } finally { setBusy(false) }
  }

  const input = 'w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-hidden focus:border-plasma/40 placeholder-ink-600'
  return (
    <div className="space-y-3 max-w-md">
      <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} placeholder="Current password" className={input} autoComplete="current-password" />
      <input type="password" value={next} onChange={(e) => setNext(e.target.value)} placeholder="New password" className={input} autoComplete="new-password" />
      <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Confirm new password" className={input} autoComplete="new-password" />
      <ul className="text-[10px] text-ink-600 space-y-0.5">
        <li className={cn(next.length >= 12 && 'text-safe')}>· at least 12 characters</li>
        <li className={cn(/[a-z]/.test(next) && /[A-Z]/.test(next) && 'text-safe')}>· upper &amp; lower case letters</li>
        <li className={cn(/\d/.test(next) && 'text-safe')}>· at least one number</li>
        {confirm.length > 0 && <li className={cn(next === confirm ? 'text-safe' : 'text-threat')}>· passwords match</li>}
      </ul>
      <button onClick={submit} disabled={!canSubmit}
        className="px-4 py-2 rounded-lg text-xs font-medium bg-plasma/15 border border-plasma/30 text-plasma hover:bg-plasma/20 disabled:opacity-40 transition-colors">
        Change password
      </button>
      {msg && <p className={cn('text-[11px]', msg.ok ? 'text-safe' : 'text-threat')} role="status">{msg.text}</p>}
    </div>
  )
}

/* -- Two-factor authentication (real TOTP, per-user) -------------- */
function MfaPanel() {
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
    mfaEnroll().then((e) => { setEnrolment(e); load() })
      .catch((e) => setMsg(e instanceof Error ? e.message : 'Could not start enrolment.'))
      .finally(() => setBusy(false))
  }
  function verify() {
    if (code.length < 6 || busy) return
    setBusy(true); setMsg(null)
    mfaVerify(code)
      .then((r) => { setEnrolment(null); setCode(''); setRecoveryCodes(r.recoveryCodes ?? null); setMsg('Two-factor authentication is ON — your next login will ask for a code.'); load() })
      .catch(() => setMsg('That code did not verify — check your authenticator and try again.'))
      .finally(() => setBusy(false))
  }
  function regenerate() {
    if (code.length < 6 || busy) return
    setBusy(true); setMsg(null)
    mfaRegenerateRecoveryCodes(code)
      .then((r) => { setCode(''); setRecoveryCodes(r.recoveryCodes); setMsg('New recovery codes generated — your old ones no longer work.'); load() })
      .catch(() => setMsg('That code did not verify — codes unchanged.'))
      .finally(() => setBusy(false))
  }
  function disable() {
    if (code.length < 6 || busy) return
    setBusy(true); setMsg(null)
    mfaDisable(code)
      .then(() => { setCode(''); setMsg('Two-factor authentication is OFF.'); load() })
      .catch(() => setMsg('That code did not verify — MFA stays on.'))
      .finally(() => setBusy(false))
  }

  const codeInput = 'w-32 px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs font-mono tracking-[0.25em] text-ink-100 focus:outline-hidden focus:border-safe/40 placeholder-ink-600'
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        {status && (
          <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold',
            status.enabled ? 'text-safe bg-safe/12' : 'text-ink-500 bg-white/6')}>
            {status.enabled ? 'enabled' : status.pending ? 'pending verification' : 'off'}
          </span>
        )}
      </div>
      {!status?.enabled && !enrolment && (
        <button onClick={start} disabled={busy}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-safe/15 border border-safe/30 text-safe hover:bg-safe/20 disabled:opacity-50 transition-colors">
          {status?.pending ? 'Restart enrolment' : 'Set up two-factor authentication'}
        </button>
      )}
      {enrolment && (
        <div className="space-y-2.5">
          <p className="text-[11px] text-ink-300">1. Add this secret to your authenticator app (or paste the otpauth URI into a QR generator):</p>
          <div className="px-3 py-2 rounded-lg bg-surface-2 border border-white/8">
            <p className="text-sm font-mono tracking-wider text-white break-all">{enrolment.secret}</p>
            <p className="text-[10px] font-mono text-ink-600 mt-1 break-all">{enrolment.otpauthUri}</p>
          </div>
          <p className="text-[10px] text-amber">Shown once — stored encrypted server-side and cannot be displayed again.</p>
          <p className="text-[11px] text-ink-300">2. Enter the current code to verify and switch MFA on:</p>
        </div>
      )}
      {(enrolment || status?.enabled) && (
        <div className="flex items-center gap-2 mt-2.5">
          <input value={code} inputMode="numeric" maxLength={6}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} placeholder="6-digit code" className={codeInput} />
          {enrolment ? (
            <button onClick={verify} disabled={busy || code.length < 6}
              className="px-3 py-2 rounded-lg text-xs font-medium bg-safe/15 border border-safe/30 text-safe hover:bg-safe/20 disabled:opacity-50 transition-colors">Verify &amp; enable</button>
          ) : (
            <button onClick={disable} disabled={busy || code.length < 6} title="Requires a valid current code (possession proof)"
              className="px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-threat disabled:opacity-40 transition-colors">Disable MFA</button>
          )}
        </div>
      )}
      {recoveryCodes && (
        <div className="mt-3 p-3 rounded-lg border border-amber/30 bg-amber/8">
          <p className="text-[11px] font-semibold text-amber mb-1">Save your recovery codes</p>
          <p className="text-[10px] text-ink-400 mb-2">Each works once if you lose your authenticator. Stored hashed — can&apos;t be shown again.</p>
          <div className="grid grid-cols-2 gap-1.5 mb-2">
            {recoveryCodes.map((c) => (
              <code key={c} className="text-[11px] font-mono text-ink-100 bg-surface-2 border border-white/8 rounded-sm px-2 py-1 text-center tracking-wider">{c}</code>
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

/* -- Active sessions ---------------------------------------------- */
function SessionsPanel() {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null)
  const [error, setError] = useState(false)
  const load = () => fetchSessions().then(setSessions).catch(() => setError(true))
  useEffect(() => { load() }, [])

  async function revoke(id: string) {
    try { await revokeSession(id); setSessions((p) => p?.filter((s) => s.id !== id) ?? p) } catch { /* ignore */ }
  }
  async function revokeOthers() {
    const others = (sessions ?? []).filter((s) => !s.current)
    await Promise.all(others.map((s) => revokeSession(s.id).catch(() => {})))
    try { await authRevokeAllSessions() } catch { /* best effort */ }
    load()
  }

  if (error) return <p className="text-[11px] text-ink-500">Sessions are unavailable right now.</p>
  if (!sessions) return <p className="text-[11px] text-ink-600">Loading sessions…</p>
  return (
    <div className="space-y-2">
      {sessions.map((s) => (
        <div key={s.id} className="flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg bg-surface-2 border border-white/6">
          <div className="min-w-0">
            <p className="text-xs text-ink-200 truncate">
              {s.userAgent ?? 'Unknown device'}
              {s.current && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded-full bg-safe/12 text-safe font-semibold">this device</span>}
            </p>
            <p className="text-[10px] text-ink-600 mt-0.5">{s.ip ?? 'no ip'} · last seen {s.lastSeen ? new Date(s.lastSeen).toLocaleString() : '—'}</p>
          </div>
          {!s.current && (
            <button onClick={() => revoke(s.id)} title="Revoke this session"
              className="p-1.5 rounded-lg text-ink-500 hover:text-threat hover:bg-threat/10 transition-colors shrink-0">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      ))}
      {sessions.filter((s) => !s.current).length > 0 && (
        <button onClick={revokeOthers}
          className="mt-1 inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-threat transition-colors">
          <LogOut className="w-3.5 h-3.5" /> Sign out all other sessions
        </button>
      )}
    </div>
  )
}

/* -- Personal Slack routing -------------------------------------- */
function NotificationsPanel() {
  const [url, setUrl] = useState('')
  const [minSev, setMinSev] = useState('high')
  const [configured, setConfigured] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    fetchMySlackRouting().then((r) => { setUrl(r.webhookUrl ?? ''); setMinSev(r.minSeverity); setConfigured(r.configured) }).catch(() => {})
  }, [])
  function save() {
    setBusy(true); setMsg(null)
    setMySlackRouting(url.trim() || null, minSev)
      .then((r) => { setConfigured(r.configured); setMsg(r.configured ? 'Saved — notifications will be mirrored to your Slack.' : 'Cleared — no Slack routing for your account.') })
      .catch(() => setMsg('Could not save (is the URL a valid http(s) webhook?).'))
      .finally(() => setBusy(false))
  }
  function testSend() {
    setBusy(true); setMsg(null)
    testMySlackRouting().then((r) => setMsg(r.delivered ? 'Test message delivered ✓' : 'Delivery failed — check the webhook URL.'))
      .catch(() => setMsg('No webhook configured yet — save one first.')).finally(() => setBusy(false))
  }
  return (
    <div className="grid sm:grid-cols-[1fr_130px_auto_auto] gap-2 items-end">
      <div>
        <label className="block text-[10px] font-medium text-ink-400 mb-1">Incoming webhook URL</label>
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.slack.com/services/…"
          className="w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-hidden focus:border-violet/40 placeholder-ink-600" />
      </div>
      <div>
        <label className="block text-[10px] font-medium text-ink-400 mb-1">Minimum severity</label>
        <select value={minSev} onChange={(e) => setMinSev(e.target.value)}
          className="w-full px-2 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-hidden focus:border-violet/40">
          {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <button onClick={save} disabled={busy}
        className="px-3 py-2 rounded-lg text-xs font-medium bg-violet/15 border border-violet/30 text-violet hover:bg-violet/20 disabled:opacity-50 transition-colors">Save</button>
      <button onClick={testSend} disabled={busy || !configured}
        className="px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white disabled:opacity-40 transition-colors">Send test</button>
      {msg && <p className="sm:col-span-4 text-[11px] text-ink-400 mt-1">{msg}</p>}
    </div>
  )
}

/* -- Preferences: experience mode + links ------------------------- */
function PreferencesPanel() {
  const [mode, setMode] = useExperienceMode()
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs font-medium text-ink-200">Power-user mode</p>
          <p className="text-[10px] text-ink-600 mt-0.5">Show full analyst detail everywhere. Off = the simplified Normal view.</p>
        </div>
        <Switch checked={mode === 'power'} onChange={(on) => setMode(on ? 'power' : 'normal')} label="Power-user mode" />
      </div>
      <Link href="/dashboard/config"
        className="flex items-center justify-between gap-4 px-3 py-2.5 rounded-lg bg-surface-2 border border-white/6 hover:border-white/12 transition-colors group">
        <div>
          <p className="text-xs font-medium text-ink-200">Appearance &amp; theme</p>
          <p className="text-[10px] text-ink-600 mt-0.5">Colour theme and text size live in system configuration.</p>
        </div>
        <ChevronRight className="w-4 h-4 text-ink-500 group-hover:text-white transition-colors" />
      </Link>
    </div>
  )
}

/* -- Personal API tokens ----------------------------------------- */
function TokensPanel() {
  const [keys, setKeys] = useState<ApiKey[] | null>(null)
  const [name, setName] = useState('')
  const [scope, setScope] = useState('read')
  const [secret, setSecret] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = () => fetchApiKeys().then((k) => setKeys(k.filter((x) => !x.revoked))).catch(() => setKeys([]))
  useEffect(() => { load() }, [])

  async function create() {
    if (!name.trim() || busy) return
    setBusy(true); setErr(null); setSecret(null)
    try {
      const r = await createApiKey(name.trim(), scope)
      setSecret(r.secret); setName(''); load()
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not create token (needs the manage-keys capability).')
    } finally { setBusy(false) }
  }
  async function revoke(id: string) {
    try { await revokeApiKey(id); setKeys((p) => p?.filter((k) => k.id !== id) ?? p) } catch { /* ignore */ }
  }

  const input = 'px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-hidden focus:border-plasma/40 placeholder-ink-600'
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 items-center">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Token name" className={cn(input, 'flex-1 min-w-[160px]')} />
        <select value={scope} onChange={(e) => setScope(e.target.value)} className={input}>
          <option value="read">read</option>
          <option value="write">write</option>
          <option value="admin">admin</option>
        </select>
        <button onClick={create} disabled={busy || !name.trim()}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-plasma/15 border border-plasma/30 text-plasma hover:bg-plasma/20 disabled:opacity-40 transition-colors">Create token</button>
      </div>
      {err && <p className="text-[11px] text-threat">{err}</p>}
      {secret && (
        <div className="p-3 rounded-lg border border-amber/30 bg-amber/8">
          <p className="text-[11px] font-semibold text-amber mb-1">Copy your token now — it won&apos;t be shown again</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-[11px] font-mono text-ink-100 bg-surface-2 border border-white/8 rounded px-2 py-1.5 break-all">{secret}</code>
            <button onClick={() => { navigator.clipboard?.writeText(secret); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
              className="p-2 rounded-lg bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">
              {copied ? <Check className="w-3.5 h-3.5 text-safe" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      )}
      <div className="space-y-1.5">
        {keys === null && <p className="text-[11px] text-ink-600">Loading tokens…</p>}
        {keys?.length === 0 && <p className="text-[11px] text-ink-600">No active tokens.</p>}
        {keys?.map((k) => (
          <div key={k.id} className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-surface-2 border border-white/6">
            <div className="min-w-0">
              <p className="text-xs text-ink-200 truncate">{k.name} <span className="text-ink-600 font-mono">{k.prefix}…</span></p>
              <p className="text-[10px] text-ink-600">{k.scope} · created {k.createdAt ? new Date(k.createdAt).toLocaleDateString() : '—'}</p>
            </div>
            <button onClick={() => revoke(k.id)} title="Revoke token"
              className="p-1.5 rounded-lg text-ink-500 hover:text-threat hover:bg-threat/10 transition-colors shrink-0">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function AccountSettingsPage() {
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-6 space-y-4">
      <div className="mb-2">
        <h1 className="text-lg font-bold text-white">Account settings</h1>
        <p className="text-xs text-ink-500 mt-0.5">Manage your personal profile, security, sessions and preferences.</p>
      </div>

      <Section icon={UserIcon} title="Profile" description="Your identity in this workspace.">
        <ProfileCard />
      </Section>
      <Section icon={KeyRound} title="Password" description="Change the password you sign in with.">
        <PasswordPanel />
      </Section>
      <Section icon={Shield} title="Two-factor authentication" description="Require a 6-digit code from your authenticator app at sign-in.">
        <MfaPanel />
      </Section>
      <Section icon={Monitor} title="Active sessions" description="Devices currently signed in to your account. Revoke any you don't recognise.">
        <SessionsPanel />
      </Section>
      <Section icon={Bell} title="Notifications" description="Mirror your platform notifications to a personal Slack webhook.">
        <NotificationsPanel />
      </Section>
      <Section icon={Sliders} title="Preferences" description="How the dashboard behaves for you.">
        <PreferencesPanel />
      </Section>
      <Section icon={Key} title="API tokens" description="Personal API tokens for programmatic access. Copy the secret when created — it isn't shown again.">
        <TokensPanel />
      </Section>
    </div>
  )
}
