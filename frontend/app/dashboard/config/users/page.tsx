'use client'
import { tk } from '@/lib/colors'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchUsers, patchUser, createUser, deleteUser, resetUserPassword, fetchAuditLog, type User as ApiUser, type UserRole, type AuditEntry } from '@/lib/api'

/* Display role ↔ backend role mapping. The UI exposes richer display names
 * (Senior Analyst, Auditor) that collapse onto the backend's four roles. */
const ROLE_TO_API: Record<string, UserRole> = {
  'Admin': 'admin', 'SOC Manager': 'manager', 'Senior Analyst': 'analyst',
  'Analyst': 'analyst', 'Read-Only': 'viewer', 'Auditor': 'viewer',
}
import {
  Users, Plus, X, ShieldCheck, ShieldOff, Check, Minus, Mail,
  Clock, Activity, KeyRound, Ban, ChevronDown, Trash2, Loader2,
  RotateCcw, Copy,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'

/* -- Types --------------------------------------------------------- */
type RoleName = 'Admin' | 'SOC Manager' | 'Senior Analyst' | 'Analyst' | 'Read-Only' | 'Auditor'
type UserStatus = 'active' | 'suspended' | 'invited'

interface TeamUser {
  id: string
  name: string
  email: string
  role: RoleName
  lastActive: string
  mfa: boolean
  status: UserStatus
}

const PERMISSIONS = [
  'View Alerts',
  'Manage Playbooks',
  'Configure Sources',
  'Manage Users',
  'Export Data',
  'Run Response Actions',
] as const

type Permission = (typeof PERMISSIONS)[number]

interface Role {
  name: RoleName
  color: string
  description: string
  userCount: number
  permissions: Record<Permission, boolean>
}

/* -- Seed data ----------------------------------------------------- */
const USERS: TeamUser[] = [
  { id: 'u01', name: 'Priya Nair',        email: 'priya.nair@acme.io',     role: 'Admin',          lastActive: '2m ago',   mfa: true,  status: 'active'    },
  { id: 'u02', name: 'Marcus Holloway',   email: 'marcus.h@acme.io',       role: 'SOC Manager',    lastActive: '14m ago',  mfa: true,  status: 'active'    },
  { id: 'u03', name: 'Elena Vasquez',     email: 'elena.v@acme.io',        role: 'Senior Analyst', lastActive: '1h ago',   mfa: true,  status: 'active'    },
  { id: 'u04', name: 'Daniel Okafor',     email: 'daniel.o@acme.io',       role: 'Senior Analyst', lastActive: '3h ago',   mfa: false, status: 'active'    },
  { id: 'u05', name: 'Sophie Lindqvist',  email: 'sophie.l@acme.io',       role: 'Analyst',        lastActive: '20m ago',  mfa: true,  status: 'active'    },
  { id: 'u06', name: 'Raj Patel',         email: 'raj.patel@acme.io',      role: 'Analyst',        lastActive: '5h ago',   mfa: true,  status: 'active'    },
  { id: 'u07', name: 'Aisha Bello',       email: 'aisha.b@acme.io',        role: 'Analyst',        lastActive: '2d ago',   mfa: false, status: 'suspended' },
  { id: 'u08', name: 'Thomas Reiner',     email: 'thomas.r@acme.io',       role: 'Read-Only',      lastActive: '1d ago',   mfa: true,  status: 'active'    },
  { id: 'u09', name: 'Mei Tanaka',        email: 'mei.tanaka@acme.io',     role: 'Auditor',        lastActive: '4h ago',   mfa: true,  status: 'active'    },
  { id: 'u10', name: 'Carlos Mendez',     email: 'carlos.m@acme.io',       role: 'Analyst',        lastActive: 'Never',    mfa: false, status: 'invited'   },
]

const ROLES: Role[] = [
  {
    name: 'Admin', color: tk('magenta'), description: 'Full platform control', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': true, 'Configure Sources': true, 'Manage Users': true, 'Export Data': true, 'Run Response Actions': true },
  },
  {
    name: 'SOC Manager', color: tk('violet'), description: 'Team oversight & operations', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': true, 'Configure Sources': true, 'Manage Users': false, 'Export Data': true, 'Run Response Actions': true },
  },
  {
    name: 'Senior Analyst', color: tk('safe'), description: 'Investigate & respond', userCount: 2,
    permissions: { 'View Alerts': true, 'Manage Playbooks': true, 'Configure Sources': false, 'Manage Users': false, 'Export Data': true, 'Run Response Actions': true },
  },
  {
    name: 'Analyst', color: tk('amber'), description: 'Triage & enrichment', userCount: 4,
    permissions: { 'View Alerts': true, 'Manage Playbooks': false, 'Configure Sources': false, 'Manage Users': false, 'Export Data': false, 'Run Response Actions': true },
  },
  {
    name: 'Read-Only', color: '#8A7DA3', description: 'View dashboards only', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': false, 'Configure Sources': false, 'Manage Users': false, 'Export Data': false, 'Run Response Actions': false },
  },
  {
    name: 'Auditor', color: tk('threat'), description: 'Compliance & export', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': false, 'Configure Sources': false, 'Manage Users': false, 'Export Data': true, 'Run Response Actions': false },
  },
]

const ROLE_COLORS: Record<RoleName, string> = {
  Admin: tk('magenta'),
  'SOC Manager': tk('violet'),
  'Senior Analyst': tk('safe'),
  Analyst: tk('amber'),
  'Read-Only': '#8A7DA3',
  Auditor: tk('threat'),
}

const STATUS_CFG: Record<UserStatus, { label: string; cls: string }> = {
  active:    { label: 'Active',    cls: 'text-safe border-safe/20 bg-safe/10'    },
  suspended: { label: 'Suspended', cls: 'text-threat border-threat/20 bg-threat/10' },
  invited:   { label: 'Invited',   cls: 'text-amber border-amber/20 bg-amber/10'  },
}

/* -- Initials avatar ----------------------------------------------- */
function Avatar({ name, color, size = 'md' }: { name: string; color: string; size?: 'sm' | 'md' }) {
  const initials = name.split(' ').map((p) => p[0]).slice(0, 2).join('')
  return (
    <div
      className={cn(
        'rounded-full flex items-center justify-center font-semibold text-white shrink-0',
        size === 'sm' ? 'w-7 h-7 text-[10px]' : 'w-12 h-12 text-sm',
      )}
      style={{ background: `${color}30`, border: `1px solid ${color}50`, color }}
    >
      {initials}
    </div>
  )
}

/* -- Invite user modal --------------------------------------------- */
function InviteModal({ onClose, onInvite }: {
  onClose: () => void
  onInvite: (body: { name: string; email: string; role: RoleName; password: string }) => Promise<void>
}) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<RoleName>('Analyst')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)
  const canSubmit = name.trim() && emailValid && password.length >= 8

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await onInvite({ name: name.trim(), email: email.trim(), role, password })
      onClose()
    } catch (err) {
      setError(err instanceof Error && err.message.includes('already exists')
        ? 'A user with that email already exists.'
        : 'Could not create the user. Check the API is running and you have admin access.')
      setSubmitting(false)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-6"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-2xl border border-white/10 bg-surface p-6"
      >
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-violet/15"><Plus className="w-4 h-4 text-violet" /></div>
            <h2 className="text-sm font-semibold text-white">Invite User</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Full name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Jane Analyst"
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-hidden focus:border-magenta/40 placeholder-ink-600" />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Work email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="jane@company.com"
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-hidden focus:border-magenta/40 placeholder-ink-600" />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Role</label>
            <div className="relative">
              <select value={role} onChange={(e) => setRole(e.target.value as RoleName)}
                className="w-full appearance-none px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-hidden focus:border-magenta/40 pr-9">
                {ROLES.map((r) => <option key={r.name}>{r.name}</option>)}
              </select>
              <ChevronDown className="w-4 h-4 text-ink-500 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Temporary password</label>
            <input type="text" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters"
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 font-mono focus:outline-hidden focus:border-magenta/40 placeholder-ink-600" />
            <p className="text-[10px] text-ink-600 mt-1">Share this with the user - they can change it after first sign-in.</p>
          </div>

          {error && (
            <p className="px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert">{error}</p>
          )}

          <button type="submit" disabled={!canSubmit || submitting}
            className={cn('w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold transition-all',
              canSubmit && !submitting ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Creating…</> : 'Send Invite'}
          </button>
        </form>
      </motion.div>
    </motion.div>
  )
}

/* -- User detail panel --------------------------------------------- */
function timeAgo(iso: string) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function UserPanel({ user, onClose, onRoleChange, onToggleSuspend, onToggleMfa, onDelete }: {
  user: TeamUser
  onClose: () => void
  onRoleChange: (role: RoleName) => void
  onToggleSuspend: () => void
  onToggleMfa: () => void
  onDelete: () => void
}) {
  const color = ROLE_COLORS[user.role]
  const [tempPw, setTempPw] = useState<string | null>(null)
  const [resetting, setResetting] = useState(false)
  const [copied, setCopied] = useState(false)
  async function resetPw() {
    if (resetting) return
    setResetting(true); setTempPw(null)
    try {
      const r = await resetUserPassword(user.id)
      setTempPw(r.temporary_password ?? '')
    } catch { setTempPw('error') }
    finally { setResetting(false) }
  }

  // Real activity for this user from the audit trail (filtered by actor email),
  // not fabricated samples. Empty is honest - the user simply hasn't acted yet.
  const [activity, setActivity] = useState<AuditEntry[] | null>(null)
  useEffect(() => {
    let live = true
    fetchAuditLog(500)
      .then((rows) => { if (live) setActivity(rows.filter((r) => r.actor === user.email).slice(0, 8)) })
      .catch(() => { if (live) setActivity([]) })
    return () => { live = false }
  }, [user.email])

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs"
      onClick={onClose}
    >
      <motion.div
        initial={{ x: 440 }}
        animate={{ x: 0 }}
        exit={{ x: 440 }}
        transition={{ type: 'tween', duration: 0.2 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto"
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/8 sticky top-0 bg-surface z-10">
          <h2 className="text-sm font-semibold text-white">User Details</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-6">
          {/* Profile */}
          <div className="flex items-center gap-4">
            <Avatar name={user.name} color={color} />
            <div className="min-w-0">
              <p className="text-base font-semibold text-white">{user.name}</p>
              <p className="text-xs text-ink-500 flex items-center gap-1"><Mail className="w-3 h-3" /> {user.email}</p>
              <span className={cn('mt-1 inline-block text-[9px] px-1.5 py-0.5 rounded-full border', STATUS_CFG[user.status].cls)}>
                {STATUS_CFG[user.status].label}
              </span>
            </div>
          </div>

          {/* Role assignment */}
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Role Assignment</label>
            <div className="relative">
              <select
                value={user.role}
                onChange={(e) => onRoleChange(e.target.value as RoleName)}
                className="w-full appearance-none px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-hidden focus:border-magenta/40 pr-9"
              >
                {ROLES.map((r) => <option key={r.name}>{r.name}</option>)}
              </select>
              <ChevronDown className="w-4 h-4 text-ink-500 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>
          </div>

          {/* Permission overrides */}
          <div>
            <p className="text-xs font-medium text-ink-300 mb-2">Permission Overrides</p>
            <div className="space-y-1.5">
              {PERMISSIONS.map((perm) => (
                <label key={perm} className="flex items-center justify-between py-1.5 px-2.5 rounded-lg bg-surface-2 border border-white/5">
                  <span className="text-[11px] text-ink-200">{perm}</span>
                  <input type="checkbox" defaultChecked={ROLES.find((r) => r.name === user.role)?.permissions[perm]} className="accent-magenta" />
                </label>
              ))}
            </div>
          </div>

          {/* Activity log - real audit-trail entries for this user */}
          <div>
            <p className="text-xs font-medium text-ink-300 mb-2 flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Activity Log</p>
            <div className="space-y-2">
              {activity === null && <p className="text-[11px] text-ink-600">Loading…</p>}
              {activity !== null && activity.length === 0 && (
                <p className="text-[11px] text-ink-600">No recorded activity for this user yet.</p>
              )}
              {activity?.map((a) => (
                <div key={a.id} className="flex items-start gap-2 text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-violet mt-1 shrink-0" />
                  <div>
                    <p className="text-ink-200">{a.action}{a.target ? ` · ${a.target}` : ''}</p>
                    <p className="text-ink-600 text-[10px]">{timeAgo(a.ts)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-2 pt-2">
            <button
              onClick={onToggleMfa}
              className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-amber/25 text-amber text-sm font-medium hover:bg-amber/5 transition-colors">
              <KeyRound className="w-4 h-4" /> {user.mfa ? 'Reset MFA' : 'Enable MFA'}
            </button>
            <button
              onClick={resetPw} disabled={resetting}
              className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-violet/25 text-violet text-sm font-medium hover:bg-violet/5 disabled:opacity-50 transition-colors">
              {resetting ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />} Reset password
            </button>
            {tempPw !== null && (
              tempPw === 'error' ? (
                <p className="text-[11px] text-threat text-center">Could not reset (admin permission required).</p>
              ) : tempPw ? (
                <div className="p-3 rounded-xl border border-amber/30 bg-amber/8">
                  <p className="text-[11px] font-semibold text-amber mb-1">Temporary password — share it securely, shown once</p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-[12px] font-mono text-ink-100 bg-surface-2 border border-white/8 rounded px-2 py-1.5 break-all">{tempPw}</code>
                    <button onClick={() => { navigator.clipboard?.writeText(tempPw); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
                      className="p-2 rounded-lg bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">
                      {copied ? <Check className="w-4 h-4 text-safe" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                  <p className="text-[10px] text-ink-500 mt-1.5">All their existing sessions were signed out.</p>
                </div>
              ) : (
                <p className="text-[11px] text-safe text-center">Password reset. Existing sessions were signed out.</p>
              )
            )}
            <button
              onClick={onToggleSuspend}
              className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-threat/25 text-threat text-sm font-medium hover:bg-threat/5 transition-colors">
              <Ban className="w-4 h-4" /> {user.status === 'suspended' ? 'Reactivate User' : 'Suspend User'}
            </button>
            <button
              onClick={() => { if (window.confirm(`Remove ${user.name}? This permanently deletes their account.`)) onDelete() }}
              className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-threat/40 bg-threat/10 text-threat text-sm font-medium hover:bg-threat/20 transition-colors">
              <Trash2 className="w-4 h-4" /> Remove User
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}

/* -- Page ---------------------------------------------------------- */
const apiToTeamUser = (u: ApiUser): TeamUser => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: (u.role === 'admin' ? 'Admin' : u.role === 'manager' ? 'SOC Manager' : u.role === 'analyst' ? 'Analyst' : 'Read-Only') as RoleName,
  lastActive: u.lastLogin ?? 'Never',
  mfa: Boolean(u.mfaEnabled),
  status: (u.status === 'active' ? 'active' : u.status === 'invited' ? 'invited' : 'suspended') as UserStatus,
})

export default function UsersRolesPage() {
  const [tab, setTab] = useState<'users' | 'roles'>('users')
  const [selected, setSelected] = useState<string | null>(null)
  // Live roster is authoritative even when empty; USERS is an offline-only
  // fallback shown solely if the API is unreachable.
  const [users, setUsers] = useState<TeamUser[]>([])
  const [showInvite, setShowInvite] = useState(false)

  useEffect(() => {
    fetchUsers()
      .then((data) => setUsers(data.map(apiToTeamUser)))
      .catch(() => setUsers(USERS))
  }, [])

  const selectedUser = users.find((u) => u.id === selected) ?? null

  // Persist a role change: optimistic local update, rollback on API failure.
  function changeRole(id: string, role: RoleName) {
    const prev = users.find((u) => u.id === id)?.role
    setUsers((us) => us.map((u) => u.id === id ? { ...u, role } : u))
    patchUser(id, { role: ROLE_TO_API[role] ?? 'analyst' }).catch(() => {
      if (prev) setUsers((us) => us.map((u) => u.id === id ? { ...u, role: prev } : u))
    })
  }

  // Suspend ↔ reactivate: the backend models this as active/disabled.
  function toggleSuspend(id: string) {
    const u = users.find((x) => x.id === id)
    if (!u) return
    const nextLocal: UserStatus = u.status === 'suspended' ? 'active' : 'suspended'
    const nextApi = nextLocal === 'active' ? 'active' : 'disabled'
    setUsers((us) => us.map((x) => x.id === id ? { ...x, status: nextLocal } : x))
    patchUser(id, { status: nextApi }).catch(() => {
      setUsers((us) => us.map((x) => x.id === id ? { ...x, status: u.status } : x))
    })
  }

  function toggleMfa(id: string) {
    const u = users.find((x) => x.id === id)
    if (!u) return
    setUsers((us) => us.map((x) => x.id === id ? { ...x, mfa: !u.mfa } : x))
    patchUser(id, { mfaEnabled: !u.mfa }).catch(() => {
      setUsers((us) => us.map((x) => x.id === id ? { ...x, mfa: u.mfa } : x))
    })
  }

  function removeUser(id: string) {
    const prev = users
    setUsers((us) => us.filter((x) => x.id !== id))
    setSelected(null)
    deleteUser(id).catch(() => setUsers(prev))
  }

  async function inviteUser(body: { name: string; email: string; role: RoleName; password: string }) {
    const created = await createUser({
      name: body.name, email: body.email,
      role: ROLE_TO_API[body.role] ?? 'analyst', password: body.password,
    })
    setUsers((us) => [...us, apiToTeamUser(created)])
  }

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-violet" />
            <h1 className="text-lg font-display font-semibold text-white">Users &amp; Roles</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Manage team access and permissions</p>
        </div>
        <button
          onClick={() => setShowInvite(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
          <Plus className="w-3.5 h-3.5" />
          Invite User
        </button>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 px-6 pt-3 border-b border-white/5 shrink-0">
        {(['users', 'roles'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              'px-4 py-2 text-xs font-medium rounded-t-lg transition-colors capitalize',
              tab === t ? 'text-magenta border-b-2 border-magenta' : 'text-ink-400 hover:text-white',
            )}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {tab === 'users' && (
          <motion.div variants={fadeInUp} initial="hidden" animate="show" className="rounded-xl border border-white/8 overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/8 text-[10px] uppercase tracking-wide text-ink-600">
                  <th className="px-4 py-3 font-medium">Name</th>
                  <th className="px-4 py-3 font-medium">Email</th>
                  <th className="px-4 py-3 font-medium">Role</th>
                  <th className="px-4 py-3 font-medium">Last Active</th>
                  <th className="px-4 py-3 font-medium text-center">MFA</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr
                    key={u.id}
                    onClick={() => setSelected(u.id)}
                    className="border-b border-white/4 last:border-0 hover:bg-white/4 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <Avatar name={u.name} color={ROLE_COLORS[u.role]} size="sm" />
                        <span className="text-xs font-medium text-white">{u.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[11px] text-ink-400 font-mono">{u.email}</td>
                    <td className="px-4 py-3">
                      <span
                        className="text-[9px] px-1.5 py-0.5 rounded-full border font-medium"
                        style={{ color: ROLE_COLORS[u.role], borderColor: `${ROLE_COLORS[u.role]}33`, background: `${ROLE_COLORS[u.role]}14` }}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[11px] text-ink-500 flex items-center gap-1"><Clock className="w-3 h-3" /> {u.lastActive}</td>
                    <td className="px-4 py-3 text-center">
                      {u.mfa
                        ? <ShieldCheck className="w-4 h-4 text-safe inline" />
                        : <ShieldOff className="w-4 h-4 text-threat inline" />}
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border', STATUS_CFG[u.status].cls)}>
                        {STATUS_CFG[u.status].label}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </motion.div>
        )}

        {tab === 'roles' && (
          <motion.div variants={fadeInUp} initial="hidden" animate="show" className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
            {ROLES.map((role) => (
              <div key={role.name} className="rounded-xl border border-white/8 bg-surface p-4">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ background: role.color }} />
                      <h3 className="text-sm font-semibold text-white">{role.name}</h3>
                    </div>
                    <p className="text-[10px] text-ink-500 mt-0.5">{role.description}</p>
                  </div>
                  <span className="text-[10px] text-ink-400 bg-white/5 px-2 py-0.5 rounded-full border border-white/8 whitespace-nowrap">
                    {role.userCount} {role.userCount === 1 ? 'user' : 'users'}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {PERMISSIONS.map((perm) => {
                    const allowed = role.permissions[perm]
                    return (
                      <div key={perm} className="flex items-center justify-between text-[11px]">
                        <span className={allowed ? 'text-ink-200' : 'text-ink-600'}>{perm}</span>
                        {allowed
                          ? <Check className="w-3.5 h-3.5 text-safe" />
                          : <Minus className="w-3.5 h-3.5 text-ink-600" />}
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </motion.div>
        )}
      </div>

      <AnimatePresence>
        {selectedUser && (
          <UserPanel
            user={selectedUser}
            onClose={() => setSelected(null)}
            onRoleChange={(role) => changeRole(selectedUser.id, role)}
            onToggleSuspend={() => toggleSuspend(selectedUser.id)}
            onToggleMfa={() => toggleMfa(selectedUser.id)}
            onDelete={() => removeUser(selectedUser.id)}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showInvite && (
          <InviteModal onClose={() => setShowInvite(false)} onInvite={inviteUser} />
        )}
      </AnimatePresence>
    </div>
  )
}
