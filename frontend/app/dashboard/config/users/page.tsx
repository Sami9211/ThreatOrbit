'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Users, Plus, X, ShieldCheck, ShieldOff, Check, Minus, Mail,
  Clock, Activity, KeyRound, Ban, Monitor, ChevronDown,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Types ───────────────────────────────────────────────────────── */
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

interface Session {
  device: string
  ip: string
  location: string
  current: boolean
}

interface ActivityEntry {
  action: string
  time: string
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

/* ── Seed data ───────────────────────────────────────────────────── */
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
    name: 'Admin', color: '#FF2E97', description: 'Full platform control', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': true, 'Configure Sources': true, 'Manage Users': true, 'Export Data': true, 'Run Response Actions': true },
  },
  {
    name: 'SOC Manager', color: '#7A3CFF', description: 'Team oversight & operations', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': true, 'Configure Sources': true, 'Manage Users': false, 'Export Data': true, 'Run Response Actions': true },
  },
  {
    name: 'Senior Analyst', color: '#34F5C5', description: 'Investigate & respond', userCount: 2,
    permissions: { 'View Alerts': true, 'Manage Playbooks': true, 'Configure Sources': false, 'Manage Users': false, 'Export Data': true, 'Run Response Actions': true },
  },
  {
    name: 'Analyst', color: '#FFB23E', description: 'Triage & enrichment', userCount: 4,
    permissions: { 'View Alerts': true, 'Manage Playbooks': false, 'Configure Sources': false, 'Manage Users': false, 'Export Data': false, 'Run Response Actions': true },
  },
  {
    name: 'Read-Only', color: '#8A7DA3', description: 'View dashboards only', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': false, 'Configure Sources': false, 'Manage Users': false, 'Export Data': false, 'Run Response Actions': false },
  },
  {
    name: 'Auditor', color: '#FF4D6D', description: 'Compliance & export', userCount: 1,
    permissions: { 'View Alerts': true, 'Manage Playbooks': false, 'Configure Sources': false, 'Manage Users': false, 'Export Data': true, 'Run Response Actions': false },
  },
]

const ROLE_COLORS: Record<RoleName, string> = {
  Admin: '#FF2E97',
  'SOC Manager': '#7A3CFF',
  'Senior Analyst': '#34F5C5',
  Analyst: '#FFB23E',
  'Read-Only': '#8A7DA3',
  Auditor: '#FF4D6D',
}

const STATUS_CFG: Record<UserStatus, { label: string; cls: string }> = {
  active:    { label: 'Active',    cls: 'text-safe border-safe/20 bg-safe/10'    },
  suspended: { label: 'Suspended', cls: 'text-threat border-threat/20 bg-threat/10' },
  invited:   { label: 'Invited',   cls: 'text-amber border-amber/20 bg-amber/10'  },
}

const SAMPLE_SESSIONS: Session[] = [
  { device: 'Chrome on macOS', ip: '203.0.113.42',  location: 'London, UK',     current: true  },
  { device: 'Safari on iOS',   ip: '198.51.100.17',  location: 'London, UK',     current: false },
  { device: 'Firefox on Linux',ip: '192.0.2.88',     location: 'Amsterdam, NL',  current: false },
]

const SAMPLE_ACTIVITY: ActivityEntry[] = [
  { action: 'Closed incident INC-2041 (Confirmed Phishing)', time: '12m ago' },
  { action: 'Ran playbook "Isolate Endpoint" on WS-4471',    time: '1h ago'  },
  { action: 'Exported alert report (CSV, 248 rows)',         time: '3h ago'  },
  { action: 'Updated detection rule R-117',                  time: '1d ago'  },
  { action: 'Signed in from London, UK',                     time: '1d ago'  },
]

/* ── Initials avatar ─────────────────────────────────────────────── */
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

/* ── User detail panel ───────────────────────────────────────────── */
function UserPanel({ user, onClose }: { user: TeamUser; onClose: () => void }) {
  const color = ROLE_COLORS[user.role]
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-sm"
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
                defaultValue={user.role}
                className="w-full appearance-none px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 pr-9"
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

          {/* Activity log */}
          <div>
            <p className="text-xs font-medium text-ink-300 mb-2 flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Activity Log</p>
            <div className="space-y-2">
              {SAMPLE_ACTIVITY.map((a, i) => (
                <div key={i} className="flex items-start gap-2 text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-violet mt-1 shrink-0" />
                  <div>
                    <p className="text-ink-200">{a.action}</p>
                    <p className="text-ink-600 text-[10px]">{a.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Sessions */}
          <div>
            <p className="text-xs font-medium text-ink-300 mb-2 flex items-center gap-1.5"><Monitor className="w-3.5 h-3.5" /> Active Sessions</p>
            <div className="space-y-2">
              {SAMPLE_SESSIONS.map((s, i) => (
                <div key={i} className="flex items-center justify-between py-2 px-3 rounded-lg bg-surface-2 border border-white/5">
                  <div>
                    <p className="text-[11px] text-ink-200">{s.device} {s.current && <span className="text-safe">&middot; current</span>}</p>
                    <p className="text-[10px] text-ink-600 font-mono">{s.ip} &middot; {s.location}</p>
                  </div>
                  {!s.current && <button className="text-[10px] text-threat hover:underline">Revoke</button>}
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-2 pt-2">
            <button className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-amber/25 text-amber text-sm font-medium hover:bg-amber/5 transition-colors">
              <KeyRound className="w-4 h-4" /> Reset MFA
            </button>
            <button className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-threat/25 text-threat text-sm font-medium hover:bg-threat/5 transition-colors">
              <Ban className="w-4 h-4" /> {user.status === 'suspended' ? 'Reactivate User' : 'Suspend User'}
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function UsersRolesPage() {
  const [tab, setTab] = useState<'users' | 'roles'>('users')
  const [selected, setSelected] = useState<string | null>(null)
  const selectedUser = USERS.find((u) => u.id === selected) ?? null

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
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
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
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-xl border border-white/8 overflow-hidden">
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
                {USERS.map((u) => (
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
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
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
        {selectedUser && <UserPanel user={selectedUser} onClose={() => setSelected(null)} />}
      </AnimatePresence>
    </div>
  )
}
