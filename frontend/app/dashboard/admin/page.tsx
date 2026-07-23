'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  ShieldCheck, Users, KeyRound, ScrollText, Bell, Plug, Database,
  Settings, Lock, ChevronRight, ShieldAlert, Loader2, Activity,
  UserCheck, UserX, BadgeCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fadeInUp, listContainer, listItem } from '@/lib/motion'
import { usePermissions } from '@/lib/usePermissions'
import { fetchUsers, fetchAuditLog, type User, type AuditEntry } from '@/lib/api'

/* Relative "x ago" for the activity feed (mirrors the config Audit Trail). */
function timeAgo(iso: string) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

/* -- Admin surfaces -------------------------------------------------
   Each card deep-links to a real, existing admin surface (the console is a
   consolidated launch-point, not a second copy of those settings). Cards are
   gated on the capability the destination actually requires, so a manager who
   lacks a given capability doesn't see a control they can't use. */
type Surface = {
  title: string
  desc: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  cap: string
  color: string
}
type SurfaceGroup = { section: string; items: Surface[] }

const SURFACES: SurfaceGroup[] = [
  {
    section: 'Identity & access',
    items: [
      { title: 'Users & roles', desc: 'Provision accounts, assign roles, suspend or reset access', href: '/dashboard/config/users', icon: Users, cap: 'users.manage', color: 'text-magenta' },
      { title: 'API keys', desc: 'Issue and revoke programmatic access tokens', href: '/dashboard/config?tab=api', icon: KeyRound, cap: 'config.manage', color: 'text-teal' },
    ],
  },
  {
    section: 'Security & compliance',
    items: [
      { title: 'Security policies', desc: 'Password policy, MFA enforcement, session controls', href: '/dashboard/config?tab=security', icon: Lock, cap: 'config.manage', color: 'text-amber' },
      { title: 'Audit trail', desc: 'Immutable record of every privileged action', href: '/dashboard/config?tab=security', icon: ScrollText, cap: 'config.manage', color: 'text-violet' },
    ],
  },
  {
    section: 'Platform & data',
    items: [
      { title: 'General settings', desc: 'Platform identity, timezone, retention, refresh cadence', href: '/dashboard/config?tab=general', icon: Settings, cap: 'config.manage', color: 'text-ink-300' },
      { title: 'Notifications', desc: 'Alert routing, Slack, email and webhook delivery', href: '/dashboard/config?tab=alerts', icon: Bell, cap: 'config.manage', color: 'text-safe' },
      { title: 'Integrations & enrichment', desc: 'VirusTotal, GreyNoise, Shodan and WHOIS providers', href: '/dashboard/config?tab=integrations', icon: Plug, cap: 'config.manage', color: 'text-teal' },
      { title: 'Feed connectors', desc: 'Threat-intel ingestion sources, cadence and health', href: '/dashboard/feeds/sources', icon: Database, cap: 'connectors.manage', color: 'text-magenta' },
    ],
  },
]

/* -- KPI tile ------------------------------------------------------- */
function Stat({ label, value, sub, icon: Icon, color }: {
  label: string; value: string; sub: string
  icon: React.ComponentType<{ className?: string }>; color: string
}) {
  return (
    <div className="glass border border-white/5 rounded-xl p-3">
      <div className="flex items-center gap-1.5 text-[10px] text-ink-500 uppercase tracking-wide">
        <Icon className={cn('w-3 h-3', color)} /> {label}
      </div>
      <p className="text-xl font-bold text-white mt-1 tabular-nums">{value}</p>
      <p className="text-[10px] text-ink-600 mt-0.5">{sub}</p>
    </div>
  )
}

export default function AdminConsolePage() {
  const { can, role, loaded } = usePermissions()
  const allowed = can('config.manage')

  const [users, setUsers] = useState<User[] | null>(null)
  const [activity, setActivity] = useState<AuditEntry[] | null>(null)

  useEffect(() => {
    if (!allowed) return
    fetchUsers().then(setUsers).catch(() => setUsers([]))
    fetchAuditLog(12).then(setActivity).catch(() => setActivity([]))
  }, [allowed])

  // Access gate: analysts/viewers land here (nav is a UI hint, not the gate)
  // and get a clear, honest "not authorised" state rather than an empty page.
  if (loaded && !allowed) {
    return (
      <div className="flex flex-col h-full min-h-0 bg-[#0A0612] items-center justify-center p-6 text-center">
        <div className="w-12 h-12 rounded-xl bg-threat/10 border border-threat/20 flex items-center justify-center mb-4">
          <ShieldAlert className="w-6 h-6 text-threat" />
        </div>
        <h1 className="text-lg font-display font-semibold text-white">Administrator access required</h1>
        <p className="text-sm text-ink-500 mt-1 max-w-sm">
          The admin console is available to administrators and SOC managers. Your role
          {role ? <> (<span className="capitalize text-ink-300">{role}</span>)</> : null} doesn&apos;t include platform administration.
        </p>
        <Link href="/dashboard" className="mt-5 px-4 py-2 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors">
          Back to Overview
        </Link>
      </div>
    )
  }

  // Real derived stats — never placeholders. Null until the first fetch resolves.
  const total = users?.length ?? null
  const active = users?.filter((u) => u.status === 'active').length ?? null
  const disabled = users?.filter((u) => u.status !== 'active').length ?? null
  const admins = users?.filter((u) => u.role === 'admin').length ?? null
  const mfaCount = users?.filter((u) => u.mfaEnabled).length ?? null
  const mfaPct = total && total > 0 && mfaCount !== null ? Math.round((mfaCount / total) * 100) : null
  const num = (n: number | null) => (n === null ? '—' : n.toLocaleString())

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Admin Console</h1>
            {role && (
              <span className="px-2 py-0.5 rounded-full border border-magenta/25 bg-magenta/10 text-[10px] font-medium text-magenta capitalize">
                {role}
              </span>
            )}
          </div>
          <p className="text-xs text-ink-500 mt-0.5">
            One place to govern identity, security policy, integrations and platform settings.
          </p>
        </div>
        <Link href="/dashboard/config/users"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors">
          <Users className="w-3.5 h-3.5" /> Manage users
        </Link>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Estate at a glance */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Stat label="Total users"  value={num(total)}    sub="provisioned accounts"        icon={Users}      color="text-magenta" />
          <Stat label="Active"       value={num(active)}   sub="able to sign in"             icon={UserCheck}  color="text-safe" />
          <Stat label="Disabled"     value={num(disabled)} sub="suspended or pending"        icon={UserX}      color="text-amber" />
          <Stat label="Admins"       value={num(admins)}   sub="full platform access"        icon={ShieldCheck} color="text-violet" />
          <Stat label="MFA coverage" value={mfaPct === null ? '—' : `${mfaPct}%`} sub={`${num(mfaCount)} of ${num(total)} enrolled`} icon={BadgeCheck} color="text-teal" />
        </div>

        {/* Admin surfaces */}
        <div className="space-y-6">
          {SURFACES.map((group) => {
            const items = group.items.filter((s) => can(s.cap))
            if (!items.length) return null
            return (
              <section key={group.section}>
                <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider mb-2">{group.section}</h2>
                <motion.div variants={listContainer()} initial="hidden" animate="show"
                  className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {items.map((s) => (
                    <motion.div key={s.title} variants={listItem}>
                      <Link href={s.href}
                        className="group flex items-start gap-3 rounded-xl glass border border-white/5 p-4 hover:border-white/15 hover:bg-white/[0.03] transition-colors">
                        <div className="w-9 h-9 rounded-lg bg-white/5 flex items-center justify-center shrink-0">
                          <s.icon className={cn('w-4 h-4', s.color)} />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1.5">
                            <h3 className="text-sm font-semibold text-white">{s.title}</h3>
                            <ChevronRight className="w-3.5 h-3.5 text-ink-600 group-hover:text-ink-300 group-hover:translate-x-0.5 transition-all" />
                          </div>
                          <p className="text-[11px] text-ink-500 mt-0.5 leading-relaxed">{s.desc}</p>
                        </div>
                      </Link>
                    </motion.div>
                  ))}
                </motion.div>
              </section>
            )
          })}
        </div>

        {/* Recent privileged activity */}
        <motion.section variants={fadeInUp} initial="hidden" animate="show">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-violet" /> Recent activity
            </h2>
            <Link href="/dashboard/config?tab=security" className="text-[11px] text-magenta hover:underline">
              Full audit trail
            </Link>
          </div>
          <div className="glass border border-white/5 rounded-xl divide-y divide-white/5">
            {activity === null && (
              <p className="text-xs text-ink-600 py-6 text-center flex items-center justify-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading activity…
              </p>
            )}
            {activity?.length === 0 && (
              <p className="text-xs text-ink-600 py-6 text-center">
                No recorded activity yet. Actions taken across the platform appear here.
              </p>
            )}
            {activity?.map((a) => (
              <div key={a.id} className="flex items-center gap-3 px-4 py-2.5">
                <div className="w-1.5 h-1.5 rounded-full bg-violet shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-xs text-ink-200 truncate">
                    <span className="text-ink-400">{a.actor ?? 'system'}</span>
                    {' · '}{a.action}{a.target ? <span className="text-ink-500"> · {a.target}</span> : null}
                  </p>
                  {a.detail && <p className="text-[10px] text-ink-600 truncate">{a.detail}</p>}
                </div>
                <span className="text-[10px] text-ink-600 shrink-0 tabular-nums">{timeAgo(a.ts)}</span>
              </div>
            ))}
          </div>
        </motion.section>
      </div>
    </div>
  )
}
