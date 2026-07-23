'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldCheck, Shield, Plus, Copy, Trash2, Check, Minus, X, Lock,
  Save, Loader2, AlertTriangle, Users,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import { usePermissions } from '@/lib/usePermissions'
import { fetchRoles, createRole, updateRole, deleteRole, type RoleDef } from '@/lib/api'

/* A role being created / cloned / edited. `id` set ⇒ editing an existing
   custom role; absent ⇒ creating a new one. */
type Draft = { id?: string; name: string; description: string; capabilities: string[] }

const ROLE_COLOR: Record<string, string> = {
  admin: '#FF2E97', manager: '#7A3CFF', analyst: '#34F5C5', viewer: '#8b8b9a',
}

export default function RolesEditor() {
  const { can } = usePermissions()
  const canManage = can('users.manage')

  const [roles, setRoles] = useState<RoleDef[] | null>(null)
  const [catalogue, setCatalogue] = useState<Record<string, string>>({})
  const [draft, setDraft] = useState<Draft | null>(null)
  const [confirmDel, setConfirmDel] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const load = useCallback(() => {
    fetchRoles()
      .then((r) => { setRoles(r.roles); setCatalogue(r.capabilities) })
      .catch(() => setRoles([]))
  }, [])
  useEffect(() => { load() }, [load])

  const capList = Object.entries(catalogue)  // [id, description]

  const startNew = () => { setError(null); setDraft({ name: '', description: '', capabilities: [] }) }
  const startClone = (r: RoleDef) => {
    setError(null)
    setDraft({ name: `${r.name} copy`, description: r.description ?? '', capabilities: [...r.capabilities] })
  }
  const startEdit = (r: RoleDef) => {
    setError(null)
    setDraft({ id: r.id, name: r.name, description: r.description ?? '', capabilities: [...r.capabilities] })
  }
  const toggleCap = (c: string) => setDraft((d) => d
    ? { ...d, capabilities: d.capabilities.includes(c) ? d.capabilities.filter((x) => x !== c) : [...d.capabilities, c] }
    : d)

  async function save() {
    if (!draft || busy) return
    if (!draft.name.trim()) { setError('A role name is required.'); return }
    setBusy(true); setError(null)
    try {
      if (draft.id) {
        await updateRole(draft.id, { name: draft.name.trim(), description: draft.description || undefined, capabilities: draft.capabilities })
        setNotice(`Role “${draft.name.trim()}” updated.`)
      } else {
        const r = await createRole({ name: draft.name.trim(), description: draft.description || undefined, capabilities: draft.capabilities })
        setNotice(`Role “${r.name}” created.`)
      }
      setDraft(null); load()
      setTimeout(() => setNotice(null), 4000)
    } catch (e) {
      // Surface the backend's honest reason (e.g. no-privilege-escalation 403,
      // duplicate 409) rather than a generic failure.
      setError(e instanceof Error ? e.message : 'Could not save the role.')
    } finally { setBusy(false) }
  }

  async function remove(r: RoleDef) {
    if (busy) return
    setBusy(true); setError(null); setConfirmDel(null)
    try {
      await deleteRole(r.id); setNotice(`Role “${r.name}” deleted.`); load()
      setTimeout(() => setNotice(null), 4000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not delete the role.')
    } finally { setBusy(false) }
  }

  if (roles === null) {
    return <p className="text-xs text-ink-600 py-8 text-center animate-pulse">Loading roles…</p>
  }

  return (
    <div>
      {/* Toolbar */}
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] text-ink-500">
          {roles.length} role{roles.length === 1 ? '' : 's'} · built-in roles are read-only; create custom roles to fit your team.
        </p>
        {canManage && (
          <button onClick={startNew}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-magenta/12 text-magenta border border-magenta/25 text-xs font-medium hover:bg-magenta/20 transition-colors">
            <Plus className="w-3.5 h-3.5" /> New role
          </button>
        )}
      </div>

      {/* Notices */}
      <AnimatePresence>
        {notice && (
          <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="mb-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-safe/10 border border-safe/20 text-[11px] text-safe">
            <Check className="w-3.5 h-3.5" />{notice}
          </motion.div>
        )}
        {error && !draft && (
          <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="mb-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-threat/10 border border-threat/20 text-[11px] text-threat">
            <AlertTriangle className="w-3.5 h-3.5" />{error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Role cards */}
      <motion.div variants={fadeInUp} initial="hidden" animate="show" className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
        {roles.map((role) => (
          <div key={role.id} className="rounded-xl border border-white/8 bg-surface p-4 flex flex-col">
            <div className="flex items-start justify-between mb-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: ROLE_COLOR[role.id] ?? '#4f6bed' }} />
                  <h3 className="text-sm font-semibold text-white truncate">{role.name}</h3>
                  {role.builtIn
                    ? <span className="inline-flex items-center gap-1 text-[9px] text-ink-500 bg-white/5 px-1.5 py-0.5 rounded-full border border-white/8"><Lock className="w-2.5 h-2.5" />Built-in</span>
                    : <span className="text-[9px] text-magenta bg-magenta/10 px-1.5 py-0.5 rounded-full border border-magenta/20">Custom</span>}
                </div>
                {role.description && <p className="text-[10px] text-ink-500 mt-0.5 truncate">{role.description}</p>}
              </div>
              <span className="text-[10px] text-ink-400 bg-white/5 px-2 py-0.5 rounded-full border border-white/8 whitespace-nowrap shrink-0">
                {role.capabilities.length} cap{role.capabilities.length === 1 ? '' : 's'}
              </span>
            </div>

            {/* Capability matrix over the full catalogue (real, from the API). */}
            <div className="space-y-1 flex-1">
              {capList.map(([cap, desc]) => {
                const on = role.capabilities.includes(cap)
                return (
                  <div key={cap} className="flex items-center justify-between gap-2 text-[11px]">
                    <span className={cn('truncate', on ? 'text-ink-200' : 'text-ink-600')} title={desc}>{cap}</span>
                    {on ? <Check className="w-3.5 h-3.5 text-safe shrink-0" /> : <Minus className="w-3.5 h-3.5 text-ink-600 shrink-0" />}
                  </div>
                )
              })}
            </div>

            {/* Actions */}
            {canManage && (
              <div className="flex items-center gap-1.5 mt-3 pt-3 border-t border-white/6">
                {role.builtIn ? (
                  <button onClick={() => startClone(role)}
                    className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
                    <Copy className="w-3 h-3" /> Clone
                  </button>
                ) : (
                  <>
                    <button onClick={() => startEdit(role)}
                      className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
                      <ShieldCheck className="w-3 h-3" /> Edit
                    </button>
                    <button onClick={() => startClone(role)}
                      className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
                      <Copy className="w-3 h-3" /> Clone
                    </button>
                    {confirmDel === role.id ? (
                      <button onClick={() => remove(role)} disabled={busy}
                        className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-threat/30 bg-threat/10 text-threat hover:bg-threat/20 transition-colors ml-auto disabled:opacity-50">
                        <Trash2 className="w-3 h-3" /> Confirm
                      </button>
                    ) : (
                      <button onClick={() => { setError(null); setConfirmDel(role.id) }}
                        className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border border-white/10 text-ink-500 hover:text-threat hover:border-threat/25 transition-colors ml-auto">
                        <Trash2 className="w-3 h-3" /> Delete
                      </button>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        ))}
      </motion.div>

      {/* Editor modal */}
      <AnimatePresence>
        {draft && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-60 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs"
            onClick={() => !busy && setDraft(null)}>
            <motion.div initial={{ opacity: 0, y: 12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 12 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-lg max-h-[85vh] flex flex-col rounded-2xl border border-white/10 bg-surface shadow-2xl overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/8 shrink-0">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-magenta" />
                  <h3 className="text-sm font-semibold text-white">{draft.id ? 'Edit role' : 'New role'}</h3>
                </div>
                <button onClick={() => !busy && setDraft(null)} className="p-1 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-5 space-y-4">
                <div>
                  <label className="text-[10px] text-ink-500 uppercase tracking-wide">Name</label>
                  <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                    placeholder="e.g. Tier-1 Analyst" autoFocus
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-sm text-ink-100 placeholder-ink-600 focus:outline-hidden focus:border-magenta/40" />
                  {!draft.id && (
                    <p className="text-[10px] text-ink-600 mt-1">The id becomes a slug of the name (e.g. <span className="font-mono">tier-1-analyst</span>).</p>
                  )}
                </div>
                <div>
                  <label className="text-[10px] text-ink-500 uppercase tracking-wide">Description</label>
                  <input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })}
                    placeholder="What this role is for (optional)"
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-sm text-ink-100 placeholder-ink-600 focus:outline-hidden focus:border-magenta/40" />
                </div>
                <div>
                  <div className="flex items-center justify-between">
                    <label className="text-[10px] text-ink-500 uppercase tracking-wide">Capabilities</label>
                    <span className="text-[10px] text-ink-600">{draft.capabilities.length} selected</span>
                  </div>
                  <p className="text-[10px] text-ink-600 mt-0.5 mb-2">You can only grant capabilities you hold yourself.</p>
                  <div className="space-y-1.5">
                    {capList.map(([cap, desc]) => {
                      const on = draft.capabilities.includes(cap)
                      return (
                        <button key={cap} type="button" onClick={() => toggleCap(cap)}
                          className={cn('w-full flex items-start gap-2.5 px-2.5 py-2 rounded-lg border text-left transition-colors',
                            on ? 'border-magenta/30 bg-magenta/8' : 'border-white/8 bg-surface-2 hover:border-white/15')}>
                          <span className={cn('mt-0.5 w-4 h-4 rounded-sm border flex items-center justify-center shrink-0',
                            on ? 'bg-magenta border-magenta' : 'border-white/20')}>
                            {on && <Check className="w-3 h-3 text-white" />}
                          </span>
                          <span className="min-w-0">
                            <span className="block text-xs font-mono text-ink-200">{cap}</span>
                            <span className="block text-[10px] text-ink-500">{desc}</span>
                          </span>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {error && (
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-threat/10 border border-threat/20 text-[11px] text-threat">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />{error}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-2 px-5 py-3.5 border-t border-white/8 shrink-0">
                <button onClick={() => !busy && setDraft(null)}
                  className="px-3 py-1.5 rounded-lg text-xs text-ink-400 hover:text-white transition-colors">Cancel</button>
                <button onClick={save} disabled={busy}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-magenta/15 text-magenta border border-magenta/30 text-xs font-medium hover:bg-magenta/25 transition-colors disabled:opacity-50">
                  {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                  {draft.id ? 'Save changes' : 'Create role'}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {!canManage && (
        <p className="mt-4 flex items-center gap-1.5 text-[11px] text-ink-600">
          <Users className="w-3.5 h-3.5" /> View-only — managing roles requires the <span className="font-mono">users.manage</span> capability.
        </p>
      )}
    </div>
  )
}
