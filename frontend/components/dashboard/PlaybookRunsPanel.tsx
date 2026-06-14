'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  History, ChevronDown, CheckCircle2, XCircle, MinusCircle,
  Loader2, UserCheck, Zap, ShieldQuestion,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchSoarRuns, approvePlaybookRun, rejectPlaybookRun,
  type PlaybookRun, type PlaybookRunStep,
} from '@/lib/api'

const RUN_STYLE: Record<string, { color: string; label: string }> = {
  'success': { color: '#34F5C5', label: 'Success' },
  'failed': { color: '#FF4D6D', label: 'Failed' },
  'awaiting-approval': { color: '#FFB23E', label: 'Awaiting approval' },
  'rejected': { color: '#665B7D', label: 'Rejected' },
}
const STEP_ICON: Record<PlaybookRunStep['status'], { icon: React.ComponentType<any>; color: string }> = {
  'success': { icon: CheckCircle2, color: '#34F5C5' },
  'failed': { icon: XCircle, color: '#FF4D6D' },
  'skipped': { icon: MinusCircle, color: '#665B7D' },
  'pending-approval': { icon: ShieldQuestion, color: '#FFB23E' },
}

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * Live playbook run history - every execution (manual or auto-triggered by the
 * engine) with its per-step audit trail, plus inline approve/reject for runs
 * paused at a human-approval gate.
 */
export default function PlaybookRunsPanel() {
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  const [awaiting, setAwaiting] = useState(0)
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState<string | null>(null)
  const [deciding, setDeciding] = useState<string | null>(null)

  const load = useCallback(() => {
    fetchSoarRuns(undefined, 30)
      .then((r) => { setRuns(r.items); setAwaiting(r.awaitingApproval) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])
  useEffect(() => {
    load()
    const t = setInterval(load, 12000)
    return () => clearInterval(t)
  }, [load])

  function decide(run: PlaybookRun, approve: boolean) {
    if (deciding) return
    setDeciding(run.id)
    ;(approve ? approvePlaybookRun(run.id) : rejectPlaybookRun(run.id))
      .then(() => load())
      .catch(() => {})
      .finally(() => setDeciding(null))
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-safe/15 border border-safe/25 shrink-0">
          <History className="w-4 h-4 text-safe" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Run history</h3>
          <p className="text-[10px] text-ink-500">Every execution with its per-step audit trail - manual and auto-triggered</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {awaiting > 0 && (
            <span className="flex items-center gap-1.5 text-[10px] font-semibold text-amber bg-amber/10 border border-amber/25 px-2 py-1 rounded-full animate-pulse">
              <UserCheck className="w-3 h-3" /> {awaiting} awaiting approval
            </span>
          )}
          <span className="text-[10px] text-ink-500"><b className="text-white font-mono">{runs.length}</b> recent</span>
        </div>
      </div>

      <div className="divide-y divide-white/4 max-h-96 overflow-y-auto">
        {loading && <p className="text-[11px] text-ink-600 py-8 text-center animate-pulse">Loading runs…</p>}
        {!loading && runs.length === 0 && (
          <p className="text-[11px] text-ink-600 py-8 text-center">
            No runs yet - hit <b className="text-ink-400">Run</b> on a playbook, or let the engine auto-trigger one.
          </p>
        )}
        {runs.map((r) => {
          const st = RUN_STYLE[r.status] ?? RUN_STYLE.success
          const isOpen = open === r.id
          const entity = r.context?.entity
          return (
            <div key={r.id}>
              <button onClick={() => setOpen(isOpen ? null : r.id)}
                className="w-full text-left flex items-center gap-3 px-5 py-3 hover:bg-white/3 transition-colors">
                <span className="w-2 h-2 rounded-full shrink-0"
                  style={{ background: st.color, boxShadow: r.status === 'awaiting-approval' ? `0 0 8px ${st.color}` : undefined }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-medium text-white truncate">{r.playbookName}</span>
                    {r.trigger === 'auto' && (
                      <span className="flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-violet/12 text-violet font-semibold uppercase">
                        <Zap className="w-2.5 h-2.5" /> auto
                      </span>
                    )}
                    <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold"
                      style={{ color: st.color, background: `${st.color}15` }}>{st.label}</span>
                  </div>
                  <p className="text-[10px] text-ink-600 mt-0.5 truncate">
                    {relTime(r.ts)} · {r.actor ?? '-'}
                    {entity ? <> · <span className="font-mono text-ink-400">{entity.type}={entity.value}</span></> : null}
                  </p>
                </div>
                {r.status === 'awaiting-approval' && (
                  <div className="flex items-center gap-1.5 shrink-0" onClick={(e) => e.stopPropagation()}>
                    <button onClick={() => decide(r, true)} disabled={deciding === r.id}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] font-semibold bg-safe/15 border border-safe/30 text-safe hover:bg-safe/25 transition-colors">
                      {deciding === r.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
                      Approve
                    </button>
                    <button onClick={() => decide(r, false)} disabled={deciding === r.id}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] font-semibold bg-threat/10 border border-threat/30 text-threat hover:bg-threat/20 transition-colors">
                      <XCircle className="w-3 h-3" /> Reject
                    </button>
                  </div>
                )}
                <ChevronDown className={cn('w-3.5 h-3.5 text-ink-600 shrink-0 transition-transform', isOpen && 'rotate-180')} />
              </button>
              <AnimatePresence>
                {isOpen && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                    <div className="px-5 pb-3 space-y-1.5">
                      {r.steps.map((s) => {
                        const cfg = STEP_ICON[s.status] ?? STEP_ICON.skipped
                        const Icon = cfg.icon
                        return (
                          <div key={s.idx} className="flex items-start gap-2.5 px-3 py-2 rounded-lg bg-surface-2/50 border border-white/5">
                            <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: cfg.color }} />
                            <div className="min-w-0">
                              <p className="text-[11px] text-ink-200">{s.name}
                                {s.kind && <span className="ml-1.5 text-[9px] font-mono text-ink-600">{s.kind}</span>}
                              </p>
                              <p className="text-[10px] text-ink-500 mt-0.5">{s.detail}</p>
                            </div>
                          </div>
                        )
                      })}
                      {r.steps.length === 0 && <p className="text-[10px] text-ink-600">No steps recorded.</p>}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )
        })}
      </div>
    </motion.div>
  )
}
