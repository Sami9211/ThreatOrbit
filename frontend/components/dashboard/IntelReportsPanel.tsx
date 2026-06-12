'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { BookOpen, Plus, Loader2, Trash2, Download, Send, Undo2, ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchIntelReports, createIntelReport, updateIntelReport, deleteIntelReport,
  exportIntelReportMisp, type IntelReport,
} from '@/lib/api'

const TLP = ['clear', 'green', 'amber', 'amber+strict', 'red']
const TLP_CLS: Record<string, string> = {
  clear: 'text-white bg-white/10', green: 'text-safe bg-safe/12',
  amber: 'text-amber bg-amber/12', 'amber+strict': 'text-amber bg-amber/20',
  red: 'text-threat bg-threat/12',
}

function relTime(iso: string | null): string {
  if (!iso) return '—'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * Intel report authoring — campaign & report management over `/cti/reports`.
 * Analysts draft reports (title, TLP, summary, body, tags), publish/unpublish
 * them, and export any report as a MISP Event for sharing. Everything here is
 * the live store; drafts persist server-side.
 */
export default function IntelReportsPanel() {
  const [reports, setReports] = useState<IntelReport[] | null>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | 'draft' | 'published'>('all')
  const [showNew, setShowNew] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // new-report form
  const [title, setTitle] = useState('')
  const [tlp, setTlp] = useState('amber')
  const [summary, setSummary] = useState('')
  const [body, setBody] = useState('')
  const [tags, setTags] = useState('')

  const load = useCallback(() => {
    fetchIntelReports().then(setReports).catch(() => setError('Could not load intel reports.'))
  }, [])
  useEffect(() => { load() }, [load])

  function create() {
    if (!title.trim() || busy) return
    setBusy(true); setError(null)
    createIntelReport({
      title: title.trim(), tlp, summary: summary.trim() || undefined,
      body: body.trim() || undefined,
      tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
    })
      .then(() => { setTitle(''); setSummary(''); setBody(''); setTags(''); setShowNew(false); load() })
      .catch(() => setError('Could not create the report.'))
      .finally(() => setBusy(false))
  }

  function setStatus(r: IntelReport, status: 'draft' | 'published') {
    updateIntelReport(r.id, { status })
      .then((u) => setReports((xs) => (xs ?? []).map((x) => (x.id === r.id ? u : x))))
      .catch(() => setError('Could not update the report.'))
  }

  function remove(id: string) {
    const prev = reports
    setReports((xs) => (xs ?? []).filter((x) => x.id !== id))
    deleteIntelReport(id).catch(() => { setReports(prev); setError('Could not delete the report.') })
  }

  function downloadMisp(r: IntelReport) {
    exportIntelReportMisp(r.id)
      .then((ev) => {
        const blob = new Blob([JSON.stringify(ev, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `misp-event-${r.title.toLowerCase().replace(/\s+/g, '-').slice(0, 40)}.json`
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(() => setError('Could not export the MISP event.'))
  }

  const visible = (reports ?? []).filter((r) => statusFilter === 'all' || r.status === statusFilter)

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
          <BookOpen className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Intel reports</h3>
          <p className="text-[10px] text-ink-500">Analyst-authored campaign reporting — draft, publish, share as MISP events</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {(['all', 'draft', 'published'] as const).map((s) => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={cn('px-2 py-1 rounded-full text-[10px] font-medium capitalize transition-colors',
                statusFilter === s ? 'bg-violet/15 text-violet border border-violet/30'
                  : 'text-ink-500 border border-white/8 hover:text-ink-200')}>
              {s}
            </button>
          ))}
          <button onClick={() => setShowNew((v) => !v)}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-violet/15 border border-violet/30 text-violet hover:bg-violet/20 transition-colors">
            <Plus className="w-3 h-3" /> New report
          </button>
        </div>
      </div>

      {/* Authoring form */}
      <AnimatePresence>
        {showNew && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }} className="overflow-hidden border-b border-white/5">
            <div className="p-4 space-y-2.5">
              <div className="flex items-center gap-2 flex-wrap">
                <input value={title} onChange={(e) => setTitle(e.target.value)}
                  placeholder="Report title — e.g. Q2 LockBit affiliate campaign against fintech"
                  className="flex-1 min-w-[240px] px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 focus:outline-none focus:border-violet/40 placeholder-ink-600" />
                <select value={tlp} onChange={(e) => setTlp(e.target.value)}
                  title="Traffic Light Protocol marking"
                  className="px-2.5 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-none focus:border-violet/40">
                  {TLP.map((t) => <option key={t} value={t}>TLP:{t.toUpperCase()}</option>)}
                </select>
              </div>
              <textarea value={summary} onChange={(e) => setSummary(e.target.value)} rows={2}
                placeholder="Executive summary"
                className="w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-none focus:border-violet/40 placeholder-ink-600 resize-y" />
              <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={4}
                placeholder="Full analysis (markdown welcome): victimology, TTPs, infrastructure, recommendations…"
                className="w-full px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-200 focus:outline-none focus:border-violet/40 placeholder-ink-600 resize-y" />
              <div className="flex items-center gap-2 flex-wrap">
                <input value={tags} onChange={(e) => setTags(e.target.value)}
                  placeholder="tags, comma, separated"
                  className="flex-1 min-w-[180px] px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-none focus:border-violet/40 placeholder-ink-600" />
                <button onClick={create} disabled={busy || !title.trim()}
                  className={cn('flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold transition-all',
                    title.trim() && !busy ? 'bg-violet/20 border border-violet/35 text-violet hover:bg-violet/30'
                      : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
                  {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  Save draft
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {error && <p className="px-5 py-2 text-[11px] text-threat">{error}</p>}

      {/* Report list */}
      <div className="divide-y divide-white/4 max-h-96 overflow-y-auto">
        {reports === null && <p className="text-[11px] text-ink-600 py-8 text-center animate-pulse">Loading reports…</p>}
        {reports !== null && visible.length === 0 && (
          <p className="text-[11px] text-ink-600 py-8 text-center">
            No {statusFilter !== 'all' ? statusFilter : ''} reports yet — draft the first one above.
          </p>
        )}
        {visible.map((r) => (
          <div key={r.id} className="px-5 py-3">
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                className="flex items-center gap-1.5 text-left flex-1 min-w-0 group">
                <ChevronDown className={cn('w-3 h-3 text-ink-600 transition-transform', expanded === r.id && 'rotate-180')} />
                <span className="text-xs font-medium text-white truncate group-hover:text-violet transition-colors">{r.title}</span>
              </button>
              <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase', TLP_CLS[r.tlp] ?? TLP_CLS.amber)}>
                TLP:{r.tlp}
              </span>
              <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold',
                r.status === 'published' ? 'text-safe bg-safe/12' : 'text-amber bg-amber/12')}>
                {r.status}
              </span>
              <span className="text-[10px] text-ink-600">{relTime(r.updatedAt)}</span>
              <div className="flex items-center gap-1">
                {r.status === 'draft' ? (
                  <button onClick={() => setStatus(r, 'published')} title="Publish"
                    className="p-1.5 rounded-lg text-ink-500 hover:text-safe hover:bg-safe/10 transition-colors">
                    <Send className="w-3.5 h-3.5" />
                  </button>
                ) : (
                  <button onClick={() => setStatus(r, 'draft')} title="Unpublish (back to draft)"
                    className="p-1.5 rounded-lg text-ink-500 hover:text-amber hover:bg-amber/10 transition-colors">
                    <Undo2 className="w-3.5 h-3.5" />
                  </button>
                )}
                <button onClick={() => downloadMisp(r)} title="Export as MISP event (carries the report's referenced IOCs)"
                  className="p-1.5 rounded-lg text-ink-500 hover:text-violet hover:bg-violet/10 transition-colors">
                  <Download className="w-3.5 h-3.5" />
                </button>
                <button onClick={() => remove(r.id)} title="Delete report"
                  className="p-1.5 rounded-lg text-ink-600 hover:text-threat hover:bg-threat/10 transition-colors">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
            {(r.summary || r.tags.length > 0) && (
              <p className="text-[10px] text-ink-600 mt-1 ml-4.5 truncate">
                {r.summary}{r.tags.length > 0 && <span className="text-violet/70"> · {r.tags.join(' · ')}</span>}
              </p>
            )}
            <AnimatePresence>
              {expanded === r.id && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                  <div className="mt-2 ml-4 p-3 rounded-lg bg-white/3 border border-white/6">
                    <p className="text-[11px] text-ink-300 whitespace-pre-wrap">
                      {r.body || r.summary || 'No analysis body yet — edit via the API or re-draft.'}
                    </p>
                    <p className="text-[10px] text-ink-600 mt-2">
                      {r.author ? `by ${r.author} · ` : ''}created {relTime(r.createdAt)}
                      {r.actors.length > 0 && ` · actors: ${r.actors.join(', ')}`}
                      {r.iocs.length > 0 && ` · ${r.iocs.length} referenced IOCs`}
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ))}
      </div>
    </motion.div>
  )
}
