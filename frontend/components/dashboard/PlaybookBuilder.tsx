'use client'
import { tk } from '@/lib/colors'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  X, Plus, GripVertical, Trash2, ArrowDown, Play, Save, Loader2,
  Search, ShieldOff, Server, UserX, FileText, MessageSquare, CheckCircle2,
  Bell, Webhook, UserCheck, GitBranch, History, RotateCcw,
} from 'lucide-react'
import {
  fetchStepKinds, createPlaybook, updatePlaybook, dryRunPlaybook,
  fetchPlaybookVersions, revertPlaybook,
  type StepKind, type BuilderStep, type PlaybookRun, type PlaybookVersion,
} from '@/lib/api'

const KIND_ICON: Record<string, React.ComponentType<any>> = {
  enrich: Search, condition: GitBranch, block_ip: ShieldOff, isolate_host: Server,
  disable_user: UserX, create_case: FileText, add_note: MessageSquare,
  close_alerts: CheckCircle2, notify: Bell, webhook: Webhook, approval: UserCheck,
}
const TYPE_COLOR: Record<string, string> = {
  check: tk('violet'), decision: tk('amber'), action: tk('threat'), notify: tk('safe'), human: tk('magenta'),
}

type EditStep = BuilderStep & { _id: string }
let _uid = 0
const mkStep = (kind: string, name: string, params: Record<string, unknown> = {}): EditStep =>
  ({ _id: `s${++_uid}`, kind, name, params })

/**
 * Visual playbook builder - compose a real, executable response workflow from
 * the step-kind palette: ordered, reorderable, per-step parameters, a live
 * dry-run (no side effects), and version history with one-click revert. Saves
 * through the real /soar/playbooks API (every save snapshots a version).
 */
export default function PlaybookBuilder({ playbook, onClose, onSaved }: {
  playbook?: { id: string; name: string; steps?: Array<{ kind?: string; name: string; params?: Record<string, unknown> }> } | null
  onClose: () => void
  onSaved: () => void
}) {
  const editing = !!playbook?.id
  const [palette, setPalette] = useState<StepKind[]>([])
  const [name, setName] = useState(playbook?.name ?? '')
  const [steps, setSteps] = useState<EditStep[]>(
    (playbook?.steps ?? []).filter((s) => s.kind).map((s) => mkStep(s.kind!, s.name, s.params ?? {})))
  const [dragIdx, setDragIdx] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [preview, setPreview] = useState<PlaybookRun | null>(null)
  const [versions, setVersions] = useState<PlaybookVersion[]>([])
  const [showVersions, setShowVersions] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => { fetchStepKinds().then(setPalette).catch(() => {}) }, [])
  useEffect(() => {
    if (!editing) return
    fetchPlaybookVersions(playbook!.id).then((vs) => {
      setVersions(vs)
      // The page's local steps drop `kind`; the latest version snapshot has the
      // real executable steps - seed the canvas from it.
      const haveKinds = steps.length > 0 && steps.every((s) => s.kind)
      if (!haveKinds && vs[0]?.steps?.length) {
        setSteps(vs[0].steps.filter((s) => s.kind).map((s) => mkStep(s.kind, s.name, s.params ?? {})))
      }
    }).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editing, playbook])

  const meta = (kind: string) => palette.find((p) => p.kind === kind)
  function add(kind: string) {
    const m = meta(kind)
    setSteps((s) => [...s, mkStep(kind, m?.label ?? kind)])
  }
  function move(from: number, to: number) {
    if (to < 0 || to >= steps.length) return
    setSteps((s) => { const a = [...s]; const [x] = a.splice(from, 1); a.splice(to, 0, x); return a })
  }
  function setParam(id: string, key: string, value: string) {
    setSteps((s) => s.map((st) => st._id === id ? { ...st, params: { ...st.params, [key]: value } } : st))
  }

  function payloadSteps(): BuilderStep[] {
    return steps.map(({ _id, ...rest }) => rest)
  }

  async function save() {
    if (!name.trim() || steps.length === 0 || busy) return
    setBusy(true); setError(null)
    try {
      if (editing) await updatePlaybook(playbook!.id, { steps: payloadSteps() })
      else await createPlaybook({ name: name.trim(), steps: payloadSteps() })
      onSaved(); onClose()
    } catch (e) { setError(e instanceof Error ? e.message : 'Save failed') }
    finally { setBusy(false) }
  }

  async function runDry() {
    if (!editing) { setError('Save the playbook first to dry-run it'); return }
    setBusy(true); setError(null)
    try { setPreview((await dryRunPlaybook(playbook!.id)).run) }
    catch { setError('Dry-run failed') }
    finally { setBusy(false) }
  }

  async function revert(v: number) {
    if (!editing) return
    await revertPlaybook(playbook!.id, v).catch(() => {})
    onSaved(); onClose()
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-80 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4" onClick={onClose}>
      <motion.div initial={{ scale: 0.97, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-4xl h-full max-h-[88vh] rounded-2xl border border-white/10 bg-surface flex flex-col overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/8 shrink-0">
          <GitBranch className="w-4 h-4 text-magenta" />
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Playbook name…"
            className="flex-1 bg-transparent text-sm font-semibold text-white focus:outline-hidden placeholder-ink-600" />
          {editing && (
            <button onClick={() => setShowVersions((v) => !v)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] text-ink-400 hover:text-white border border-white/10">
              <History className="w-3.5 h-3.5" /> v{versions[0]?.version ?? 1}
            </button>
          )}
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white"><X className="w-4 h-4" /></button>
        </div>

        <div className="flex-1 flex min-h-0">
          {/* Palette */}
          <div className="w-48 shrink-0 border-r border-white/8 overflow-y-auto p-3 space-y-1">
            <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-2">Add step</p>
            {palette.map((p) => {
              const Icon = KIND_ICON[p.kind] ?? Plus
              return (
                <button key={p.kind} onClick={() => add(p.kind)}
                  className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-[11px] text-ink-300 hover:bg-white/5 hover:text-white transition-colors text-left">
                  <Icon className="w-3.5 h-3.5 shrink-0" style={{ color: TYPE_COLOR[p.type] ?? tk('violet') }} />
                  <span className="truncate">{p.label}</span>
                </button>
              )
            })}
          </div>

          {/* Canvas */}
          <div className="flex-1 overflow-y-auto p-5">
            {showVersions && editing ? (
              <div className="space-y-2">
                <p className="text-[11px] text-ink-500 uppercase tracking-wider mb-1">Version history</p>
                {versions.map((v) => (
                  <div key={v.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-surface-2/60 border border-white/8">
                    <span className="text-xs font-mono text-violet shrink-0">v{v.version}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-[11px] text-ink-200">{v.note} · {v.steps.length} steps</p>
                      <p className="text-[10px] text-ink-600">{v.author} · {new Date(v.createdAt).toLocaleString()}</p>
                    </div>
                    <button onClick={() => revert(v.version)}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] text-violet border border-violet/30 hover:bg-violet/15">
                      <RotateCcw className="w-3 h-3" /> Restore
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-0">
                {steps.length === 0 && (
                  <p className="text-xs text-ink-600 text-center py-16">Add steps from the palette to compose the response flow.</p>
                )}
                {steps.map((s, i) => {
                  const m = meta(s.kind)
                  const Icon = KIND_ICON[s.kind] ?? Plus
                  const color = TYPE_COLOR[m?.type ?? 'action'] ?? tk('threat')
                  return (
                    <div key={s._id}>
                      <div draggable onDragStart={() => setDragIdx(i)}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={() => { if (dragIdx !== null) move(dragIdx, i); setDragIdx(null) }}
                        className="flex items-start gap-2 p-3 rounded-xl border border-white/10 bg-surface-2/60 group">
                        <GripVertical className="w-4 h-4 text-ink-700 mt-0.5 cursor-grab shrink-0" />
                        <div className="p-1.5 rounded-lg shrink-0" style={{ background: `${color}18` }}>
                          <Icon className="w-3.5 h-3.5" style={{ color }} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-[9px] px-1.5 py-0.5 rounded-sm uppercase font-semibold" style={{ color, background: `${color}18` }}>{m?.type ?? 'action'}</span>
                            <input value={s.name} onChange={(e) => setSteps((st) => st.map((x) => x._id === s._id ? { ...x, name: e.target.value } : x))}
                              className="flex-1 bg-transparent text-[12px] text-white focus:outline-hidden border-b border-transparent focus:border-white/15" />
                          </div>
                          {(m?.params ?? []).length > 0 && (
                            <div className="grid grid-cols-2 gap-1.5 mt-2">
                              {m!.params.map((p) => (
                                <input key={p} value={String(s.params?.[p] ?? '')} onChange={(e) => setParam(s._id, p, e.target.value)}
                                  placeholder={p}
                                  className="px-2 py-1 rounded-sm bg-surface-3/60 border border-white/8 text-[10px] font-mono text-ink-200 focus:outline-hidden focus:border-magenta/40 placeholder-ink-700" />
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="flex flex-col gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button onClick={() => move(i, i - 1)} className="text-ink-600 hover:text-white text-[10px]">▲</button>
                          <button onClick={() => move(i, i + 1)} className="text-ink-600 hover:text-white text-[10px]">▼</button>
                          <button onClick={() => setSteps((st) => st.filter((x) => x._id !== s._id))} className="text-ink-600 hover:text-threat"><Trash2 className="w-3 h-3" /></button>
                        </div>
                      </div>
                      {i < steps.length - 1 && <div className="flex justify-center py-1"><ArrowDown className="w-3.5 h-3.5 text-ink-700" /></div>}
                    </div>
                  )
                })}

                {preview && (
                  <div className="mt-4 rounded-xl border border-white/8 bg-[#080614] p-3 space-y-1.5">
                    <p className="text-[10px] text-ink-500 uppercase tracking-wider">Dry-run preview · {preview.status}</p>
                    {preview.steps.map((st) => (
                      <div key={st.idx} className="flex items-start gap-2 text-[10px]">
                        <span className="font-mono text-ink-600 shrink-0">{st.kind}</span>
                        <span className="text-ink-300">{st.detail}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 px-5 py-3 border-t border-white/8 shrink-0">
          {error && <span className="text-[11px] text-threat">{error}</span>}
          <div className="ml-auto flex items-center gap-2">
            {editing && (
              <button onClick={runDry} disabled={busy}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white">
                <Play className="w-3.5 h-3.5" /> Dry-run
              </button>
            )}
            <button onClick={save} disabled={busy || !name.trim() || steps.length === 0}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-magenta/20 border border-magenta/35 text-magenta hover:bg-magenta/30 disabled:opacity-40">
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
              {editing ? 'Save version' : 'Create playbook'}
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}
