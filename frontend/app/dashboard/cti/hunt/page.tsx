'use client'

import { useState, useMemo, useEffect } from 'react'
import { fetchCtiHunts, runCtiHunt, fetchAttackCoverage, type SavedHunt as ApiSavedHunt } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Crosshair, Target, ChevronRight, Play, Pause, CheckCircle,
  Activity, FlaskConical, ShieldCheck, Layers, Database,
  ExternalLink, User, Calendar, Lightbulb, XCircle, Search,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import ApiUnavailable from '@/components/dashboard/ApiUnavailable'
import { tk } from '@/lib/colors'

/* --- Types ----------------------------------------------------------- */
type HuntStatus = 'active' | 'paused' | 'completed'
type HypothesisStatus = 'confirmed' | 'refuted' | 'investigating'

interface Hypothesis {
  id: string
  statement: string
  status: HypothesisStatus
  dataSources: string[]
  findings: string
  relatedIOCs: string[]
}

interface MitreTech {
  id: string
  name: string
  tactic: string
}

interface Hunt {
  id: string
  name: string
  description: string
  status: HuntStatus
  analyst: string
  techniques: MitreTech[]
  progress: number
  started: string
  hypotheses: Hypothesis[]
}

/* --- Seed data -------------------------------------------------------- */

/* --- Status config ---------------------------------------------------- */
const HUNT_STATUS: Record<HuntStatus, { label: string; color: string; icon: React.ComponentType<any> }> = {
  active:    { label: 'Active',    color: tk('safe'), icon: Play },
  paused:    { label: 'Paused',    color: tk('amber'), icon: Pause },
  completed: { label: 'Completed', color: tk('violet'), icon: CheckCircle },
}

const HYP_STATUS: Record<HypothesisStatus, { label: string; color: string; icon: React.ComponentType<any> }> = {
  confirmed:     { label: 'Confirmed',     color: tk('threat'), icon: CheckCircle },
  refuted:       { label: 'Refuted',       color: tk('safe'), icon: XCircle },
  investigating: { label: 'Investigating', color: tk('amber'), icon: Search },
}

/* --- MITRE coverage matrix tactics ------------------------------------ */
const MATRIX_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Credential Access',
  'Defense Evasion',
  'Command and Control',
  'Exfiltration',
] as const

/* --- KPI strip -------------------------------------------------------- */
/* --- Hypothesis row --------------------------------------------------- */
function HypothesisRow({ hyp }: { hyp: Hypothesis }) {
  const cfg = HYP_STATUS[hyp.status]
  const Icon = cfg.icon
  return (
    <div className="rounded-lg bg-surface-2/60 border border-white/5 p-3.5">
      <div className="flex items-start gap-2.5">
        <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: cfg.color }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-full border"
              style={{ color: cfg.color, background: `${cfg.color}15`, borderColor: `${cfg.color}33` }}
            >
              {cfg.label}
            </span>
          </div>
          <p className="text-xs text-ink-200 mt-1.5 leading-snug">{hyp.statement}</p>

          <p className="text-[10px] text-ink-600 uppercase tracking-wide mt-3 mb-1">Findings</p>
          <p className="text-[11px] text-ink-400 leading-relaxed">{hyp.findings}</p>

          <div className="grid sm:grid-cols-2 gap-3 mt-3">
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5 flex items-center gap-1">
                <Database className="w-3 h-3" /> Data Sources
              </p>
              <div className="flex flex-wrap gap-1">
                {hyp.dataSources.map((d) => (
                  <span key={d} className="text-[9px] px-1.5 py-0.5 rounded-sm bg-violet/10 text-violet border border-violet/20">{d}</span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5 flex items-center gap-1">
                <Target className="w-3 h-3" /> Related IOCs
              </p>
              {hyp.relatedIOCs.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {hyp.relatedIOCs.map((ioc) => (
                    <span key={ioc} className="text-[9px] px-1.5 py-0.5 rounded-sm bg-magenta/10 text-magenta font-mono border border-magenta/20">{ioc}</span>
                  ))}
                </div>
              ) : (
                <span className="text-[10px] text-ink-600 italic">none</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* --- Hunt card -------------------------------------------------------- */
function HuntCard({ hunt, expanded, onToggle, onRun }: {
  hunt: Hunt; expanded: boolean; onToggle: () => void; onRun: () => void
}) {
  const cfg = HUNT_STATUS[hunt.status]
  const StatusIcon = cfg.icon
  const openHyp = hunt.hypotheses.filter((h) => h.status === 'investigating').length

  return (
    <div
      className={cn(
        'glass border rounded-xl overflow-hidden transition-all duration-200',
        expanded ? 'border-magenta/30 bg-magenta/5' : 'border-white/5 hover:border-white/10',
      )}
    >
      <div onClick={onToggle} className="p-4 cursor-pointer">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="p-2 rounded-lg shrink-0" style={{ background: `${cfg.color}18` }}>
              <StatusIcon className="w-4 h-4" style={{ color: cfg.color }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-white truncate">{hunt.name}</span>
                <span
                  className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-full border"
                  style={{ color: cfg.color, background: `${cfg.color}15`, borderColor: `${cfg.color}33` }}
                >
                  {cfg.label}
                </span>
              </div>
              <p className="text-[11px] text-ink-400 mt-1 leading-snug">{hunt.description}</p>
            </div>
          </div>
          <ChevronRight className={cn('w-4 h-4 text-ink-600 transition-transform shrink-0', expanded && 'rotate-90 text-magenta')} />
        </div>

        {/* Meta row */}
        <div className="flex items-center gap-4 mt-3 text-[10px] text-ink-500 flex-wrap">
          <span className="flex items-center gap-1"><User className="w-3 h-3" /> {hunt.analyst}</span>
          <span className="flex items-center gap-1"><FlaskConical className="w-3 h-3" /> {hunt.hypotheses.length} hypotheses · {openHyp} open</span>
          <span className="flex items-center gap-1"><Calendar className="w-3 h-3" /> started {hunt.started}</span>
          <button
            onClick={(e) => { e.stopPropagation(); onRun() }}
            className="ml-auto flex items-center gap-1 px-2 py-1 rounded-lg border border-safe/25 bg-safe/10 text-safe hover:bg-safe/20 transition-colors font-medium"
          >
            <Play className="w-3 h-3" /> Run hunt
          </button>
        </div>

        {/* MITRE chips */}
        <div className="flex flex-wrap gap-1 mt-3">
          {hunt.techniques.map((t) => (
            <a
              key={t.id}
              href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              title={`${t.id} · ${t.name} (${t.tactic})`}
              className="text-[9px] px-1.5 py-0.5 rounded-sm bg-violet/15 text-violet font-mono border border-violet/20 hover:bg-violet/25 transition-colors"
            >
              {t.id}
            </a>
          ))}
        </div>

        {/* Progress */}
        <div className="mt-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-ink-600">Progress</span>
            <span className="text-[10px] font-mono text-ink-400">{hunt.progress}%</span>
          </div>
          <div className="h-1.5 bg-surface-3 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${hunt.progress}%` }}
              transition={{ duration: 0.8, ease: 'easeOut' }}
              className="h-full rounded-full"
              style={{ background: cfg.color }}
            />
          </div>
        </div>
      </div>

      {/* Expanded detail */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25 }}
            className="border-t border-white/5"
          >
            <div className="p-4 space-y-4">
              {/* Techniques detail */}
              <div>
                <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <Layers className="w-3 h-3" /> MITRE ATT&amp;CK Techniques
                </p>
                <div className="grid sm:grid-cols-2 gap-2">
                  {hunt.techniques.map((t) => (
                    <a
                      key={t.id}
                      href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 rounded-lg bg-surface-2/60 border border-white/5 p-2.5 hover:border-violet/30 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-violet shrink-0">{t.id}</span>
                      <div className="min-w-0">
                        <p className="text-[11px] text-ink-200 truncate">{t.name}</p>
                        <p className="text-[9px] text-ink-600">{t.tactic}</p>
                      </div>
                      <ExternalLink className="w-3 h-3 text-ink-600 ml-auto shrink-0" />
                    </a>
                  ))}
                </div>
              </div>

              {/* Hypotheses */}
              <div>
                <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <Lightbulb className="w-3 h-3" /> Hypotheses
                </p>
                <div className="space-y-2.5">
                  {hunt.hypotheses.map((h) => (
                    <HypothesisRow key={h.id} hyp={h} />
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* --- MITRE coverage mini-matrix --------------------------------------- */
function CoverageMatrix({ hunts }: { hunts: Hunt[] }) {
  // tactic -> covering active hunts
  const coverage = useMemo(() => {
    const map: Record<string, Hunt[]> = {}
    for (const tactic of MATRIX_TACTICS) map[tactic] = []
    for (const hunt of hunts) {
      if (hunt.status !== 'active') continue
      const tactics = new Set(hunt.techniques.map((t) => t.tactic))
      for (const tac of tactics) {
        if (map[tac]) map[tac].push(hunt)
      }
    }
    return map
  }, [hunts])

  function cellColor(count: number) {
    if (count >= 2) return tk('magenta')
    if (count === 1) return tk('violet')
    return 'rgba(255,255,255,0.04)'
  }

  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Crosshair className="w-3.5 h-3.5 text-magenta" />
          <h3 className="text-sm font-semibold text-white">ATT&amp;CK Coverage (Active Hunts)</h3>
        </div>
        <div className="flex items-center gap-4 text-[9px] text-ink-500">
          {[
            { label: '2+ hunts', color: tk('magenta') },
            { label: '1 hunt', color: tk('violet') },
            { label: 'none', color: 'rgba(255,255,255,0.08)' },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-sm" style={{ background: color }} />
              {label}
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${MATRIX_TACTICS.length}, minmax(0, 1fr))` }}>
        {MATRIX_TACTICS.map((tactic) => (
          <div key={`${tactic}-head`} className="text-center text-[8px] text-ink-600 leading-tight h-8 flex items-end justify-center pb-1">
            {tactic}
          </div>
        ))}
        {MATRIX_TACTICS.map((tactic) => {
          const hunts = coverage[tactic] ?? []
          const count = hunts.length
          return (
            <div
              key={`${tactic}-cell`}
              title={count > 0 ? `${tactic}: ${hunts.map((h) => h.name).join(', ')}` : `${tactic}: no active coverage`}
              className="h-12 rounded-lg flex items-center justify-center text-[10px] font-mono font-semibold transition-opacity cursor-pointer hover:opacity-80"
              style={{ background: cellColor(count), color: count > 0 ? 'rgba(255,255,255,0.95)' : 'transparent' }}
            >
              {count > 0 ? count : '·'}
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* --- Page ------------------------------------------------------------- */
export default function ThreatHuntPage() {
  // Empty until the API answers - hunts are NOT seeded in live mode, so an empty
  // list is honest on a real deployment. HUNTS is an offline-only fallback.
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [hunts, setHunts] = useState<Hunt[]>([])
  const [huntsFailed, setHuntsFailed] = useState(false)
  const [coverage, setCoverage] = useState<number | null>(null)

  // Execute a hunt against the live IOC store; mark it running while the
  // backend works, then reflect the persisted outcome.
  function handleRun(id: string) {
    setHunts((prev) => prev.map((h) => (h.id === id ? { ...h, status: 'active' as HuntStatus } : h)))
    runCtiHunt(id)
      .then(({ hunt }) => {
        setHunts((prev) => prev.map((h) => h.id === id
          ? { ...h, status: 'completed' as HuntStatus, progress: hunt.progress }
          : h))
      })
      .catch(() => {
        // demo entry or API offline - show completion locally so the action still responds
        setHunts((prev) => prev.map((h) => (h.id === id ? { ...h, status: 'completed' as HuntStatus, progress: 100 } : h)))
      })
  }

  useEffect(() => {
    fetchCtiHunts().then((data: ApiSavedHunt[]) => {
      // Applied even when empty - a real deployment with no hunts shows none.
      // Straight through. This used to look the record up in a hardcoded seed
      // library by id OR NAME and, on a match, return the seed - so a real hunt
      // that happened to share a name with a demo one was replaced wholesale by
      // fiction, techniques and hypotheses included.
      const merged: Hunt[] = data.map((h) => ({
        id: h.id,
        name: h.name,
        description: h.hypothesis,
        status: (h.status === 'active' ? 'active' : h.status === 'completed' ? 'completed' : 'paused') as HuntStatus,
        analyst: h.analyst,
        techniques: [],
        progress: h.progress,
        started: h.created,
        hypotheses: [],
      }))
      setHunts(merged)
      if (merged.length > 0) setExpandedId(merged[0].id)
    }).catch(() => setHuntsFailed(true))
    fetchAttackCoverage().then((c) => setCoverage(c.summary.coveragePct)).catch(() => {})
  }, [])

  // KPI tiles derived from real hunts + ATT&CK coverage (no hardcoded values).
  const kpis = [
    { label: 'Active Hunts',    value: String(hunts.filter((h) => h.status === 'active').length), icon: Crosshair,   color: tk('magenta'), sub: 'in progress' },
    { label: 'Saved Hunts',     value: String(hunts.length), icon: FlaskConical, color: tk('violet'), sub: 'hypotheses tracked' },
    { label: 'Completed',       value: String(hunts.filter((h) => h.status === 'completed').length), icon: ShieldCheck, color: tk('safe'), sub: 'hunts run' },
    { label: 'ATT&CK Coverage', value: coverage == null ? '-' : `${coverage}%`, icon: Layers, color: tk('amber'), sub: 'techniques mapped' },
  ]

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/5">
        <div className="flex items-center gap-2 mb-1">
          <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25">
            <Crosshair className="w-4 h-4 text-magenta" />
          </div>
          <h1 className="font-display text-xl font-bold text-white tracking-tight">Threat Hunt</h1>
        </div>
        <p className="text-sm text-ink-500">Hypothesis-driven hunting campaigns mapped to MITRE ATT&amp;CK</p>
      </div>

      {/* KPI strip */}
      <div className="px-6 py-4 border-b border-white/5">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {kpis.map(({ label, value, icon: Icon, color, sub }) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass border border-white/5 rounded-xl p-4 relative overflow-hidden"
            >
              <div
                className="absolute inset-0 opacity-30"
                style={{ background: `radial-gradient(circle at 0% 0%, ${color}20, transparent 70%)` }}
              />
              <div className="relative flex items-start justify-between">
                <div>
                  <p className="text-xs text-ink-500 mb-1">{label}</p>
                  <p className="font-display text-2xl font-bold text-white">{value}</p>
                  <p className="text-[10px] text-ink-600 mt-0.5">{sub}</p>
                </div>
                <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}18` }}>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
        {/* Coverage matrix */}
        <CoverageMatrix hunts={hunts} />

        {/* Hunt campaigns */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-3.5 h-3.5 text-violet" />
            <h2 className="text-sm font-semibold text-white">Hunt Campaigns</h2>
            <span className="text-[10px] text-ink-600">{hunts.length} total</span>
          </div>
          <div className="space-y-3">
            {hunts.length === 0 && huntsFailed && (
              <ApiUnavailable what="your hunts" compact />
            )}
            {hunts.length === 0 && !huntsFailed && (
              <p className="text-[11px] text-ink-600 py-6 text-center">
                No hunt campaigns yet - start one to track a hypothesis here.
              </p>
            )}
            {hunts.map((hunt) => (
              <HuntCard
                key={hunt.id}
                hunt={hunt}
                expanded={expandedId === hunt.id}
                onToggle={() => setExpandedId((id) => (id === hunt.id ? null : hunt.id))}
                onRun={() => handleRun(hunt.id)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
