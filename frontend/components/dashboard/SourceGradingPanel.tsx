'use client'
import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Award, Loader2, Check, Info } from 'lucide-react'
import { tk } from '@/lib/colors'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import { fetchIntelSources, gradeIntelSource, type IntelSource, type IntelSourceScale } from '@/lib/api'

/**
 * Admiralty source reliability, editable.
 *
 * The composite score multiplies every claim by its source's grade, which makes
 * this the single most consequential number an operator can set - and it shipped
 * identical for every feed, so the multiplier differentiated nothing. Measured on
 * a real 327,981-indicator store: 20 distinct scores, 95% of them inside a
 * 15-point band, and a list "sorted by relevance" that opened on whichever
 * phishing domain sorted first alphabetically.
 *
 * The shipped grades are OUR starting assessment, and each states the property it
 * rests on: does the feed publish per-entry evidence, is it curated or
 * aggregated, does it age its own entries out. An operator knows things we do not
 * - which feeds have burned them, what their environment looks like - so their
 * grading is recorded against their name and is never overwritten by a later
 * revision of ours.
 */
const GRADE_COLOR: Record<string, string> = {
  A: tk('safe'), B: tk('safe'), C: tk('amber'), D: tk('violet'),
  E: tk('magenta'), F: tk('magenta'),
}

function GradeChip({ grade, active, onClick, title }: {
  grade: string; active: boolean; onClick: () => void; title: string
}) {
  return (
    <button type="button" onClick={onClick} title={title}
      className={cn('w-6 h-6 rounded text-[10px] font-semibold transition-all',
        'border hover:scale-110',
        active ? 'border-transparent text-black' : 'border-white/12 text-ink-500 hover:text-ink-300')}
      style={active ? { background: GRADE_COLOR[grade] } : undefined}>
      {grade}
    </button>
  )
}

export default function SourceGradingPanel() {
  const [sources, setSources] = useState<IntelSource[]>([])
  const [scale, setScale] = useState<IntelSourceScale[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  // `loading` starts true, so the effect never has to set it: the fetch is the
  // only thing it does, and setting state directly in an effect body is the
  // pattern React's lint rule is right to object to.
  const load = useCallback(() => {
    fetchIntelSources()
      .then((r) => { setSources(r.items); setScale(r.scale); setErr(null) })
      .catch(() => setErr('Could not load intel sources.'))
      .finally(() => setLoading(false))
  }, [])
  useEffect(load, [load])

  const grade = async (s: IntelSource, g: string) => {
    if (g === s.reliability) return
    setSaving(s.id); setSaved(null); setErr(null)
    try {
      const updated = await gradeIntelSource(s.id, g)
      setSources((prev) => prev.map((x) => (x.id === s.id
        ? { ...x, reliability: updated.reliability, weight: updated.weight,
            reason: updated.reason, gradedBy: updated.gradedBy, isDefault: false }
        : x)))
      setSaved(s.id)
      window.setTimeout(() => setSaved(null), 2000)
    } catch {
      setErr(`Could not re-grade ${s.name}.`)
    } finally {
      setSaving(null)
    }
  }

  return (
    <motion.div variants={fadeInUp} initial="hidden" animate="show"
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5">
        <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
          <Award className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">How much each source is trusted</h3>
          <p className="text-[10px] text-ink-500">
            Admiralty reliability. Multiplies every score the source contributes —
            so a 90% claim from a feed we cannot judge lands below a 70% claim
            from one we can.
          </p>
        </div>
        {loading && <Loader2 className="ml-auto w-3.5 h-3.5 animate-spin text-ink-600" />}
      </div>

      {err && <p className="px-5 py-3 text-[11px]" style={{ color: tk('magenta') }}>{err}</p>}

      {!loading && sources.length === 0 && (
        <p className="px-5 py-6 text-[11px] text-ink-600 text-center">
          No source has asserted a value yet. Sources appear here after the first sync.
        </p>
      )}

      {sources.length > 0 && (
        <>
          <div className="px-5 py-2.5 border-b border-white/5 flex items-center gap-3 flex-wrap">
            <Info className="w-3 h-3 text-ink-600 shrink-0" />
            {scale.map((s) => (
              <span key={s.grade} className="flex items-center gap-1 text-[10px] text-ink-600">
                <span className="w-2 h-2 rounded-sm" style={{ background: GRADE_COLOR[s.grade] }} />
                <span className="text-ink-400">{s.grade}</span> {s.label}
                <span className="tabular-nums text-ink-600">×{s.weight.toFixed(2)}</span>
              </span>
            ))}
          </div>
          <div className="divide-y divide-white/5">
            {sources.map((s) => (
              <div key={s.id} className="px-5 py-3">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-[11px] text-white truncate" title={s.id}>{s.name}</p>
                    <p className="text-[10px] text-ink-600">
                      <span className="tabular-nums">{s.values.toLocaleString()}</span> values
                      {' · '}
                      {/* Whose judgement is in force. Not decoration: a shipped
                          default may be revised on upgrade, an operator's grading
                          never is. */}
                      <span style={{ color: s.isDefault ? undefined : tk('safe') }}>
                        {s.isDefault ? 'shipped default' : `graded by ${s.gradedBy}`}
                      </span>
                      {' · '}
                      <span className="tabular-nums">×{s.weight.toFixed(2)}</span>
                    </p>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {saving === s.id && <Loader2 className="w-3 h-3 animate-spin text-ink-600 mr-1" />}
                    {saved === s.id && <Check className="w-3 h-3 mr-1" style={{ color: tk('safe') }} />}
                    {scale.map((g) => (
                      <GradeChip key={g.grade} grade={g.grade}
                        active={s.reliability === g.grade}
                        title={`${g.grade} — ${g.label} (×${g.weight.toFixed(2)})`}
                        onClick={() => grade(s, g.grade)} />
                    ))}
                  </div>
                </div>
                {s.reason && (
                  <p className="text-[10px] text-ink-600 mt-1.5 leading-snug max-w-2xl">
                    {s.reason}
                  </p>
                )}
              </div>
            ))}
          </div>
          <p className="px-5 py-3 text-[10px] text-ink-600 border-t border-white/5 leading-snug">
            A change takes effect on the next maintenance pass, which rescores the
            whole store. The shipped grades are our reading of how each feed
            works — whether it publishes evidence per entry, whether it is curated
            or aggregated, whether it retires its own entries — not a measurement
            of how often it is right. If a feed has burned you, that is knowledge
            we do not have: re-grade it and your grading stands.
          </p>
        </>
      )}
    </motion.div>
  )
}
