'use client'
import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Award, Loader2, Check, Info, AlertTriangle, Radio, CloudOff } from 'lucide-react'
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
/**
 * A second thing this panel now has to say, learned the hard way.
 *
 * `values` is history. A feed that died last week still shows the 200,000 values
 * it contributed before it died, so the row looks healthy - and that is exactly
 * how all thirty-five malware-family trails returned 404 for days after the
 * upstream project moved them, while every sync reported success and this panel
 * showed nothing wrong. A dead feed and a quiet feed look identical at the count.
 *
 * So the LAST FETCH is now the first thing a row says, failing sources sort to
 * the top regardless of size, and "failing" carries the date it started.
 */
/** Reachability, not correctness. A feed can be perfectly reachable and wrong;
 *  that is what the Admiralty grade below is for. */
const HEALTH: Record<string, { label: string; color: string; icon: typeof Radio; hint: string }> = {
  failed: { label: 'not answering', color: tk('magenta'), icon: AlertTriangle,
    hint: 'The last fetch failed. The store keeps this source\u2019s existing values but is learning nothing new from it.' },
  mirrored: { label: 'via mirror', color: tk('amber'), icon: CloudOff,
    hint: 'This source\u2019s own host refused the connection, so the same list was fetched from somewhere that republishes it. Same source, different host.' },
  ok: { label: 'answering', color: tk('safe'), icon: Radio, hint: 'The last fetch returned content.' },
  unchanged: { label: 'no change', color: tk('safe'), icon: Radio,
    hint: 'The source answered and had nothing new. That is a healthy feed, not a silent one.' },
}

/** "failing since Tuesday" beats "failing". */
function sinceLabel(iso: string | null): string | null {
  if (!iso) return null
  const then = new Date(iso).getTime()
  if (!Number.isFinite(then)) return null
  const days = Math.floor((Date.now() - then) / 86_400_000)
  if (days <= 0) return 'today'
  if (days === 1) return 'yesterday'
  if (days < 31) return `${days} days ago`
  return new Date(iso).toLocaleDateString()
}

/** The detail worth showing. A source that fetched everything it was asked for
 *  has nothing to report, and printing "all 35 family trails fetched" on a green
 *  row trains people to skip the line that matters when one is missing. */
function detailOf(s: IntelSource): string | null {
  if (!s.statusDetail) return null
  if (s.status !== 'failed' && !/unavailable|unreachable/i.test(s.statusDetail)) return null
  return s.statusDetail
}

function HealthPill({ s }: { s: IntelSource }) {
  const h = s.status ? HEALTH[s.status] : null
  if (!h) return null
  const Icon = h.icon
  const since = sinceLabel(s.lastOk)
  return (
    <span
      title={`${h.hint}${since ? `\n\nLast answered: ${since}.` : ''}${s.servedVia ? `\n\nServed from: ${s.servedVia}` : ''}`}
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[9px] font-medium
                 transition-transform hover:scale-105 cursor-default shrink-0"
      style={{ color: h.color, borderColor: `${h.color}40`, background: `${h.color}12` }}>
      <Icon className="w-2.5 h-2.5" />
      {h.label}
      {s.status === 'failed' && since && (
        <span className="opacity-70">· last ok {since}</span>
      )}
    </span>
  )
}

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
      .then((r) => {
        // Failing sources first, whatever their size. The API sorts by value
        // count, which is precisely the order that hides an outage: the feeds
        // that contributed most before they died sort to the top and look like
        // the healthiest rows on the page.
        const rank = (x: IntelSource) => (x.status === 'failed' ? 0 : x.status === 'mirrored' ? 1 : 2)
        setSources([...r.items].sort((a, b) => rank(a) - rank(b) || b.values - a.values))
        setScale(r.scale); setErr(null)
      })
      .catch(() => setErr('Could not load intel sources.'))
      .finally(() => setLoading(false))
  }, [])
  useEffect(load, [load])

  const broken = sources.filter((s) => s.status === 'failed')

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

      {/* Reachability before reliability. There is no point weighing how much to
          trust a source that is not answering. */}
      {broken.length > 0 && (
        <div className="px-5 py-2.5 border-b flex items-start gap-2"
          style={{ borderColor: `${tk('magenta')}25`, background: `${tk('magenta')}0d` }}>
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" style={{ color: tk('magenta') }} />
          <p className="text-[10px] leading-snug" style={{ color: tk('magenta') }}>
            <span className="font-semibold">
              {broken.length} source{broken.length > 1 ? 's are' : ' is'} not answering
            </span>
            <span className="text-ink-400">
              {' — '}{broken.map((b) => b.name).join(', ')}. Their existing values are still
              in the store and still scored; they are simply not learning anything new.
            </span>
          </p>
        </div>
      )}

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
                    <div className="flex items-center gap-2 min-w-0">
                      <p className="text-[11px] text-white truncate" title={s.id}>{s.name}</p>
                      <HealthPill s={s} />
                    </div>
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
                {/* What went wrong, in the words it arrived in - or, on a
                    source that is answering but no longer complete, exactly what
                    is missing. "4 of 35 family trails unavailable: redline, ..."
                    is a coverage decision somebody should get to make; a green
                    row saying nothing is not. A clean success has nothing to add
                    here, so it stays quiet. */}
                {detailOf(s) && (
                  <p className="text-[10px] mt-1.5 leading-snug max-w-2xl"
                    style={{ color: s.status === 'failed' ? tk('magenta') : tk('amber') }}>
                    {detailOf(s)}
                  </p>
                )}
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
