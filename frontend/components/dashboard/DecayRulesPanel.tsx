'use client'
import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Hourglass, Loader2, RotateCcw, Check } from 'lucide-react'
import { tk } from '@/lib/colors'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import { fetchDecayRules, updateDecayRule, type DecayRule } from '@/lib/api'

/**
 * Decay policy, editable.
 *
 * How fast intel stops being worth acting on is a policy decision that differs
 * per deployment - a bank hunting payment fraud and a hosting provider fighting
 * abuse do not agree on how long a phishing URL stays actionable. It used to be
 * a constant in the source, which in practice means nobody ever tunes it and the
 * platform quietly imposes one opinion on every customer.
 *
 * The shipped values are exactly the previous hardcoded ones, so nothing changes
 * until somebody deliberately changes it.
 */
export default function DecayRulesPanel() {
  const [rules, setRules] = useState<DecayRule[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  // Pending edits per rule, so a half-typed number never hits the API.
  const [draft, setDraft] = useState<Record<string, { hl: string; revoke: string }>>({})

  const load = useCallback(() => {
    setLoading(true)
    fetchDecayRules()
      .then((rs) => {
        setRules(rs)
        setDraft(Object.fromEntries(rs.map((r) => [r.id, {
          hl: String(r.halfLifeDays), revoke: String(r.revokeScore),
        }])))
      })
      .catch(() => setErr('Could not load decay rules.'))
      .finally(() => setLoading(false))
  }, [])
  useEffect(load, [load])

  function save(r: DecayRule) {
    const d = draft[r.id]
    if (!d) return
    const hl = Number(d.hl)
    const revoke = Number(d.revoke)
    // Checked here as well as server-side: a 0-day half-life expires the whole
    // store instantly, and the server's 400 is a worse way to learn that.
    if (!Number.isFinite(hl) || hl < 1 || hl > 3650) {
      setErr('Half-life must be between 1 and 3650 days.'); return
    }
    if (!Number.isFinite(revoke) || revoke < 1 || revoke > 99) {
      setErr('Revoke score must be between 1 and 99 - at 100 every indicator is '
             + 'revoked the moment it is imported.'); return
    }
    setErr(null)
    setSaving(r.id)
    updateDecayRule(r.id, { half_life_days: hl, revoke_score: revoke })
      .then((updated) => {
        setRules((cur) => cur.map((x) => (x.id === updated.id ? updated : x)))
        setSaved(r.id)
        window.setTimeout(() => setSaved((s) => (s === r.id ? null : s)), 2000)
      })
      .catch(() => setErr('Could not save (needs cti.write).'))
      .finally(() => setSaving(null))
  }

  const dirty = (r: DecayRule) => {
    const d = draft[r.id]
    return !!d && (Number(d.hl) !== r.halfLifeDays || Number(d.revoke) !== r.revokeScore)
  }

  return (
    <motion.div variants={fadeInUp} initial="hidden" animate="show"
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5">
        <div className="p-1.5 rounded-lg bg-amber/15 border border-amber/25 shrink-0">
          <Hourglass className="w-4 h-4 text-amber" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Indicator decay policy</h3>
          <p className="text-[10px] text-ink-500">
            How fast intel stops being actionable. Applied on the next maintenance pass.
          </p>
        </div>
        <button onClick={load} title="Reload"
          className="ml-auto p-1.5 rounded-lg text-ink-500 hover:text-amber hover:bg-amber/10 transition-colors">
          <RotateCcw className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="px-5 py-3 border-b border-white/5">
        <p className="text-[10px] text-ink-500 leading-relaxed">
          An indicator&apos;s confidence halves once per <b className="text-ink-300">half-life</b>.
          At the <b className="text-ink-300">revoke score</b> it stops matching, so
          stale intel cannot raise alerts. The shipped values are the ones this
          platform used before they were editable - nothing changes until you
          change it.
        </p>
      </div>

      {err && (
        <p className="mx-5 my-3 text-[11px] text-magenta bg-magenta/10 border border-magenta/25 rounded-lg px-3 py-2">
          {err}
        </p>
      )}

      <div className="divide-y divide-white/4">
        {loading && <p className="text-[11px] text-ink-600 py-8 text-center animate-pulse">Loading policy…</p>}
        {!loading && rules.length === 0 && (
          <p className="text-[11px] text-ink-600 py-8 text-center">No decay rules configured.</p>
        )}
        {rules.map((r) => (
          <div key={r.id} className="px-5 py-3">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className="text-[11px] text-white">{r.name}</span>
              {r.builtin && (
                <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-white/6 text-ink-500 uppercase">
                  builtin
                </span>
              )}
              {!r.enabled && (
                <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase"
                  style={{ color: tk('amber'), background: `${tk('amber')}18` }}>
                  disabled
                </span>
              )}
              <span className="text-[9px] text-ink-600 font-mono truncate">
                {r.appliesTo.join(', ')}
              </span>
            </div>
            <div className="flex items-end gap-3 flex-wrap">
              <label className="block">
                <span className="block text-[9px] text-ink-600 mb-0.5">Half-life (days)</span>
                <input type="number" min={1} max={3650} value={draft[r.id]?.hl ?? ''}
                  onChange={(e) => setDraft((d) => ({ ...d, [r.id]: { ...d[r.id], hl: e.target.value } }))}
                  className="w-24 px-2 py-1 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 font-mono focus:outline-hidden focus:border-amber/40" />
              </label>
              <label className="block">
                <span className="block text-[9px] text-ink-600 mb-0.5">Revoke score</span>
                <input type="number" min={1} max={99} value={draft[r.id]?.revoke ?? ''}
                  onChange={(e) => setDraft((d) => ({ ...d, [r.id]: { ...d[r.id], revoke: e.target.value } }))}
                  className="w-24 px-2 py-1 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 font-mono focus:outline-hidden focus:border-amber/40" />
              </label>
              <div className="min-w-0">
                <span className="block text-[9px] text-ink-600 mb-0.5">Reaction points</span>
                <div className="flex items-center gap-1 h-[26px]">
                  {r.reactionPoints.length === 0
                    ? <span className="text-[10px] text-ink-700">none</span>
                    : r.reactionPoints.map((p) => (
                      <span key={p} title="Reported as the score falls through this value"
                        className="text-[9px] font-mono px-1.5 py-0.5 rounded-sm bg-white/6 text-ink-400">
                        {p}
                      </span>
                    ))}
                </div>
              </div>
              <button onClick={() => save(r)} disabled={!dirty(r) || saving === r.id}
                className={cn('ml-auto px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-colors flex items-center gap-1.5',
                  dirty(r)
                    ? 'bg-amber/15 border border-amber/30 text-amber hover:bg-amber/25'
                    : 'border border-white/8 text-ink-600 cursor-not-allowed')}>
                {saving === r.id ? <Loader2 className="w-3 h-3 animate-spin" />
                  : saved === r.id ? <Check className="w-3 h-3" /> : null}
                {saved === r.id ? 'Saved' : 'Save'}
              </button>
            </div>
            {/* What the numbers mean in practice, computed from what is typed -
                so the effect is visible before it is committed to 315k rows. */}
            <p className="text-[9px] text-ink-600 mt-1.5">
              An indicator asserted at 80% reaches its revoke score after{' '}
              <span className="font-mono text-ink-400">
                {(() => {
                  const hl = Number(draft[r.id]?.hl)
                  const rv = Number(draft[r.id]?.revoke)
                  if (!Number.isFinite(hl) || !Number.isFinite(rv) || hl < 1 || rv < 1 || rv >= 80) return '—'
                  return `${Math.round(hl * Math.log2(80 / rv))} days`
                })()}
              </span>
              , or sooner if nothing re-asserts it.
            </p>
          </div>
        ))}
      </div>
    </motion.div>
  )
}
