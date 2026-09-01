'use client'

import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Crosshair, X, ShieldCheck, ShieldAlert, ExternalLink } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchAttackCoverage, type AttackCoverage, type AttackTechnique } from '@/lib/api'
import { tk } from '@/lib/colors'

export default function AttackNavigatorPage() {
  const [cov, setCov] = useState<AttackCoverage | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AttackTechnique | null>(null)

  useEffect(() => {
    const load = () => fetchAttackCoverage().then(setCov).catch(() => {}).finally(() => setLoading(false))
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  // Deep-link: ?technique=<T1234> opens that technique's coverage drawer once
  // the matrix has loaded - the Entity Risk drill-down links each observed
  // technique straight to its coverage record here.
  const techDeepLinked = useRef(false)
  useEffect(() => {
    if (techDeepLinked.current || !cov) return
    techDeepLinked.current = true
    const id = new URLSearchParams(window.location.search).get('technique')
    if (!id) return
    const match = cov.tactics.flatMap((tac) => tac.techniques).find((t) => t.technique === id)
    if (match) setSelected(match)
  }, [cov])

  function cellColor(t: AttackTechnique): string {
    if (!t.covered) return 'rgba(255,255,255,0.04)'
    if (t.alerts >= 20) return tk('magenta')
    if (t.alerts >= 5) return tk('threat')
    if (t.alerts > 0) return tk('amber')
    return tk('safe')  // covered, no alerts yet
  }

  const kpis = [
    { label: 'Techniques', value: cov?.summary.techniques ?? 0, color: 'text-white' },
    { label: 'Covered', value: cov?.summary.covered ?? 0, color: 'text-safe' },
    // The actionable number, and the reason this page is worth opening: not
    // "which of ATT&CK's 697 techniques do we miss" - almost all of them, for
    // every SOC that has ever existed - but "which techniques do the malware
    // families in OUR OWN STORE use, that nothing here would see". A separate
    // "coverage gaps" KPI sat beside it reading the same number, because every
    // technique on this grid is one something here touches: two labels, one
    // measure, and a reader left wondering which one was broken.
    { label: 'Blind to our own threats', value: cov?.summary.threatGaps ?? 0, color: 'text-threat' },
    { label: 'Coverage', value: `${cov?.summary.coveragePct ?? 0}%`, color: 'text-violet' },
  ]

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      <div className="flex items-center justify-between gap-3 px-6 py-4 border-b border-white/5 shrink-0 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">ATT&amp;CK Navigator</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">
            Detection coverage by MITRE technique, ranked within each tactic by how much of
            <em> this store </em> uses it — green = covered, brighter = more alerts, dim = gap
          </p>
        </div>
        <div className="flex items-center gap-3 text-[9px] text-ink-500">
          {[['Gap', 'rgba(255,255,255,0.12)'], ['Covered', tk('safe')], ['Active', tk('amber')], ['Hot', tk('magenta')]].map(([l, c]) => (
            <div key={l} className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm" style={{ background: c as string }} />{l}</div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {kpis.map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-6">
        {loading && <p className="text-xs text-ink-600 py-10 text-center animate-pulse">Loading coverage…</p>}
        {!loading && cov && (
          <div className="flex gap-3 min-w-max">
            {cov.tactics.map((tac) => (
              <div key={tac.tactic} className="w-44 shrink-0">
                <div className="text-[10px] font-semibold text-ink-300 uppercase tracking-wide mb-2 h-8 leading-tight">{tac.tactic}</div>
                <div className="space-y-1.5">
                  {tac.techniques.map((t) => (
                    <button key={t.technique} onClick={() => setSelected(t)}
                      className="w-full text-left p-2 rounded-lg border border-white/8 hover:border-white/20 transition-colors"
                      style={{ background: cellColor(t) + (t.covered ? '22' : ''), borderColor: t.covered ? cellColor(t) + '55' : undefined }}>
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-[10px] font-mono" style={{ color: t.covered ? cellColor(t) : '#6b6385' }}>{t.technique}</span>
                        {t.covered ? <ShieldCheck className="w-3 h-3" style={{ color: cellColor(t) }} /> : <ShieldAlert className="w-3 h-3 text-ink-700" />}
                      </div>
                      <p className="text-[10px] text-ink-300 leading-tight mt-0.5 truncate">{t.name}</p>
                      <p className="text-[9px] text-ink-600 mt-0.5">{t.rules} rule{t.rules === 1 ? '' : 's'} · {t.alerts} alerts</p>
                      {/* The cell that matters: families in THIS store use this
                          technique and nothing here would see it. A blank cell
                          for a technique none of our threats use is a gap of no
                          consequence; this one is the next rule to write. */}
                      {t.threatGap && (t.familyCount ?? 0) > 0 && (
                        <p className="text-[9px] text-threat mt-0.5 font-semibold truncate"
                          title={`${(t.families ?? []).map((f) => f.label).join(', ')} — ${(t.indicators ?? 0).toLocaleString()} indicators in this store, and no enabled rule covers it`}>
                          ⚠ {t.familyCount} famil{t.familyCount === 1 ? 'y' : 'ies'} here · {(t.indicators ?? 0).toLocaleString()}
                        </p>
                      )}
                      {!t.threatGap && (t.familyCount ?? 0) > 0 && (
                        <p className="text-[9px] text-ink-600 mt-0.5 truncate"
                          title={(t.families ?? []).map((f) => f.label).join(', ')}>
                          {t.familyCount} famil{t.familyCount === 1 ? 'y' : 'ies'} here
                        </p>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <AnimatePresence>
        {selected && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs" onClick={() => setSelected(null)}>
            <motion.div initial={{ x: 420 }} animate={{ x: 0 }} exit={{ x: 420 }} transition={{ type: 'tween', duration: 0.2 }}
              onClick={(e) => e.stopPropagation()} className="w-full max-w-sm h-full bg-surface border-l border-white/8 overflow-y-auto p-5 space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-[10px] font-mono text-magenta">{selected.technique}</p>
                  <h2 className="text-sm font-semibold text-white">{selected.name}</h2>
                </div>
                <button onClick={() => setSelected(null)} className="p-1.5 rounded-lg text-ink-500 hover:text-white"><X className="w-4 h-4" /></button>
              </div>
              <div className={cn('px-3 py-2.5 rounded-xl border text-xs',
                selected.covered ? 'border-safe/25 bg-safe/10 text-safe' : 'border-amber/25 bg-amber/10 text-amber')}>
                {selected.covered
                  ? (selected.coveredBy
                      // Inherited from a parent: detecting "command interpreter
                      // execution" catches PowerShell and cmd alike. Said out
                      // loud, because "covered" the reader cannot check is not
                      // a claim worth making.
                      ? `Covered through ${selected.coveredBy}, the parent technique — a rule there sees this one too.`
                      : `Covered by ${selected.rules} detection rule${selected.rules === 1 ? '' : 's'}.`)
                  : 'Coverage gap — no enabled rule maps to this technique.'}
              </div>

              {/* Whose problem this is. A gap matters in proportion to what your
                  own feeds say is out there using it. */}
              {(selected.familyCount ?? 0) > 0 && (
                <div className={cn('px-3 py-2.5 rounded-xl border',
                  selected.threatGap ? 'border-threat/25 bg-threat/8' : 'border-white/8 bg-surface-2/40')}>
                  <p className="text-[11px] text-ink-200">
                    <b className="tabular-nums">{selected.familyCount}</b>{' '}
                    famil{selected.familyCount === 1 ? 'y' : 'ies'} in this store use{selected.familyCount === 1 ? 's' : ''} it,
                    across <b className="tabular-nums">{(selected.indicators ?? 0).toLocaleString()}</b> indicators.
                  </p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {(selected.families ?? []).map((f) => (
                      <a key={f.key} href={`/dashboard/cti/malware/${encodeURIComponent(f.key)}`}
                        className="px-1.5 py-0.5 rounded border border-magenta/25 bg-magenta/10 text-[10px]
                                   text-magenta hover:bg-magenta/20 transition-all hover:scale-105">
                        {f.label}
                      </a>
                    ))}
                  </div>
                  <p className="text-[10px] text-ink-600 mt-2 leading-snug">
                    From MITRE&apos;s record of what these families do. It says these threats use this
                    technique — not that any of them has been on this network.
                  </p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2">
                <div className="px-3 py-2 rounded-lg bg-surface-2/60 border border-white/8"><div className="text-lg font-bold font-mono text-white">{selected.rules}</div><div className="text-[10px] text-ink-500">rules</div></div>
                <div className="px-3 py-2 rounded-lg bg-surface-2/60 border border-white/8"><div className="text-lg font-bold font-mono text-magenta">{selected.alerts}</div><div className="text-[10px] text-ink-500">alerts observed</div></div>
              </div>
              <div className="flex flex-col gap-2 pt-1">
                <a href={`/dashboard/siem?q=${selected.technique}`} className="flex items-center justify-between px-3 py-2.5 rounded-xl border border-white/10 text-xs text-ink-200 hover:border-magenta/40 hover:bg-magenta/5 transition-colors">View matching alerts<ExternalLink className="w-3.5 h-3.5" /></a>
                <a href="/dashboard/siem/rules" className="flex items-center justify-between px-3 py-2.5 rounded-xl border border-white/10 text-xs text-ink-200 hover:border-magenta/40 hover:bg-magenta/5 transition-colors">{selected.covered ? 'Review rules' : 'Author a rule for this technique'}<ExternalLink className="w-3.5 h-3.5" /></a>
                <a href={`https://attack.mitre.org/techniques/${selected.technique.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer" className="flex items-center justify-between px-3 py-2.5 rounded-xl border border-white/10 text-xs text-ink-400 hover:text-white transition-colors">MITRE ATT&amp;CK reference<ExternalLink className="w-3.5 h-3.5" /></a>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
