'use client'

import { useMemo, useState } from 'react'
import Link from 'next/link'
import {
  ListChecks, Loader2, AlertTriangle, ShieldCheck, Download, Search, Eraser,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { SEVERITY_COLOR as SEV_COLOR, tk } from '@/lib/colors'
import EntityHoverCard from '@/components/dashboard/EntityHoverCard'
import { lookupIocsBulk, BULK_LOOKUP_MAX, type BulkLookupRow } from '@/lib/api'

/** Verdict presentation. `unverified` is deliberately NOT styled as a pass:
 *  absence from our intel proves nothing, and colouring it green would turn
 *  "we have never seen this" into "this is safe". */
const VERDICT: Record<string, { label: string; cls: string }> = {
  malicious:  { label: 'Malicious',  cls: 'text-threat border-threat/30 bg-threat/10' },
  suspicious: { label: 'Suspicious', cls: 'text-amber border-amber/30 bg-amber/10' },
  clean:      { label: 'Low',        cls: 'text-ink-300 border-white/10 bg-white/5' },
  benign:     { label: 'Known good', cls: 'text-safe border-safe/30 bg-safe/10' },
  expired:    { label: 'Expired',    cls: 'text-ink-400 border-white/10 bg-white/5' },
  unverified: { label: 'Not in intel', cls: 'text-ink-500 border-white/8 bg-white/2' },
}

const HITS = new Set(['malicious', 'suspicious'])

// Intel-score band -> colour. Distinct from the severity palette on purpose:
// severity is what the indicator would DO, the score is how much evidence
// stands behind the claim.
const BAND_COLOR: Record<string, string> = {
  high: tk('magenta'), moderate: tk('amber'), low: tk('violet'), weak: '#665B7D',
}

/** Split a paste into candidate indicators. Analysts paste log extracts, CSV
 *  columns and one-per-line lists interchangeably, so accept all three rather
 *  than making them reformat first. */
function parseValues(raw: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const piece of raw.split(/[\s,;]+/)) {
    const v = piece.trim().replace(/^["'<(]+|["'>),.]+$/g, '')
    if (v && !seen.has(v)) { seen.add(v); out.push(v) }
  }
  return out
}

export default function BulkCheckPage() {
  const [text, setText] = useState('')
  const [rows, setRows] = useState<BulkLookupRow[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [hitsOnly, setHitsOnly] = useState(false)
  const [elapsed, setElapsed] = useState<number | null>(null)

  const parsed = useMemo(() => parseValues(text), [text])
  const overLimit = parsed.length > BULK_LOOKUP_MAX

  async function run() {
    if (!parsed.length || busy || overLimit) return
    setBusy(true); setError(null)
    const t0 = performance.now()
    try {
      const res = await lookupIocsBulk(parsed)
      setRows(res.results)
      setElapsed(Math.round(performance.now() - t0))
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : 'Bulk check failed.')
      setRows(null)
    } finally {
      setBusy(false)
    }
  }

  const summary = useMemo(() => {
    const s = { total: 0, malicious: 0, suspicious: 0, known: 0, unknown: 0 }
    for (const r of rows ?? []) {
      s.total++
      if (r.verdict === 'malicious') s.malicious++
      else if (r.verdict === 'suspicious') s.suspicious++
      if (r.found) s.known++; else s.unknown++
    }
    return s
  }, [rows])

  const shown = (rows ?? []).filter((r) => !hitsOnly || HITS.has(r.verdict))

  function exportCsv() {
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const csv = [
      'value,verdict,matched_indicator,intel_score,score_band,source_count,sources,'
      + 'severity,confidence,threat_type,actor,source,last_seen',
      ...(rows ?? []).map((r) => [r.value, r.verdict, r.matched ?? '',
        r.found ? (r.intelScore ?? '') : '', r.found ? (r.scoreBand ?? '') : '',
        r.found ? (r.sourceCount ?? 1) : 0, (r.sources ?? []).join('; '), r.severity ?? '',
        r.confidence, r.threatType ?? '', r.actor ?? '', r.source ?? '', r.lastSeen ?? '']
        .map(esc).join(',')),
    ].join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `threatorbit-bulk-check-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#0A0612]">
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <ListChecks className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Bulk check</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">
            Paste indicators from a firewall, proxy or EDR extract and check them all against the
            intel store at once — up to {BULK_LOOKUP_MAX.toLocaleString()} per run.
          </p>
        </div>
        <Link href="/dashboard/scanner"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors">
          <Search className="w-3.5 h-3.5" /> Single-value analysis
        </Link>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-5">
        <div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={7}
            spellCheck={false}
            placeholder={'198.51.100.4\nevil.example\nhttps://phish.example/login\n44d88612fea8a8f36de82e1278abb02f'}
            className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-xs font-mono text-ink-100 focus:outline-hidden focus:border-magenta/40 placeholder-ink-700 resize-y"
          />
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <button
              onClick={run}
              disabled={!parsed.length || busy || overLimit}
              className={cn('flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold transition-all',
                parsed.length && !busy && !overLimit
                  ? 'bg-plasma text-white hover:shadow-magenta-sm'
                  : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
              {busy ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Checking…</>
                    : <><ListChecks className="w-3.5 h-3.5" /> Check {parsed.length || ''}</>}
            </button>
            {(text || rows) && (
              <button onClick={() => { setText(''); setRows(null); setError(null); setElapsed(null) }}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl glass border border-white/10 text-xs text-ink-400 hover:text-white transition-colors">
                <Eraser className="w-3.5 h-3.5" /> Clear
              </button>
            )}
            <span className="text-[10px] text-ink-600">
              {parsed.length.toLocaleString()} unique value{parsed.length === 1 ? '' : 's'} parsed
            </span>
            {overLimit && (
              <span className="text-[10px] text-threat">
                Over the {BULK_LOOKUP_MAX.toLocaleString()} limit — trim the list and run it in batches.
              </span>
            )}
          </div>
        </div>

        {error && (
          <p className="flex items-center gap-2 px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />{error}
          </p>
        )}

        {rows && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'Checked', value: summary.total.toLocaleString(),
                  sub: elapsed !== null ? `in ${elapsed} ms` : '', color: 'text-ink-300' },
                { label: 'Malicious', value: summary.malicious.toLocaleString(),
                  sub: 'act on these first', color: 'text-threat' },
                { label: 'Suspicious', value: summary.suspicious.toLocaleString(),
                  sub: 'worth a second look', color: 'text-amber' },
                // Not "clean": we only know we have no record of them.
                { label: 'Not in intel', value: summary.unknown.toLocaleString(),
                  sub: 'no record either way', color: 'text-ink-400' },
              ].map((k) => (
                <div key={k.label} className="glass border border-white/5 rounded-xl p-3">
                  <p className="text-[10px] text-ink-500 uppercase tracking-wide">{k.label}</p>
                  <p className={cn('text-xl font-bold mt-1 tabular-nums', k.color)}>{k.value}</p>
                  <p className="text-[10px] text-ink-600 mt-0.5">{k.sub}</p>
                </div>
              ))}
            </div>

            <p className="text-[11px] text-ink-500 px-3 py-2 rounded-lg border border-white/8 bg-surface">
              <b>&ldquo;Not in intel&rdquo; is not a clean bill of health.</b> It means this deployment
              holds no record of the value — absence of evidence, not evidence of absence.
            </p>

            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={() => setHitsOnly((s) => !s)}
                className={cn('px-3 py-1.5 rounded-lg border text-xs transition-colors',
                  hitsOnly ? 'border-magenta/40 text-magenta bg-magenta/10'
                           : 'border-white/10 text-ink-400 hover:text-white')}>
                {hitsOnly ? 'Showing hits only' : 'Show hits only'}
              </button>
              <button onClick={exportCsv}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors">
                <Download className="w-3.5 h-3.5" /> Export all {summary.total.toLocaleString()} as CSV
              </button>
            </div>

            <div className="rounded-xl border border-white/8 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-white/3 text-ink-500">
                    <tr className="text-left">
                      <th className="px-3 py-2 font-medium">Value</th>
                      <th className="px-3 py-2 font-medium">Verdict</th>
                      <th className="px-3 py-2 font-medium">Sources</th>
                      <th className="px-3 py-2 font-medium">Threat</th>
                      <th className="px-3 py-2 font-medium">Actor</th>
                      <th className="px-3 py-2 font-medium">Source</th>
                      <th className="px-3 py-2 font-medium text-right"
                        title="Composite intel score: aged confidence weighted by source reliability, plus corroboration, local sightings and attribution">
                        Score
                      </th>
                      <th className="px-3 py-2 font-medium text-right"
                        title="The originating feed's own claim, unweighted">Conf.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((r) => {
                      const v = VERDICT[r.verdict] ?? VERDICT.unverified
                      return (
                        <tr key={r.value} className="border-t border-white/5 hover:bg-white/2">
                          <td className="px-3 py-2 font-mono text-ink-200 max-w-[280px]">
                            {/* Hover for the four things that decide whether a
                                row is worth opening, without leaving the page. */}
                            <EntityHoverCard value={r.matched ?? r.value}>
                              <Link href={`/dashboard/scanner?value=${encodeURIComponent(r.value)}&run=1`}
                                className="hover:text-magenta break-all">{r.value}</Link>
                            </EntityHoverCard>
                            {/* A domain query can hit a URL hosted on it - show
                                which indicator actually matched, or the verdict
                                looks like it came from nowhere. */}
                            {r.matched && r.matched !== r.value && (
                              <span className="block text-[10px] text-ink-600 break-all">
                                matched {r.matched}
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2">
                            <span className={cn('inline-flex px-1.5 py-0.5 rounded-full border text-[10px] whitespace-nowrap', v.cls)}>
                              {v.label}
                            </span>
                          </td>
                          {/* Corroboration. Four independent feeds agreeing is a
                              different claim from one feed's word, and the store
                              could not previously tell them apart. */}
                          <td className="px-3 py-2">
                            {r.found ? (
                              <span
                                title={(r.sources ?? []).join('\n') || undefined}
                                className={cn('inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full border text-[10px] tabular-nums',
                                  (r.sourceCount ?? 1) >= 3 ? 'text-threat border-threat/30 bg-threat/10'
                                    : (r.sourceCount ?? 1) === 2 ? 'text-amber border-amber/30 bg-amber/10'
                                    : 'text-ink-400 border-white/10 bg-white/5')}>
                                {r.sourceCount ?? 1}×
                              </span>
                            ) : <span className="text-ink-600">—</span>}
                          </td>
                          <td className="px-3 py-2 text-ink-400">{r.threatType || '—'}</td>
                          <td className="px-3 py-2 text-ink-400">{r.actor || '—'}</td>
                          <td className="px-3 py-2 text-ink-500 max-w-[180px] truncate" title={r.source ?? ''}>
                            {r.source || '—'}
                          </td>
                          {/* Score, then the raw feed claim it was built from -
                              side by side, so a 90%-confidence value that only
                              one unreliable feed asserts cannot pass itself off
                              as the strongest thing on the page. */}
                          <td className="px-3 py-2 text-right">
                            {r.found && typeof r.intelScore === 'number' ? (
                              <span className="inline-flex px-1.5 py-0.5 rounded-md text-[10px] font-semibold tabular-nums border"
                                title={`${r.scoreBand} confidence in this claim`}
                                style={{
                                  color: BAND_COLOR[r.scoreBand ?? 'weak'],
                                  background: `${BAND_COLOR[r.scoreBand ?? 'weak']}14`,
                                  borderColor: `${BAND_COLOR[r.scoreBand ?? 'weak']}40`,
                                }}>
                                {r.intelScore}
                              </span>
                            ) : <span className="text-ink-600">—</span>}
                          </td>
                          <td className="px-3 py-2 text-right tabular-nums"
                            style={{ color: r.severity ? (SEV_COLOR[r.severity] ?? '#999') : '#666' }}>
                            {r.found ? r.confidence : '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              {shown.length === 0 && (
                <p className="flex items-center justify-center gap-2 text-xs text-safe py-6">
                  <ShieldCheck className="w-4 h-4" />
                  No malicious or suspicious hits among the {summary.total.toLocaleString()} values checked.
                </p>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
