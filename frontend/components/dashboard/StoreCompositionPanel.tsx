'use client'
import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Layers, Loader2 } from 'lucide-react'
import { tk } from '@/lib/colors'
import { fadeInUp } from '@/lib/motion'
import { fetchStoreSummary, type StoreSummary } from '@/lib/api'

/**
 * What is actually IN the store.
 *
 * "315,185 indicators" is a number that flatters and explains nothing. These are
 * the numbers that decide whether the store is worth having: how much of it we
 * believe, how much is backed by more than one source, what kind of activity it
 * describes, and which feeds are actually contributing.
 *
 * The corroboration figure is deliberately prominent and deliberately not
 * softened. On a store that is almost entirely single-source it reads close to
 * zero, and that IS the finding - a headline count hides it, which is the reason
 * this panel exists.
 */
const BAND_COLOR: Record<string, string> = {
  high: tk('magenta'), moderate: tk('amber'), low: tk('violet'), weak: '#665B7D',
}

function Bar({ parts, total }: { parts: Array<{ key: string; n: number; color: string }>; total: number }) {
  if (!total) return <div className="h-2 rounded-full bg-white/8" />
  return (
    <div className="h-2 rounded-full bg-white/8 overflow-hidden flex">
      {parts.filter((p) => p.n > 0).map((p) => (
        <div key={p.key} title={`${p.key}: ${p.n.toLocaleString()}`}
          style={{ width: `${(p.n / total) * 100}%`, background: p.color }} />
      ))}
    </div>
  )
}

export default function StoreCompositionPanel() {
  const [s, setS] = useState<StoreSummary | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    // Loaded once. It is a ~700 ms aggregate over the whole store, so polling it
    // would cost far more than the freshness is worth.
    fetchStoreSummary().then(setS).catch(() => setFailed(true))
  }, [])

  return (
    <motion.div variants={fadeInUp} initial="hidden" animate="show"
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5">
        <div className="p-1.5 rounded-lg bg-teal/15 border border-teal/25 shrink-0">
          <Layers className="w-4 h-4 text-teal" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">What is in the store</h3>
          <p className="text-[10px] text-ink-500">
            A count on its own says nothing about whether the intel is worth having.
          </p>
        </div>
        {!s && !failed && <Loader2 className="ml-auto w-3.5 h-3.5 animate-spin text-ink-600" />}
      </div>

      {failed && (
        <p className="px-5 py-6 text-[11px] text-ink-600 text-center">
          Could not load the store summary.
        </p>
      )}

      {s && (
        <div className="p-5 space-y-4">
          {/* Belief distribution */}
          <div>
            <div className="flex items-baseline justify-between text-[10px] mb-1">
              <span className="text-ink-500">How much we believe it</span>
              <span className="text-ink-600 tabular-nums">{s.total.toLocaleString()} indicators</span>
            </div>
            <Bar total={s.total} parts={[
              { key: 'high', n: s.bands.high, color: BAND_COLOR.high },
              { key: 'moderate', n: s.bands.moderate, color: BAND_COLOR.moderate },
              { key: 'low', n: s.bands.low, color: BAND_COLOR.low },
              { key: 'weak', n: s.bands.weak, color: BAND_COLOR.weak },
            ]} />
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              {(['high', 'moderate', 'low', 'weak'] as const).map((k) => (
                <span key={k} className="flex items-center gap-1 text-[10px] text-ink-500">
                  <span className="w-2 h-2 rounded-sm" style={{ background: BAND_COLOR[k] }} />
                  {k} <span className="text-ink-300 tabular-nums">{s.bands[k].toLocaleString()}</span>
                </span>
              ))}
            </div>
          </div>

          {/* Corroboration - the signal a multi-feed platform exists to produce.
              Shown as a share AND a raw count, so a near-zero percentage reads as
              the finding it is rather than as a broken widget. */}
          <div className="rounded-lg border border-white/8 bg-surface-2/40 p-3">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-[10px] text-ink-500">Backed by more than one source</span>
              <span className="text-sm font-semibold tabular-nums"
                style={{ color: s.corroboratedShare >= 10 ? tk('safe') : tk('amber') }}>
                {s.corroboratedShare}%
              </span>
            </div>
            <p className="text-[10px] text-ink-600 mt-1 leading-snug">
              {(s.corroboration['2'] + s.corroboration['3+']).toLocaleString()} of{' '}
              {s.total.toLocaleString()} values are asserted by two or more independent
              feeds. This is the one signal a single public feed cannot give you —
              and a low number here means the feeds largely do not overlap, not
              that the intel is wrong.
            </p>
            {/* Without this, a low share is ambiguous between "the feeds do not
                overlap" and "most feeds never fetched". Leaving the reader to
                deduce which is how a number gets misread. */}
            {s.sourcesConfigured > 0 && (
              <p className="text-[10px] mt-1.5"
                style={{ color: s.sourcesContributing < s.sourcesConfigured ? tk('amber') : tk('safe') }}>
                {s.sourcesContributing} of {s.sourcesConfigured} configured feeds have
                contributed
                {s.sourcesTotal > s.sourcesContributing &&
                  ` (${s.sourcesTotal} sources in all, counting non-feed intel)`}.
                {s.sourcesContributing < s.sourcesConfigured && (
                  <span className="text-ink-600">
                    {' '}The rest have not fetched — check Sources for errors, since
                    missing feeds depress this figure independently of real overlap.
                  </span>
                )}
              </p>
            )}
          </div>

          {/* Seen here. The only number on this panel a public CTI library
              structurally cannot produce - everything else describes what
              someone else published. Shown even at zero, because "we have never
              seen any of this" is itself the finding on a store of 328,000. */}
          <div className="rounded-lg border border-white/8 bg-surface-2/40 p-3">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-[10px] text-ink-500">Seen in your own telemetry</span>
              <span className="text-sm font-semibold tabular-nums"
                style={{ color: s.seenLocally > 0 ? tk('magenta') : tk('violet') }}>
                {s.seenLocally.toLocaleString()}
              </span>
            </div>
            <p className="text-[10px] text-ink-600 mt-1 leading-snug">
              {s.seenLocally > 0 ? (
                <>
                  {s.seenLocally.toLocaleString()} of these values have been
                  observed on your network, across{' '}
                  {s.localObservations.toLocaleString()} observations. A value
                  seen here concerns you in a way a value merely listed does not,
                  and it outranks any amount of third-party agreement.
                </>
              ) : (
                <>
                  None of these values have been observed on your network yet.
                  Addresses, DNS queries, proxy destinations and URLs are all
                  compared as logs arrive — so this stays at zero until either
                  something matches, or logs stop arriving.
                </>
              )}
            </p>
          </div>

          {/* What the store can NAME. A blocklist says a value is bad; a
              malware-family trail says what it IS, and that is the difference
              between an indicator you can investigate and one you can only
              block. Shown even at zero, because "we cannot name any of this"
              is the finding on a store of 300,000. */}
          <div className="rounded-lg border border-white/8 bg-surface-2/40 p-3">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-[10px] text-ink-500">Attributed to a named malware family</span>
              <span className="text-sm font-semibold tabular-nums"
                style={{ color: s.attributedShare >= 10 ? tk('safe') : tk('amber') }}>
                {s.attributedShare}%
              </span>
            </div>
            <p className="text-[10px] text-ink-600 mt-1 leading-snug">
              {s.attributedToFamily > 0 ? (
                <>
                  {s.attributedToFamily.toLocaleString()} of {s.total.toLocaleString()}{' '}
                  values carry the malware family a source named for them — so the
                  indicator has something to pivot on and a write-up behind it,
                  rather than only a verdict.
                </>
              ) : (
                <>
                  None of these values carry a malware family. Bulk blocklists
                  publish a value and the claim that it is bad, and nothing else;
                  attribution arrives with the per-family trails and the feeds
                  that ship a family per entry.
                </>
              )}
            </p>
            {/* Naming a family is half the job. The half that decides whether an
                indicator is investigable is whether the platform can then say
                what that family DOES - and for the families MITRE describes it
                can, in kill-chain order, with a link per technique. A value with
                a kill chain attached is a different object from a string on a
                blocklist, so the store says how much of it is which. */}
            {s.profiledByAttack > 0 && (
              <div className="mt-2 pt-2 border-t border-white/6 flex items-baseline gap-2 flex-wrap">
                <span className="text-sm font-semibold tabular-nums" style={{ color: tk('violet') }}>
                  {s.profiledShare}%
                </span>
                <span className="text-[10px] text-ink-500">
                  of the store — {s.profiledByAttack.toLocaleString()} values across{' '}
                  {s.profiledFamilies} families — also carries MITRE ATT&amp;CK&apos;s record
                  of what that malware does.
                </span>
              </div>
            )}
            {s.families.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {s.families.slice(0, 8).map((f) => (
                  <a key={f.family}
                    href={`/dashboard/cti/malware/${encodeURIComponent(f.family)}`}
                    className="px-1.5 py-0.5 rounded border border-white/10 bg-white/4 text-[10px] text-ink-300 hover:text-white hover:border-magenta/40 transition-colors">
                    <span className="capitalize">{f.family}</span>{' '}
                    <span className="text-ink-600 tabular-nums">{f.count.toLocaleString()}</span>
                  </a>
                ))}
              </div>
            )}
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            {/* What kind of activity */}
            <div>
              <p className="text-[10px] text-ink-500 mb-1.5">What it describes</p>
              <div className="space-y-1">
                {s.activities.slice(0, 5).map((a) => (
                  <div key={a.activity} className="flex items-center justify-between gap-2 text-[10px]">
                    <span className="text-ink-300 truncate">{a.activity}</span>
                    <span className="text-ink-500 tabular-nums shrink-0">
                      {a.count.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            {/* Which feeds actually contribute */}
            <div>
              <p className="text-[10px] text-ink-500 mb-1.5">Contributing sources</p>
              <div className="space-y-1">
                {s.sources.slice(0, 5).map((x) => (
                  <div key={x.source} className="flex items-center justify-between gap-2 text-[10px]">
                    <span className="text-ink-300 truncate" title={x.source}>{x.source}</span>
                    <span className="text-ink-500 tabular-nums shrink-0">
                      {x.values.toLocaleString()}
                    </span>
                  </div>
                ))}
                {s.sources.length === 0 && (
                  <p className="text-[10px] text-ink-600">No source attributions recorded yet.</p>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 pt-1 border-t border-white/6 text-[10px] flex-wrap">
            <span className="text-ink-500">
              Revoked within 7 days{' '}
              <span className="text-ink-300 tabular-nums">
                {s.expiringWithin7Days.toLocaleString()}
              </span>
            </span>
            {Object.entries(s.verdicts).map(([k, v]) => (
              <span key={k} className="text-ink-500">
                {k} <span className="text-ink-300 tabular-nums">{v}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}
