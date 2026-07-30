'use client'
import { useState, useRef, useCallback, useEffect } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import { tk } from '@/lib/colors'
import { lookupIoc, type IocLookup } from '@/lib/api'

/**
 * What an indicator IS, without navigating away.
 *
 * The useful version of a hover affordance, not the decorative one: an analyst
 * scanning a queue wants to know whether a value is worth opening, and opening
 * it to find out is the cost this removes. It answers the four questions that
 * decide that - how much do we believe it, who else says so, when did we last
 * see it, and have WE seen it - and nothing else.
 *
 * One shared component on purpose. A hover card that behaves differently in the
 * IOC list, the bulk check and the alert table is three things to learn instead
 * of one, and the inconsistency is what makes people stop trusting it.
 */

// Resolved lookups, shared across every instance for the life of the page. An
// analyst sweeping a queue crosses the same value repeatedly, and re-fetching on
// each pass would turn a hover into a burst of requests.
const cache = new Map<string, IocLookup>()
// In-flight requests, so two cards over the same value share one call rather
// than racing.
const inflight = new Map<string, Promise<IocLookup>>()

// Long enough that sweeping the pointer across a table fires nothing, short
// enough that a deliberate hover feels immediate.
const OPEN_DELAY_MS = 350

function load(value: string): Promise<IocLookup> {
  const hit = cache.get(value)
  if (hit) return Promise.resolve(hit)
  const pending = inflight.get(value)
  if (pending) return pending
  const p = lookupIoc(value)
    .then((r) => { cache.set(value, r); return r })
    .finally(() => inflight.delete(value))
  inflight.set(value, p)
  return p
}

const BAND: Record<string, string> = {
  high: tk('magenta'), moderate: tk('amber'), low: tk('violet'), weak: '#665B7D',
}

function rel(iso: string | null | undefined): string {
  if (!iso) return '—'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

export default function EntityHoverCard(
  { value, children, className, link }:
  {
    value: string; children: React.ReactNode; className?: string
    /** Render the trigger as a link to the indicator's own page. Off by default:
     *  several call sites already sit inside a button or a link of their own,
     *  and nesting interactive elements produces markup a keyboard cannot use. */
    link?: boolean
  },
) {
  const [open, setOpen] = useState(false)
  const [data, setData] = useState<IocLookup | null>(cache.get(value) ?? null)
  const [failed, setFailed] = useState(false)
  const timer = useRef<number | null>(null)
  const alive = useRef(true)
  useEffect(() => () => { alive.current = false }, [])

  const enter = useCallback(() => {
    if (timer.current) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => {
      setOpen(true)
      if (!cache.get(value)) {
        load(value)
          .then((r) => { if (alive.current) setData(r) })
          // An unreachable API must not render a card claiming the value is
          // unknown - "we could not ask" and "we have no record" are different
          // answers, and only one of them is about the indicator.
          .catch(() => { if (alive.current) setFailed(true) })
      } else {
        setData(cache.get(value)!)
      }
    }, OPEN_DELAY_MS)
  }, [value])

  const leave = useCallback(() => {
    if (timer.current) window.clearTimeout(timer.current)
    setOpen(false)
  }, [])

  return (
    <span className={className} onMouseEnter={enter} onMouseLeave={leave}
      onFocus={enter} onBlur={leave} style={{ position: 'relative', display: 'inline-block' }}>
      {link
        ? <Link href={`/dashboard/cti/indicator/${encodeURIComponent(value)}`}
            className="hover:underline decoration-dotted underline-offset-2">{children}</Link>
        : children}
      <AnimatePresence>
        {open && (
          <motion.span
            initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }} transition={{ duration: 0.12 }}
            // pointer-events-none: the card is for reading, and a card that can
            // swallow a click makes the row underneath feel broken.
            className="pointer-events-none absolute left-0 top-full z-50 mt-1 w-72 rounded-xl border border-white/10 bg-surface shadow-xl p-3"
            role="tooltip">
            {failed ? (
              <p className="text-[10px] text-ink-500">
                Could not reach the intelligence store — this says nothing about
                the value itself.
              </p>
            ) : !data ? (
              <p className="text-[10px] text-ink-600 animate-pulse">Looking up…</p>
            ) : !data.found ? (
              <p className="text-[10px] text-ink-500">
                <span className="text-ink-300">Not in the store.</span> No feed this
                deployment ingests has published it — absence of evidence, not
                evidence of absence.
              </p>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold tabular-nums"
                    style={{ color: BAND[data.scoreBand ?? 'weak'] }}>
                    {data.intelScore ?? 0}
                  </span>
                  <span className="text-[9px] uppercase tracking-wider"
                    style={{ color: BAND[data.scoreBand ?? 'weak'] }}>
                    {data.scoreBand ?? 'unscored'}
                  </span>
                  <span className="ml-auto text-[9px] text-ink-600 uppercase">{data.severity}</span>
                </div>
                <p className="text-[10px] text-ink-400 leading-snug">
                  {data.threatType || 'indicator'}
                  {data.actor ? <> · attributed to <span className="text-ink-200">{data.actor}</span></> : null}
                </p>
                <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[10px]">
                  <span className="text-ink-600">Sources</span>
                  <span className="text-right"
                    style={{ color: (data.sourceCount ?? 1) > 1 ? tk('safe') : undefined }}>
                    {data.sourceCount ?? 1}{(data.sourceCount ?? 1) > 1 ? ' agree' : ''}
                  </span>
                  <span className="text-ink-600">Seen here</span>
                  <span className="text-right text-ink-300">
                    {data.sightings ?? 0}×
                  </span>
                  <span className="text-ink-600">Last asserted</span>
                  <span className="text-right text-ink-300">{rel(data.lastSeen)}</span>
                  <span className="text-ink-600">First seen</span>
                  <span className="text-right text-ink-300">{rel(data.firstSeen)}</span>
                </div>
                {data.knownGood && (
                  <p className="text-[10px]" style={{ color: tk('violet') }}>
                    Marked known-good — it does not match.
                  </p>
                )}
                {/* The card answers "what is this?" in place. When that is not
                    enough, the indicator has a page - and the hover is where to
                    say so, since an analyst who does not know a destination
                    exists never navigates to it. Only claimed where the trigger
                    really is a link. */}
                {link && (
                  <p className="text-[9px] text-ink-700 pt-1 border-t border-white/6">
                    Click for sources, relations, enrichment and history.
                  </p>
                )}
              </div>
            )}
          </motion.span>
        )}
      </AnimatePresence>
    </span>
  )
}
