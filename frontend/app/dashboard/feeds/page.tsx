'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Radio, CheckCircle2, HelpCircle, X,
  Shield, Zap, ChevronDown,
  Activity, Download,
  Flame, ExternalLink, RotateCcw, Crosshair,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import SavedViewsButton from '@/components/dashboard/SavedViewsButton'
import AnimatedNumber from '@/components/dashboard/AnimatedNumber'
import { SkeletonRows } from '@/components/dashboard/Skeleton'
import { fetchFeeds, fetchFeedsSummary, createAlert, importIocs, fetchIocs, type Feed as ApiFeed, type FeedsSummary, type Ioc } from '@/lib/api'
import { tk } from '@/lib/colors'

/* Classify a raw IOC string for the CTI store; returns null for values that
 * are not importable indicators (filenames, command lines, …). */
function classifyIoc(v: string): 'ip' | 'cve' | 'hash' | 'url' | 'domain' | null {
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d+)?$/.test(v)) return 'ip'
  if (/^CVE-\d{4}-\d+$/i.test(v)) return 'cve'
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return 'hash'
  if (v.includes('://')) return 'url'
  if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(v)) return 'domain'
  return null
}

/* -- Types ---------------------------------------------------------- */
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type ThreatStatus = 'confirmed' | 'unconfirmed'

type ThreatEntry = {
  id: string
  ts: string
  cve: string | null
  title: string
  attackType: string
  source: string
  sourceCountry: string
  /** Attributed actor, when the source provides one. Kept SEPARATE from
   *  sourceCountry: an actor name was previously stuffed into that field, and
   *  escalating the entry then wrote "APT29" into the SIEM alert's src_country,
   *  which the overview's country rollup groups by. */
  actor?: string
  severity: Severity
  sectors: string[]
  summary: string
  feedSources: string[]
  aiConfidence: number
  iocs: string[]
  mitre: string[]
  status: ThreatStatus
  correlated: number
  tags: string[]
}


const SEV_COLOR: Record<Severity, string> = {
  critical: 'bg-magenta/15 text-magenta border-magenta/20',
  high:     `bg-threat/15 text-[${tk('threat')}] border-threat/20`,
  medium:   'bg-amber/15 text-amber border-amber/20',
  low:      'bg-safe/15 text-safe border-safe/20',
  info:     'bg-violet/15 text-violet border-violet/20',
}

const SEV_DOT: Record<Severity, string> = {
  critical: tk('magenta'),
  high:     tk('threat'),
  medium:   tk('amber'),
  low:      tk('safe'),
  info:     tk('violet'),
}

function timeAgo(ts: string) {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

/* -- Confidence Ring ----------------------------------------------- */
function ConfidenceRing({ value }: { value: number }) {
  const r = 10
  const circ = 2 * Math.PI * r
  const color = value >= 85 ? 'rgb(var(--magenta))' : value >= 65 ? 'rgb(var(--amber))' : 'rgb(var(--safe))'
  return (
    <svg width="28" height="28" viewBox="0 0 28 28" className="shrink-0">
      {/* Only the rings are rotated so progress starts at 12 o'clock; the
          label stays upright and perfectly centred. */}
      <g transform="rotate(-90 14 14)">
        <circle cx="14" cy="14" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
        <circle
          cx="14" cy="14" r={r} fill="none"
          stroke={color} strokeWidth="3"
          strokeDasharray={`${(value / 100) * circ} ${circ}`}
          strokeLinecap="round"
        />
      </g>
      <text
        x="14" y="14"
        dominantBaseline="central" textAnchor="middle"
        fill={color} fontSize="7" fontWeight="700"
      >
        {value}
      </text>
    </svg>
  )
}

/* -- Threat Card --------------------------------------------------- */
function ThreatCard({
  entry,
  onConfirm,
  onDismiss,
  isNew,
}: {
  entry: ThreatEntry
  onConfirm?: (id: string) => void
  onDismiss: (id: string) => void
  isNew?: boolean
}) {
  const [expanded, setExpanded] = useState(false)
  // Action feedback can carry a link straight to the record the action just
  // created - the user must never have to go search for it afterwards.
  const [actionMsg, setActionMsg] = useState<{ text: string; href?: string; hrefLabel?: string } | null>(null)
  // Block IOCs writes real indicators into the CTI store and there's no
  // one-click "unblock", so it's confirm-gated: the first click arms, the
  // second commits. Auto-disarms after a few seconds if not confirmed.
  const [blockArmed, setBlockArmed] = useState(false)
  const [blocking, setBlocking] = useState(false)

  function note(text: string, href?: string, hrefLabel?: string) {
    setActionMsg({ text, href, hrefLabel })
    // Linked results stay up longer - the link is the point.
    setTimeout(() => setActionMsg(null), href ? 12_000 : 4000)
  }

  // Raise a real SIEM alert from this intel entry.
  function sendToSiem(e: React.MouseEvent) {
    e.stopPropagation()
    createAlert({
      title: entry.title,
      severity: entry.severity,
      description: entry.summary,
      srcIp: classifyIoc(entry.source) === 'ip' ? entry.source : undefined,
      // Only a real country goes in the country field; '-' means we do not know
      // one, and the actor belongs nowhere near it.
      srcCountry: entry.sourceCountry && entry.sourceCountry !== '-'
        ? entry.sourceCountry : undefined,
      mitreTechId: entry.mitre[0],
      ruleName: 'Threat Intel Escalation',
      tiHits: entry.feedSources.length,
    })
      .then((a) => note(`SIEM alert raised (${a.id.slice(0, 8)}…)`,
        `/dashboard/siem?alert=${encodeURIComponent(a.id)}`, 'Open alert →'))
      .catch(() => note('Could not raise alert - is the dashboard API running?'))
  }

  // Push this entry's importable indicators into the CTI store as a blocklist.
  // Confirm-gated (see blockArmed): first click arms, second commits.
  function blockIocs(e: React.MouseEvent) {
    e.stopPropagation()
    if (blocking) return
    const indicators = entry.iocs.flatMap((v) => {
      const type = classifyIoc(v)
      return type ? [{ type, value: v }] : []
    })
    if (indicators.length === 0) { note('No importable indicators on this entry'); return }
    if (!blockArmed) {
      setBlockArmed(true)
      setTimeout(() => setBlockArmed(false), 4000)  // auto-disarm if not confirmed
      return
    }
    setBlockArmed(false)
    setBlocking(true)
    importIocs({
      indicators,
      severity: entry.severity === 'info' ? 'low' : entry.severity,
      confidence: entry.aiConfidence,
      source: 'feed-blocklist',
      threat_type: entry.attackType,
      tags: ['blocklist', ...entry.tags.slice(0, 3)],
    })
      .then((out) => note(`${out.imported} IOC${out.imported === 1 ? '' : 's'} added to blocklist (${out.duplicates} already known)`,
        '/dashboard/cti', 'View IOC store →'))
      .catch(() => note('Could not import IOCs - is the dashboard API running?'))
      .finally(() => setBlocking(false))
  }

  return (
    <motion.div
      layout
      initial={isNew ? { opacity: 0, y: -16, scale: 0.97 } : { opacity: 1 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, x: -20, scale: 0.95 }}
      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      className={cn(
        'rounded-xl border bg-surface overflow-hidden',
        entry.status === 'confirmed'
          ? 'border-white/8'
          : 'border-amber/15',
        isNew && 'ring-1 ring-magenta/40',
      )}
    >
      {/* Card header */}
      <div
        className="flex items-start gap-3 p-3 cursor-pointer select-none"
        onClick={() => setExpanded((e) => !e)}
      >
        <span
          className="mt-0.5 w-2 h-2 rounded-full shrink-0"
          style={{ background: SEV_DOT[entry.severity] }}
        />

        <div className="flex-1 min-w-0">
          <div className="flex items-start gap-2 flex-wrap">
            {entry.cve && (
              // The CVE id links straight to its official NVD record (new tab) -
              // it used to be dead text ("official documentation links missing").
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(entry.cve)}`}
                target="_blank" rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                title="View this CVE on NVD"
                className="inline-flex items-center gap-1 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm bg-violet/15 text-violet border border-violet/20 shrink-0 hover:bg-violet/25 hover:text-white transition-colors"
              >
                {entry.cve}<ExternalLink className="w-2.5 h-2.5" />
              </a>
            )}
            <span className={cn(
              'text-[9px] font-semibold px-1.5 py-0.5 rounded-full border uppercase tracking-wide shrink-0',
              SEV_COLOR[entry.severity],
            )}>
              {entry.severity}
            </span>
            {isNew && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-magenta/20 text-magenta border border-magenta/30 shrink-0 animate-pulse">
                NEW
              </span>
            )}
          </div>
          <p className="text-xs text-ink-100 mt-1 leading-snug line-clamp-2">{entry.title}</p>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            <span className="text-[10px] text-ink-500">{entry.attackType}</span>
            <span className="text-ink-700 text-[10px]">·</span>
            <span className="text-[10px] text-ink-600">{entry.actor || entry.sourceCountry}</span>
            <span className="text-ink-700 text-[10px]">·</span>
            <span suppressHydrationWarning className="text-[10px] text-ink-600">{timeAgo(entry.ts)}</span>
          </div>
          {/* Feed sources */}
          <div className="flex items-center gap-1 mt-1.5 flex-wrap">
            {entry.feedSources.map(src => (
              <span key={src} className="text-[9px] px-1.5 py-0.5 rounded-sm bg-white/5 text-ink-500 border border-white/8">
                {src}
              </span>
            ))}
            {entry.correlated > 0 && (
              <span className="text-[9px] px-1.5 py-0.5 rounded-sm bg-violet/10 text-violet border border-violet/15">
                {entry.correlated} correlated
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0">
          {entry.status === 'unconfirmed' && (
            <ConfidenceRing value={entry.aiConfidence} />
          )}
          <ChevronDown className={cn(
            'w-3.5 h-3.5 text-ink-600 transition-transform',
            expanded && 'rotate-180',
          )} />
        </div>
      </div>

      {/* Expanded detail */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="px-3 pb-3 border-t border-white/5 pt-3 space-y-3">
              <p className="text-xs text-ink-300 leading-relaxed">{entry.summary}</p>

              {entry.iocs.length > 0 && (
                <div>
                  <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-1.5">Extracted IOCs</p>
                  <div className="flex flex-wrap gap-1.5">
                    {entry.iocs.map(ioc => {
                      // Each extracted IOC pivots to a live IntelScope lookup -
                      // these chips were dead text before.
                      const t = classifyIoc(ioc)
                      return (
                        <Link key={ioc}
                          href={`/dashboard/scanner?value=${encodeURIComponent(ioc)}${t ? `&type=${t}` : ''}&run=1`}
                          onClick={(e) => e.stopPropagation()}
                          title="Look up in IntelScope"
                          className="text-[10px] font-mono px-2 py-0.5 rounded-sm bg-black/30 text-ink-300 border border-white/8 hover:text-white hover:border-magenta/40 transition-colors">
                          {ioc}
                        </Link>
                      )
                    })}
                  </div>
                </div>
              )}

              {entry.mitre.length > 0 && (
                <div>
                  <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-1.5">MITRE ATT&CK</p>
                  <div className="flex flex-wrap gap-1.5">
                    {entry.mitre.map(t => (
                      <a
                        key={t}
                        href={`https://attack.mitre.org/techniques/${t.replace('T', 'T').replace('.', '/')}/`}
                        target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="text-[10px] font-mono px-2 py-0.5 rounded-sm bg-violet/10 text-violet border border-violet/20 hover:bg-violet/20 transition-colors"
                      >
                        {t}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="flex items-center gap-2 pt-1 flex-wrap">
                {onConfirm && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onConfirm(entry.id) }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-safe/15 text-safe border border-safe/25 text-xs font-medium hover:bg-safe/25 transition-colors"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Confirm Threat
                  </button>
                )}
                <button
                  onClick={sendToSiem}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-magenta/12 text-magenta border border-magenta/25 text-xs font-medium hover:bg-magenta/20 transition-colors"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Send to SIEM
                </button>
                <button
                  onClick={blockIocs}
                  disabled={blocking}
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors disabled:opacity-50',
                    blockArmed
                      ? 'bg-amber/15 text-amber border-amber/30 hover:bg-amber/25'
                      : 'bg-white/5 text-ink-300 border-white/10 hover:bg-white/8',
                  )}
                >
                  <Shield className="w-3.5 h-3.5" />
                  {blocking ? 'Blocking…' : blockArmed ? 'Confirm block?' : 'Block IOCs'}
                </button>
                {actionMsg && (
                  <span className="text-[10px] text-safe basis-full sm:basis-auto" role="status">
                    {actionMsg.text}
                    {actionMsg.href && (
                      <Link href={actionMsg.href} onClick={(e) => e.stopPropagation()}
                        className="ml-2 text-magenta underline underline-offset-2 hover:text-white">
                        {actionMsg.hrefLabel ?? 'Open →'}
                      </Link>
                    )}
                  </span>
                )}
                <button
                  onClick={(e) => { e.stopPropagation(); onDismiss(entry.id) }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/4 text-ink-500 border border-white/8 text-xs font-medium hover:text-ink-300 transition-colors ml-auto"
                >
                  <X className="w-3.5 h-3.5" />
                  Dismiss
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* -- Source Health Pills ------------------------------------------- */

/* -- Main Page ----------------------------------------------------- */
export default function FeedsPage() {
  // Start EMPTY, not seeded. The IOC store is the source of truth - an empty
  // store is an honest "no threats yet". An unreachable store is a third thing
  // again, and it used to be answered with hardcoded threats PLUS a simulator
  // that streamed newly-invented ones in every 8-14 seconds, animated and
  // pulsing. During an outage a SOC analyst watched fiction arrive live.
  const [confirmed, setConfirmed] = useState<ThreatEntry[]>([])
  const [unconfirmed, setUnconfirmed] = useState<ThreatEntry[]>([])
  const [apiFeeds, setApiFeeds] = useState<ApiFeed[]>([])
  const [feedsSummary, setFeedsSummary] = useState<FeedsSummary | null>(null)
  // Written only by the removed offline simulator; the highlight-on-arrival
  // affordance now has nothing to announce, because nothing arrives unasked.
  const [newIds] = useState<Set<string>>(new Set())
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [confidenceFilter, setConfidenceFilter] = useState<string>('all') // all|high|medium|low
  const [sourceFilter, setSourceFilter] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [liveCount, setLiveCount] = useState(0)
  const [pulse] = useState(false)
  // Dismiss is reversible: the just-dismissed card is stashed and an undo toast
  // offers to restore it into the exact list it came from. Auto-clears (the
  // dismissal becomes permanent) after the toast window elapses.
  const [dismissed, setDismissed] = useState<{ entry: ThreatEntry; list: 'confirmed' | 'unconfirmed' } | null>(null)
  const dismissTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // liveMode: the API answered (we show its data, even if empty).
  // feedsFailed: it did not answer, which is neither data nor emptiness.
  const [liveMode, setLiveMode] = useState(false)
  const [feedsFailed, setFeedsFailed] = useState(false)

  // Map a real IOC into the rich threat-feed card shape (faithfully, no fabrication).
  const iocToEntry = useCallback((i: Ioc): ThreatEntry => ({
    id: i.id,
    ts: i.lastSeen || i.firstSeen || new Date().toISOString(),
    cve: i.type === 'cve' ? i.value : null,
    title: `${i.threatType || 'Indicator'} - ${i.value}`,
    attackType: i.threatType || i.type.toUpperCase(),
    source: i.value,
    sourceCountry: '-',          // a blocklist indicator carries no geography
    actor: i.actor || '',
    severity: (['critical', 'high', 'medium', 'low', 'info'].includes(i.severity) ? i.severity : 'medium') as Severity,
    sectors: [],
    summary: `${i.type.toUpperCase()} indicator ingested from ${i.source}. Confidence ${i.confidence}%.${i.actor ? ` Attributed to ${i.actor}.` : ''}`,
    feedSources: [i.source],
    aiConfidence: i.confidence,
    iocs: [i.value],
    mitre: [],
    status: (i.confidence >= 70 ? 'confirmed' : 'unconfirmed') as ThreatStatus,
    correlated: 0,
    tags: Array.isArray(i.tags) ? i.tags : [],
  }), [])

  // Deep-link: ?family=<name> narrows the library to one malware family. The
  // store-composition panel links here from each family it can name, and a link
  // that landed on an unfiltered list would be a link that does nothing.
  const [family, setFamily] = useState<string | null>(null)
  const [familyTotal, setFamilyTotal] = useState(0)
  useEffect(() => {
    const f = new URLSearchParams(window.location.search).get('family')
    if (f) setFamily(f.toLowerCase())
  }, [])

  // Load feed sources, summary, and real indicators from the API.
  useEffect(() => {
    fetchFeeds().then(setApiFeeds).catch(() => {})
    fetchFeedsSummary().then(setFeedsSummary).catch(() => {})
    fetchIocs({
      limit: '60',
      // Sorted by relevance within a family: "show me Emotet" wants the values
      // most worth looking at, not the ones that happened to arrive last.
      sort: family ? 'score' : 'last_seen', order: 'desc',
      ...(family ? { family } : {}),
    }).then(({ items, total }) => {
      setFamilyTotal(total)
      // The API answered - we are LIVE, even when the store is empty (fresh
      // real-feeds install). Render its real indicators; never fall back to seeds.
      const entries = items.map(iocToEntry)
      setConfirmed(entries.filter(e => e.status === 'confirmed'))
      setUnconfirmed(entries.filter(e => e.status === 'unconfirmed'))
      setLiveCount(items.length)
      setLiveMode(true)
    }).catch(() => setFeedsFailed(true))
  }, [iocToEntry, family])

  function handleConfirm(id: string) {
    const entry = unconfirmed.find(e => e.id === id)
    if (!entry) return
    setUnconfirmed(prev => prev.filter(e => e.id !== id))
    setConfirmed(prev => [{ ...entry, status: 'confirmed' }, ...prev])
  }

  // Stash the dismissed entry and arm the undo toast; the entry is removed
  // from view immediately but can be restored until the toast auto-clears.
  function armDismiss(entry: ThreatEntry, list: 'confirmed' | 'unconfirmed') {
    if (dismissTimer.current) clearTimeout(dismissTimer.current)
    setDismissed({ entry, list })
    dismissTimer.current = setTimeout(() => setDismissed(null), 7000)
  }

  function handleDismissUnconfirmed(id: string) {
    const entry = unconfirmed.find(e => e.id === id)
    setUnconfirmed(prev => prev.filter(e => e.id !== id))
    if (entry) armDismiss(entry, 'unconfirmed')
  }

  function handleDismissConfirmed(id: string) {
    const entry = confirmed.find(e => e.id === id)
    setConfirmed(prev => prev.filter(e => e.id !== id))
    if (entry) armDismiss(entry, 'confirmed')
  }

  // Restore the last-dismissed card into the list it came from (de-duped, in
  // case a live refresh already re-added it) and dismiss the undo toast.
  function undoDismiss() {
    if (!dismissed) return
    const { entry, list } = dismissed
    const restore = (prev: ThreatEntry[]) =>
      prev.some(e => e.id === entry.id) ? prev : [entry, ...prev]
    if (list === 'confirmed') setConfirmed(restore)
    else setUnconfirmed(restore)
    if (dismissTimer.current) clearTimeout(dismissTimer.current)
    setDismissed(null)
  }

  // Download the live IOC store as CSV; fall back to the visible entries'
  // indicators when the API is unreachable.
  const [exporting, setExporting] = useState(false)
  const [exportNote, setExportNote] = useState<string | null>(null)
  async function exportIocs() {
    if (exporting) return
    setExporting(true)
    setExportNote(null)
    const download = (csv: string) => {
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threatorbit-iocs-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    }
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
    try {
      // Page through the store. This used to take a single limit=1000 request
      // and hand back a file that looked complete: against a 310k-indicator
      // store the analyst silently got 0.3% of it, with nothing in the CSV or
      // the UI saying so. Bounded so the browser isn't asked to build a
      // several-hundred-megabyte string in memory - and when the bound bites,
      // it says exactly how much was written.
      const PAGE = 1000
      const MAX_ROWS = 100_000
      const first = await fetchIocs({ limit: String(PAGE) })
      const items = [...first.items]
      const wanted = Math.min(first.total, MAX_ROWS)
      while (items.length < wanted) {
        const { items: page } = await fetchIocs({ limit: String(PAGE), offset: String(items.length) })
        if (!page.length) break
        items.push(...page)
      }
      download([
        'type,value,severity,confidence,threat_type,actor,source,first_seen,last_seen',
        ...items.map((i) => [i.type, i.value, i.severity, i.confidence, i.threatType, i.actor, i.source, i.firstSeen, i.lastSeen].map(esc).join(',')),
      ].join('\n'))
      setExportNote(items.length < first.total
        ? `Exported the ${items.length.toLocaleString()} most recent of ${first.total.toLocaleString()} indicators (export is capped).`
        : `Exported all ${items.length.toLocaleString()} indicators.`)
    } catch {
      const rows = [...confirmed, ...unconfirmed].flatMap((e) =>
        e.iocs.map((v) => [classifyIoc(v) ?? 'unknown', v, e.severity, e.aiConfidence, e.attackType, '', e.feedSources[0] ?? '', '', '']))
      download(['type,value,severity,confidence,threat_type,actor,source,first_seen,last_seen',
        ...rows.map((r) => r.map(esc).join(','))].join('\n'))
      // Say which file they actually got: this fallback is the indicators
      // visible on screen, not the store, and the two are very different sizes.
      setExportNote(`API unreachable — exported the ${rows.length.toLocaleString()} indicators shown on this page, not the full store.`)
    } finally {
      setExporting(false)
    }
  }

  // Multi-dimensional filtering (severity + confidence band + source + free
  // text over title/attack-type/country/IOCs/sources). Saved as a view below.
  const confBand = (c: number) => (c >= 85 ? 'high' : c >= 65 ? 'medium' : 'low')
  const allSources = Array.from(
    new Set([...confirmed, ...unconfirmed].flatMap(e => e.feedSources ?? []))
  ).sort()
  const matchEntry = (e: ThreatEntry) => {
    if (severityFilter !== 'all' && e.severity !== severityFilter) return false
    if (confidenceFilter !== 'all' && confBand(e.aiConfidence) !== confidenceFilter) return false
    if (sourceFilter !== 'all' && !(e.feedSources ?? []).includes(sourceFilter)) return false
    if (search) {
      const q = search.toLowerCase()
      const hay = [e.title, e.attackType, e.sourceCountry, e.actor ?? '', ...(e.iocs ?? []),
        ...(e.feedSources ?? []), ...(e.mitre ?? [])].join(' ').toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  }
  const filteredConfirmed = confirmed.filter(matchEntry)
  const filteredUnconfirmed = unconfirmed.filter(matchEntry)

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#0A0612]">

      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Threat Feeds</h1>
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-safe/10 border border-safe/20 text-[10px] font-medium text-safe">
              <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
              LIVE
            </span>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">
            Real-time threat intelligence from {apiFeeds.length} sources · {liveCount} new today
          </p>
        </div>
        <div className="flex items-center gap-2">
          {exportNote && (
            <span className="text-[10px] text-ink-500 max-w-[320px] text-right" role="status">{exportNote}</span>
          )}
          <button
            onClick={exportIocs}
            disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors disabled:opacity-50">
            <Download className="w-3.5 h-3.5" />
            {exporting ? 'Exporting…' : 'Export IOCs'}
          </button>
        </div>
      </div>

      {/* Source health strip */}
      <div className="px-6 py-2.5 border-b border-white/4 bg-white/1 shrink-0 overflow-x-auto">
        <div className="flex items-center gap-2 min-w-max">
          <span className="text-[10px] text-ink-600 uppercase tracking-widest mr-1">Sources</span>
          {(apiFeeds.length > 0
            ? apiFeeds.map(f => ({ name: f.name, status: f.status === 'active' ? 'live' : 'degraded', rate: `${f.indicators}` }))
            : []
          ).map(src => (
            <div key={src.name} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/5 border border-white/8">
              <span className={cn(
                'w-1.5 h-1.5 rounded-full',
                src.status === 'live' ? 'bg-safe animate-pulse' : 'bg-amber',
              )} />
              <span className="text-[10px] text-ink-300">{src.name}</span>
              <span className="text-[10px] text-ink-600">{src.rate}</span>
            </div>
          ))}
          {apiFeeds.length === 0 && !feedsFailed && (
            <span className="text-[10px] text-ink-600">No sources configured yet - add one under <span className="text-violet">Sources</span>.</span>
          )}
        </div>
      </div>

      {/* Scoped to one malware family. Says what is being shown, how many there
          are in all, and how to leave - a filter you cannot see is a filter that
          makes the rest of the library look empty. */}
      {family && (
        <div className="flex items-center gap-2 px-6 py-2 border-b border-white/5 bg-violet/8 shrink-0 text-[11px]">
          <Crosshair className="w-3.5 h-3.5 text-violet shrink-0" />
          <span className="text-ink-200">
            Showing <span className="capitalize font-semibold text-white">{family}</span>{' '}
            infrastructure — <span className="tabular-nums">{familyTotal.toLocaleString()}</span>{' '}
            {familyTotal === 1 ? 'indicator' : 'indicators'} in this store carry that family,
            ranked by relevance.
          </span>
          <a href="/dashboard/feeds" className="ml-auto text-violet hover:underline shrink-0">
            Show everything
          </a>
        </div>
      )}

      {/* KPI strip */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Confirmed', value: confirmed.length, color: 'text-safe', icon: CheckCircle2 },
          { label: 'Unconfirmed', value: unconfirmed.length, color: 'text-amber', icon: HelpCircle },
          { label: 'Critical', value: [...confirmed, ...unconfirmed].filter(e => e.severity === 'critical').length, color: 'text-magenta', icon: Flame },
          { label: 'Total IOCs', value: feedsSummary ? feedsSummary.totalIndicators.toLocaleString() : '-', color: 'text-violet', icon: Activity },
        ].map(kpi => (
          <div key={kpi.label} className="flex items-center gap-3 px-4 py-3">
            <kpi.icon className={cn('w-4 h-4 shrink-0', kpi.color)} />
            <div>
              <div className={cn('text-base font-bold font-mono', kpi.color)}>
                {typeof kpi.value === 'number' ? <AnimatedNumber value={kpi.value} /> : kpi.value}
              </div>
              <div className="text-[10px] text-ink-600">{kpi.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters: severity + confidence + source + search (saveable views) */}
      <div className="flex items-center gap-1.5 px-6 py-2 border-b border-white/4 shrink-0 overflow-x-auto">
        {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={cn(
              'px-3 py-1 rounded-full text-[11px] font-medium capitalize transition-colors whitespace-nowrap',
              severityFilter === sev
                ? 'bg-magenta/20 text-magenta border border-magenta/30'
                : 'bg-white/4 text-ink-500 border border-white/8 hover:text-ink-200',
            )}
          >
            {sev === 'all' ? 'All Severities' : sev}
          </button>
        ))}
        <span className="w-px h-4 bg-white/10 mx-1 shrink-0" />
        <select value={confidenceFilter} onChange={(e) => setConfidenceFilter(e.target.value)}
          aria-label="Confidence" title="Confidence"
          className="px-2 py-1 rounded-lg bg-white/4 border border-white/8 text-[11px] text-ink-300 focus:outline-hidden focus:border-magenta/40 shrink-0">
          <option value="all">Any confidence</option>
          <option value="high">High (≥85%)</option>
          <option value="medium">Medium (65-84%)</option>
          <option value="low">Low (&lt;65%)</option>
        </select>
        <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}
          aria-label="Source" title="Feed source"
          className="px-2 py-1 rounded-lg bg-white/4 border border-white/8 text-[11px] text-ink-300 focus:outline-hidden focus:border-magenta/40 shrink-0 max-w-[160px]">
          <option value="all">All sources</option>
          {allSources.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input value={search} onChange={(e) => setSearch(e.target.value)}
          placeholder="Search title, IOC, actor, technique…" aria-label="Search feeds"
          className="px-2.5 py-1 rounded-lg bg-white/4 border border-white/8 text-[11px] text-ink-200 placeholder-ink-600 focus:outline-hidden focus:border-magenta/40 shrink-0 w-52" />
        {(severityFilter !== 'all' || confidenceFilter !== 'all' || sourceFilter !== 'all' || search) && (
          <button onClick={() => { setSeverityFilter('all'); setConfidenceFilter('all'); setSourceFilter('all'); setSearch('') }}
            className="px-2 py-1 rounded-lg text-[11px] text-ink-500 hover:text-white border border-white/8 shrink-0">
            Clear
          </button>
        )}
        <div className="ml-auto shrink-0">
          <SavedViewsButton
            section="feeds"
            filters={{ severity: severityFilter, confidence: confidenceFilter, source: sourceFilter, q: search }}
            onApply={(f) => {
              setSeverityFilter(f.severity ?? 'all')
              setConfidenceFilter(f.confidence ?? 'all')
              setSourceFilter(f.source ?? 'all')
              setSearch(f.q ?? '')
            }}
          />
        </div>
      </div>

      {/* Split columns */}
      <div className="flex-1 min-h-0 grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/5 overflow-hidden">

        {/* -- Confirmed Threats -- */}
        <div className="flex flex-col overflow-hidden">
          {/* Column header */}
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 bg-safe/3 shrink-0">
            <CheckCircle2 className="w-4 h-4 text-safe" />
            <span className="text-xs font-semibold text-safe">Confirmed Threats</span>
            <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-safe/15 text-safe border border-safe/25 font-mono">
              {filteredConfirmed.length}
            </span>
          </div>

          {/* Feed list */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            <AnimatePresence mode="popLayout">
              {filteredConfirmed.map(entry => (
                <ThreatCard
                  key={entry.id}
                  entry={entry}
                  onDismiss={handleDismissConfirmed}
                />
              ))}
              {filteredConfirmed.length === 0 && (
                !liveMode && !feedsFailed
                  ? <SkeletonRows rows={5} className="px-1" />
                  : (
                    <div className="flex flex-col items-center justify-center h-32 text-ink-600">
                      <CheckCircle2 className="w-8 h-8 mb-2 opacity-30" />
                      <p className="text-xs">No confirmed threats match filter</p>
                    </div>
                  )
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* -- Unconfirmed Threats -- */}
        <div className="flex flex-col overflow-hidden">
          {/* Column header */}
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 bg-amber/3 shrink-0">
            <HelpCircle className={cn('w-4 h-4 text-amber', pulse && 'animate-bounce')} />
            <span className="text-xs font-semibold text-amber">Unconfirmed / Under Analysis</span>
            <div className="ml-auto flex items-center gap-2">
              <span className="text-[9px] text-ink-500 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-amber animate-pulse" />
                Live updates
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber/15 text-amber border border-amber/25 font-mono">
                {filteredUnconfirmed.length}
              </span>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {/* AI confidence legend */}
            <div className="flex items-center gap-4 px-1 mb-1">
              <span className="text-[10px] text-ink-600">AI Confidence:</span>
              {[['≥85%', 'text-magenta'], ['65-84%', 'text-amber'], ['<65%', 'text-safe']].map(([label, cls]) => (
                <span key={label} className={cn('text-[10px] font-medium', cls)}>{label}</span>
              ))}
            </div>
            <AnimatePresence mode="popLayout">
              {filteredUnconfirmed.map(entry => (
                <ThreatCard
                  key={entry.id}
                  entry={entry}
                  onConfirm={handleConfirm}
                  onDismiss={handleDismissUnconfirmed}
                  isNew={newIds.has(entry.id)}
                />
              ))}
              {filteredUnconfirmed.length === 0 && (
                !liveMode && !feedsFailed
                  ? <SkeletonRows rows={5} className="px-1" />
                  : (
                    <div className="flex flex-col items-center justify-center h-32 text-ink-600">
                      <HelpCircle className="w-8 h-8 mb-2 opacity-30" />
                      <p className="text-xs">No unconfirmed threats - feed is quiet</p>
                    </div>
                  )
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Undo toast - dismiss is reversible until this clears */}
      <AnimatePresence>
        {dismissed && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            transition={{ duration: 0.2 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 px-4 py-2.5 rounded-xl glass border border-white/10 shadow-lg"
            role="status"
          >
            <X className="w-3.5 h-3.5 text-ink-500 shrink-0" />
            <span className="text-xs text-ink-200">
              Dismissed <span className="text-ink-400">“{dismissed.entry.title.slice(0, 42)}{dismissed.entry.title.length > 42 ? '…' : ''}”</span>
            </span>
            <button
              onClick={undoDismiss}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-magenta/12 text-magenta border border-magenta/25 text-xs font-medium hover:bg-magenta/20 transition-colors"
            >
              <RotateCcw className="w-3 h-3" /> Undo
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
