'use client'
import { tk } from '@/lib/colors'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Fingerprint, X, ShieldCheck, ShieldOff, Eye, Clock,
  TrendingDown, RefreshCw, Loader2, Share2, Sparkles, Gauge, Search, BookOpen,
  Send, FolderPlus, ArrowUpRight, Network, ShieldAlert,
} from 'lucide-react'
import { cn, isSimulatedSource } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import {
  fetchIocs, fetchIoc, addIocSighting, setIocKnownGood, removeIocKnownGood, runIocDecay,
  fetchStixBundle, enrichIoc, fetchIocFpAssessment, createAlert, createCase,
  fetchIocRelated, recordIocVerdict,
  type Ioc, type IocDetail, type EnrichmentResult, type FpAssessment, type RelatedGroup,
} from '@/lib/api'

// Analyst context per indicator TYPE - honest, generic SOC guidance keyed on
// what the indicator actually is (not fabricated threat specifics). The "why"
// line is built from the record's REAL fields (source/confidence/actor/tags).
const IOC_TYPE_CONTEXT: Record<string, { what: string; impact: string; action: string }> = {
  ip: {
    what: 'An IP address flagged as malicious - typically attacker infrastructure (command-and-control, scanning, or a compromised host).',
    impact: 'Traffic to or from this address can indicate C2 beaconing, data exfiltration, or an active intrusion attempt.',
    action: 'Hunt your firewall/proxy/flow logs for connections to it, block it at the perimeter if confirmed, and investigate any internal host that communicated with it.',
  },
  domain: {
    what: 'A domain name linked to malicious activity - phishing, malware delivery, or command-and-control.',
    impact: 'DNS resolutions or web requests to it can indicate a phished user or a host beaconing to attacker infrastructure.',
    action: 'Block/sinkhole it at DNS or the web proxy, hunt DNS logs for resolutions, and investigate any host that queried it.',
  },
  url: {
    what: 'A specific URL hosting or delivering malicious content - a phishing page, exploit kit, or malware payload.',
    impact: 'A user who opened this URL may have been phished or served malware.',
    action: 'Block it at the email gateway / web proxy and check which users or hosts requested it.',
  },
  hash: {
    what: 'A cryptographic file hash (MD5/SHA-1/SHA-256) identified as malicious.',
    impact: 'The presence of this file on an endpoint indicates a likely malware infection.',
    action: 'Search EDR/endpoint telemetry for the hash, quarantine matching files, and isolate affected hosts.',
  },
  email: {
    what: 'An email address used in malicious activity - a phishing sender or an abused/compromised account.',
    impact: 'Messages from this address may be phishing or business-email-compromise attempts.',
    action: 'Block the sender, search the mail gateway for other recipients, and warn any targeted users.',
  },
  cve: {
    what: 'A published vulnerability identifier (CVE) - not attacker infrastructure, but a weakness that may be exploited.',
    impact: 'Unpatched assets running the affected software are exposed to exploitation.',
    action: 'Scan the fleet for the affected software/versions, prioritise patching by exposure, and add detection for exploitation attempts.',
  },
}

function iocContext(d: {
  type: string; severity: string; source?: string; actor?: string
  threatType?: string; confidence?: number; effectiveConfidence?: number
  tags?: string[]; sightings?: number
}): { what: string; why: string; impact: string; action: string } {
  const base = IOC_TYPE_CONTEXT[d.type] ?? {
    what: `An indicator of type "${d.type}" reported as associated with malicious activity.`,
    impact: 'It may point to attacker infrastructure, tooling, or activity relevant to your environment.',
    action: 'Pivot into IntelScope and your SIEM to establish whether it appears in your own telemetry.',
  }
  const parts: string[] = []
  parts.push(`Reported by ${d.source || 'an intelligence source'}`)
  if (d.actor) parts.push(`attributed to ${d.actor}`)
  if (d.threatType) parts.push(`classified as ${d.threatType}`)
  const conf = d.confidence ?? d.effectiveConfidence
  if (typeof conf === 'number') parts.push(`${conf}% confidence`)
  parts.push(`${d.severity} severity`)
  if (typeof d.sightings === 'number') parts.push(`${d.sightings} sighting${d.sightings === 1 ? '' : 's'} recorded`)
  let why = parts.join(', ') + '.'
  if (d.tags && d.tags.length) why += ` Tags: ${d.tags.join(', ')}.`
  return { what: base.what, why, impact: base.impact, action: base.action }
}

const FP_BAND_STYLE: Record<string, { color: string; label: string }> = {
  'likely-fp': { color: tk('safe'), label: 'Likely false positive' },
  uncertain: { color: tk('amber'), label: 'Uncertain' },
  'likely-real': { color: tk('magenta'), label: 'Likely real' },
}

const VERDICT_COLOR: Record<string, string> = {
  malicious: tk('magenta'), suspicious: tk('amber'), benign: tk('safe'), clean: tk('safe'), unknown: '#665B7D',
}

const SEV_COLOR: Record<string, string> = {
  critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe'), info: tk('violet'),
}
const STATUS_STYLE: Record<string, { color: string; label: string }> = {
  active: { color: tk('safe'), label: 'Active' },
  expired: { color: '#665B7D', label: 'Expired' },
  'known-good': { color: tk('violet'), label: 'Known-good' },
}
const FILTERS = ['all', 'active', 'expired', 'known-good']
const TYPES = ['all', 'ip', 'domain', 'url', 'hash', 'email', 'cve']
const PAGE = 60

// Intel score band -> colour. Deliberately not SEV_COLOR: severity is what the
// thing would DO, the score is how much we believe it, and painting them the
// same makes an unbelievable "critical" look like an emergency.
const BAND_STYLE: Record<string, { color: string; label: string }> = {
  high: { color: tk('magenta'), label: 'High' },
  moderate: { color: tk('amber'), label: 'Moderate' },
  low: { color: tk('violet'), label: 'Low' },
  weak: { color: '#665B7D', label: 'Weak' },
}

// Ordering. Score is the DEFAULT: a store this size sorted by arrival time
// shows whatever a bulk feed happened to write last, which is not the same
// thing as what an analyst should look at first.
const SORTS: Array<{ key: string; label: string; hint: string }> = [
  { key: 'score', label: 'Score', hint: 'Corroboration, source reliability, decay and local sightings combined' },
  { key: 'last_seen', label: 'Recent', hint: 'Most recently asserted first' },
  { key: 'confidence', label: 'Confidence', hint: "The originating feed's own claim, unweighted" },
]

/** What an analyst can conclude. Deliberately three options: a vocabulary an
 *  analyst has to think about is one they will use inconsistently.
 *  `benign-here` is separate from `false-positive` because the indicator may be
 *  perfectly real and simply expected in this network - collapsing them would
 *  lose the distinction and over-suppress genuine intel. */
const VERDICT_CHOICES = [
  { key: 'confirmed', label: 'Confirmed', color: tk('magenta'), icon: ShieldAlert,
    hint: 'Really is malicious here — raises the score for everyone in this workspace' },
  { key: 'false-positive', label: 'False positive', color: tk('safe'), icon: ShieldCheck,
    hint: 'Not malicious at all — the feed is wrong. Lowers the score most.' },
  { key: 'benign-here', label: 'Expected here', color: tk('teal'), icon: ShieldOff,
    hint: 'Real elsewhere, but normal traffic in this network. Lowers the score less.' },
] as const

const VERDICT_COLOR_BY_KEY: Record<string, string> = {
  confirmed: tk('magenta'), 'false-positive': tk('safe'), 'benign-here': tk('teal'),
}

/** Where "See all N" goes, or null when the list cannot actually serve it.
 *
 *  Only the pivots the IOC list has a real filter for get a link. `report` and
 *  `asn` do not: their pivot value is a UUID / an AS number, and `?q=` is a
 *  substring search over the indicator VALUE, so the link would land on a page
 *  matching nothing while looking like it worked. A missing link is honest; a
 *  link that silently does the wrong thing is not. */
function pivotHref(g: RelatedGroup): string | null {
  const p = g.pivot
  if (p.kind === 'actor') return `/dashboard/cti?actor=${encodeURIComponent(p.value)}`
  // host and domain are both substrings of every value in their group, so `q`
  // reproduces the group exactly.
  if (p.kind === 'host' || p.kind === 'domain') {
    return `/dashboard/cti?q=${encodeURIComponent(p.value)}`
  }
  return null
}

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * IOC database with lifecycle - confidence decay, sightings, expiry and
 * known-good handling. The effective-confidence bar shows decay against the
 * asserted value; analysts can record a sighting (refreshes/reactivates) or
 * whitelist an indicator (stops it matching).
 */
export default function IocLifecyclePanel() {
  const [items, setItems] = useState<Ioc[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [filter, setFilter] = useState('all')
  const [sort, setSort] = useState('score')
  // Set by a deep link from an actor pivot; empty means no actor narrowing.
  const [actorFilter, setActorFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState<IocDetail | null>(null)
  const [busy, setBusy] = useState(false)
  const [decaying, setDecaying] = useState(false)
  const [enrichment, setEnrichment] = useState<EnrichmentResult | null>(null)
  const [enriching, setEnriching] = useState(false)
  const [fpAssessment, setFpAssessment] = useState<FpAssessment | null>(null)
  const [fpChecking, setFpChecking] = useState(false)
  const [actionMsg, setActionMsg] = useState<{ text: string; href: string; label: string } | null>(null)
  const [related, setRelated] = useState<{ groups: RelatedGroup[]; total: number } | null>(null)
  const [relating, setRelating] = useState(false)
  const [verdicting, setVerdicting] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    const params: Record<string, string> = {
      limit: String(PAGE), offset: String(page * PAGE), sort, order: 'desc',
    }
    if (filter !== 'all') params.status = filter
    if (typeFilter !== 'all') params.type = typeFilter
    if (query.trim()) params.q = query.trim()
    if (actorFilter) params.actor = actorFilter
    // `total` was thrown away and there was no offset: the panel showed the 60
    // most recent indicators and nothing else, so a store holding 310k was
    // 99.98% unreachable from the UI.
    fetchIocs(params)
      .then(({ items, total }) => { setItems(items); setTotal(total) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [filter, typeFilter, query, page, sort, actorFilter])

  // Deep links from a pivot ("See all 1,939 siblings under corolain.ru"). Read
  // once on mount, same pattern the SIEM and Actors pages already use. Without
  // this the pivot link lands here and shows the whole store, silently ignoring
  // the thing the analyst clicked - which is worse than not offering the link.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search)
    const q = p.get('q')
    const a = p.get('actor')
    if (q) setQuery(q)
    if (a) setActorFilter(a)
  }, [])

  useEffect(() => {
    // Debounced: at this table size every keystroke would otherwise run a
    // substring scan over the whole store.
    const t = window.setTimeout(load, query ? 300 : 0)
    return () => window.clearTimeout(t)
  }, [load, query])

  // Any change to what is being asked for restarts at the first page - staying
  // on page 40 of a filter that now has three results shows an empty list. Done
  // in the handlers rather than an effect so it batches into a single render:
  // resetting after the fact fetched once at the stale offset and again at zero,
  // flashing the wrong rows in between.
  const applyFilter = (f: string) => { setFilter(f); setPage(0) }
  const applyType = (t: string) => { setTypeFilter(t); setPage(0) }
  const applyQuery = (q: string) => { setQuery(q); setPage(0) }
  const applySort = (s: string) => { setSort(s); setPage(0) }

  function open(id: string) {
    setEnrichment(null)
    setFpAssessment(null)
    setActionMsg(null)
    // Cleared, not left showing the PREVIOUS indicator's relations while the new
    // ones load - stale pivots are worse than none, because they look current.
    setRelated(null)
    setRelating(true)
    fetchIoc(id).then(setDetail).catch(() => {})
    fetchIocRelated(id).then(setRelated).catch(() => {}).finally(() => setRelating(false))
  }
  function enrich() {
    if (!detail || enriching) return
    setEnriching(true)
    enrichIoc(detail.id).then(setEnrichment).catch(() => {}).finally(() => setEnriching(false))
  }
  function checkFp() {
    if (!detail || fpChecking) return
    setFpChecking(true)
    fetchIocFpAssessment(detail.id).then(setFpAssessment).catch(() => {}).finally(() => setFpChecking(false))
  }
  function refreshDetail(id: string) {
    fetchIoc(id).then(setDetail).catch(() => {})
    load()
  }

  function sight() {
    if (!detail || busy) return
    setBusy(true)
    addIocSighting(detail.id, 'analyst', 'Confirmed from CTI console')
      .then((d) => { setDetail(d); load() }).catch(() => {}).finally(() => setBusy(false))
  }
  function submitVerdict(verdict: string) {
    if (!detail || verdicting) return
    // Optional, because forcing a reason on every click is how a required field
    // becomes a field full of "." - but it is asked for, because the reason is
    // what makes the conclusion useful to the next analyst.
    const reason = window.prompt(
      `Why is this "${verdict}"? (optional, but the next analyst will thank you)`) ?? undefined
    setVerdicting(verdict)
    recordIocVerdict(detail.id, verdict, reason || undefined)
      .then(() => { refreshDetail(detail.id) })
      .catch(() => setActionMsg({
        text: 'Could not record the verdict (needs cti.write).', href: '', label: '',
      }))
      .finally(() => setVerdicting(null))
  }

  function toggleKnownGood() {
    if (!detail || busy) return
    setBusy(true)
    const fn = detail.lifecycle.status === 'known-good' ? removeIocKnownGood : setIocKnownGood
    fn(detail.id).then(() => refreshDetail(detail.id)).catch(() => {}).finally(() => setBusy(false))
  }
  // Raise a SIEM alert to investigate this indicator, then link straight to it.
  function sendToSiem() {
    if (!detail || busy) return
    setBusy(true); setActionMsg(null)
    createAlert({
      title: `Investigate indicator: ${detail.value}`,
      severity: detail.severity,
      description: `${detail.threatType || detail.type} indicator from ${detail.source || 'CTI'} escalated from the IOC console for investigation.`,
      srcIp: detail.type === 'ip' ? detail.value : undefined,
      ruleName: 'IOC escalation',
    })
      .then((a) => setActionMsg({ text: 'Alert raised in the SIEM.', href: `/dashboard/siem?alert=${a.id}`, label: 'Open alert' }))
      .catch(() => setActionMsg({ text: 'Could not raise the alert (needs siem.write).', href: '', label: '' }))
      .finally(() => setBusy(false))
  }
  // Open an investigation case seeded with this indicator as an entity.
  function createCaseFromIoc() {
    if (!detail || busy) return
    setBusy(true); setActionMsg(null)
    createCase({
      title: `Investigation: ${detail.value}`,
      severity: detail.severity,
      type: 'investigation',
      description: `Case opened from the IOC console for the ${detail.type} indicator ${detail.value} (${detail.threatType || 'unclassified'}, source ${detail.source || 'CTI'}).`,
      entities: [{ type: detail.type, value: detail.value }],
    })
      .then((c) => setActionMsg({ text: 'Case created.', href: `/dashboard/soar?case=${c.id}`, label: 'Open case' }))
      .catch(() => setActionMsg({ text: 'Could not create the case (needs soar.write).', href: '', label: '' }))
      .finally(() => setBusy(false))
  }
  function decay() {
    setDecaying(true)
    runIocDecay().then(() => load()).catch(() => {}).finally(() => setDecaying(false))
  }
  function exportStix() {
    fetchStixBundle().then((b) => {
      const blob = new Blob([JSON.stringify(b, null, 2)], { type: 'application/stix+json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threatorbit-stix-bundle-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    }).catch(() => {})
  }

  return (
    <motion.div variants={fadeInUp} initial="hidden" animate="show"
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
          <Fingerprint className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">IOC database &amp; lifecycle</h3>
          <p className="text-[10px] text-ink-500">
            {total.toLocaleString()} indicator{total === 1 ? '' : 's'}
            {query || filter !== 'all' || typeFilter !== 'all' ? ' matching' : ''} · confidence decay ·
            sightings · expiry
          </p>
        </div>
        <div className="ml-auto flex items-center gap-1">
          {FILTERS.map((f) => (
            <button key={f} onClick={() => applyFilter(f)}
              className={cn('px-2.5 py-1 rounded-lg text-[11px] font-medium capitalize transition-colors',
                filter === f ? 'bg-violet/15 text-violet border border-violet/30' : 'text-ink-500 hover:text-ink-200 border border-white/8')}>
              {f}
            </button>
          ))}
          <button onClick={decay} disabled={decaying} title="Run decay maintenance"
            className="ml-1 p-1.5 rounded-lg text-ink-500 hover:text-violet hover:bg-violet/10 transition-colors">
            {decaying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
          </button>
          <button onClick={exportStix} title="Export STIX 2.1 bundle (also served via TAXII 2.1 at /taxii2/)"
            className="p-1.5 rounded-lg text-ink-500 hover:text-violet hover:bg-violet/10 transition-colors">
            <Share2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Search + type narrowing. With hundreds of thousands of indicators,
          scrolling is not a way to find one. */}
      <div className="flex items-center gap-2 px-5 py-2.5 border-b border-white/5 flex-wrap">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="w-3.5 h-3.5 text-ink-600 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={query} onChange={(e) => applyQuery(e.target.value)}
            placeholder="Search indicator value…"
            className="w-full pl-8 pr-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-100 font-mono focus:outline-hidden focus:border-violet/40 placeholder-ink-700" />
        </div>
        <select value={typeFilter} onChange={(e) => applyType(e.target.value)}
          className="px-2 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-hidden focus:border-violet/40">
          {TYPES.map((t) => <option key={t} value={t}>{t === 'all' ? 'All types' : t}</option>)}
        </select>
        {/* Ranking. Explicit rather than implied - an analyst working a queue
            has to know whether the top row is the most believed or merely the
            most recent. */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-ink-600 mr-0.5">Rank by</span>
          {SORTS.map((s) => (
            <button key={s.key} onClick={() => applySort(s.key)} title={s.hint}
              className={cn('px-2 py-1 rounded-lg text-[10px] font-medium transition-colors',
                sort === s.key ? 'bg-violet/15 text-violet border border-violet/30'
                               : 'text-ink-500 hover:text-ink-200 border border-white/8')}>
              {s.label}
            </button>
          ))}
        </div>
      </div>

      <div className="divide-y divide-white/4 max-h-96 overflow-y-auto">
        {loading && <p className="text-[11px] text-ink-600 py-8 text-center animate-pulse">Loading indicators…</p>}
        {!loading && items.length === 0 && (
          <p className="text-[11px] text-ink-600 py-8 text-center">
            {query.trim()
              ? <>No indicator matches <span className="font-mono text-ink-400">{query.trim()}</span>. Absence from this store is not proof the value is safe.</>
              : <>No indicators{filter !== 'all' ? ` (${filter})` : ''} yet.</>}
          </p>
        )}
        {items.map((i) => {
          const st = STATUS_STYLE[i.status] ?? STATUS_STYLE.active
          const decayed = i.effectiveConfidence < i.confidence - 2
          const band = BAND_STYLE[i.scoreBand ?? 'weak'] ?? BAND_STYLE.weak
          const srcN = i.sourceCount ?? 1
          return (
            <button key={i.id} onClick={() => open(i.id)}
              className="group w-full text-left flex items-center gap-3 px-5 py-2.5 hover:bg-white/3 transition-colors">
              {/* Intel score. First thing on the row because it is the answer to
                  "does this deserve my next ten minutes?" */}
              <span
                title={`Intel score ${i.intelScore ?? 0}/100 (${band.label}) - ${srcN} source${srcN === 1 ? '' : 's'}, ${i.effectiveConfidence}% aged confidence. Open for the full breakdown.`}
                className="shrink-0 w-9 h-9 rounded-lg grid place-items-center text-[12px] font-semibold tabular-nums border transition-transform duration-150 group-hover:scale-110"
                style={{ color: band.color, background: `${band.color}14`, borderColor: `${band.color}40` }}>
                {i.intelScore ?? 0}
              </span>
              <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded-sm bg-white/5 text-ink-400 shrink-0 w-12 text-center">{i.type}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-white truncate">{i.value}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold shrink-0"
                    style={{ color: st.color, background: `${st.color}15` }}>{st.label}</span>
                  {/* Corroboration is the one signal a single public feed can
                      never give you, so it goes on the row rather than buried. */}
                  {srcN > 1 && (
                    <span title={(i.sources ?? []).join(', ')}
                      className="text-[9px] px-1.5 py-0.5 rounded-full shrink-0 font-semibold"
                      style={{ color: tk('safe'), background: `${tk('safe')}14`, border: `1px solid ${tk('safe')}40` }}>
                      {srcN}× corroborated
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-ink-600 mt-0.5 truncate">
                  {i.threatType || 'indicator'} · {i.sightings} sighting{i.sightings !== 1 ? 's' : ''} · {relTime(i.lastSeen)}
                  {/* Revealed on hover: which feed(s) actually asserted it. */}
                  <span className="text-ink-700 opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                    {' · '}{srcN > 1 ? (i.sources ?? []).join(', ') : (i.source || 'unattributed')}
                  </span>
                </p>
              </div>
              {/* effective vs asserted confidence */}
              <div className="w-24 shrink-0 hidden sm:block">
                <div className="flex items-center justify-between text-[9px] mb-0.5">
                  <span className="text-ink-600 flex items-center gap-0.5">{decayed && <TrendingDown className="w-2.5 h-2.5 text-amber" />}conf</span>
                  <span style={{ color: SEV_COLOR[i.severity] ?? tk('violet') }}>{i.effectiveConfidence}<span className="text-ink-700">/{i.confidence}</span></span>
                </div>
                <div className="h-1.5 rounded-full bg-white/8 overflow-hidden relative">
                  <div className="absolute inset-y-0 left-0 rounded-full bg-white/15" style={{ width: `${i.confidence}%` }} />
                  <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${i.effectiveConfidence}%`, background: SEV_COLOR[i.severity] ?? tk('violet') }} />
                </div>
              </div>
            </button>
          )
        })}
      </div>

      {/* Pager. Offset paging over a server-side total, so the whole store is
          reachable rather than only its most recent page. */}
      {total > PAGE && (
        <div className="flex items-center justify-between gap-3 px-5 py-2.5 border-t border-white/5">
          <span className="text-[10px] text-ink-600 tabular-nums">
            {(page * PAGE + 1).toLocaleString()}–{Math.min((page + 1) * PAGE, total).toLocaleString()}
            {' of '}{total.toLocaleString()}
          </span>
          <div className="flex items-center gap-1.5">
            <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0 || loading}
              className="px-2.5 py-1 rounded-lg border border-white/10 text-[11px] text-ink-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
              Previous
            </button>
            <button onClick={() => setPage((p) => p + 1)}
              disabled={(page + 1) * PAGE >= total || loading}
              className="px-2.5 py-1 rounded-lg border border-white/10 text-[11px] text-ink-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
              Next
            </button>
          </div>
        </div>
      )}

      {/* Detail drawer */}
      <AnimatePresence>
        {detail && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs" onClick={() => setDetail(null)}>
            <motion.div initial={{ x: 440 }} animate={{ x: 0 }} exit={{ x: 440 }} transition={{ type: 'tween', duration: 0.2 }}
              onClick={(e) => e.stopPropagation()} className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto p-5 space-y-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] text-ink-500 uppercase">{detail.type} indicator</p>
                  <h2 className="text-sm font-semibold text-white font-mono break-all">{detail.value}</h2>
                </div>
                <button onClick={() => setDetail(null)} className="p-1.5 rounded-lg text-ink-500 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
              </div>

              {/* Intel score, WITH its derivation. A ranking an analyst cannot
                  interrogate is a ranking they are right not to trust, so every
                  term that moved the number is shown with the reason it applied
                  and the parts always reconcile to the total. */}
              {typeof detail.intelScore === 'number' && (() => {
                const band = BAND_STYLE[detail.scoreBand ?? 'weak'] ?? BAND_STYLE.weak
                const comps = detail.scoreComponents ?? []
                return (
                  <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <span className="text-[10px] text-ink-500 uppercase tracking-wider">Intel score</span>
                        <p className="text-[10px] text-ink-600 mt-0.5">
                          How much to believe this, not how bad it would be
                        </p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                          style={{ color: band.color, background: `${band.color}18` }}>{band.label}</span>
                        <span className="text-lg font-semibold tabular-nums" style={{ color: band.color }}>
                          {detail.intelScore}<span className="text-[11px] text-ink-600">/100</span>
                        </span>
                      </div>
                    </div>
                    <div className="h-2 rounded-full bg-white/8 overflow-hidden">
                      <motion.div className="h-full rounded-full" style={{ background: band.color }}
                        initial={{ width: 0 }} animate={{ width: `${detail.intelScore}%` }}
                        transition={{ duration: 0.4, ease: 'easeOut' }} />
                    </div>
                    <div className="space-y-1.5">
                      {comps.map((c, n) => (
                        <div key={n} title={c.why}
                          className="flex items-start justify-between gap-3 rounded-lg px-2 py-1.5 hover:bg-white/4 transition-colors">
                          <div className="min-w-0">
                            <div className="text-[11px] text-ink-200">{c.label}</div>
                            <div className="text-[10px] text-ink-600 leading-snug">{c.why}</div>
                          </div>
                          <span className="text-[11px] font-mono tabular-nums shrink-0"
                            style={{ color: c.delta < 0 ? tk('amber') : tk('safe') }}>
                            {c.delta > 0 ? '+' : ''}{c.delta}
                          </span>
                        </div>
                      ))}
                    </div>
                    {(detail.sources?.length ?? 0) > 0 && (
                      <div className="flex flex-wrap gap-1 pt-1 border-t border-white/6">
                        <span className="text-[10px] text-ink-600 mr-1 mt-0.5">Asserted by</span>
                        {detail.sources!.map((s) => (
                          <span key={s} className="text-[9px] font-mono px-1.5 py-0.5 rounded-sm bg-white/6 text-ink-300">{s}</span>
                        ))}
                        {detail.reliability && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded-sm bg-white/6 text-ink-400"
                            title="Admiralty reliability of the best-rated source asserting this value">
                            grade {detail.reliability}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                )
              })()}

              {/* Lifecycle */}
              {(() => {
                const lc = detail.lifecycle
                const st = STATUS_STYLE[lc.status] ?? STATUS_STYLE.active
                return (
                  <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-ink-500 uppercase tracking-wider">Lifecycle</span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                        style={{ color: st.color, background: `${st.color}18` }}>{st.label}</span>
                    </div>
                    <div>
                      <div className="flex items-center justify-between text-[10px] mb-1">
                        <span className="text-ink-500">Effective confidence (decayed)</span>
                        <span className="font-mono text-white">{lc.effectiveConfidence}<span className="text-ink-600"> / {lc.assertedConfidence}</span></span>
                      </div>
                      <div className="h-2 rounded-full bg-white/8 overflow-hidden relative">
                        <div className="absolute inset-y-0 left-0 rounded-full bg-white/15" style={{ width: `${lc.assertedConfidence}%` }} />
                        <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${lc.effectiveConfidence}%`, background: SEV_COLOR[detail.severity] ?? tk('violet') }} />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center">
                      {[
                        { label: 'age', value: `${lc.ageDays}d` },
                        { label: 'half-life', value: `${lc.halfLifeDays}d` },
                        { label: lc.status === 'expired' ? 'expired' : 'expires in', value: lc.expiresInDays == null ? '-' : `${lc.expiresInDays}d` },
                      ].map((m) => (
                        <div key={m.label} className="rounded-lg bg-surface-2/60 border border-white/6 px-2 py-1.5">
                          <div className="text-xs font-mono text-white">{m.value}</div>
                          <div className="text-[9px] text-ink-600">{m.label}</div>
                        </div>
                      ))}
                    </div>
                    {/* The POLICY behind those numbers, named. "Expires in 12
                        days" is a fact an analyst cannot argue with; "under the
                        14-day IP rule, revoked below 15" is one they can go and
                        change in Settings → Feed Sources. */}
                    {lc.rule && (
                      <div className="pt-2 border-t border-white/6 space-y-1">
                        <div className="flex items-baseline justify-between gap-2 text-[10px]">
                          <span className="text-ink-500">Decay rule</span>
                          <a href="/dashboard/config?tab=sources"
                            className="text-ink-300 hover:text-violet transition-colors truncate text-right">
                            {lc.rule.name}
                          </a>
                        </div>
                        <div className="flex items-baseline justify-between gap-2 text-[10px]">
                          <span className="text-ink-500">Stops matching below</span>
                          <span className="font-mono text-ink-300">{lc.revokeScore}</span>
                        </div>
                        {lc.validUntil && (
                          <div className="flex items-baseline justify-between gap-2 text-[10px]">
                            <span className="text-ink-500">Revoked on</span>
                            <span className="font-mono text-ink-300">{lc.validUntil.slice(0, 10)}</span>
                          </div>
                        )}
                        {lc.nextReaction && (
                          <div className="flex items-baseline justify-between gap-2 text-[10px]">
                            <span className="text-ink-500" title="Decay with no reaction points is invisible until the indicator silently vanishes">
                              Next review at {lc.nextReaction.score}
                            </span>
                            <span className="font-mono text-ink-300">
                              in {lc.nextReaction.inDays}d
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })()}

              {/* Pivots: the indicator itself is never a dead end */}
              <div className="flex items-center gap-2 flex-wrap">
                <a href={`/dashboard/scanner?value=${encodeURIComponent(detail.value)}&run=1`}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-magenta/12 border border-magenta/30 text-magenta hover:bg-magenta/20 transition-colors">
                  <Search className="w-3.5 h-3.5" /> Open in IntelScope
                </a>
                <a href={`/dashboard/siem?q=${encodeURIComponent(detail.value)}`}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">
                  <Eye className="w-3.5 h-3.5" /> Matching alerts
                </a>
              </div>

              {/* Analyst context: what the indicator is, why it's flagged (from
                  its real fields), likely impact, and the recommended first
                  action - so an indicator is never shown without explanation. */}
              {(() => {
                const ctx = iocContext(detail)
                const rows: Array<[string, string]> = [
                  ['What it is', ctx.what],
                  ['Why it’s flagged', ctx.why],
                  ['Potential impact', ctx.impact],
                  ['Recommended action', ctx.action],
                ]
                return (
                  <div className="rounded-xl border border-white/8 bg-surface-2/40 p-4 space-y-2.5">
                    <div className="flex items-center gap-1.5">
                      <BookOpen className="w-3.5 h-3.5 text-ink-400" />
                      <span className="text-[10px] text-ink-500 uppercase tracking-wider">Context</span>
                    </div>
                    {rows.map(([label, body]) => (
                      <div key={label}>
                        <p className="text-[10px] font-semibold text-ink-400">{label}</p>
                        <p className="text-[11px] text-ink-200 leading-relaxed mt-0.5">{body}</p>
                      </div>
                    ))}
                  </div>
                )
              })()}

              {/* Analyst conclusions. Until this existed, nothing an analyst
                  concluded ever reached the intel store: twenty minutes spent
                  establishing a false positive was written into a case note and
                  the store scored the value the same way next week, for the next
                  analyst, who spent the same twenty minutes. */}
              <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-2.5">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[10px] text-ink-500 uppercase tracking-wider">
                    Your team&apos;s verdict
                  </span>
                  {detail.verdictSummary && detail.verdictSummary.shift !== 0 && (
                    <span className="text-[10px] font-mono"
                      style={{ color: detail.verdictSummary.shift < 0 ? tk('safe') : tk('magenta') }}>
                      {detail.verdictSummary.shift > 0 ? '+' : ''}{detail.verdictSummary.shift} to score
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-ink-600 leading-snug">
                  Recorded as evidence for this workspace only, and it moves the
                  score — unlike known-good, which stops the indicator matching
                  altogether.
                </p>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {VERDICT_CHOICES.map((v) => (
                    <button key={v.key} onClick={() => submitVerdict(v.key)}
                      disabled={verdicting !== null}
                      title={v.hint}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border transition-colors disabled:opacity-50"
                      style={{ color: v.color, borderColor: `${v.color}40`, background: `${v.color}12` }}>
                      {verdicting === v.key
                        ? <Loader2 className="w-3 h-3 animate-spin" />
                        : <v.icon className="w-3 h-3" />}
                      {v.label}
                    </button>
                  ))}
                </div>
                {(detail.verdicts?.length ?? 0) > 0 && (
                  <div className="space-y-1 pt-1 border-t border-white/6">
                    {detail.verdicts!.slice(0, 4).map((v) => (
                      <div key={v.id} className="text-[10px]">
                        <span style={{ color: VERDICT_COLOR_BY_KEY[v.verdict] ?? tk('violet') }}>
                          {v.verdict}
                        </span>
                        <span className="text-ink-600"> · {v.analyst} · {relTime(v.ts)}</span>
                        {v.reason && <div className="text-ink-500 leading-snug">{v.reason}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 flex-wrap">
                <button onClick={sight} disabled={busy}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-safe/15 border border-safe/30 text-safe hover:bg-safe/25 transition-colors">
                  {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />} Record sighting
                </button>
                <button onClick={toggleKnownGood} disabled={busy}
                  className={cn('flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border transition-colors',
                    detail.lifecycle.status === 'known-good'
                      ? 'bg-magenta/12 border-magenta/30 text-magenta hover:bg-magenta/20'
                      : 'bg-violet/12 border-violet/30 text-violet hover:bg-violet/20')}>
                  {detail.lifecycle.status === 'known-good'
                    ? <><ShieldOff className="w-3.5 h-3.5" /> Un-whitelist</>
                    : <><ShieldCheck className="w-3.5 h-3.5" /> Mark known-good</>}
                </button>
                <button onClick={enrich} disabled={enriching}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-amber/12 border border-amber/30 text-amber hover:bg-amber/20 transition-colors">
                  {enriching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />} Enrich
                </button>
                <button onClick={checkFp} disabled={fpChecking}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-violet/12 border border-violet/30 text-violet hover:bg-violet/20 transition-colors">
                  {fpChecking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Gauge className="w-3.5 h-3.5" />} FP likelihood
                </button>
                <button onClick={sendToSiem} disabled={busy}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">
                  <Send className="w-3.5 h-3.5" /> Send to SIEM
                </button>
                <button onClick={createCaseFromIoc} disabled={busy}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">
                  <FolderPlus className="w-3.5 h-3.5" /> Create case
                </button>
              </div>

              {/* Feedback for the create actions: confirm + link the new record */}
              {actionMsg && (
                <div className="flex items-center justify-between gap-2 rounded-lg border border-white/8 bg-surface-2/50 px-3 py-2">
                  <span className="text-[11px] text-ink-300">{actionMsg.text}</span>
                  {actionMsg.href && (
                    <a href={actionMsg.href} className="flex items-center gap-1 text-[11px] font-semibold text-magenta hover:underline shrink-0">
                      {actionMsg.label} <ArrowUpRight className="w-3 h-3" />
                    </a>
                  )}
                </div>
              )}

              {/* FP-likelihood assessment - advisory only, never auto-acts */}
              {fpAssessment && (
                <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-ink-500 uppercase tracking-wider">False-positive likelihood</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                      style={{ color: FP_BAND_STYLE[fpAssessment.band].color, background: `${FP_BAND_STYLE[fpAssessment.band].color}18` }}>
                      {FP_BAND_STYLE[fpAssessment.band].label} · {fpAssessment.score}
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-white/8 overflow-hidden relative">
                    <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${fpAssessment.score}%`, background: FP_BAND_STYLE[fpAssessment.band].color }} />
                  </div>
                  {fpAssessment.evidence.length === 0 && (
                    <p className="text-[10px] text-ink-600">No corroborating or contradicting evidence found - treat as unassessed, not benign.</p>
                  )}
                  {fpAssessment.evidence.map((e) => (
                    <div key={e.signal} className="flex items-start gap-2.5">
                      <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                        style={{ background: e.weight >= 0 ? tk('safe') : tk('magenta') }} />
                      <div className="min-w-0 flex-1">
                        <p className="text-[10px] text-ink-500">{e.detail}</p>
                      </div>
                      <span className="text-[10px] font-mono shrink-0" style={{ color: e.weight >= 0 ? tk('safe') : tk('magenta') }}>
                        {e.weight >= 0 ? '+' : ''}{e.weight}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Enrichment results */}
              {enrichment && (
                <div className="rounded-xl border border-white/8 bg-surface-2/50 p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-ink-500 uppercase tracking-wider">Enrichment</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                      style={{ color: VERDICT_COLOR[enrichment.verdict] ?? '#665B7D', background: `${VERDICT_COLOR[enrichment.verdict] ?? '#665B7D'}18` }}>
                      {enrichment.verdict}
                    </span>
                  </div>
                  {enrichment.providers.map((p) => (
                    <div key={p.provider} className="flex items-start gap-2.5">
                      <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                        style={{ background: p.available ? (VERDICT_COLOR[p.verdict] ?? '#665B7D') : '#3a3450' }} />
                      <div className="min-w-0 flex-1">
                        <p className="text-[11px] text-ink-200 capitalize">
                          {p.provider}
                          {!p.available && <span className="ml-1.5 text-[9px] text-ink-600">not configured</span>}
                          {p.cached && <span className="ml-1.5 text-[9px] text-ink-700">cached</span>}
                        </p>
                        <p className="text-[10px] text-ink-500">{p.available ? p.summary : p.reason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                {[
                  ['Severity', detail.severity], ['Threat type', detail.threatType || '-'],
                  ['Actor', detail.actor || '-'],
                  // Provenance matters: engine:* indicators are SIMULATED (random
                  // values from the Live Processing Engine), not observed intel.
                  ['Source', isSimulatedSource(detail.source)
                    ? `${detail.source} — SIMULATED, not real intel`
                    : (detail.source || '-')],
                  // Provenance an analyst can act on: which campaign reported
                  // this. Bulk blocklist entries honestly have none - saying so
                  // is the point, because "no campaign" is real information.
                  ['Reported in', detail.report?.title
                    ? `${detail.report.title}${detail.report.tlp ? ` (TLP:${detail.report.tlp})` : ''}`
                    : 'Bulk feed - no campaign context'],
                  ['First seen', relTime(detail.firstSeen)], ['Last seen', relTime(detail.lastSeen)],
                ].map(([k, v]) => (
                  <div key={k} className="px-3 py-2 rounded-lg bg-surface-2/40 border border-white/5">
                    <div className="text-[9px] text-ink-600 uppercase">{k}</div>
                    <div className="text-ink-200 truncate capitalize">{v}</div>
                  </div>
                ))}
              </div>

              {/* Pivots. An indicator an analyst cannot pivot from is a dead
                  end, and 315k dead ends is a list rather than intelligence.
                  Each group states the evidence for the link, so an analyst can
                  judge the edge instead of taking the graph's word for it. */}
              <div>
                <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Network className="w-3 h-3" /> Related
                  {relating && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
                  {related && related.total > 0 && (
                    <span className="text-ink-600 normal-case tracking-normal">
                      {related.total.toLocaleString()} across {related.groups.length} link
                      {related.groups.length === 1 ? '' : 's'}
                    </span>
                  )}
                </p>
                {!relating && related && related.groups.length === 0 && (
                  <p className="text-[10px] text-ink-600">
                    Nothing else in the store connects to this. An isolated indicator
                    is a real answer - a graph padded with coincidental edges would
                    be worse than none.
                  </p>
                )}
                <div className="space-y-2">
                  {(related?.groups ?? []).map((g) => (
                    <div key={g.key} className="rounded-lg border border-white/6 bg-surface-2/40 overflow-hidden">
                      <div className="px-2.5 py-1.5 border-b border-white/5">
                        <div className="flex items-baseline justify-between gap-2">
                          <span className="text-[10px] text-ink-200 truncate">{g.label}</span>
                          <span className="text-[9px] text-ink-600 tabular-nums shrink-0">
                            {g.total.toLocaleString()}
                          </span>
                        </div>
                        <p className="text-[9px] text-ink-600 leading-snug">{g.why}</p>
                      </div>
                      <div className="divide-y divide-white/4">
                        {g.items.map((i) => (
                          <button key={i.id} onClick={() => open(i.id)}
                            className="w-full text-left flex items-center gap-2 px-2.5 py-1.5 hover:bg-white/4 transition-colors group/row">
                            <span className="text-[9px] font-mono tabular-nums w-6 text-center shrink-0"
                              style={{ color: (BAND_STYLE[i.intelScore >= 75 ? 'high' : i.intelScore >= 50 ? 'moderate' : i.intelScore >= 25 ? 'low' : 'weak']).color }}>
                              {i.intelScore}
                            </span>
                            <span className="text-[8px] font-mono uppercase px-1 py-0.5 rounded-sm bg-white/5 text-ink-500 shrink-0 w-9 text-center">
                              {i.type}
                            </span>
                            <span className="text-[10px] font-mono text-ink-300 truncate flex-1">{i.value}</span>
                            <ArrowUpRight className="w-2.5 h-2.5 text-ink-700 opacity-0 group-hover/row:opacity-100 transition-opacity shrink-0" />
                          </button>
                        ))}
                      </div>
                      {g.total > g.items.length && (pivotHref(g)
                        ? (
                          <a href={pivotHref(g)!}
                            className="block px-2.5 py-1.5 text-[9px] text-violet hover:bg-violet/8 transition-colors border-t border-white/5">
                            See all {g.total.toLocaleString()} →
                          </a>
                        ) : (
                          <p className="px-2.5 py-1.5 text-[9px] text-ink-600 border-t border-white/5">
                            {(g.total - g.items.length).toLocaleString()} more
                          </p>
                        ))}
                    </div>
                  ))}
                </div>
              </div>

              {/* Sightings timeline */}
              <div>
                <p className="text-[10px] text-ink-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Clock className="w-3 h-3" /> Sightings ({detail.sightingsHistory.length})
                </p>
                <div className="space-y-1.5">
                  {detail.sightingsHistory.length === 0 && <p className="text-[10px] text-ink-600">No recorded sightings yet.</p>}
                  {detail.sightingsHistory.map((s) => (
                    <div key={s.id} className="flex items-start gap-2 px-2.5 py-1.5 rounded-lg bg-surface-2/40 border border-white/5">
                      <span className="w-1.5 h-1.5 rounded-full bg-safe mt-1 shrink-0" />
                      <div className="min-w-0">
                        <p className="text-[10px] text-ink-300">{s.source} <span className="text-ink-600">· {relTime(s.ts)}</span></p>
                        {s.context && <p className="text-[10px] text-ink-600 truncate">{s.context}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
