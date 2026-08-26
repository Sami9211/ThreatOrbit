'use client'
import { useState, useEffect, useCallback, use } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  ArrowLeft, Loader2, Share2, Layers, Activity, Sparkles, ShieldCheck,
  AlertTriangle, Radio, Eye, Gavel, UserCog, Bell, Bug,
} from 'lucide-react'
import { tk } from '@/lib/colors'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import EntityHoverCard from '@/components/dashboard/EntityHoverCard'
import {
  lookupIoc, fetchIoc, fetchIocRelated, fetchIocTimeline, fetchScanEnrich,
  recordIocVerdict,
  type IocDetail, type RelatedGroup, type IocTimelineEvent, type EnrichProvider,
} from '@/lib/api'

/**
 * One indicator, everything we know about it, at a URL.
 *
 * The store could describe an indicator only inside a drawer on a list page:
 * you could not link to one, an alert could not point at one, and closing the
 * list lost your place. This is the destination - addressed by VALUE rather than
 * by record id, so an alert's matched indicator, a pasted log line and a bulk
 * check row all reach it without first having to find out where it lives.
 *
 * The tabs follow the question order an analyst actually asks: should I care
 * (Overview), what is it connected to (Knowledge), what else can we find out
 * (Enrichment), and what has already happened to it (Activity).
 */
const BAND_STYLE: Record<string, { color: string; label: string }> = {
  high: { color: tk('magenta'), label: 'high' },
  moderate: { color: tk('amber'), label: 'moderate' },
  low: { color: tk('violet'), label: 'low' },
  weak: { color: '#665B7D', label: 'weak' },
}
const STATUS_STYLE: Record<string, { color: string; label: string }> = {
  active: { color: tk('magenta'), label: 'active' },
  expired: { color: '#665B7D', label: 'expired' },
  'known-good': { color: tk('safe'), label: 'known-good' },
}
const KIND_ICON: Record<string, typeof Radio> = {
  asserted: Radio, reasserted: Radio, sighting: Eye, verdict: Gavel,
  action: UserCog, alert: Bell,
}
const KIND_COLOR: Record<string, string> = {
  asserted: tk('violet'), reasserted: '#665B7D', sighting: tk('magenta'),
  verdict: tk('amber'), action: tk('safe'), alert: tk('magenta'),
}
const VERDICT_CHOICES = [
  { key: 'confirmed', label: 'Confirmed here', hint: 'We saw this and it was real.' },
  { key: 'false-positive', label: 'False positive', hint: 'This fired and it was wrong.' },
  { key: 'benign-here', label: 'Benign here', hint: 'Real elsewhere, expected on our network.' },
]
const TABS = [
  { key: 'overview', label: 'Overview', icon: ShieldCheck },
  { key: 'knowledge', label: 'Knowledge', icon: Share2 },
  { key: 'enrichment', label: 'Enrichment', icon: Sparkles },
  { key: 'activity', label: 'Activity', icon: Activity },
] as const
type TabKey = (typeof TABS)[number]['key']

function rel(iso: string | null | undefined): string {
  if (!iso) return '—'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

function Card({ title, hint, children }: {
  title: string; hint?: string; children: React.ReactNode
}) {
  return (
    <div className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="px-4 py-2.5 border-b border-white/5">
        <h3 className="text-[11px] font-semibold text-white">{title}</h3>
        {hint && <p className="text-[10px] text-ink-600 mt-0.5 leading-snug">{hint}</p>}
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

export default function IndicatorPage({ params }: { params: Promise<{ value: string }> }) {
  const { value: raw } = use(params)
  const value = decodeURIComponent(raw)

  const [tab, setTab] = useState<TabKey>('overview')
  const [id, setId] = useState<string | null>(null)
  const [detail, setDetail] = useState<IocDetail | null>(null)
  const [groups, setGroups] = useState<RelatedGroup[]>([])
  const [timeline, setTimeline] = useState<IocTimelineEvent[]>([])
  const [providers, setProviders] = useState<EnrichProvider[] | null>(null)
  const [state, setState] = useState<'loading' | 'found' | 'absent' | 'failed'>('loading')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let alive = true
    lookupIoc(value)
      .then(async (hit) => {
        if (!alive) return
        if (!hit.found || !hit.id) { setState('absent'); return }
        setId(hit.id)
        const [d, r, t] = await Promise.all([
          fetchIoc(hit.id),
          fetchIocRelated(hit.id, 8).catch(() => ({ groups: [], total: 0 })),
          fetchIocTimeline(hit.id).catch(() => ({ value, total: 0, items: [] })),
        ])
        if (!alive) return
        setDetail(d); setGroups(r.groups); setTimeline(t.items); setState('found')
      })
      // "We could not ask" and "we have no record" are different answers, and
      // only one of them is about the indicator.
      .catch(() => { if (alive) setState('failed') })
    return () => { alive = false }
  }, [value])

  // Enrichment is deliberately lazy: it can call out to providers, so it runs
  // when an analyst asks for it rather than on every page view.
  const loadEnrichment = useCallback(() => {
    if (providers !== null) return
    fetchScanEnrich(value).then((r) => setProviders(r.providers)).catch(() => setProviders([]))
  }, [value, providers])
  useEffect(() => { if (tab === 'enrichment') loadEnrichment() }, [tab, loadEnrichment])

  const vote = async (verdict: string) => {
    if (!id) return
    setSaving(true)
    try {
      const r = await recordIocVerdict(id, verdict)
      setDetail((d) => (d ? {
        ...d, intelScore: r.intelScore, scoreBand: r.scoreBand,
        scoreComponents: r.scoreComponents, verdictSummary: r.summary,
        verdicts: [r.verdict, ...(d.verdicts ?? [])],
      } : d))
      fetchIocTimeline(id).then((t) => setTimeline(t.items)).catch(() => {})
    } finally {
      setSaving(false)
    }
  }

  const band = BAND_STYLE[detail?.scoreBand ?? 'weak'] ?? BAND_STYLE.weak
  const st = STATUS_STYLE[detail?.status ?? 'active'] ?? STATUS_STYLE.active

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <Link href="/dashboard/cti"
        className="inline-flex items-center gap-1.5 text-[11px] text-ink-500 hover:text-ink-200 mb-4">
        <ArrowLeft className="w-3 h-3" /> Threat intelligence
      </Link>

      {/* Header. The value itself is the title - an analyst arrives here holding
          a string, and the first thing they need is confirmation it is the one. */}
      <motion.div variants={fadeInUp} initial="hidden" animate="show"
        className="glass border border-white/8 rounded-xl p-5 mb-5">
        <div className="flex items-start gap-4 flex-wrap">
          {state === 'found' && (
            <span className="shrink-0 w-14 h-14 rounded-xl grid place-items-center border"
              title={`Intel score ${detail?.intelScore ?? 0}/100 (${band.label})`}
              style={{ color: band.color, background: `${band.color}14`, borderColor: `${band.color}40` }}>
              <span className="text-lg font-semibold tabular-nums">{detail?.intelScore ?? 0}</span>
            </span>
          )}
          <div className="min-w-0 flex-1">
            <h1 className="text-base font-mono text-white break-all">{value}</h1>
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              {state === 'loading' && (
                <span className="text-[10px] text-ink-600 flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" /> looking it up…
                </span>
              )}
              {state === 'found' && detail && (
                <>
                  <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded-sm bg-white/5 text-ink-400">
                    {detail.type}
                  </span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full uppercase font-semibold"
                    style={{ color: st.color, background: `${st.color}15` }}>{st.label}</span>
                  {/* The family belongs in the header, beside the type: it is
                      the first thing that makes this value a THING rather than
                      a string somebody blocked. */}
                  {detail.malwareFamily && (
                    <Link href={`/dashboard/cti/malware/${encodeURIComponent(detail.malwareFamily)}`}
                      className="flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded-full border border-magenta/30 bg-magenta/10 text-magenta hover:bg-magenta/20 transition-colors">
                      <Bug className="w-2.5 h-2.5" />
                      <span className="capitalize">{detail.malwareFamily}</span>
                    </Link>
                  )}
                  <span className="text-[10px] text-ink-500">
                    {detail.threatType || 'indicator'} · {detail.sourceCount ?? 1} source
                    {(detail.sourceCount ?? 1) === 1 ? '' : 's'} · last asserted {rel(detail.lastSeen)}
                  </span>
                </>
              )}
            </div>
          </div>
          {state === 'found' && (
            <div className="flex items-center gap-1.5 shrink-0">
              {saving && <Loader2 className="w-3 h-3 animate-spin text-ink-600" />}
              {VERDICT_CHOICES.map((v) => (
                <button key={v.key} onClick={() => vote(v.key)} title={v.hint} disabled={saving}
                  className="px-2.5 py-1.5 rounded-lg text-[10px] border border-white/10
                             text-ink-400 hover:text-white hover:border-white/25 transition-colors
                             disabled:opacity-50">
                  {v.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </motion.div>

      {state === 'failed' && (
        <p className="text-[11px] text-center py-10" style={{ color: tk('amber') }}>
          We could not reach the intel store. That is not the same as this value
          being unknown — do not read it as a clean result.
        </p>
      )}

      {state === 'absent' && (
        <div className="glass border border-white/8 rounded-xl p-8 text-center">
          <AlertTriangle className="w-5 h-5 mx-auto mb-2 text-ink-600" />
          <p className="text-[12px] text-ink-300">Not in this store.</p>
          <p className="text-[11px] text-ink-600 mt-1.5 max-w-md mx-auto leading-relaxed">
            No configured source has asserted this value, and nothing in this
            deployment has reported seeing it. That is genuinely all it means:
            absence from a threat-intel library is not evidence a value is safe,
            only that nobody we listen to has said otherwise.
          </p>
        </div>
      )}

      {state === 'found' && detail && (
        <>
          <div className="flex items-center gap-1 mb-4 border-b border-white/6">
            {TABS.map((t) => (
              <button key={t.key} onClick={() => setTab(t.key)}
                className={cn('flex items-center gap-1.5 px-3 py-2 text-[11px] border-b-2 -mb-px transition-colors',
                  tab === t.key ? 'border-violet text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}>
                <t.icon className="w-3 h-3" /> {t.label}
              </button>
            ))}
          </div>

          {tab === 'overview' && (
            <div className="grid lg:grid-cols-2 gap-4">
              <Card title="Why this score"
                hint="A ranking an analyst cannot interrogate is one they are right to ignore.">
                <div className="space-y-1.5">
                  {(detail.scoreComponents ?? []).map((c, i) => (
                    <div key={i} className="flex items-baseline gap-2 text-[10px]">
                      <span className="tabular-nums w-9 shrink-0 text-right font-semibold"
                        style={{ color: c.delta >= 0 ? tk('safe') : tk('magenta') }}>
                        {c.delta >= 0 ? '+' : ''}{c.delta}
                      </span>
                      <span className="text-ink-300 shrink-0">{c.label}</span>
                      <span className="text-ink-600 leading-snug">{c.why}</span>
                    </div>
                  ))}
                  <div className="flex items-baseline gap-2 text-[11px] pt-1.5 border-t border-white/6">
                    <span className="tabular-nums w-9 text-right font-semibold text-white">
                      {detail.intelScore ?? 0}
                    </span>
                    <span className="text-ink-400">out of 100 · {band.label}</span>
                  </div>
                </div>
              </Card>

              <Card title="How long it stays worth acting on"
                hint={detail.lifecycle?.rule
                  ? `Policy: ${detail.lifecycle.rule.name}. Editable in Settings → Feed Sources.`
                  : undefined}>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[10px]">
                  {[
                    ['Asserted confidence', `${detail.lifecycle?.assertedConfidence ?? detail.confidence}%`],
                    ['Aged to', `${detail.lifecycle?.effectiveConfidence ?? detail.confidence}%`],
                    ['Age', `${detail.lifecycle?.ageDays ?? 0} days`],
                    ['Half-life', `${detail.lifecycle?.halfLifeDays ?? 0} days`],
                    ['Revoked at score', detail.lifecycle?.revokeScore ?? '—'],
                    ['Revoked on', detail.lifecycle?.validUntil?.slice(0, 10) ?? 'not yet dated'],
                  ].map(([k, v]) => (
                    <div key={k as string} className="flex items-baseline justify-between gap-2">
                      <span className="text-ink-600">{k}</span>
                      <span className="text-ink-200 tabular-nums">{v}</span>
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Who says so"
                hint="Independent sources agreeing is the one signal a single public feed cannot give you.">
                {(detail.sources ?? []).length === 0 && (
                  <p className="text-[10px] text-ink-600">
                    Only {detail.source || 'one unrecorded source'} — a single
                    feed&apos;s word.
                  </p>
                )}
                <div className="space-y-1">
                  {(detail.sources ?? []).map((s) => (
                    <div key={s} className="text-[10px] text-ink-300 truncate" title={s}>{s}</div>
                  ))}
                </div>
                {(detail.sourceCount ?? 1) > 1 && (
                  <p className="text-[10px] mt-2" style={{ color: tk('safe') }}>
                    {detail.sourceCount} independent sources assert this value.
                  </p>
                )}
              </Card>

              <Card title="What your team concluded"
                hint="Conclusions are evidence, not an override: they move the score and accumulate as history.">
                {(detail.verdicts ?? []).length === 0 ? (
                  <p className="text-[10px] text-ink-600">
                    Nobody here has recorded a conclusion yet. The buttons above
                    write one, and it will change this indicator&apos;s score for
                    your workspace only.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {(detail.verdicts ?? []).slice(0, 6).map((v) => (
                      <div key={v.id} className="text-[10px]">
                        <span className="text-ink-200">{v.verdict}</span>
                        <span className="text-ink-600"> — {v.analyst}, {rel(v.ts)}</span>
                        {v.reason && <p className="text-ink-600 leading-snug">{v.reason}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )}

          {tab === 'knowledge' && (
            <div className="space-y-4">
              {groups.length === 0 && (
                <p className="text-[11px] text-ink-600 text-center py-10">
                  Nothing in this store links to it. Nothing invents a
                  relationship here, so &ldquo;no relations&rdquo; is a real answer
                  rather than a failure to look.
                </p>
              )}
              {groups.map((g) => (
                <Card key={g.key} title={`${g.label} · ${g.total}`} hint={g.why}>
                  {/* A family is the one pivot that has somewhere better to go
                      than a list of siblings: a page saying what the thing IS,
                      and whether anyone can honestly name who runs it. */}
                  {g.key === 'malware' && (
                    <Link href={`/dashboard/cti/malware/${encodeURIComponent(g.pivot.value)}`}
                      className="inline-flex items-center gap-1.5 mb-2 text-[10px] text-magenta hover:underline">
                      <Bug className="w-3 h-3" /> What is {g.pivot.value}?
                    </Link>
                  )}
                  <div className="grid sm:grid-cols-2 gap-x-4 gap-y-1">
                    {g.items.map((i) => (
                      <Link key={i.id} href={`/dashboard/cti/indicator/${encodeURIComponent(i.value)}`}
                        className="flex items-center gap-2 text-[10px] group py-0.5">
                        <span className="tabular-nums w-7 shrink-0 text-right"
                          style={{ color: (BAND_STYLE[i.intelScore >= 75 ? 'high'
                            : i.intelScore >= 50 ? 'moderate' : i.intelScore >= 25 ? 'low' : 'weak']).color }}>
                          {i.intelScore}
                        </span>
                        {/* Not truncated. A host pivot returns one site's page
                            set - .../atb/login.html, .../atb/details.html,
                            .../atb/logging.php - which differ only in the tail,
                            so cutting the tail renders four identical rows and
                            throws away the only thing that made them worth
                            listing. */}
                        <EntityHoverCard value={i.value} className="min-w-0">
                          <span className="font-mono text-ink-300 group-hover:text-white break-all">
                            {i.value}
                          </span>
                        </EntityHoverCard>
                      </Link>
                    ))}
                  </div>
                  {g.total > g.items.length && (
                    <p className="text-[10px] text-ink-600 mt-2">
                      Showing {g.items.length} of {g.total.toLocaleString()}.
                    </p>
                  )}
                </Card>
              ))}
            </div>
          )}

          {tab === 'enrichment' && (
            <div className="space-y-3">
              {providers === null && (
                <p className="text-[11px] text-ink-600 text-center py-10 flex items-center justify-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> asking every configured provider…
                </p>
              )}
              {providers?.length === 0 && (
                <p className="text-[11px] text-ink-600 text-center py-10">
                  No enrichment provider returned anything for this value.
                </p>
              )}
              {(providers ?? []).map((p) => (
                <Card key={p.provider} title={p.provider}>
                  {p.available ? (
                    <>
                      {p.verdict && (
                        <p className="text-[10px] mb-1" style={{ color: tk('amber') }}>{p.verdict}</p>
                      )}
                      <p className="text-[10px] text-ink-300 leading-snug">
                        {p.summary || 'No summary returned.'}
                      </p>
                      {p.ts && (
                        <p className="text-[10px] text-ink-700 mt-1.5">
                          collected {rel(p.ts)}{p.cached ? ' · cached' : ''}
                        </p>
                      )}
                    </>
                  ) : (
                    // An unconfigured provider reports that it is unconfigured.
                    // It never reports a clean result it did not obtain.
                    <p className="text-[10px] text-ink-600">
                      Not available{p.reason ? ` — ${p.reason}` : ''}. This is not
                      a clean result; nobody was asked.
                    </p>
                  )}
                </Card>
              ))}
            </div>
          )}

          {tab === 'activity' && (
            <Card title={`Everything that has happened to it · ${timeline.length}`}
              hint="Assembled from the assertion ledger, our own sightings, analyst conclusions, deliberate actions and the alerts it raised. Lifecycle transitions are recorded nowhere, so they are absent rather than reconstructed.">
              {timeline.length === 0 && (
                <p className="text-[10px] text-ink-600">Nothing recorded yet.</p>
              )}
              <div className="space-y-2.5">
                {timeline.map((e, i) => {
                  const Icon = KIND_ICON[e.kind] ?? Layers
                  const color = KIND_COLOR[e.kind] ?? tk('violet')
                  return (
                    <div key={i} className="flex items-start gap-2.5">
                      <span className="mt-0.5 w-5 h-5 rounded grid place-items-center shrink-0"
                        style={{ background: `${color}14`, color }}>
                        <Icon className="w-3 h-3" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-[10px] text-ink-200 leading-snug">{e.title}</p>
                        {e.detail && (
                          <p className="text-[10px] text-ink-600 leading-snug">{e.detail}</p>
                        )}
                        <p className="text-[10px] text-ink-700">
                          {e.actor || 'unattributed'} · {rel(e.ts)}
                        </p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
