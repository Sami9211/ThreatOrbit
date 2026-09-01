'use client'

import { useState, useMemo, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'
import { fetchActors, fetchActor, fetchCtiSummary,
  type Actor as ApiActor, type ActorDetail, type CtiSummary,
  type AttackProfile } from '@/lib/api'
import {
  UserSearch, Search, X, ExternalLink, Shield,
  Crosshair, Bug, Clock, Activity, Building2, Filter,
  Globe, Skull, DollarSign, Megaphone, Flame, Users, Fingerprint,
} from 'lucide-react'
import { tk, withAlpha } from '@/lib/colors'
import ApiUnavailable from '@/components/dashboard/ApiUnavailable'
import AttackPanel from '@/components/dashboard/AttackPanel'

/* --- Types ----------------------------------------------------------- */
type Motivation = 'Espionage' | 'Financial' | 'Hacktivism' | 'Destruction' | 'Disruption'
type ActorType = 'Nation-State' | 'Cybercrime' | 'Hacktivist'

interface Campaign {
  year: string
  name: string
  note: string
}

/** Where a group is FROM, when anybody can say so.
 *
 *  Not every group has one. Emotet's operators are generally assessed as
 *  Eastern European and the 2021 takedown involved arrests in Ukraine, but no
 *  government has attributed the group to a state - and a flag on a card reads
 *  as certainty. So the library leaves TA542's origin blank, and blank has to
 *  render as a statement rather than as a gap before a separator.
 */
const originLabel = (origin: string) => origin?.trim() || 'origin not established'
const originFlag = (flag: string) => flag?.trim() || '🌐'

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  origin: string
  flag: string
  type: ActorType
  motivations: Motivation[]
  sophistication: number // 1..5
  threatLevel: 'critical' | 'high' | 'elevated'
  sectors: string[]
  campaignCount: number
  firstSeen: string
  lastSeen?: string
  active?: boolean
  malware: string[]
  ttps: string[]
  recentActivity: string
  /** Indicators in THIS store attributed to the group. Derived server-side and
   *  zero until something real attributes - see recompute_actor_activity. */
  iocCount: number
  description: string
  campaigns: Campaign[]
  iocs: string[]
}

/* Attribution confidence, derived transparently from the corroborating
 * evidence actually present on the record - never a fabricated number. More
 * independent signals (named origin, cross-vendor aliases, mapped TTPs,
 * attributed tooling, documented campaigns) = higher confidence. The reasons
 * are shown alongside the band so the assessment is auditable, not asserted. */
function attributionAssessment(actor: ThreatActor, attack?: AttackProfile | null, campaignCount?: number): { band: 'High' | 'Moderate' | 'Low'; color: string; reasons: string[] } {
  const reasons: string[] = []
  const named = actor.origin && !/unknown|^n\/?a$/i.test(actor.origin.trim())
  if (named) reasons.push(`Named origin (${actor.origin})`)
  if (actor.aliases.length >= 2) reasons.push(`${actor.aliases.length} cross-vendor aliases`)
  // Count MITRE's techniques when MITRE has this group, because that is the
  // number rendered a few inches further down the same drawer. The library's
  // hand-written four or five sitting above ATT&CK's sixty-four does not read as
  // two sources - it reads as the page contradicting itself.
  const ttps = attack?.tracked ? attack.techniqueCount : actor.ttps.length
  if (ttps >= 3) {
    reasons.push(attack?.tracked
      ? `${ttps} ATT&CK techniques mapped by MITRE (${attack.id})`
      : `${ttps} mapped ATT&CK techniques`)
  }
  if (actor.malware.length >= 1) reasons.push(`${actor.malware.length} attributed tool${actor.malware.length === 1 ? '' : 's'}`)
  // Same rule as the technique count above: what the drawer shows is what the
  // assessment counts, or the page argues with itself.
  const campaigns = campaignCount ?? actor.campaignCount
  if (campaigns >= 1) reasons.push(`${campaigns} documented campaign${campaigns === 1 ? '' : 's'}`)
  const score = reasons.length
  if (score >= 4) return { band: 'High', color: tk('safe'), reasons }
  if (score >= 2) return { band: 'Moderate', color: tk('amber'), reasons }
  return { band: 'Low', color: tk('ink'), reasons: reasons.length ? reasons : ['Limited corroborating evidence on file'] }
}


/* --- Config / lookups ------------------------------------------------ */
const MOTIVATION_CFG: Record<Motivation, { color: string; icon: React.ComponentType<any> }> = {
  Espionage:   { color: tk('violet'), icon: Globe },
  Financial:   { color: tk('safe'), icon: DollarSign },
  Hacktivism:  { color: tk('amber'), icon: Megaphone },
  Destruction: { color: tk('threat'), icon: Flame },
  Disruption:  { color: tk('threat'), icon: Flame },
}
// Neutral fallback so an unrecognised motivation/threat value from the API can
// never crash the page (the lookups below are all `?? FALLBACK_*`).
const FALLBACK_MOTIVATION = { color: '#8A7DA3', icon: Crosshair }

const THREAT_CFG: Record<ThreatActor['threatLevel'], { color: string; label: string }> = {
  critical: { color: tk('magenta'), label: 'Critical' },
  high:     { color: tk('threat'), label: 'High' },
  elevated: { color: tk('amber'), label: 'Elevated' },
}
const FALLBACK_THREAT = { color: tk('amber'), label: 'Elevated' }
// Lookup that tolerates any string the API might send.
const threatCfg = (lvl: string) => THREAT_CFG[lvl as ThreatActor['threatLevel']] ?? FALLBACK_THREAT

/* --- Sophistication meter -------------------------------------------- */
function SophMeter({ level, color = tk('magenta') }: { level: number; color?: string }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((n) => (
        <span
          key={n}
          className="w-1.5 rounded-xs"
          style={{
            height: `${6 + n * 2}px`,
            background: n <= level ? color : 'rgba(255,255,255,0.10)',
          }}
        />
      ))}
    </div>
  )
}

/* --- Motivation badge ------------------------------------------------ */
function MotivationBadge({ m }: { m: string }) {
  const cfg = MOTIVATION_CFG[m as Motivation] ?? FALLBACK_MOTIVATION
  const Icon = cfg.icon
  return (
    <span
      className="inline-flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded-full border"
      style={{ color: cfg.color, background: `${cfg.color}15`, borderColor: `${cfg.color}33` }}
    >
      <Icon className="w-2.5 h-2.5" /> {m}
    </span>
  )
}

/* --- Actor card ------------------------------------------------------ */
function ActorCard({ actor, onSelect }: { actor: ThreatActor; onSelect: () => void }) {
  const threat = threatCfg(actor.threatLevel)
  return (
    <div
      onClick={onSelect}
      className="glass border border-white/5 rounded-xl p-4 cursor-pointer transition-all duration-200 hover:border-magenta/30 hover:bg-magenta/5"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-lg leading-none">{originFlag(actor.flag)}</span>
            <span className="text-sm font-semibold text-white truncate">{actor.name}</span>
          </div>
          <p className="text-[10px] text-ink-500 mt-1 truncate">{actor.aliases.slice(0, 2).join(' · ')}</p>
        </div>
        <span
          className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded-full border shrink-0"
          style={{ color: threat.color, background: `${threat.color}15`, borderColor: `${threat.color}33` }}
        >
          {threat.label}
        </span>
      </div>

      <p className="text-[10px] text-ink-500 mt-2">{originLabel(actor.origin)} · {actor.type}</p>

      <div className="flex items-center justify-between mt-3">
        <div className="flex flex-wrap gap-1">
          {actor.motivations.map((m) => <MotivationBadge key={m} m={m} />)}
        </div>
        <SophMeter level={actor.sophistication} color={threat.color} />
      </div>

      <div className="flex flex-wrap gap-1 mt-3">
        {actor.sectors.slice(0, 3).map((s) => (
          <span key={s} className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-3 border border-white/8 text-ink-500">{s}</span>
        ))}
        {actor.sectors.length > 3 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-3 border border-white/8 text-ink-600">+{actor.sectors.length - 3}</span>
        )}
      </div>

      <div className="flex items-center gap-3 mt-3 pt-3 border-t border-white/5 text-[10px] text-ink-500">
        <span className="flex items-center gap-1"><Crosshair className="w-3 h-3" /> {actor.campaignCount} campaigns</span>
        <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> since {actor.firstSeen}</span>
      </div>
    </div>
  )
}

/* --- Detail slide-over ----------------------------------------------- */
function ActorPanel({ actor, onClose }: { actor: ThreatActor; onClose: () => void }) {
  const threat = threatCfg(actor.threatLevel)
  // The two malware relationships come from the detail endpoint, because they
  // are computed against the live store rather than stored on the actor row.
  const [detail, setDetail] = useState<ActorDetail | null>(null)
  useEffect(() => {
    let alive = true
    setDetail(null)
    fetchActor(actor.id).then((d) => { if (alive) setDetail(d) }).catch(() => {})
    return () => { alive = false }
  }, [actor.id])
  // Both sources, because both are rendered below. The stored count is 0 on
  // every actor of every live deployment - the library carries no campaign
  // records - and it sat directly above a section listing three of MITRE's.
  const campaignCount = (detail?.attack?.campaigns?.length ?? 0) + actor.campaigns.length
  return (
    <motion.div
      key={actor.id}
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="fixed right-0 top-0 bottom-0 z-60 w-full max-w-[600px] flex flex-col bg-surface border-l border-white/8 shadow-2xl overflow-hidden"
    >
      {/* Header */}
      <div className="p-5 border-b border-white/8 shrink-0">
        <div className="flex items-start gap-3">
          <span className="text-3xl leading-none">{originFlag(actor.flag)}</span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="font-display text-lg font-bold text-white">{actor.name}</h2>
              <span
                className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded-full border"
                style={{ color: threat.color, background: `${threat.color}15`, borderColor: `${threat.color}33` }}
              >
                {threat.label} Threat
              </span>
            </div>
            <p className="text-[10px] text-ink-500 mt-1">{originLabel(actor.origin)} · {actor.type} · since {actor.firstSeen}</p>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {actor.aliases.map((a) => (
                <span key={a} className="text-[10px] px-1.5 py-0.5 rounded-sm bg-surface-3 text-ink-500 font-mono">{a}</span>
              ))}
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center gap-4 mt-4 flex-wrap">
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Sophistication</span>
            <div className="mt-1"><SophMeter level={actor.sophistication} color={threat.color} /></div>
          </div>
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Campaigns</span>
            {/* Count what the drawer actually lists. This read 0 on every actor
                of every live deployment - the library carries no campaign
                records - directly above a section listing three of MITRE's. */}
            <span className="text-sm font-semibold text-white mt-0.5">{campaignCount}</span>
          </div>
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Active</span>
            <span className="text-sm font-semibold text-white mt-0.5 flex items-center gap-1.5">
              {actor.firstSeen}
              {(() => {
                const end = actor.active ? 'present' : (actor.lastSeen && actor.lastSeen !== actor.firstSeen ? actor.lastSeen : null)
                return end ? <>–{end}</> : null
              })()}
              {actor.active && <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" title="Currently active" />}
            </span>
          </div>
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Motivation</span>
            <div className="flex gap-1 mt-1">{actor.motivations.map((m) => <MotivationBadge key={m} m={m} />)}</div>
          </div>
          <a
            href={`https://attack.mitre.org/groups/?search=${encodeURIComponent(actor.name)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto flex items-center gap-1 text-xs text-magenta hover:underline"
          >
            <ExternalLink className="w-3 h-3" /> MITRE ATT&amp;CK
          </a>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        <section>
          <SectionHead icon={UserSearch} title="Description" />
          <p className="text-xs text-ink-300 leading-relaxed mt-2">{actor.description}</p>
        </section>

        {/* Attribution assessment - transparent, evidence-based confidence band */}
        {(() => {
          const att = attributionAssessment(actor, detail?.attack, campaignCount)
          return (
            <section>
              <SectionHead icon={Fingerprint} title="Attribution Assessment" />
              <div className="mt-2 flex items-center gap-2">
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full border"
                  style={{ color: att.color, background: withAlpha(att.color, 0.12), borderColor: withAlpha(att.color, 0.25) }}>
                  {att.band} confidence
                </span>
                <span className="text-[10px] text-ink-600">derived from documented evidence</span>
              </div>
              <ul className="mt-2 space-y-1">
                {att.reasons.map((r) => (
                  <li key={r} className="flex items-center gap-1.5 text-[11px] text-ink-400">
                    <span className="w-1 h-1 rounded-full bg-ink-600 shrink-0" />{r}
                  </li>
                ))}
              </ul>
            </section>
          )
        })()}

        {/* This used to render `actor.description` a second time under a
            heading that promised activity - two identical paragraphs, one of
            them mislabelled. What this deployment has actually seen IS
            available, so say that instead, including when the answer is
            nothing. */}
        <section>
          <SectionHead icon={Activity} title="Activity in this deployment" />
          <p className="text-xs text-ink-300 leading-relaxed mt-2">
            {actor.iocCount > 0 ? (
              <>
                <b className="text-white tabular-nums">{actor.iocCount.toLocaleString()}</b>{' '}
                indicators in this store are attributed to this group
                {detail && detail.operatedMalware.length > 0 && (
                  <> — all of them through the {detail.operatedMalware.map((m) => m.label).join(', ')}{' '}
                    {detail.operatedMalware.length === 1 ? 'family it operates' : 'families it operates'}</>
                )}
                {actor.lastSeen && <>, most recently asserted in {actor.lastSeen}</>}.
              </>
            ) : (
              <>
                Nothing in this store is attributed to this group. Blocklists publish values
                without naming an adversary, so an actor stays at zero until a source names
                it or it is linked through a malware family it operates.
              </>
            )}
          </p>
        </section>

        {/* MITRE's own reading of this group, when MITRE has one.
            The library ships four or five techniques per actor as a hand-written
            summary; ATT&CK carries between 33 and 93 for the same groups, in
            kill-chain order and each with a link. Where the two exist, MITRE's
            wins - it is sourced and ours is a paraphrase. Where MITRE has
            nothing, the library's summary is still shown and labelled as ours,
            because a page that hides what it knows to avoid an awkward caveat is
            the wrong trade. */}
        {detail?.attack?.tracked ? (
          <AttackPanel a={detail.attack} release={detail.attackRelease} subject="actor"
            title="What they do"
            hint="MITRE ATT&CK, quoted. Every technique links to MITRE, so none of this rests on our say-so."
            untracked={null} />
        ) : (
          <section>
            <SectionHead icon={Shield} title="MITRE ATT&CK Techniques" />
            {detail && (
              <p className="text-[10px] text-ink-600 mt-1.5 leading-snug max-w-2xl">
                MITRE ATT&amp;CK does not track a group under this name, so these are this
                library&apos;s own summary rather than MITRE&apos;s. ATT&amp;CK models 10 of the
                13 actors shipped here; the ones it leaves out are mostly ransomware brands
                and operator names other vendors use.
              </p>
            )}
            <div className="flex flex-wrap gap-1.5 mt-2">
              {actor.ttps.map((t) => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] px-2 py-0.5 rounded-sm bg-violet/15 text-violet font-mono border border-violet/20 hover:bg-violet/25 transition-colors"
                >
                  {t}
                </a>
              ))}
            </div>
          </section>
        )}

        {/* Two relationships that look identical on a card and mean opposite
            amounts. Operating a family makes its indicators this group's
            infrastructure; being reported to USE one says nothing about who
            owns any particular value, because most families are sold, leaked,
            open-source or cracked. They are shown apart and never summed. */}
        {(detail?.operatedMalware.length ?? 0) > 0 && (
          <section>
            <SectionHead icon={Bug} title="Infrastructure we hold" />
            <p className="text-[10px] text-ink-600 mt-1 leading-snug">
              Families this group operates. Every indicator below is counted as theirs,
              and nothing else on this page is.
            </p>
            <div className="mt-2 space-y-1.5">
              {detail!.operatedMalware.map((m) => (
                <Link key={m.family} href={`/dashboard/cti/malware/${encodeURIComponent(m.family)}`}
                  className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-magenta/25 bg-magenta/8 hover:bg-magenta/15 transition-colors">
                  <span className="text-[11px] font-semibold text-white">{m.label}</span>
                  <span className="text-[10px] text-ink-500">{m.role}</span>
                  <span className="ml-auto text-[10px] text-magenta tabular-nums">
                    {m.indicators.toLocaleString()} indicators here
                  </span>
                </Link>
              ))}
            </div>
          </section>
        )}

        {(() => {
          // A family already shown above - as theirs, or as a row with a count -
          // is not also a bare chip. Saying it twice reads as two separate
          // pieces of evidence, and an empty heading reads as a broken panel.
          const shown = new Set([
            ...(detail?.operatedMalware ?? []).map((o) => o.family),
            ...(detail?.reportedMalware ?? []).map((o) => o.family),
          ])
          const chips = actor.malware.filter(
            (m) => !shown.has(m.toLowerCase().replace(/[\s-]/g, '')))
          if (chips.length === 0 && (detail?.reportedMalware.length ?? 0) === 0) return null
          return (
        <section>
          <SectionHead icon={Bug} title="Reported to use" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {chips
              .map((m) => (
                <a key={m} href={`https://attack.mitre.org/software/?search=${encodeURIComponent(m)}`}
                  target="_blank" rel="noopener noreferrer" title={`${m} on MITRE ATT&CK`}
                  className="text-[10px] px-2 py-0.5 rounded-sm bg-threat/10 text-threat border border-threat/20 hover:bg-threat/20 hover:text-white transition-colors">{m}</a>
              ))}
          </div>
          {(detail?.reportedMalware.length ?? 0) > 0 && (
            <>
              <div className="mt-2 space-y-1.5">
                {detail!.reportedMalware.map((m) => (
                  <Link key={m.family} href={`/dashboard/cti/malware/${encodeURIComponent(m.family)}`}
                    className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-white/10 bg-surface-2 hover:border-white/25 transition-colors">
                    <span className="text-[11px] text-ink-200">{m.label}</span>
                    <span className="text-[10px] text-ink-600">{m.role}</span>
                    <span className="ml-auto text-[10px] text-ink-400 tabular-nums">
                      {m.indicators.toLocaleString()} in the store
                    </span>
                  </Link>
                ))}
              </div>
              <p className="text-[10px] text-ink-600 mt-2 leading-snug">
                Held, but <b className="text-ink-400">not counted as this group&apos;s</b>. These
                families were distributed by several crews, so an indicator carrying one says
                which malware it is, not whose campaign it belongs to.
              </p>
            </>
          )}
        </section>
          )
        })()}

        <section>
          <SectionHead icon={Building2} title="Target Sectors" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {actor.sectors.map((s) => (
              <span key={s} className="text-[10px] px-2 py-0.5 rounded-full bg-surface-2 border border-white/10 text-ink-300">{s}</span>
            ))}
          </div>
        </section>

        {/* An empty heading reads as a broken panel, not as "we have none". This
            section was a title with nothing under it on every actor of every
            live deployment - the library carries no campaign records, and only
            the demo seeder ever added illustrative ones.

            MITRE publishes real ones: dated, named, attributed, cited. Six of
            the thirteen shipped actors have them, and they are the campaigns an
            analyst already knows by name - SolarWinds Compromise, Operation
            Dream Job, the three Ukraine electric power attacks. */}
        {((detail?.attack?.campaigns?.length ?? 0) > 0 || actor.campaigns.length > 0) && (
        <section>
          <SectionHead icon={Clock} title="Known Campaigns" />
          <div className="mt-3 space-y-3 relative before:absolute before:left-[5px] before:top-1 before:bottom-1 before:w-px before:bg-white/8">
            {(detail?.attack?.campaigns ?? []).map((c) => (
              <div key={c.id} className="flex items-start gap-3 pl-5 relative group">
                <span className="absolute left-px top-1 w-2.5 h-2.5 rounded-full border border-white/20
                                 transition-transform group-hover:scale-125"
                  style={{ background: threat.color }} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* A span, not a year: "2015-12 → 2016-01" is what the
                        reporting supports, and a campaign that ran across a
                        new year is not a 2015 campaign. */}
                    <span className="text-[10px] font-mono text-magenta whitespace-nowrap">
                      {c.firstSeen?.slice(0, 7)}
                      {c.lastSeen && c.lastSeen.slice(0, 7) !== c.firstSeen?.slice(0, 7) && (
                        <> → {c.lastSeen.slice(0, 7)}</>
                      )}
                    </span>
                    <a href={c.url ?? '#'} target="_blank" rel="noopener noreferrer"
                      className="text-xs text-ink-200 font-medium hover:text-white transition-colors">
                      {c.name}
                    </a>
                    <span className="text-[9px] font-mono text-ink-600">{c.id}</span>
                  </div>
                  {c.description && (
                    <p className="text-[11px] text-ink-500 mt-0.5 leading-snug line-clamp-3">
                      {c.description}
                    </p>
                  )}
                  <div className="flex flex-wrap items-center gap-1 mt-1">
                    {c.families.map((f) => (
                      <Link key={f} href={`/dashboard/cti/malware/${encodeURIComponent(f)}`}
                        className="px-1.5 py-0.5 rounded border border-magenta/25 bg-magenta/10
                                   text-[9px] text-magenta hover:bg-magenta/20 transition-all hover:scale-105">
                        {f}
                      </Link>
                    ))}
                    {/* Who reported it. MITRE writes these inline in the prose;
                        they are lifted out rather than deleted, because a claim
                        without its source is the thing this platform exists not
                        to publish. */}
                    {c.citations.length > 0 && (
                      <span className="text-[9px] text-ink-600"
                        title={c.citations.join(' · ')}>
                        reported by {c.citations.slice(0, 2).join(', ')}
                        {c.citations.length > 2 && ` +${c.citations.length - 2}`}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
            {/* Anything the library itself carries, kept below MITRE's. */}
            {actor.campaigns.map((c) => (
              <div key={c.name} className="flex items-start gap-3 pl-5 relative">
                <span className="absolute left-px top-1 w-2.5 h-2.5 rounded-full border border-white/20" style={{ background: threat.color }} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-magenta">{c.year}</span>
                    <span className="text-xs text-ink-200 font-medium">{c.name}</span>
                  </div>
                  <p className="text-[11px] text-ink-500 mt-0.5 leading-snug">{c.note}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
        )}

        {(actor.iocs.length > 0 || (detail?.operatedMalware.length ?? 0) > 0) && (
        <section>
          <SectionHead icon={Crosshair} title="Associated IOCs" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {actor.iocs.map((ioc) => (
              <a key={ioc} href={`/dashboard/scanner?value=${encodeURIComponent(ioc)}&run=1`}
                title="Look up in IntelScope"
                className="text-[10px] px-2 py-0.5 rounded-sm bg-magenta/10 text-magenta font-mono border border-magenta/20 hover:bg-magenta/20 hover:text-white transition-colors">{ioc}</a>
            ))}
          </div>
          {/* The record itself carries a handful at most; the thousands reached
              through an operated family live on that family's page, which is
              where the ranking and the sources are. */}
          {actor.iocs.length === 0 && (detail?.operatedMalware.length ?? 0) > 0 && (
            <p className="text-[11px] text-ink-500 mt-1 leading-snug">
              None are pinned to this record. The{' '}
              {detail!.operatedMalware.reduce((n, m) => n + m.indicators, 0).toLocaleString()}{' '}
              held through{' '}
              {detail!.operatedMalware.map((m, i, arr) => (
                <span key={m.family}>
                  <Link href={`/dashboard/cti/malware/${encodeURIComponent(m.family)}`}
                    className="text-magenta hover:underline">{m.label}</Link>
                  {i < arr.length - 2 ? ', ' : i === arr.length - 2 ? ' and ' : ''}
                </span>
              ))}{' '}
              are ranked and sourced on the family page.
            </p>
          )}
        </section>
        )}
      </div>
    </motion.div>
  )
}

function SectionHead({ icon: Icon, title }: { icon: React.ComponentType<any>; title: string }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 text-ink-600" />
      <span className="text-[10px] font-semibold text-ink-500 uppercase tracking-widest">{title}</span>
    </div>
  )
}

/* --- KPI strip ------------------------------------------------------- */
const KPIS: { label: string; value: string | number; icon: React.ComponentType<any>; color: string; sub: string }[] = [
  { label: 'Tracked Actors',     value: 47, icon: Users,    color: tk('violet'), sub: 'in library' },
  { label: 'Active Campaigns',   value: 12, icon: Activity, color: tk('magenta'), sub: 'ongoing' },
  { label: 'Nation-State',       value: 23, icon: Globe,    color: tk('threat'), sub: 'APT groups' },
  { label: 'Ransomware Groups',  value: 16, icon: Skull,    color: tk('amber'), sub: 'RaaS / extortion' },
]

/* --- Filter pill ----------------------------------------------------- */
function FilterSelect({
  value, onChange, options, icon: Icon,
}: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  icon: React.ComponentType<any>
}) {
  return (
    <div className="relative flex items-center gap-2 px-3 py-2 rounded-xl bg-surface-2 border border-white/8 hover:border-white/15 transition-colors">
      <Icon className="w-3.5 h-3.5 text-ink-600 shrink-0" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none bg-transparent text-xs text-ink-300 focus:outline-hidden cursor-pointer pr-3"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-[#100A1C]">{o.label}</option>
        ))}
      </select>
    </div>
  )
}

/* --- Page ------------------------------------------------------------ */
export default function ActorProfilesPage() {
  const [search, setSearch] = useState('')

  // Deep-link: ?q=<actor> pre-fills the search - dark-web findings and other
  // surfaces link a named threat actor straight to their profile here.
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('q')
    if (q) setSearch(q)
  }, [])
  const [filterOrigin, setFilterOrigin] = useState<string>('all')
  const [filterMotivation, setFilterMotivation] = useState<string>('all')
  const [filterType, setFilterType] = useState<string>('all')
  const [filterSector, setFilterSector] = useState<string>('all')
  const [filterSoph, setFilterSoph] = useState<string>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Deep-link: ?actor=<id> opens that actor directly. A malware family page
  // names its operator; without this the link would land on an unfiltered list
  // and leave the reader to find the row themselves.
  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get('actor')
    if (id) setSelectedId(id)
  }, [])
  // Empty until the API answers, and it stays empty if the API does not. The
  // actor library is a backend record: whatever it holds is what this
  // deployment knows, including the gaps.
  const [actors, setActors] = useState<ThreatActor[]>([])
  const [summary, setSummary] = useState<CtiSummary | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    fetchCtiSummary().then(setSummary).catch(() => {})
    fetchActors().then((data: ApiActor[]) => {
      // Straight through from the API. This used to merge a hardcoded frontend
      // seed over the live record - and the seed WON, so a real deployment
      // showed compiled-in malware names, campaign lists and "recent activity"
      // prose in place of its own data, with undated claims about what an actor
      // is doing NOW that nobody was maintaining. Where the record is empty, the
      // UI says so; that is a prompt to record something, not a gap to fill in.
      const mapped: ThreatActor[] = data.map((a) => ({
        id: a.id,
        name: a.name,
        aliases: Array.isArray(a.aliases) ? a.aliases : [],
        origin: a.origin,
        flag: a.flag || '🌐',
        type: ((t) => t === 'nation-state' ? 'Nation-State' : t === 'cybercrime' ? 'Cybercrime' : 'Hacktivist')((a.type ?? '').toLowerCase()) as ActorType,
        motivations: (Array.isArray(a.motivations) ? a.motivations : [])
          .filter((m): m is string => typeof m === 'string')
          .map((m) => (m.charAt(0).toUpperCase() + m.slice(1).toLowerCase())) as Motivation[],
        sophistication: a.sophistication,
        threatLevel: (a.threatLevel as 'critical' | 'high' | 'elevated') ?? 'high',
        sectors: Array.isArray(a.sectors) ? a.sectors : [],
        campaignCount: a.campaignCount ?? (Array.isArray(a.campaigns) ? a.campaigns.length : 0),
        firstSeen: a.firstSeen?.split('-')[0] ?? 'Unknown',
        lastSeen: a.lastSeen?.split('-')[0],
        active: !!a.active,
        malware: Array.isArray(a.malware) ? a.malware : [],
        ttps: Array.isArray(a.ttps) ? a.ttps : [],
        // `recentActivity` is no longer read from the row - the section that
        // used it now derives from what the store actually holds.
        recentActivity: a.recentActivity ?? '',
        iocCount: a.iocCount ?? 0,
        description: a.description,
        campaigns: (Array.isArray(a.campaigns) ? a.campaigns : [])
          .map((c) => ({ year: '', name: c, note: '' })),
        iocs: [],
      }))
      setActors(mapped)
    }).catch(() => setFailed(true))
  }, [])

  const selected = actors.find((a) => a.id === selectedId) ?? null

  // Live KPI values from the API summary, falling back to the static demo figures.
  const kpis = useMemo(() => {
    if (!summary) return KPIS
    const live: Record<string, number> = {
      'Tracked Actors': summary.trackedActors,
      'Active Campaigns': summary.activeCampaigns,
      'Nation-State': summary.nationState,
      'Ransomware Groups': summary.cybercrime,
    }
    return KPIS.map((k) => ({ ...k, value: live[k.label] ?? k.value }))
  }, [summary])

  const origins = useMemo(() => {
    // A blank is not a filterable origin - it is the absence of one, and an
    // empty entry in the dropdown reads as a broken option.
    const set = new Set(actors.map((a) => a.origin).filter((o) => o.trim()))
    return Array.from(set).sort()
  }, [actors])
  const sectors = useMemo(() => {
    const set = new Set(actors.flatMap((a) => a.sectors))
    return Array.from(set).sort()
  }, [actors])

  const filtered = useMemo(() => actors.filter((a) => {
    if (filterOrigin !== 'all' && a.origin !== filterOrigin) return false
    if (filterMotivation !== 'all' && !a.motivations.includes(filterMotivation as Motivation)) return false
    if (filterType !== 'all' && a.type !== filterType) return false
    if (filterSector !== 'all' && !a.sectors.includes(filterSector)) return false
    if (filterSoph !== 'all' && String(a.sophistication) !== filterSoph) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((al) => al.toLowerCase().includes(q)) ||
        a.origin.toLowerCase().includes(q) ||
        a.malware.some((m) => m.toLowerCase().includes(q)) ||
        a.sectors.some((s) => s.toLowerCase().includes(q))
      )
    }
    return true
  }), [actors, search, filterOrigin, filterMotivation, filterType, filterSector, filterSoph])

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/5 shrink-0">
        <div className="flex items-center gap-2 mb-1">
          <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25">
            <UserSearch className="w-4 h-4 text-magenta" />
          </div>
          <h1 className="font-display text-xl font-bold text-white tracking-tight">Actor Profiles</h1>
        </div>
        <p className="text-sm text-ink-500">Tracked threat actors, APT groups, and their TTPs</p>
      </div>

      {/* KPI strip */}
      <div className="px-6 py-4 border-b border-white/5 shrink-0">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {kpis.map(({ label, value, icon: Icon, color, sub }) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass border border-white/5 rounded-xl p-4 relative overflow-hidden"
            >
              <div className="absolute inset-0 opacity-30" style={{ background: `radial-gradient(circle at 0% 0%, ${color}20, transparent 70%)` }} />
              <div className="relative flex items-start justify-between">
                <div>
                  <p className="text-xs text-ink-500 mb-1">{label}</p>
                  <p className="font-display text-2xl font-bold text-white">{value}</p>
                  <p className="text-[10px] text-ink-600 mt-0.5">{sub}</p>
                </div>
                <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}18` }}>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Filter bar */}
      <div className="px-6 py-3 border-b border-white/5 shrink-0">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-xs px-3 py-2 rounded-xl bg-surface-2 border border-white/8 focus-within:border-violet/40 transition-colors">
            <Search className="w-3.5 h-3.5 text-ink-600 shrink-0" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search actors, aliases, malware…"
              className="flex-1 bg-transparent text-xs text-ink-200 placeholder-ink-700 focus:outline-hidden"
            />
            {search && (
              <button onClick={() => setSearch('')} className="text-ink-600 hover:text-ink-300">
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <FilterSelect
            value={filterOrigin}
            onChange={setFilterOrigin}
            icon={Globe}
            options={[{ value: 'all', label: 'All Origins' }, ...origins.map((o) => ({ value: o, label: o }))]}
          />
          <FilterSelect
            value={filterMotivation}
            onChange={setFilterMotivation}
            icon={Crosshair}
            options={[
              { value: 'all', label: 'All Motivations' },
              { value: 'Espionage', label: 'Espionage' },
              { value: 'Financial', label: 'Financial' },
              { value: 'Hacktivism', label: 'Hacktivism' },
              { value: 'Destruction', label: 'Destruction' },
            ]}
          />
          <FilterSelect
            value={filterType}
            onChange={setFilterType}
            icon={Filter}
            options={[
              { value: 'all', label: 'All Types' },
              { value: 'Nation-State', label: 'Nation-State' },
              { value: 'Cybercrime', label: 'Cybercrime' },
              { value: 'Hacktivist', label: 'Hacktivist' },
            ]}
          />
          <FilterSelect
            value={filterSector}
            onChange={setFilterSector}
            icon={Crosshair}
            options={[{ value: 'all', label: 'All Industries' }, ...sectors.map((s) => ({ value: s, label: s }))]}
          />
          <FilterSelect
            value={filterSoph}
            onChange={setFilterSoph}
            icon={Filter}
            options={[
              { value: 'all', label: 'Any Sophistication' },
              { value: '5', label: 'Sophistication 5 (highest)' },
              { value: '4', label: 'Sophistication 4' },
              { value: '3', label: 'Sophistication 3' },
              { value: '2', label: 'Sophistication 2' },
              { value: '1', label: 'Sophistication 1' },
            ]}
          />

          <span className="text-[10px] text-ink-600 ml-auto">{filtered.length} of {actors.length} actors</span>
        </div>
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {failed ? (
          // Never a demo library. An empty screen that says why is honest; a
          // screen of compiled-in actors is a claim this deployment tracks them.
          <ApiUnavailable what="the threat actor library" />
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center text-ink-600 text-sm">No actors match current filters</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filtered.map((actor) => (
              <ActorCard key={actor.id} actor={actor} onSelect={() => setSelectedId(actor.id)} />
            ))}
          </div>
        )}
      </div>

      {/* Slide-over */}
      <AnimatePresence>
        {selected && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[2px]"
              onClick={() => setSelectedId(null)}
            />
            <ActorPanel actor={selected} onClose={() => setSelectedId(null)} />
          </>
        )}
      </AnimatePresence>
    </div>
  )
}
