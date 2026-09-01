'use client'
import { useState } from 'react'
import Link from 'next/link'
import { Users, Crosshair, BookOpen, Bug } from 'lucide-react'
import { tk } from '@/lib/colors'
import { cn } from '@/lib/utils'
import type { AttackProfile, AttackRelease } from '@/lib/api'

/**
 * What MITRE ATT&CK says a family or a group DOES.
 *
 * This is the layer that separates a threat intelligence platform from a list of
 * bad addresses. An analyst who learns a domain is Emotet infrastructure still
 * has to know what Emotet does on a host before they can act on it, and until
 * now that meant leaving the platform. Every technique here carries its Txxxx id
 * and its attack.mitre.org link, so nothing on this panel is our opinion.
 *
 * The tactic ORDER is the kill chain, taken from ATT&CK's own matrix rather than
 * a list held here - the tactics were renamed in v19, and a hardcoded list would
 * render last year's kill chain while claiming to quote MITRE.
 *
 * One component for both pages because it is the same question asked of two
 * subjects: on a family it means "what does this malware do", on a group "what
 * does this crew do". The difference is what hangs off the bottom - a family
 * lists the groups reported to use it, a group lists the families it uses.
 */
export interface AttackPanelProps {
  a: AttackProfile
  release: AttackRelease | null
  /** 'family' | 'actor' - decides the wording and what the footer links to. */
  subject: 'family' | 'actor'
  /** Shown when MITRE tracks nothing under this name. */
  untracked: React.ReactNode
  title?: string
  hint?: string
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

export default function AttackPanel({
  a, release, subject, untracked,
  title = 'What it does',
  hint = 'MITRE ATT&CK, quoted. Every technique links to MITRE so nothing here has to be taken on our word.',
}: AttackPanelProps) {
  const [openTactic, setOpenTactic] = useState<string | null>(null)

  if (!a.tracked) return <Card title={title} hint={hint}>{untracked}</Card>

  const groups = a.groups ?? []
  const families = a.families ?? []

  return (
    <Card title={title} hint={hint}>
      <div className="flex items-center gap-2 flex-wrap mb-3">
        <a href={a.url ?? '#'} target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-teal/25 bg-teal/10
                     text-[10px] text-teal hover:bg-teal/20 transition-colors">
          <BookOpen className="w-3 h-3" /> {a.id} · {a.name}
          {a.kind === 'tool' && <span className="opacity-70">(tool)</span>}
        </a>
        <span className="text-[10px] text-ink-500">
          <span className="tabular-nums text-ink-300">{a.techniqueCount}</span> techniques
          across <span className="tabular-nums text-ink-300">{a.byTactic.length}</span> tactics
        </span>
        {release && (
          <span className="ml-auto text-[10px] text-ink-600" title={`Fetched ${release.fetchedAt}`}>
            ATT&amp;CK v{release.version}
          </span>
        )}
      </div>

      {/* Kill-chain order, top to bottom as MITRE publishes it. */}
      <div className="space-y-1.5">
        {a.byTactic.map((b) => {
          const open = openTactic === b.shortname
          return (
            <div key={b.shortname}
              className="rounded-lg border border-white/6 bg-surface-2/30 overflow-hidden
                         transition-colors hover:border-white/12">
              <button type="button"
                onClick={() => setOpenTactic(open ? null : b.shortname)}
                className="w-full flex items-center gap-2 px-3 py-2 text-left group">
                <Crosshair className="w-3 h-3 shrink-0" style={{ color: tk('violet') }} />
                <span className="text-[11px] text-white">{b.name}</span>
                <span className="text-[10px] text-ink-600 tabular-nums">{b.techniques.length}</span>
                <span className="ml-auto flex flex-wrap gap-1 justify-end max-w-[60%]">
                  {(open ? [] : b.techniques.slice(0, 5)).map((t) => (
                    <span key={t.id}
                      className="px-1 py-px rounded bg-white/5 text-[9px] font-mono text-ink-500
                                 group-hover:text-ink-300 transition-colors">
                      {t.id}
                    </span>
                  ))}
                  {!open && b.techniques.length > 5 && (
                    <span className="text-[9px] text-ink-600">+{b.techniques.length - 5}</span>
                  )}
                </span>
              </button>
              {open && (
                <div className="px-3 pb-2.5 pt-0.5 grid sm:grid-cols-2 gap-x-4 gap-y-1">
                  {b.techniques.map((t) => (
                    <a key={t.id} href={t.url ?? '#'} target="_blank" rel="noopener noreferrer"
                      className="flex items-baseline gap-1.5 text-[10px] group/t">
                      <span className="font-mono shrink-0 tabular-nums"
                        style={{ color: tk('violet') }}>{t.id}</span>
                      <span className={cn('truncate transition-colors',
                        t.isSubtechnique ? 'text-ink-500' : 'text-ink-300',
                        'group-hover/t:text-white')} title={t.name}>
                        {t.name}
                      </span>
                    </a>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* A family lists everyone reported to use it. Thirty names against one
          family is a better argument for "this does not name the adversary"
          than any amount of warning text. */}
      {subject === 'family' && groups.length > 0 && (
        <div className="mt-4 pt-3 border-t border-white/6">
          <p className="text-[10px] text-ink-500 flex items-center gap-1.5 mb-2">
            <Users className="w-3 h-3" />
            <span className="tabular-nums text-ink-300">{groups.length}</span>
            {groups.length === 1 ? ' group is' : ' groups are'} reported by MITRE to use {a.name}
          </p>
          <div className="flex flex-wrap gap-1.5">
            {groups.map((g) => (
              <a key={g.id} href={g.url ?? '#'} target="_blank" rel="noopener noreferrer"
                className="px-1.5 py-0.5 rounded border border-white/10 bg-white/5 text-[10px]
                           text-ink-400 hover:text-white hover:border-white/20 transition-all hover:scale-105"
                title={`${g.id} — opens MITRE's page for this group`}>
                {g.name}
              </a>
            ))}
          </div>
          <p className="text-[10px] text-ink-600 mt-2 leading-relaxed">
            {groups.length > 3 ? (
              <>
                This is the reason the card above will not name an operator. {groups.length} different
                groups are reported using {a.name}, so knowing an indicator belongs to this family
                says nothing about who is behind it. None of these names is written onto any
                indicator here.
              </>
            ) : (
              <>
                Reported to use it — not an attribution of any indicator in this store. A group
                using a family does not make every sighting of that family theirs.
              </>
            )}
          </p>
        </div>
      )}

      {/* A group lists the families it is reported to use, restricted to the ones
          this engine actually imports - so each is a page, not a dead name. */}
      {subject === 'actor' && families.length > 0 && (
        <div className="mt-4 pt-3 border-t border-white/6">
          <p className="text-[10px] text-ink-500 flex items-center gap-1.5 mb-2">
            <Bug className="w-3 h-3" />
            MITRE reports {a.name} using {families.length}
            {families.length === 1 ? ' family' : ' families'} this engine imports
          </p>
          <div className="flex flex-wrap gap-1.5">
            {families.map((f) => (
              <Link key={f} href={`/dashboard/cti/malware/${encodeURIComponent(f)}`}
                className="px-1.5 py-0.5 rounded border border-magenta/25 bg-magenta/10 text-[10px]
                           text-magenta hover:bg-magenta/20 transition-all hover:scale-105">
                {f}
              </Link>
            ))}
          </div>
          <p className="text-[10px] text-ink-600 mt-2 leading-relaxed">
            Reported use, from MITRE. It does not make this store&apos;s indicators of those
            families theirs — most are commodity, distributed by several crews at once.
          </p>
        </div>
      )}
    </Card>
  )
}
