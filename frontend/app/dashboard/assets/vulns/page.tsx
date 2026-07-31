'use client'

import { useState, useMemo, useEffect } from 'react'
import Link from 'next/link'
import { fetchFleetVulnFindings, fetchVulnSummary, type FleetVulnFinding, type VulnSummary } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldAlert, Bug, Search, X, ExternalLink, Crosshair, Clock,
  User, Server, FileText, Wrench, Activity, Zap, ShieldCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import ApiUnavailable from '@/components/dashboard/ApiUnavailable'
import { tk } from '@/lib/colors'
import { SkeletonRows } from '@/components/dashboard/Skeleton'

/* -- Types --------------------------------------------------------- */
type Severity = 'critical' | 'high' | 'medium' | 'low'
type VulnStatus = 'open' | 'in-progress' | 'patched' | 'accepted'
type ExploitMaturity = 'kev' | 'weaponized' | 'poc' | 'none'

interface Vuln {
  id: string
  cvss: number
  title: string
  description: string
  severity: Severity
  status: VulnStatus
  exploit: ExploitMaturity
  kev: boolean
  exploitAvailable: boolean
  affectedAssets: string[]
  ageDays: number
  assignee: string | null
  cvssVector: string
  vectorBreakdown: { label: string; value: string }[]
  epss: number
  remediation: string[]
  references: string[]
}

/* -- Meta --------------------------------------------------------- */
const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: tk('magenta') },
  high:     { label: 'High',     color: tk('threat') },
  medium:   { label: 'Medium',   color: tk('amber') },
  low:      { label: 'Low',      color: tk('safe') },
}

const STATUS_META: Record<VulnStatus, { label: string; color: string; bg: string }> = {
  open:          { label: 'Open',          color: tk('threat'), bg: 'bg-threat/10' },
  'in-progress': { label: 'In Progress',   color: tk('amber'), bg: 'bg-amber/10'  },
  patched:       { label: 'Patched',       color: tk('safe'), bg: 'bg-safe/10'   },
  accepted:      { label: 'Accepted Risk', color: tk('violet'), bg: 'bg-violet/10' },
}

const EXPLOIT_META: Record<ExploitMaturity, { label: string; color: string }> = {
  kev:        { label: 'KEV',        color: tk('magenta') },
  weaponized: { label: 'Weaponized', color: tk('threat') },
  poc:        { label: 'PoC',        color: tk('amber') },
  none:       { label: 'None',       color: '#665B7D' },
}

function cvssColor(score: number): string {
  if (score >= 9.0) return tk('magenta')
  if (score >= 7.0) return tk('threat')
  if (score >= 4.0) return tk('amber')
  return tk('safe')
}


/* -- Seed data ---------------------------------------------------- */

/* -- Sub-components ----------------------------------------------- */
function SeverityDistribution({ vulns }: { vulns: Vuln[] }) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  vulns.forEach((v) => { counts[v.severity] += 1 })
  const total = vulns.length || 1
  const order: Severity[] = ['critical', 'high', 'medium', 'low']
  return (
    <div className="flex items-center gap-4">
      <div className="flex-1 h-2.5 rounded-full overflow-hidden flex bg-white/5 min-w-[140px]">
        {order.map((s) => counts[s] > 0 && (
          <div key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: SEVERITY_META[s].color }} />
        ))}
      </div>
      <div className="flex items-center gap-3 shrink-0">
        {order.map((s) => (
          <div key={s} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_META[s].color }} />
            <span className="text-[10px] text-ink-500">{SEVERITY_META[s].label}</span>
            <span className="text-[10px] font-bold font-mono" style={{ color: SEVERITY_META[s].color }}>{counts[s]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function CvssPill({ score }: { score: number }) {
  const color = cvssColor(score)
  return (
    <span className="inline-flex items-center justify-center min-w-[40px] px-2 py-0.5 rounded-md text-xs font-bold font-mono"
      style={{ color, background: color + '1a', border: `1px solid ${color}40` }}>
      {score.toFixed(1)}
    </span>
  )
}

function ExploitBadge({ exploit }: { exploit: ExploitMaturity }) {
  const m = EXPLOIT_META[exploit]
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
      style={{ color: m.color, background: m.color + '18', border: `1px solid ${m.color}30` }}>
      {exploit === 'kev' && <Crosshair className="w-2.5 h-2.5" />}
      {exploit === 'weaponized' && <Zap className="w-2.5 h-2.5" />}
      {m.label}
    </span>
  )
}

/* -- Main page --------------------------------------------------- */
export default function VulnsPage() {
  // Empty by default; real findings from the scanner replace it. SEED shows only
  // when the API is unreachable (offline preview) - never on a real deployment
  // with an empty vuln store (which is honestly "nothing found yet").
  const [vulns, setVulns] = useState<Vuln[]>([])
  // First answer pending → skeleton rows, not "No vulnerabilities match"
  const [vulnsPending, setVulnsPending] = useState(true)
  const [vulnsFailed, setVulnsFailed] = useState(false)
  const [vsum, setVsum] = useState<VulnSummary | null>(null)
  useEffect(() => { fetchVulnSummary().then(setVsum).catch(() => {}) }, [])

  useEffect(() => {
    // Real per-CVE findings from the scanner (grouped fleet-wide). The API
    // response REPLACES the list, even when empty.
    fetchFleetVulnFindings().then((rows: FleetVulnFinding[]) => {
      const ageDays = (iso: string) =>
        Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 86400000))
      setVulns(rows.map((r) => ({
        id: r.cve,
        cvss: r.cvss,
        title: r.summary || r.cve,
        description: `${r.summary}. Affects ${r.products.join(', ')}.`
          + (r.fixedIn ? ` Fixed in ${r.fixedIn}.` : ''),
        severity: (['critical', 'high', 'medium', 'low'].includes(r.severity)
          ? r.severity : 'medium') as Severity,
        status: 'open' as VulnStatus,
        exploit: (r.kev ? 'kev' : r.exploit ? 'weaponized' : 'none') as ExploitMaturity,
        kev: r.kev,
        exploitAvailable: r.exploit,
        affectedAssets: r.affectedAssets,
        ageDays: ageDays(r.firstFound),
        assignee: r.owners[0] ?? null,
        cvssVector: '',
        vectorBreakdown: [],
        epss: 0,
        remediation: r.fixedIn
          ? [`Upgrade ${r.products.join(', ')} to ${r.fixedIn} or later.`]
          : ['Apply the vendor patch for this CVE.'],
        references: [r.reference],
      })))
    }).catch(() => setVulnsFailed(true))   // never invented findings
      .finally(() => setVulnsPending(false))
  }, [])
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<VulnStatus | 'all'>('all')
  const [kevOnly, setKevOnly] = useState(false)
  const [exploitOnly, setExploitOnly] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const selected = vulns.find((v) => v.id === selectedId) ?? null

  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') setSelectedId(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const filtered = useMemo(() => vulns.filter((v) =>
    (sevFilter === 'all' || v.severity === sevFilter) &&
    (statusFilter === 'all' || v.status === statusFilter) &&
    (!kevOnly || v.kev) &&
    (!exploitOnly || v.exploitAvailable) &&
    (!search ||
      v.id.toLowerCase().includes(search.toLowerCase()) ||
      v.title.toLowerCase().includes(search.toLowerCase()))
  ), [vulns, sevFilter, statusFilter, kevOnly, exploitOnly, search])

  const kpis = [
    { label: 'Total CVEs',         value: vsum ? vsum.distinctCves.toLocaleString() : '-', color: 'text-white'  },
    { label: 'Critical',           value: vsum ? String(vsum.bySeverity.critical) : '-',   color: 'text-magenta' },
    { label: 'Actively Exploited', value: vsum ? String(vsum.activelyExploited) : '-',     color: 'text-threat' },
    { label: 'Avg Patch Age',      value: vsum ? `${vsum.avgPatchAge}d` : '-',             color: 'text-amber'  },
    { label: 'Exposure Score',     value: vsum ? `${Math.round(vsum.exposureScore)}/100` : '-', color: 'text-threat' },
  ]

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-magenta" />
            <h1 className="text-lg font-display font-semibold text-white">Vulnerabilities</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">CVE exposure across your asset surface</p>
        </div>
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/10 bg-white/5">
          <Bug className="w-3.5 h-3.5 text-violet" />
          <span className="text-[11px] text-ink-400">{vulns.filter((v) => v.kev).length} KEV listed · {vulns.filter((v) => v.exploitAvailable).length} with exploits</span>
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {kpis.map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Severity distribution */}
      <div className="px-6 py-3 border-b border-white/4 shrink-0">
        <div className="flex items-center justify-between gap-4">
          <span className="text-[10px] text-ink-600 uppercase tracking-wider shrink-0">Severity Distribution</span>
          <SeverityDistribution vulns={vulns} />
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 px-6 py-3 border-b border-white/4 shrink-0">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 flex-1 min-w-[180px] max-w-xs">
          <Search className="w-3 h-3 text-ink-500 shrink-0" />
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search CVE ID or title…"
            className="flex-1 bg-transparent text-xs text-white placeholder-ink-600 outline-hidden" />
          {search && <button onClick={() => setSearch('')}><X className="w-3 h-3 text-ink-500" /></button>}
        </div>

        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as Severity | 'all')}
          className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/10 bg-white/5 text-ink-400 outline-hidden cursor-pointer">
          <option value="all" className="bg-surface">All Severities</option>
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
            <option key={s} value={s} className="bg-surface">{SEVERITY_META[s].label}</option>
          ))}
        </select>

        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as VulnStatus | 'all')}
          className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/10 bg-white/5 text-ink-400 outline-hidden cursor-pointer">
          <option value="all" className="bg-surface">All Statuses</option>
          {(['open', 'in-progress', 'patched', 'accepted'] as VulnStatus[]).map((s) => (
            <option key={s} value={s} className="bg-surface">{STATUS_META[s].label}</option>
          ))}
        </select>

        <button onClick={() => setKevOnly((v) => !v)}
          className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-medium transition-colors border',
            kevOnly ? 'bg-magenta/20 text-magenta border-magenta/30' : 'bg-white/4 text-ink-500 border-white/8 hover:text-ink-200')}>
          <Crosshair className="w-3 h-3" /> KEV only
        </button>
        <button onClick={() => setExploitOnly((v) => !v)}
          className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-medium transition-colors border',
            exploitOnly ? 'bg-amber/20 text-amber border-amber/30' : 'bg-white/4 text-ink-500 border-white/8 hover:text-ink-200')}>
          <Zap className="w-3 h-3" /> Exploit available
        </button>

        <span className="ml-auto text-[10px] text-ink-600">{filtered.length} of {vulns.length}</span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-[#0A0612] border-b border-white/8">
            <tr>
              {['CVE ID', 'CVSS', 'Title', 'Assets', 'Exploit', 'Age', 'Status', 'Assignee'].map((h) => (
                <th key={h} className="text-left px-4 py-2.5 text-[10px] text-ink-500 font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((v, i) => {
              const st = STATUS_META[v.status]
              const isSel = selectedId === v.id
              return (
                <motion.tr key={v.id}
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}
                  onClick={() => setSelectedId(isSel ? null : v.id)}
                  className={cn('border-b border-white/4 cursor-pointer transition-colors',
                    isSel ? 'bg-magenta/5 border-l-2 border-l-magenta/50' : 'hover:bg-white/3',
                    i % 2 !== 0 && !isSel && 'bg-white/1')}>
                  <td className="px-4 py-3 font-mono text-ink-100 whitespace-nowrap">{v.id}</td>
                  <td className="px-4 py-3"><CvssPill score={v.cvss} /></td>
                  <td className="px-4 py-3 text-ink-300 max-w-[260px] truncate">{v.title}</td>
                  <td className="px-4 py-3 font-mono text-ink-400 text-center">{v.affectedAssets.length}</td>
                  <td className="px-4 py-3"><ExploitBadge exploit={v.exploit} /></td>
                  <td className={cn('px-4 py-3 font-mono whitespace-nowrap', v.ageDays > 30 ? 'text-threat' : v.ageDays > 7 ? 'text-amber' : 'text-safe')}>{v.ageDays}d</td>
                  <td className="px-4 py-3">
                    <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold', st.bg)} style={{ color: st.color }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: st.color }} />
                      {st.label}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-ink-400 whitespace-nowrap">
                    {v.assignee ? (
                      <span className="flex items-center gap-1.5"><User className="w-3 h-3 text-ink-600" />{v.assignee}</span>
                    ) : <span className="text-ink-700">Unassigned</span>}
                  </td>
                </motion.tr>
              )
            })}
          </tbody>
        </table>
        {filtered.length === 0 && vulnsPending && <SkeletonRows rows={8} />}
        {filtered.length === 0 && !vulnsPending && vulnsFailed && (
          <ApiUnavailable what="the vulnerability findings" />
        )}
        {filtered.length === 0 && !vulnsPending && !vulnsFailed && (
          <div className="py-14 text-center">
            <ShieldCheck className="w-7 h-7 text-ink-700 mx-auto mb-2" />
            <p className="text-sm text-ink-500">No vulnerabilities match your filters</p>
            <button onClick={() => { setSearch(''); setSevFilter('all'); setStatusFilter('all'); setKevOnly(false); setExploitOnly(false) }}
              className="mt-3 text-xs text-magenta hover:underline">Clear filters</button>
          </div>
        )}
      </div>

      {/* Detail panel */}
      <AnimatePresence>
        {selected && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setSelectedId(null)}
              className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs" />
            <motion.div
              initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 30, stiffness: 280 }}
              className="fixed right-0 top-0 bottom-0 z-60 w-full max-w-md bg-surface border-l border-white/10 shadow-2xl overflow-y-auto">
              {(() => {
                const v = selected
                return (
                  <div className="p-5 space-y-5">
                    {/* Head */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <CvssPill score={v.cvss} />
                          <ExploitBadge exploit={v.exploit} />
                        </div>
                        <p className="font-mono text-sm text-white">{v.id}</p>
                        <p className="text-xs text-ink-400 mt-0.5">{v.title}</p>
                      </div>
                      <button onClick={() => setSelectedId(null)} className="p-1.5 rounded-lg hover:bg-white/8 text-ink-500 shrink-0">
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    {/* Actions: official NVD record + carry the CVE into IntelScope */}
                    <div className="grid grid-cols-2 gap-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}`}
                        target="_blank" rel="noopener noreferrer"
                        className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
                        <ExternalLink className="w-3.5 h-3.5" /> View on NVD
                      </a>
                      <Link
                        href={`/dashboard/scanner?value=${encodeURIComponent(v.id)}&type=cve&run=1`}
                        className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-magenta/15 border border-magenta/30 text-magenta hover:bg-magenta/25 transition-colors">
                        <Search className="w-3.5 h-3.5" /> Look up in IntelScope
                      </Link>
                    </div>

                    {/* Quick stats */}
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { label: 'Severity', value: SEVERITY_META[v.severity].label, color: SEVERITY_META[v.severity].color },
                        { label: 'CVSS', value: v.cvss.toFixed(1), color: cvssColor(v.cvss) },
                        { label: 'Finding Age', value: `${v.ageDays}d`, color: v.ageDays > 30 ? tk('threat') : tk('amber') },
                      ].map(({ label, value, color }) => (
                        <div key={label} className="rounded-xl border border-white/8 bg-white/3 px-3 py-2">
                          <p className="text-[9px] text-ink-600 uppercase tracking-wider">{label}</p>
                          <p className="text-sm font-bold font-mono mt-0.5" style={{ color }}>{value}</p>
                        </div>
                      ))}
                    </div>

                    {/* Description */}
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><FileText className="w-3 h-3" /> Description</p>
                      <p className="text-xs text-ink-300 leading-relaxed">{v.description}</p>
                    </div>

                    {/* CVSS vector (only when the source supplies one) */}
                    {v.cvssVector && (
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5">CVSS Vector</p>
                      <p className="font-mono text-[10px] text-violet bg-violet/5 border border-violet/15 rounded-lg px-2.5 py-1.5 mb-2 break-all">{v.cvssVector}</p>
                      <div className="grid grid-cols-2 gap-1.5">
                        {v.vectorBreakdown.map((b) => (
                          <div key={b.label} className="flex items-center justify-between text-[10px] py-1 px-2 rounded-sm bg-white/3">
                            <span className="text-ink-500">{b.label}</span>
                            <span className="text-ink-200 font-medium">{b.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    )}

                    {/* Exploit maturity */}
                    <div className="rounded-xl border border-white/8 bg-white/3 px-3 py-2.5 flex items-center justify-between">
                      <div>
                        <p className="text-[10px] text-ink-600 uppercase tracking-wider">Exploit Maturity</p>
                        <p className="text-xs font-semibold mt-0.5" style={{ color: EXPLOIT_META[v.exploit].color }}>
                          {EXPLOIT_META[v.exploit].label}
                          {v.kev && ' · CISA KEV'}
                        </p>
                      </div>
                      <Activity className="w-5 h-5" style={{ color: EXPLOIT_META[v.exploit].color }} />
                    </div>

                    {/* Affected assets */}
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><Server className="w-3 h-3" /> Affected Assets ({v.affectedAssets.length})</p>
                      <div className="flex flex-wrap gap-1.5">
                        {v.affectedAssets.map((a) => (
                          <span key={a} className="font-mono text-[10px] px-2 py-1 rounded-lg bg-white/5 border border-white/8 text-ink-300">{a}</span>
                        ))}
                      </div>
                    </div>

                    {/* Remediation */}
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5 flex items-center gap-1.5"><Wrench className="w-3 h-3" /> Remediation</p>
                      <ol className="space-y-1.5">
                        {v.remediation.map((r, idx) => (
                          <li key={idx} className="flex gap-2 text-xs text-ink-300">
                            <span className="shrink-0 w-4 h-4 rounded-full bg-safe/15 text-safe text-[9px] font-bold flex items-center justify-center mt-0.5">{idx + 1}</span>
                            <span className="leading-relaxed">{r}</span>
                          </li>
                        ))}
                      </ol>
                    </div>

                    {/* Assignee */}
                    <div className="flex items-center justify-between text-xs py-2 border-t border-white/5">
                      <span className="text-ink-600 flex items-center gap-1.5"><User className="w-3 h-3" /> Assignee</span>
                      <span className="text-ink-200">{v.assignee ?? 'Unassigned'}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs py-1">
                      <span className="text-ink-600 flex items-center gap-1.5"><Clock className="w-3 h-3" /> First Detected</span>
                      <span className="text-ink-200">{v.ageDays} days ago</span>
                    </div>

                    {/* References */}
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5">References</p>
                      {v.references.map((ref) => (
                        <a key={ref} href={ref} target="_blank" rel="noopener noreferrer"
                          className="flex items-center gap-1.5 text-xs text-violet hover:text-magenta transition-colors py-1">
                          <ExternalLink className="w-3 h-3" />
                          <span className="truncate">{ref.replace('https://', '')}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )
              })()}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  )
}
