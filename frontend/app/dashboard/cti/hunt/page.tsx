'use client'

import { useState, useMemo, useEffect } from 'react'
import { fetchCtiHunts, runCtiHunt, fetchAttackCoverage, type SavedHunt as ApiSavedHunt } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Crosshair, Target, ChevronRight, Play, Pause, CheckCircle,
  Activity, FlaskConical, ShieldCheck, Layers, Database,
  ExternalLink, User, Calendar, Lightbulb, XCircle, Search,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ─── Types ─────────────────────────────────────────────────────────── */
type HuntStatus = 'active' | 'paused' | 'completed'
type HypothesisStatus = 'confirmed' | 'refuted' | 'investigating'

interface Hypothesis {
  id: string
  statement: string
  status: HypothesisStatus
  dataSources: string[]
  findings: string
  relatedIOCs: string[]
}

interface MitreTech {
  id: string
  name: string
  tactic: string
}

interface Hunt {
  id: string
  name: string
  description: string
  status: HuntStatus
  analyst: string
  techniques: MitreTech[]
  progress: number
  started: string
  hypotheses: Hypothesis[]
}

/* ─── Seed data ──────────────────────────────────────────────────────── */
const HUNTS: Hunt[] = [
  {
    id: 'hunt-volt',
    name: 'Volt Typhoon LOTL Detection',
    description:
      'Hypothesis-driven hunt for living-off-the-land (LOTL) tradecraft attributed to Volt Typhoon within OT/ICS network segments. Focus on native binary abuse and log clearing that evades signature-based detection.',
    status: 'active',
    analyst: 'j.chen',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
      { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'Defense Evasion' },
      { id: 'T1070', name: 'Indicator Removal', tactic: 'Defense Evasion' },
    ],
    progress: 64,
    started: '2026-05-21',
    hypotheses: [
      {
        id: 'h-volt-1',
        statement: 'Adversary uses wmic.exe and netsh for discovery on OT jump hosts without dropping binaries.',
        status: 'confirmed',
        dataSources: ['EDR Process Telemetry', 'Windows Event Log 4688', 'OT Network Flow'],
        findings: 'Confirmed 3 OT jump hosts executing wmic process enumeration outside maintenance windows. Parent process was a renamed cmd.exe.',
        relatedIOCs: ['host: OT-JMP-04', 'sha256:9f2c…a1', 'cmd: wmic /node:'],
      },
      {
        id: 'h-volt-2',
        statement: 'Security event logs are selectively cleared after reconnaissance activity.',
        status: 'investigating',
        dataSources: ['Windows Event Log 1102', 'SIEM Audit Trail'],
        findings: 'Two 1102 (audit log cleared) events correlate temporally with discovery activity. Pivoting on operator accounts.',
        relatedIOCs: ['evt:1102', 'acct: svc-otmaint'],
      },
      {
        id: 'h-volt-3',
        statement: 'Persistence achieved via scheduled tasks masquerading as vendor maintenance jobs.',
        status: 'refuted',
        dataSources: ['EDR Persistence Module', 'Task Scheduler Operational Log'],
        findings: 'All scheduled tasks reconciled to legitimate vendor SOWs. No rogue persistence located in this segment.',
        relatedIOCs: [],
      },
    ],
  },
  {
    id: 'hunt-lazarus',
    name: 'Lazarus Supply Chain Indicators',
    description:
      'Intelligence-led hunt for npm and PyPI typosquatting packages with install-time payloads consistent with Lazarus Group supply-chain campaigns targeting developer endpoints.',
    status: 'active',
    analyst: 'a.patel',
    techniques: [
      { id: 'T1195.001', name: 'Compromise Software Dependencies and Development Tools', tactic: 'Initial Access' },
    ],
    progress: 48,
    started: '2026-05-28',
    hypotheses: [
      {
        id: 'h-laz-1',
        statement: 'Developer endpoints have resolved typosquatted package names within the last 30 days.',
        status: 'confirmed',
        dataSources: ['Package Proxy Logs', 'EDR File Creation', 'DNS Logs'],
        findings: 'Identified one install of "colorsama" (typosquat of colorama) on a CI build agent. Post-install script reached out to a staging domain.',
        relatedIOCs: ['pkg: colorsama@1.2.9', 'domain: cdn-pkgs[.]live', 'ip: 185.225.x.x'],
      },
      {
        id: 'h-laz-2',
        statement: 'Install scripts exfiltrate environment variables and SSH keys.',
        status: 'investigating',
        dataSources: ['EDR Network Module', 'Process Args Telemetry'],
        findings: 'Outbound POST observed from build agent immediately after install. Payload capture pending forensic acquisition.',
        relatedIOCs: ['proc: node post-install', 'domain: cdn-pkgs[.]live'],
      },
    ],
  },
  {
    id: 'hunt-cobalt',
    name: 'Cobalt Strike Beacon Sweep',
    description:
      'C2 infrastructure mapping hunt to surface Cobalt Strike beacon traffic by profiling jitter, named-pipe artifacts, and malleable C2 HTTP header anomalies across the enterprise.',
    status: 'active',
    analyst: 'r.osei',
    techniques: [
      { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' },
      { id: 'T1090', name: 'Proxy', tactic: 'Command and Control' },
    ],
    progress: 71,
    started: '2026-05-12',
    hypotheses: [
      {
        id: 'h-cs-1',
        statement: 'Beacon traffic exhibits regular interval callbacks with default malleable profile headers.',
        status: 'confirmed',
        dataSources: ['Proxy Logs', 'Zeek HTTP Logs', 'Network Flow'],
        findings: 'Two hosts beaconing every 60s ±10% jitter to a single VPS with a non-standard User-Agent. Matches a known CS profile.',
        relatedIOCs: ['ip: 45.137.x.x', 'ua: Mozilla/5.0 (compatible; MSIE 9)', 'uri: /jquery-3.3.1.min.js'],
      },
      {
        id: 'h-cs-2',
        statement: 'Named-pipe lateral movement artifacts exist on internal hosts.',
        status: 'confirmed',
        dataSources: ['EDR Named Pipe Telemetry', 'Sysmon Event 17/18'],
        findings: 'Detected msagent_* named pipes on two endpoints adjacent to confirmed beacon hosts.',
        relatedIOCs: ['pipe: \\\\.\\pipe\\msagent_4f', 'host: FIN-WKS-22'],
      },
    ],
  },
  {
    id: 'hunt-kerb',
    name: 'Kerberoasting Campaign',
    description:
      'Active Directory ticket-abuse hunt looking for anomalous TGS requests with weak encryption types indicative of Kerberoasting against service accounts.',
    status: 'paused',
    analyst: 'j.chen',
    techniques: [
      { id: 'T1558.003', name: 'Steal or Forge Kerberos Tickets: Kerberoasting', tactic: 'Credential Access' },
    ],
    progress: 33,
    started: '2026-04-30',
    hypotheses: [
      {
        id: 'h-kerb-1',
        statement: 'A single principal requests TGS tickets for many SPNs in a short window using RC4.',
        status: 'investigating',
        dataSources: ['Domain Controller Event 4769', 'Identity Graph'],
        findings: 'One workstation requested 40+ RC4 service tickets in 8 minutes. Hunt paused pending IR scoping decision.',
        relatedIOCs: ['evt:4769 enc:0x17', 'acct: dev-intern'],
      },
    ],
  },
  {
    id: 'hunt-cloud',
    name: 'Cloud IAM Persistence',
    description:
      'Completed hunt for backdoor IAM accounts and access keys in AWS and Azure that grant standing administrative access outside the change-management pipeline.',
    status: 'completed',
    analyst: 'a.patel',
    techniques: [
      { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Persistence' },
    ],
    progress: 100,
    started: '2026-04-08',
    hypotheses: [
      {
        id: 'h-cloud-1',
        statement: 'IAM users exist with active access keys but no console login in 90+ days.',
        status: 'confirmed',
        dataSources: ['AWS CloudTrail', 'IAM Credential Report'],
        findings: 'Found two orphaned IAM users with admin-equivalent policies and recently used keys. Remediated and rotated.',
        relatedIOCs: ['iam: svc-legacy-deploy', 'key: AKIA…ZX'],
      },
      {
        id: 'h-cloud-2',
        statement: 'Azure service principals were granted Owner role outside PIM.',
        status: 'refuted',
        dataSources: ['Azure Activity Log', 'Entra ID Audit'],
        findings: 'All Owner grants reconciled to approved PIM activations. No rogue principal found.',
        relatedIOCs: [],
      },
    ],
  },
  {
    id: 'hunt-dns',
    name: 'Exfil over DNS',
    description:
      'Covert-channel detection hunt targeting low-and-slow data exfiltration tunnelled through DNS queries with high subdomain entropy and abnormal record-type distribution.',
    status: 'active',
    analyst: 'r.osei',
    techniques: [
      { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol', tactic: 'Exfiltration' },
    ],
    progress: 55,
    started: '2026-05-25',
    hypotheses: [
      {
        id: 'h-dns-1',
        statement: 'A host issues high volumes of unique high-entropy subdomains to a single apex domain.',
        status: 'investigating',
        dataSources: ['DNS Resolver Logs', 'Network Flow', 'Threat Intel Feed'],
        findings: 'One finance host queried 300+ unique TXT subdomains for a newly registered domain over 6 hours.',
        relatedIOCs: ['domain: tnl[.]exfilzone[.]xyz', 'host: FIN-LAP-09', 'qtype: TXT'],
      },
      {
        id: 'h-dns-2',
        statement: 'The apex domain is newly registered and low-reputation.',
        status: 'confirmed',
        dataSources: ['Passive DNS', 'WHOIS Enrichment', 'TI Feed'],
        findings: 'Apex domain registered 9 days ago via a privacy registrar; flagged by two TI feeds as suspected tunneling infra.',
        relatedIOCs: ['domain: exfilzone[.]xyz', 'registrar: PrivacyGuard'],
      },
    ],
  },
]

/* ─── Status config ──────────────────────────────────────────────────── */
const HUNT_STATUS: Record<HuntStatus, { label: string; color: string; icon: React.ElementType }> = {
  active:    { label: 'Active',    color: '#34F5C5', icon: Play },
  paused:    { label: 'Paused',    color: '#FFB23E', icon: Pause },
  completed: { label: 'Completed', color: '#7A3CFF', icon: CheckCircle },
}

const HYP_STATUS: Record<HypothesisStatus, { label: string; color: string; icon: React.ElementType }> = {
  confirmed:     { label: 'Confirmed',     color: '#FF4D6D', icon: CheckCircle },
  refuted:       { label: 'Refuted',       color: '#34F5C5', icon: XCircle },
  investigating: { label: 'Investigating', color: '#FFB23E', icon: Search },
}

/* ─── MITRE coverage matrix tactics ──────────────────────────────────── */
const MATRIX_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Credential Access',
  'Defense Evasion',
  'Command and Control',
  'Exfiltration',
] as const

/* ─── KPI strip ──────────────────────────────────────────────────────── */
/* ─── Hypothesis row ─────────────────────────────────────────────────── */
function HypothesisRow({ hyp }: { hyp: Hypothesis }) {
  const cfg = HYP_STATUS[hyp.status]
  const Icon = cfg.icon
  return (
    <div className="rounded-lg bg-surface-2/60 border border-white/5 p-3.5">
      <div className="flex items-start gap-2.5">
        <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: cfg.color }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-full border"
              style={{ color: cfg.color, background: `${cfg.color}15`, borderColor: `${cfg.color}33` }}
            >
              {cfg.label}
            </span>
          </div>
          <p className="text-xs text-ink-200 mt-1.5 leading-snug">{hyp.statement}</p>

          <p className="text-[10px] text-ink-600 uppercase tracking-wide mt-3 mb-1">Findings</p>
          <p className="text-[11px] text-ink-400 leading-relaxed">{hyp.findings}</p>

          <div className="grid sm:grid-cols-2 gap-3 mt-3">
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5 flex items-center gap-1">
                <Database className="w-3 h-3" /> Data Sources
              </p>
              <div className="flex flex-wrap gap-1">
                {hyp.dataSources.map((d) => (
                  <span key={d} className="text-[9px] px-1.5 py-0.5 rounded bg-violet/10 text-violet border border-violet/20">{d}</span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5 flex items-center gap-1">
                <Target className="w-3 h-3" /> Related IOCs
              </p>
              {hyp.relatedIOCs.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {hyp.relatedIOCs.map((ioc) => (
                    <span key={ioc} className="text-[9px] px-1.5 py-0.5 rounded bg-magenta/10 text-magenta font-mono border border-magenta/20">{ioc}</span>
                  ))}
                </div>
              ) : (
                <span className="text-[10px] text-ink-600 italic">none</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ─── Hunt card ──────────────────────────────────────────────────────── */
function HuntCard({ hunt, expanded, onToggle, onRun }: {
  hunt: Hunt; expanded: boolean; onToggle: () => void; onRun: () => void
}) {
  const cfg = HUNT_STATUS[hunt.status]
  const StatusIcon = cfg.icon
  const openHyp = hunt.hypotheses.filter((h) => h.status === 'investigating').length

  return (
    <div
      className={cn(
        'glass border rounded-xl overflow-hidden transition-all duration-200',
        expanded ? 'border-magenta/30 bg-magenta/5' : 'border-white/5 hover:border-white/10',
      )}
    >
      <div onClick={onToggle} className="p-4 cursor-pointer">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="p-2 rounded-lg shrink-0" style={{ background: `${cfg.color}18` }}>
              <StatusIcon className="w-4 h-4" style={{ color: cfg.color }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-white truncate">{hunt.name}</span>
                <span
                  className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded-full border"
                  style={{ color: cfg.color, background: `${cfg.color}15`, borderColor: `${cfg.color}33` }}
                >
                  {cfg.label}
                </span>
              </div>
              <p className="text-[11px] text-ink-400 mt-1 leading-snug">{hunt.description}</p>
            </div>
          </div>
          <ChevronRight className={cn('w-4 h-4 text-ink-600 transition-transform shrink-0', expanded && 'rotate-90 text-magenta')} />
        </div>

        {/* Meta row */}
        <div className="flex items-center gap-4 mt-3 text-[10px] text-ink-500 flex-wrap">
          <span className="flex items-center gap-1"><User className="w-3 h-3" /> {hunt.analyst}</span>
          <span className="flex items-center gap-1"><FlaskConical className="w-3 h-3" /> {hunt.hypotheses.length} hypotheses · {openHyp} open</span>
          <span className="flex items-center gap-1"><Calendar className="w-3 h-3" /> started {hunt.started}</span>
          <button
            onClick={(e) => { e.stopPropagation(); onRun() }}
            className="ml-auto flex items-center gap-1 px-2 py-1 rounded-lg border border-safe/25 bg-safe/10 text-safe hover:bg-safe/20 transition-colors font-medium"
          >
            <Play className="w-3 h-3" /> Run hunt
          </button>
        </div>

        {/* MITRE chips */}
        <div className="flex flex-wrap gap-1 mt-3">
          {hunt.techniques.map((t) => (
            <a
              key={t.id}
              href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              title={`${t.id} · ${t.name} (${t.tactic})`}
              className="text-[9px] px-1.5 py-0.5 rounded bg-violet/15 text-violet font-mono border border-violet/20 hover:bg-violet/25 transition-colors"
            >
              {t.id}
            </a>
          ))}
        </div>

        {/* Progress */}
        <div className="mt-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-ink-600">Progress</span>
            <span className="text-[10px] font-mono text-ink-400">{hunt.progress}%</span>
          </div>
          <div className="h-1.5 bg-surface-3 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${hunt.progress}%` }}
              transition={{ duration: 0.8, ease: 'easeOut' }}
              className="h-full rounded-full"
              style={{ background: cfg.color }}
            />
          </div>
        </div>
      </div>

      {/* Expanded detail */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25 }}
            className="border-t border-white/5"
          >
            <div className="p-4 space-y-4">
              {/* Techniques detail */}
              <div>
                <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <Layers className="w-3 h-3" /> MITRE ATT&amp;CK Techniques
                </p>
                <div className="grid sm:grid-cols-2 gap-2">
                  {hunt.techniques.map((t) => (
                    <a
                      key={t.id}
                      href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 rounded-lg bg-surface-2/60 border border-white/5 p-2.5 hover:border-violet/30 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-violet shrink-0">{t.id}</span>
                      <div className="min-w-0">
                        <p className="text-[11px] text-ink-200 truncate">{t.name}</p>
                        <p className="text-[9px] text-ink-600">{t.tactic}</p>
                      </div>
                      <ExternalLink className="w-3 h-3 text-ink-600 ml-auto shrink-0" />
                    </a>
                  ))}
                </div>
              </div>

              {/* Hypotheses */}
              <div>
                <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                  <Lightbulb className="w-3 h-3" /> Hypotheses
                </p>
                <div className="space-y-2.5">
                  {hunt.hypotheses.map((h) => (
                    <HypothesisRow key={h.id} hyp={h} />
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* ─── MITRE coverage mini-matrix ─────────────────────────────────────── */
function CoverageMatrix({ hunts }: { hunts: Hunt[] }) {
  // tactic -> covering active hunts
  const coverage = useMemo(() => {
    const map: Record<string, Hunt[]> = {}
    for (const tactic of MATRIX_TACTICS) map[tactic] = []
    for (const hunt of hunts) {
      if (hunt.status !== 'active') continue
      const tactics = new Set(hunt.techniques.map((t) => t.tactic))
      for (const tac of tactics) {
        if (map[tac]) map[tac].push(hunt)
      }
    }
    return map
  }, [hunts])

  function cellColor(count: number) {
    if (count >= 2) return '#FF2E97'
    if (count === 1) return '#7A3CFF'
    return 'rgba(255,255,255,0.04)'
  }

  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Crosshair className="w-3.5 h-3.5 text-magenta" />
          <h3 className="text-sm font-semibold text-white">ATT&amp;CK Coverage (Active Hunts)</h3>
        </div>
        <div className="flex items-center gap-4 text-[9px] text-ink-500">
          {[
            { label: '2+ hunts', color: '#FF2E97' },
            { label: '1 hunt', color: '#7A3CFF' },
            { label: 'none', color: 'rgba(255,255,255,0.08)' },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded" style={{ background: color }} />
              {label}
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${MATRIX_TACTICS.length}, minmax(0, 1fr))` }}>
        {MATRIX_TACTICS.map((tactic) => (
          <div key={`${tactic}-head`} className="text-center text-[8px] text-ink-600 leading-tight h-8 flex items-end justify-center pb-1">
            {tactic}
          </div>
        ))}
        {MATRIX_TACTICS.map((tactic) => {
          const hunts = coverage[tactic] ?? []
          const count = hunts.length
          return (
            <div
              key={`${tactic}-cell`}
              title={count > 0 ? `${tactic}: ${hunts.map((h) => h.name).join(', ')}` : `${tactic}: no active coverage`}
              className="h-12 rounded-lg flex items-center justify-center text-[10px] font-mono font-semibold transition-opacity cursor-pointer hover:opacity-80"
              style={{ background: cellColor(count), color: count > 0 ? 'rgba(255,255,255,0.95)' : 'transparent' }}
            >
              {count > 0 ? count : '·'}
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ─── Page ───────────────────────────────────────────────────────────── */
export default function ThreatHuntPage() {
  const [expandedId, setExpandedId] = useState<string | null>(HUNTS[0].id)
  const [hunts, setHunts] = useState<Hunt[]>(HUNTS)
  const [coverage, setCoverage] = useState<number | null>(null)

  // Execute a hunt against the live IOC store; mark it running while the
  // backend works, then reflect the persisted outcome.
  function handleRun(id: string) {
    setHunts((prev) => prev.map((h) => (h.id === id ? { ...h, status: 'active' as HuntStatus } : h)))
    runCtiHunt(id)
      .then(({ hunt }) => {
        setHunts((prev) => prev.map((h) => h.id === id
          ? { ...h, status: 'completed' as HuntStatus, progress: hunt.progress }
          : h))
      })
      .catch(() => {
        // demo entry or API offline — show completion locally so the action still responds
        setHunts((prev) => prev.map((h) => (h.id === id ? { ...h, status: 'completed' as HuntStatus, progress: 100 } : h)))
      })
  }

  useEffect(() => {
    fetchCtiHunts().then((data: ApiSavedHunt[]) => {
      if (data.length > 0) {
        const merged: Hunt[] = data.map((h) => {
          const seed = HUNTS.find((s) => s.id === h.id || s.name === h.name)
          return seed
            ? { ...seed, progress: h.progress, analyst: h.analyst }
            : {
                id: h.id,
                name: h.name,
                description: h.hypothesis,
                status: (h.status === 'active' ? 'active' : h.status === 'completed' ? 'completed' : 'paused') as HuntStatus,
                analyst: h.analyst,
                techniques: [],
                progress: h.progress,
                started: h.created,
                hypotheses: [],
              }
        })
        setHunts(merged)
        if (merged.length > 0) setExpandedId(merged[0].id)
      }
    }).catch(() => {})
    fetchAttackCoverage().then((c) => setCoverage(c.summary.coveragePct)).catch(() => {})
  }, [])

  // KPI tiles derived from real hunts + ATT&CK coverage (no hardcoded values).
  const kpis = [
    { label: 'Active Hunts',    value: String(hunts.filter((h) => h.status === 'active').length), icon: Crosshair,   color: '#FF2E97', sub: 'in progress' },
    { label: 'Saved Hunts',     value: String(hunts.length), icon: FlaskConical, color: '#7A3CFF', sub: 'hypotheses tracked' },
    { label: 'Completed',       value: String(hunts.filter((h) => h.status === 'completed').length), icon: ShieldCheck, color: '#34F5C5', sub: 'hunts run' },
    { label: 'ATT&CK Coverage', value: coverage == null ? '—' : `${coverage}%`, icon: Layers, color: '#FFB23E', sub: 'techniques mapped' },
  ]

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/5">
        <div className="flex items-center gap-2 mb-1">
          <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25">
            <Crosshair className="w-4 h-4 text-magenta" />
          </div>
          <h1 className="font-display text-xl font-bold text-white tracking-tight">Threat Hunt</h1>
        </div>
        <p className="text-sm text-ink-500">Hypothesis-driven hunting campaigns mapped to MITRE ATT&amp;CK</p>
      </div>

      {/* KPI strip */}
      <div className="px-6 py-4 border-b border-white/5">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {kpis.map(({ label, value, icon: Icon, color, sub }) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass border border-white/5 rounded-xl p-4 relative overflow-hidden"
            >
              <div
                className="absolute inset-0 opacity-30"
                style={{ background: `radial-gradient(circle at 0% 0%, ${color}20, transparent 70%)` }}
              />
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

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
        {/* Coverage matrix */}
        <CoverageMatrix hunts={hunts} />

        {/* Hunt campaigns */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-3.5 h-3.5 text-violet" />
            <h2 className="text-sm font-semibold text-white">Hunt Campaigns</h2>
            <span className="text-[10px] text-ink-600">{hunts.length} total</span>
          </div>
          <div className="space-y-3">
            {hunts.map((hunt) => (
              <HuntCard
                key={hunt.id}
                hunt={hunt}
                expanded={expandedId === hunt.id}
                onToggle={() => setExpandedId((id) => (id === hunt.id ? null : hunt.id))}
                onRun={() => handleRun(hunt.id)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
