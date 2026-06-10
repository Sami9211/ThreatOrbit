'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Radio, CheckCircle2, HelpCircle, X, RefreshCw, ExternalLink,
  AlertTriangle, Shield, Zap, ChevronDown, ChevronRight, Filter,
  Activity, Globe, Hash, Link, Download, Send, Eye, Clock,
  TrendingUp, MoreHorizontal, Flame, Cpu, Lock,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchFeeds, toggleFeed, fetchFeedsSummary, type Feed as ApiFeed, type FeedsSummary } from '@/lib/api'

/* ── Types ────────────────────────────────────────────────────────── */
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

/* ── Seed data ────────────────────────────────────────────────────── */
const CONFIRMED_SEED: ThreatEntry[] = [
  {
    id: 'c001', ts: '2024-11-12T14:22:00Z', cve: 'CVE-2024-6387',
    title: 'OpenSSH glibc RCE — unauthenticated remote code execution',
    attackType: 'RCE', source: '45.95.147.236', sourceCountry: 'Russia',
    severity: 'critical', sectors: ['Healthcare', 'Finance', 'Government'],
    summary: 'Signal handler race condition in OpenSSH before 9.8p1 allows unauthenticated RCE as root. 700k+ internet-exposed instances. Mass exploitation confirmed.',
    feedSources: ['NVD', 'MISP', 'RecordedFuture', 'CrowdStrike'],
    aiConfidence: 99, iocs: ['45.95.147.236', '185.220.101.1', 'CVE-2024-6387'],
    mitre: ['T1190', 'T1133'], status: 'confirmed', correlated: 14, tags: ['openssh', 'regresshion', 'linux', 'rce'],
  },
  {
    id: 'c002', ts: '2024-11-12T14:18:00Z', cve: 'CVE-2024-3094',
    title: 'XZ Utils backdoor — malicious supply chain compromise',
    attackType: 'Supply Chain', source: '185.220.101.1', sourceCountry: 'North Korea',
    severity: 'critical', sectors: ['Technology', 'Government', 'Defense'],
    summary: 'Malicious code injected into XZ Utils 5.6.0-5.6.1 via social engineering. SSH authentication bypass via backdoor. CISA Emergency Directive issued.',
    feedSources: ['CISA', 'NVD', 'MISP', 'GreyNoise', 'AlienVault'],
    aiConfidence: 100, iocs: ['185.220.101.1', 'CVE-2024-3094', 'liblzma.so'],
    mitre: ['T1195.001', 'T1078'], status: 'confirmed', correlated: 22, tags: ['xz', 'supply-chain', 'ssh'],
  },
  {
    id: 'c003', ts: '2024-11-12T14:11:00Z', cve: null,
    title: 'Lazarus Group deploys BLINDINGCAN RAT against defense sector',
    attackType: 'APT', source: '165.22.120.1', sourceCountry: 'North Korea',
    severity: 'critical', sectors: ['Defense', 'Aerospace'],
    summary: 'FBI and CISA joint advisory confirms Lazarus Group (UNC4736) deploying BLINDINGCAN RAT via weaponized job offer PDFs targeting defense contractors.',
    feedSources: ['FBI', 'CISA', 'RecordedFuture', 'Mandiant'],
    aiConfidence: 97, iocs: ['165.22.120.1', '103.248.12.3', 'resume_final.pdf.exe'],
    mitre: ['T1566.001', 'T1105'], status: 'confirmed', correlated: 8, tags: ['lazarus', 'apt', 'rat', 'dprk'],
  },
  {
    id: 'c004', ts: '2024-11-12T14:04:00Z', cve: 'CVE-2024-21762',
    title: 'FortiOS SSL VPN out-of-bounds write — actively exploited',
    attackType: 'Authentication Bypass', source: '91.92.251.103', sourceCountry: 'Iran',
    severity: 'critical', sectors: ['Government', 'Finance', 'Critical Infrastructure'],
    summary: 'Critical out-of-bounds write in FortiOS SSL VPN allows unauthenticated RCE. Actively exploited by Iranian threat actors targeting government networks in Middle East.',
    feedSources: ['Fortinet', 'CISA', 'NVD', 'Shodan'],
    aiConfidence: 99, iocs: ['91.92.251.103', '194.165.16.51', 'CVE-2024-21762'],
    mitre: ['T1190', 'T1078.001'], status: 'confirmed', correlated: 11, tags: ['fortios', 'vpn', 'authentication-bypass'],
  },
  {
    id: 'c005', ts: '2024-11-12T13:58:00Z', cve: null,
    title: 'Volt Typhoon pre-positioning in US critical infrastructure',
    attackType: 'APT', source: '103.148.20.3', sourceCountry: 'China',
    severity: 'critical', sectors: ['Critical Infrastructure', 'Energy', 'Water'],
    summary: 'CISA advisory: Chinese Volt Typhoon living-off-the-land in US critical infrastructure. Pre-positioning for potential destructive attacks, not espionage.',
    feedSources: ['CISA', 'NSA', 'FBI', 'Mandiant'],
    aiConfidence: 98, iocs: ['103.148.20.3', 'netstat.exe', 'ipconfig /all'],
    mitre: ['T1078', 'T1218'], status: 'confirmed', correlated: 19, tags: ['volt-typhoon', 'china', 'ics', 'lotl'],
  },
  {
    id: 'c006', ts: '2024-11-12T13:45:00Z', cve: 'CVE-2024-23897',
    title: 'Jenkins arbitrary file read leading to RCE',
    attackType: 'RCE', source: '185.199.108.1', sourceCountry: 'Romania',
    severity: 'high', sectors: ['Technology', 'Software Development'],
    summary: 'Jenkins CLI path traversal allows unauthenticated users to read arbitrary files on the controller filesystem, enabling RCE through multiple attack chains.',
    feedSources: ['NVD', 'MISP', 'GreyNoise'],
    aiConfidence: 96, iocs: ['185.199.108.1', '/var/jenkins/secrets/initialAdminPassword'],
    mitre: ['T1190', 'T1083'], status: 'confirmed', correlated: 7, tags: ['jenkins', 'ci-cd', 'rce'],
  },
  {
    id: 'c007', ts: '2024-11-12T13:38:00Z', cve: null,
    title: 'BlackBasta ransomware expanding healthcare sector targeting',
    attackType: 'Ransomware', source: '23.184.48.200', sourceCountry: 'Russia',
    severity: 'critical', sectors: ['Healthcare'],
    summary: 'HHS warns Black Basta has attacked 500+ healthcare orgs. Initial access via QakBot phishing → Cobalt Strike → data exfil → encryption. Average ransom: $1.5M.',
    feedSources: ['HHS', 'MISP', 'SentinelOne', 'CrowdStrike'],
    aiConfidence: 99, iocs: ['23.184.48.200', '104.149.168.0', 'qakbot.dll'],
    mitre: ['T1566', 'T1486'], status: 'confirmed', correlated: 16, tags: ['blackbasta', 'ransomware', 'healthcare'],
  },
  {
    id: 'c008', ts: '2024-11-12T13:22:00Z', cve: 'CVE-2024-21413',
    title: 'Microsoft Outlook Moniker Link RCE — NTLM hash leak',
    attackType: 'NTLM Relay', source: '94.102.61.14', sourceCountry: 'Russia',
    severity: 'high', sectors: ['Finance', 'Government', 'Enterprise'],
    summary: 'MonikerLink bug in Outlook forces NTLM credential leak via email preview panel. Actively exploited in spear-phishing campaigns against financial sector.',
    feedSources: ['Microsoft', 'NVD', 'Proofpoint', 'MISP'],
    aiConfidence: 98, iocs: ['94.102.61.14', 'CVE-2024-21413', '185.220.101.0/24'],
    mitre: ['T1187', 'T1566.001'], status: 'confirmed', correlated: 9, tags: ['outlook', 'ntlm', 'email'],
  },
]

const UNCONFIRMED_SEED: ThreatEntry[] = [
  {
    id: 'u001', ts: '2024-11-12T14:45:00Z', cve: null,
    title: 'Suspicious Cobalt Strike beacon activity from 185.220.101.88',
    attackType: 'C2 Beacon', source: '185.220.101.88', sourceCountry: 'Russia',
    severity: 'high', sectors: ['Enterprise'],
    summary: 'GreyNoise flagged IP with C2 communication pattern. Timing analysis suggests Cobalt Strike default profile. No MISP match. Awaiting correlation with SIEM logs.',
    feedSources: ['GreyNoise', 'AbuseIPDB'],
    aiConfidence: 78, iocs: ['185.220.101.88', 'beacon.min.js'],
    mitre: ['T1071.001'], status: 'unconfirmed', correlated: 2, tags: ['cobalt-strike', 'c2'],
  },
  {
    id: 'u002', ts: '2024-11-12T14:52:00Z', cve: null,
    title: 'Potential credential stuffing — 1,400 login failures against /api/auth in 5min',
    attackType: 'Credential Stuffing', source: '45.227.254.100', sourceCountry: 'Brazil',
    severity: 'medium', sectors: ['Finance', 'SaaS'],
    summary: 'AbuseIPDB score 89/100. Bot-like pattern: sequential usernames, consistent User-Agent, 5ms inter-request interval. No successful logins confirmed yet.',
    feedSources: ['AbuseIPDB', 'InternalSIEM'],
    aiConfidence: 72, iocs: ['45.227.254.100', '/api/auth'],
    mitre: ['T1110.004'], status: 'unconfirmed', correlated: 1, tags: ['brute-force', 'credential-stuffing'],
  },
  {
    id: 'u003', ts: '2024-11-12T14:38:00Z', cve: 'CVE-2024-49113',
    title: 'LDAP Nightmare scanner detected — CVE-2024-49113 probe',
    attackType: 'Reconnaissance', source: '198.98.62.55', sourceCountry: 'Germany',
    severity: 'medium', sectors: ['Enterprise', 'Active Directory'],
    summary: 'Shodan scanner IP probing for LDAP Nightmare vulnerability. Legitimate research or pre-attack reconnaissance unclear. IP belongs to known security scanner vendor.',
    feedSources: ['Shodan', 'GreyNoise'],
    aiConfidence: 55, iocs: ['198.98.62.55', 'LDAP/636'],
    mitre: ['T1595.001'], status: 'unconfirmed', correlated: 0, tags: ['ldap', 'reconnaissance'],
  },
  {
    id: 'u004', ts: '2024-11-12T14:31:00Z', cve: null,
    title: 'Large-scale DNS TXT record queries from internal host WS-DEV-012',
    attackType: 'Potential Exfiltration', source: '10.20.0.12', sourceCountry: 'Internal',
    severity: 'high', sectors: ['Internal'],
    summary: '12,000 DNS TXT queries in 20 minutes from developer workstation. Unusual domains with high-entropy subdomains. Pattern matches DNS tunneling toolkits. No C2 IOC match yet.',
    feedSources: ['InternalSIEM', 'DNS Analytics'],
    aiConfidence: 84, iocs: ['10.20.0.12', 'x3kp7.malicious-tunnel.io'],
    mitre: ['T1048.003'], status: 'unconfirmed', correlated: 3, tags: ['dns-tunnel', 'exfil', 'internal'],
  },
  {
    id: 'u005', ts: '2024-11-12T14:20:00Z', cve: null,
    title: 'Typosquatted npm package "lodash-secure" detected in CI pipeline',
    attackType: 'Supply Chain', source: 'npm registry', sourceCountry: 'Unknown',
    severity: 'critical', sectors: ['Technology', 'DevOps'],
    summary: 'Unknown package "lodash-secure" (not official lodash team) installed in 3 CI containers. Contains base64-encoded eval() in postinstall. Package age: 2 days. Downloads: 41.',
    feedSources: ['npm Audit', 'Sonatype'],
    aiConfidence: 91, iocs: ['lodash-secure@1.0.2', 'npm-postinstall.js'],
    mitre: ['T1195.001', 'T1059.007'], status: 'unconfirmed', correlated: 0, tags: ['npm', 'supply-chain', 'typosquatting'],
  },
  {
    id: 'u006', ts: '2024-11-12T14:15:00Z', cve: null,
    title: 'Tor exit node traffic to PROD-DB-01 on port 5432',
    attackType: 'Suspicious Traffic', source: '192.42.116.202', sourceCountry: 'Anonymous',
    severity: 'high', sectors: ['Finance', 'Healthcare'],
    summary: 'Danbooru Tor exit node attempting TCP connection to production database. Connection blocked by firewall. Source is on known Tor exit node list. Purpose unknown.',
    feedSources: ['TorProject', 'Firewall Logs'],
    aiConfidence: 68, iocs: ['192.42.116.202', 'postgres/5432'],
    mitre: ['T1090.003'], status: 'unconfirmed', correlated: 1, tags: ['tor', 'database', 'suspicious'],
  },
]

const LIVE_UNCONFIRMED: Partial<ThreatEntry>[] = [
  { title: 'Brute force SSH — 2,400 attempts/min from 45.152.67.88', attackType: 'Brute Force', severity: 'medium', sourceCountry: 'China', aiConfidence: 67, feedSources: ['AbuseIPDB'], iocs: ['45.152.67.88'] },
  { title: 'Suspicious PowerShell encoded command on WORKSTATION-044', attackType: 'Defense Evasion', severity: 'high', sourceCountry: 'Internal', aiConfidence: 82, feedSources: ['InternalSIEM'], iocs: ['WS-044', 'powershell.exe'] },
  { title: 'Reconnaissance scan: 14 ports probed on API gateway', attackType: 'Reconnaissance', severity: 'low', sourceCountry: 'Netherlands', aiConfidence: 45, feedSources: ['GreyNoise'], iocs: ['52.212.100.41'] },
  { title: 'Unrecognized outbound HTTPS to high-entropy domain', attackType: 'C2 Beacon', severity: 'medium', sourceCountry: 'Internal', aiConfidence: 73, feedSources: ['DNS Analytics'], iocs: ['xm4k9p.cloudflare-ntp.org'] },
  { title: 'Mass email relay attempt — 80K messages queued in 3 min', attackType: 'Spam/Relay', severity: 'high', sourceCountry: 'Russia', aiConfidence: 88, feedSources: ['SpamHaus'], iocs: ['91.108.56.88'] },
]

const SEV_COLOR: Record<Severity, string> = {
  critical: 'bg-magenta/15 text-magenta border-magenta/20',
  high:     'bg-threat/15 text-[#FF4D6D] border-threat/20',
  medium:   'bg-amber/15 text-amber border-amber/20',
  low:      'bg-safe/15 text-safe border-safe/20',
  info:     'bg-violet/15 text-violet border-violet/20',
}

const SEV_DOT: Record<Severity, string> = {
  critical: '#FF2E97',
  high:     '#FF4D6D',
  medium:   '#FFB23E',
  low:      '#34F5C5',
  info:     '#7A3CFF',
}

let liveCounter = 0
function makeLiveEntry(): ThreatEntry {
  const pool = LIVE_UNCONFIRMED[liveCounter % LIVE_UNCONFIRMED.length]
  liveCounter++
  const now = new Date()
  return {
    id: `live-${Date.now()}-${liveCounter}`,
    ts: now.toISOString(),
    cve: null,
    source: `${Math.floor(Math.random() * 180 + 60)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
    sourceCountry: pool.sourceCountry ?? 'Unknown',
    attackType: pool.attackType ?? 'Unknown',
    severity: pool.severity ?? 'medium',
    sectors: ['Enterprise'],
    summary: `Live detection: ${pool.title?.toLowerCase()}. Awaiting analyst review.`,
    feedSources: pool.feedSources ?? ['Automated'],
    aiConfidence: pool.aiConfidence ?? 60,
    iocs: pool.iocs ?? [],
    mitre: [],
    status: 'unconfirmed',
    correlated: 0,
    tags: ['live'],
    title: pool.title ?? 'Unknown threat',
  }
}

function timeAgo(ts: string) {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

/* ── Confidence Ring ─────────────────────────────────────────────── */
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

/* ── Threat Card ─────────────────────────────────────────────────── */
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
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-violet/15 text-violet border border-violet/20 shrink-0">
                {entry.cve}
              </span>
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
            <span className="text-[10px] text-ink-600">{entry.sourceCountry}</span>
            <span className="text-ink-700 text-[10px]">·</span>
            <span suppressHydrationWarning className="text-[10px] text-ink-600">{timeAgo(entry.ts)}</span>
          </div>
          {/* Feed sources */}
          <div className="flex items-center gap-1 mt-1.5 flex-wrap">
            {entry.feedSources.map(src => (
              <span key={src} className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 text-ink-500 border border-white/8">
                {src}
              </span>
            ))}
            {entry.correlated > 0 && (
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-violet/10 text-violet border border-violet/15">
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
                    {entry.iocs.map(ioc => (
                      <span key={ioc} className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/30 text-ink-300 border border-white/8">
                        {ioc}
                      </span>
                    ))}
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
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet/10 text-violet border border-violet/20 hover:bg-violet/20 transition-colors"
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
                  onClick={(e) => { e.stopPropagation() }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-magenta/12 text-magenta border border-magenta/25 text-xs font-medium hover:bg-magenta/20 transition-colors"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Send to SIEM
                </button>
                <button
                  onClick={(e) => { e.stopPropagation() }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 text-ink-300 border border-white/10 text-xs font-medium hover:bg-white/8 transition-colors"
                >
                  <Shield className="w-3.5 h-3.5" />
                  Block IOCs
                </button>
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

/* ── Source Health Pills ─────────────────────────────────────────── */
const SOURCES_FALLBACK = [
  { name: 'MISP', status: 'live', rate: '847/h' },
  { name: 'RecordedFuture', status: 'live', rate: '234/h' },
  { name: 'GreyNoise', status: 'live', rate: '1.2k/h' },
  { name: 'AbuseIPDB', status: 'live', rate: '509/h' },
  { name: 'Shodan', status: 'live', rate: '88/h' },
  { name: 'CISA', status: 'live', rate: '12/h' },
  { name: 'AlienVault', status: 'degraded', rate: '43/h' },
  { name: 'NVD', status: 'live', rate: '6/h' },
]

/* ── Main Page ───────────────────────────────────────────────────── */
export default function FeedsPage() {
  const [confirmed, setConfirmed] = useState<ThreatEntry[]>(CONFIRMED_SEED)
  const [unconfirmed, setUnconfirmed] = useState<ThreatEntry[]>(UNCONFIRMED_SEED)
  const [apiFeeds, setApiFeeds] = useState<ApiFeed[]>([])
  const [feedsSummary, setFeedsSummary] = useState<FeedsSummary | null>(null)
  const [newIds, setNewIds] = useState<Set<string>>(new Set())
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [liveCount, setLiveCount] = useState(0)
  const [pulse, setPulse] = useState(false)

  // Load feed sources and summary from API
  useEffect(() => {
    fetchFeeds().then(setApiFeeds).catch(() => {})
    fetchFeedsSummary().then(setFeedsSummary).catch(() => {})
  }, [])

  // Simulate live incoming unconfirmed threats every 8–14 seconds
  useEffect(() => {
    const jitter = () => 8000 + Math.random() * 6000
    let timer: ReturnType<typeof setTimeout>
    const schedule = () => {
      timer = setTimeout(() => {
        const entry = makeLiveEntry()
        setUnconfirmed(prev => [entry, ...prev].slice(0, 30))
        setNewIds(prev => new Set(Array.from(prev).concat(entry.id)))
        setLiveCount(c => c + 1)
        setPulse(true)
        setTimeout(() => {
          setNewIds(prev => { const n = new Set(prev); n.delete(entry.id); return n })
          setPulse(false)
        }, 8000)
        schedule()
      }, jitter())
    }
    schedule()
    return () => clearTimeout(timer)
  }, [])

  function handleConfirm(id: string) {
    const entry = unconfirmed.find(e => e.id === id)
    if (!entry) return
    setUnconfirmed(prev => prev.filter(e => e.id !== id))
    setConfirmed(prev => [{ ...entry, status: 'confirmed' }, ...prev])
  }

  function handleDismissUnconfirmed(id: string) {
    setUnconfirmed(prev => prev.filter(e => e.id !== id))
  }

  function handleDismissConfirmed(id: string) {
    setConfirmed(prev => prev.filter(e => e.id !== id))
  }

  const filteredConfirmed = severityFilter === 'all'
    ? confirmed
    : confirmed.filter(e => e.severity === severityFilter)

  const filteredUnconfirmed = severityFilter === 'all'
    ? unconfirmed
    : unconfirmed.filter(e => e.severity === severityFilter)

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
            Real-time threat intelligence from {apiFeeds.length || SOURCES_FALLBACK.length} sources · {liveCount} new today
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white transition-colors">
            <Download className="w-3.5 h-3.5" />
            Export IOCs
          </button>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-magenta/15 border border-magenta/25 text-xs text-magenta font-medium hover:bg-magenta/25 transition-colors">
            <Filter className="w-3.5 h-3.5" />
            Filters
          </button>
        </div>
      </div>

      {/* Source health strip */}
      <div className="px-6 py-2.5 border-b border-white/4 bg-white/[0.01] shrink-0 overflow-x-auto">
        <div className="flex items-center gap-2 min-w-max">
          <span className="text-[10px] text-ink-600 uppercase tracking-widest mr-1">Sources</span>
          {(apiFeeds.length > 0 ? apiFeeds.map(f => ({ name: f.name, status: f.status === 'active' ? 'live' : 'degraded', rate: `${f.indicators}` })) : SOURCES_FALLBACK).map(src => (
            <div key={src.name} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/5 border border-white/8">
              <span className={cn(
                'w-1.5 h-1.5 rounded-full',
                src.status === 'live' ? 'bg-safe animate-pulse' : 'bg-amber',
              )} />
              <span className="text-[10px] text-ink-300">{src.name}</span>
              <span className="text-[10px] text-ink-600">{src.rate}</span>
            </div>
          ))}
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-4 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {[
          { label: 'Confirmed', value: confirmed.length, color: 'text-safe', icon: CheckCircle2 },
          { label: 'Unconfirmed', value: unconfirmed.length, color: 'text-amber', icon: HelpCircle },
          { label: 'Critical', value: [...confirmed, ...unconfirmed].filter(e => e.severity === 'critical').length, color: 'text-magenta', icon: Flame },
          { label: 'Total IOCs', value: feedsSummary ? feedsSummary.totalIndicators.toLocaleString() : '—', color: 'text-violet', icon: Activity },
        ].map(kpi => (
          <div key={kpi.label} className="flex items-center gap-3 px-4 py-3">
            <kpi.icon className={cn('w-4 h-4 shrink-0', kpi.color)} />
            <div>
              <div className={cn('text-base font-bold font-mono', kpi.color)}>{kpi.value}</div>
              <div className="text-[10px] text-ink-600">{kpi.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Severity filter */}
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
      </div>

      {/* Split columns */}
      <div className="flex-1 min-h-0 grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/5 overflow-hidden">

        {/* ── Confirmed Threats ── */}
        <div className="flex flex-col overflow-hidden">
          {/* Column header */}
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 bg-safe/[0.03] shrink-0">
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
                <div className="flex flex-col items-center justify-center h-32 text-ink-600">
                  <CheckCircle2 className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-xs">No confirmed threats match filter</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* ── Unconfirmed Threats ── */}
        <div className="flex flex-col overflow-hidden">
          {/* Column header */}
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 bg-amber/[0.03] shrink-0">
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
                <div className="flex flex-col items-center justify-center h-32 text-ink-600">
                  <HelpCircle className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-xs">No unconfirmed threats — feed is quiet</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  )
}
