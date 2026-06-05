'use client'

import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Filter, X, RefreshCw, ExternalLink, ChevronDown,
  AlertTriangle, Globe, Hash, Link, Zap, Shield,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Types ────────────────────────────────────────────────────────── */
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type FeedEntry = {
  id: string
  ts: string
  cve: string | null
  title: string
  attackType: string
  source: string
  sourceCountry: string
  destination: string
  destCountry: string
  severity: Severity
  sectors: string[]
  summary: string
  recommendations: string[]
  docLink: string | null
  cvssScore: number | null
  tags: string[]
}

/* ── Master dataset (50 entries) ─────────────────────────────────── */
const ALL_FEEDS: FeedEntry[] = [
  {
    id: 'f001', ts: '2024-11-12T14:22:00Z', cve: 'CVE-2024-6387',
    title: 'OpenSSH glibc RCE — unauthenticated remote code execution',
    attackType: 'RCE', source: '45.95.147.236', sourceCountry: 'Russia',
    destination: '10.44.0.15', destCountry: 'United Kingdom',
    severity: 'critical', sectors: ['Healthcare', 'Finance', 'Government'],
    summary: 'Signal handler race condition in OpenSSH before 9.8p1 allows unauthenticated RCE as root. Requires glibc-based Linux. Estimated 700k+ internet-exposed instances.',
    recommendations: ['Patch to OpenSSH 9.8p1 immediately', 'Restrict SSH to VPN/bastion hosts', 'Enable MFA for SSH', 'Monitor auth logs for failed root login attempts'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
    cvssScore: 8.1, tags: ['openssh', 'regresshion', 'linux', 'rce'],
  },
  {
    id: 'f002', ts: '2024-11-12T14:18:00Z', cve: 'CVE-2024-3094',
    title: 'XZ Utils backdoor — malicious supply chain compromise',
    attackType: 'Supply Chain', source: '185.220.101.1', sourceCountry: 'North Korea',
    destination: '192.168.44.10', destCountry: 'Germany',
    severity: 'critical', sectors: ['Technology', 'Government', 'Defense'],
    summary: 'Malicious code injected into XZ Utils 5.6.0-5.6.1 by a long-running social engineering campaign. Backdoor allows unauthorized SSH access bypassing authentication.',
    recommendations: ['Downgrade XZ Utils to 5.4.x', 'Audit all SSH daemons on affected distros', 'Review supply chain integrity processes', 'Implement SLSA level 3+ for build pipelines'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
    cvssScore: 10.0, tags: ['xz', 'supply-chain', 'ssh', 'backdoor'],
  },
  {
    id: 'f003', ts: '2024-11-12T14:11:00Z', cve: null,
    title: 'Lazarus Group deploys BLINDINGCAN RAT against defense sector',
    attackType: 'APT', source: '165.22.120.1', sourceCountry: 'North Korea',
    destination: '172.16.0.55', destCountry: 'United States',
    severity: 'critical', sectors: ['Defense', 'Aerospace'],
    summary: 'FBI and CISA joint advisory confirms Lazarus Group (UNC4736) deploying BLINDINGCAN remote access trojan via weaponized job offer PDFs targeting defense contractors.',
    recommendations: ['Block C2 IOCs at perimeter', 'Enable EDR behavioral detection', 'Restrict macro execution in Office docs', 'User awareness training on job offer phishing'],
    docLink: null,
    cvssScore: null, tags: ['lazarus', 'apt', 'rat', 'defense', 'dprk'],
  },
  {
    id: 'f004', ts: '2024-11-12T14:04:00Z', cve: 'CVE-2024-21762',
    title: 'FortiOS SSL VPN out-of-bounds write — actively exploited',
    attackType: 'Authentication Bypass', source: '91.92.251.103', sourceCountry: 'Iran',
    destination: '10.8.0.0/24', destCountry: 'Israel',
    severity: 'critical', sectors: ['Government', 'Finance', 'Critical Infrastructure'],
    summary: 'Critical out-of-bounds write in FortiOS SSL VPN allows unauthenticated RCE. Actively exploited in the wild by Iranian threat actors targeting government networks.',
    recommendations: ['Apply Fortinet patch immediately', 'Disable SSL VPN if patch unavailable', 'Review VPN access logs for anomalies', 'Enable 2FA on VPN'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21762',
    cvssScore: 9.6, tags: ['fortios', 'vpn', 'authentication-bypass'],
  },
  {
    id: 'f005', ts: '2024-11-12T13:58:00Z', cve: null,
    title: 'Volt Typhoon pre-positioning in US critical infrastructure',
    attackType: 'APT', source: '103.148.20.3', sourceCountry: 'China',
    destination: '198.51.100.0/24', destCountry: 'United States',
    severity: 'critical', sectors: ['Critical Infrastructure', 'Energy', 'Water'],
    summary: 'CISA advisory: Chinese state-sponsored Volt Typhoon living-off-the-land in US critical infrastructure. Focus on pre-positioning for potential destructive attacks, not espionage.',
    recommendations: ['Audit all LOTL tool usage (LOLBins)', 'Harden Active Directory', 'Implement network segmentation for OT/ICS', 'Review all outbound connections from OT networks'],
    docLink: null,
    cvssScore: null, tags: ['volt-typhoon', 'china', 'apt', 'ics', 'ot'],
  },
  {
    id: 'f006', ts: '2024-11-12T13:45:00Z', cve: 'CVE-2024-23897',
    title: 'Jenkins arbitrary file read leading to RCE',
    attackType: 'RCE', source: '185.199.108.1', sourceCountry: 'Romania',
    destination: '10.0.1.50', destCountry: 'Netherlands',
    severity: 'high', sectors: ['Technology', 'Software Development'],
    summary: 'Jenkins 2.441 and earlier CLI path traversal allows unauthenticated users to read arbitrary files on the controller filesystem, enabling RCE through multiple attack chains.',
    recommendations: ['Upgrade Jenkins to 2.442+', 'Restrict Jenkins CLI access', 'Expose Jenkins internally only', 'Rotate all secrets stored in Jenkins credentials'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-23897',
    cvssScore: 9.8, tags: ['jenkins', 'ci-cd', 'path-traversal', 'rce'],
  },
  {
    id: 'f007', ts: '2024-11-12T13:38:00Z', cve: null,
    title: 'Scattered Spider BEC campaign targeting MGM-style hospitality firms',
    attackType: 'Social Engineering', source: 'Multiple', sourceCountry: 'United States',
    destination: 'Internal', destCountry: 'United States',
    severity: 'high', sectors: ['Hospitality', 'Gaming', 'Retail'],
    summary: 'Scattered Spider (UNC3944) conducting vishing attacks against IT help desks, impersonating employees to reset MFA. Deploying ALPHV/BlackCat ransomware post-access.',
    recommendations: ['Implement strict help desk identity verification', 'Enable phishing-resistant MFA (FIDO2)', 'Train staff to recognize vishing', 'Segment POS systems from corporate network'],
    docLink: null,
    cvssScore: null, tags: ['scattered-spider', 'bec', 'vishing', 'ransomware'],
  },
  {
    id: 'f008', ts: '2024-11-12T13:22:00Z', cve: 'CVE-2024-21413',
    title: 'Microsoft Outlook Moniker Link RCE — NTLM hash leak',
    attackType: 'NTLM Relay', source: '94.102.61.0/24', sourceCountry: 'Russia',
    destination: 'Email servers', destCountry: 'Global',
    severity: 'high', sectors: ['Finance', 'Government', 'Enterprise'],
    summary: 'MonikerLink bug in Outlook allows attackers to force NTLM credential leak and execute arbitrary commands by sending a malicious email — preview panel triggers the exploit.',
    recommendations: ['Apply MS February 2024 patches', 'Block outbound SMB at firewall', 'Disable NTLM where possible', 'Enable Extended Protection for Authentication'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21413',
    cvssScore: 9.8, tags: ['outlook', 'ntlm', 'rce', 'email'],
  },
  {
    id: 'f009', ts: '2024-11-12T13:10:00Z', cve: null,
    title: 'BlackBasta ransomware expanding healthcare sector targeting',
    attackType: 'Ransomware', source: '23.184.48.200', sourceCountry: 'Russia',
    destination: '10.20.0.0/16', destCountry: 'United States',
    severity: 'critical', sectors: ['Healthcare'],
    summary: 'HHS warns Black Basta has attacked 500+ healthcare orgs. Initial access via QakBot phishing → Cobalt Strike → data exfiltration → encryption. Average ransom: $1.5M.',
    recommendations: ['Implement offline backup strategy', 'Restrict RDP and remote management', 'Deploy endpoint detection on all hosts', 'Practice incident response tabletop exercises'],
    docLink: null,
    cvssScore: null, tags: ['blackbasta', 'ransomware', 'healthcare', 'qakbot'],
  },
  {
    id: 'f010', ts: '2024-11-12T12:55:00Z', cve: 'CVE-2024-4577',
    title: 'PHP CGI argument injection on Windows — RCE without authentication',
    attackType: 'RCE', source: '185.220.101.56', sourceCountry: 'Belarus',
    destination: '203.0.113.15', destCountry: 'Japan',
    severity: 'critical', sectors: ['Technology', 'Retail', 'Education'],
    summary: 'Critical RCE in PHP on Windows due to argument injection in CGI mode. Exploits Windows character conversion quirk. CVSS 10.0. Active mass exploitation within 24h of disclosure.',
    recommendations: ['Upgrade PHP to 8.1.29, 8.2.20, or 8.3.8', 'Disable PHP CGI mode', 'Use PHP-FPM instead', 'Apply WAF rules for PHP CGI exploitation'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
    cvssScore: 10.0, tags: ['php', 'cgi', 'windows', 'rce'],
  },
  {
    id: 'f011', ts: '2024-11-12T12:40:00Z', cve: null,
    title: 'DNS tunneling campaign exfiltrating from air-gapped networks',
    attackType: 'Exfiltration', source: '8.8.4.4', sourceCountry: 'Unknown',
    destination: '192.168.1.0/24', destCountry: 'South Korea',
    severity: 'high', sectors: ['Defense', 'Government', 'Nuclear'],
    summary: 'Novel DNS tunneling technique bypassing DLP tools by encoding data in TXT/NULL records with timing-based covert channel. Associated with Kimsuky APT activity.',
    recommendations: ['Deploy DNS security filtering (PDNS)', 'Monitor for high-volume DNS TXT queries', 'Implement DNS sinkholing', 'Restrict recursive DNS to known resolvers'],
    docLink: null,
    cvssScore: null, tags: ['dns-tunneling', 'kimsuky', 'exfiltration', 'apt'],
  },
  {
    id: 'f012', ts: '2024-11-12T12:25:00Z', cve: 'CVE-2024-38094',
    title: 'Microsoft SharePoint deserialization RCE — authenticated user',
    attackType: 'RCE', source: '45.134.26.0/24', sourceCountry: 'China',
    destination: 'SharePoint Online', destCountry: 'Australia',
    severity: 'high', sectors: ['Government', 'Education', 'Enterprise'],
    summary: 'Deserialization vulnerability in Microsoft SharePoint allows authenticated attackers to execute arbitrary code on the server. Used in targeted espionage campaigns against government.',
    recommendations: ['Apply July 2024 Cumulative Update', 'Restrict SharePoint to internal access', 'Monitor SharePoint audit logs', 'Enable Microsoft Defender for SharePoint'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-38094',
    cvssScore: 7.2, tags: ['sharepoint', 'deserialization', 'microsoft', 'rce'],
  },
  {
    id: 'f013', ts: '2024-11-12T12:10:00Z', cve: null,
    title: 'LockBit 3.0 affiliate targeting law firms across EU',
    attackType: 'Ransomware', source: '45.227.254.26', sourceCountry: 'Russia',
    destination: '10.10.0.0/16', destCountry: 'France',
    severity: 'high', sectors: ['Legal', 'Finance'],
    summary: 'LockBit affiliates targeting EU law firms via spear-phishing. Exfiltrating client privileged communications before encryption. Double extortion with 72-hour deadline.',
    recommendations: ['Air-gap legal document repositories', 'Implement privileged access management', 'Deploy email gateway scanning', 'Regular offline backups for case files'],
    docLink: null,
    cvssScore: null, tags: ['lockbit', 'ransomware', 'law', 'eu'],
  },
  {
    id: 'f014', ts: '2024-11-12T11:55:00Z', cve: 'CVE-2024-20353',
    title: 'Cisco ASA DoS vulnerability — actively exploited in the wild',
    attackType: 'DoS', source: '194.165.16.0/24', sourceCountry: 'Iran',
    destination: 'Network perimeter', destCountry: 'Israel',
    severity: 'high', sectors: ['Government', 'Finance', 'ISP'],
    summary: 'Cisco ASA and FTD management tunnel parsing flaw allows unauthenticated remote DoS. CISA KEV listed. Exploited alongside CVE-2024-20359 for persistent access.',
    recommendations: ['Apply Cisco security advisory updates', 'Disable management access from internet', 'Implement management network segmentation', 'Monitor for unexpected ASA reboots'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-20353',
    cvssScore: 8.6, tags: ['cisco', 'asa', 'dos', 'network'],
  },
  {
    id: 'f015', ts: '2024-11-12T11:40:00Z', cve: null,
    title: 'FIN7 deploying POWERTRASH shellcode loader via fake job sites',
    attackType: 'Initial Access', source: '104.21.45.0/24', sourceCountry: 'Russia',
    destination: 'Endpoints', destCountry: 'United States',
    severity: 'high', sectors: ['Finance', 'Retail'],
    summary: 'FIN7 creating fake recruitment portals impersonating Fortune 500 companies. Victims lured to download "assessment tools" containing POWERTRASH → Carbanak RAT chain.',
    recommendations: ['Block known FIN7 infrastructure IOCs', 'Enable PowerShell script block logging', 'Deploy application whitelisting', 'Review recruitment email filtering'],
    docLink: null,
    cvssScore: null, tags: ['fin7', 'powershell', 'loader', 'recruitment-lure'],
  },
  {
    id: 'f016', ts: '2024-11-12T11:25:00Z', cve: 'CVE-2024-27956',
    title: 'WordPress Automatic Plugin SQL injection — 200K sites at risk',
    attackType: 'SQL Injection', source: 'Botnets', sourceCountry: 'Global',
    destination: 'Web servers', destCountry: 'Global',
    severity: 'critical', sectors: ['Technology', 'Retail', 'Media'],
    summary: 'Unauthenticated SQL injection in WP Automatic Plugin (≤3.92.0) allows complete database takeover and admin account creation. Mass exploitation scanning detected.',
    recommendations: ['Update WP Automatic to 3.92.1+', 'Audit WordPress plugins immediately', 'Enable WAF with SQL injection rules', 'Review admin user accounts for unauthorized additions'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-27956',
    cvssScore: 9.9, tags: ['wordpress', 'sqli', 'cms', 'plugin'],
  },
  {
    id: 'f017', ts: '2024-11-12T11:10:00Z', cve: null,
    title: 'Cl0p ransomware exploiting MOVEit Transfer zero-day (ongoing)',
    attackType: 'SQL Injection / RCE', source: '195.123.246.0/24', sourceCountry: 'Russia',
    destination: 'MOVEit installations', destCountry: 'United States',
    severity: 'critical', sectors: ['Finance', 'Healthcare', 'Government'],
    summary: 'Cl0p continues mass exploitation of MOVEit Transfer SQLi vulnerability affecting 2,700+ organizations. Data from 93M individuals exposed. Affiliate model expanding.',
    recommendations: ['Apply all MOVEit patches', 'Conduct forensic investigation if exposed', 'Notify affected data subjects (GDPR Article 33)', 'Implement DMZ for file transfer services'],
    docLink: null,
    cvssScore: null, tags: ['clop', 'moveit', 'sqli', 'data-breach'],
  },
  {
    id: 'f018', ts: '2024-11-12T10:55:00Z', cve: 'CVE-2024-30051',
    title: 'Windows DWM Core Library privilege escalation — zero-day',
    attackType: 'Privilege Escalation', source: '91.108.56.0/24', sourceCountry: 'Russia',
    destination: 'Windows endpoints', destCountry: 'Global',
    severity: 'high', sectors: ['Enterprise', 'Government'],
    summary: 'Heap-based buffer overflow in Windows Desktop Window Manager allows local privilege escalation to SYSTEM. Used alongside CVE-2024-30040 in QakBot campaigns.',
    recommendations: ['Apply May 2024 Patch Tuesday updates', 'Deploy EDR with memory protection', 'Monitor for SYSTEM-level process spawning from user context', 'Enforce least privilege'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-30051',
    cvssScore: 7.8, tags: ['windows', 'privesc', 'dwm', 'zero-day'],
  },
  {
    id: 'f019', ts: '2024-11-12T10:40:00Z', cve: null,
    title: 'UNC4899 targeting software developers with trojanized Python packages',
    attackType: 'Supply Chain', source: 'PyPI', sourceCountry: 'North Korea',
    destination: 'Developer workstations', destCountry: 'Global',
    severity: 'high', sectors: ['Technology', 'Cryptocurrency', 'Finance'],
    summary: 'North Korean APT (linked to Lazarus) publishing fake crypto utility packages to PyPI with typosquatted names. Backdoor collects SSH keys, AWS credentials, browser passwords.',
    recommendations: ['Audit installed Python packages against PyPI', 'Pin dependencies to specific hashes', 'Implement code signing for internal packages', 'Deploy developer endpoint protection'],
    docLink: null,
    cvssScore: null, tags: ['pypi', 'supply-chain', 'typosquatting', 'dprk', 'crypto'],
  },
  {
    id: 'f020', ts: '2024-11-12T10:20:00Z', cve: 'CVE-2024-49113',
    title: 'LDAP Nightmare — Windows LDAP DoS via malicious server',
    attackType: 'DoS', source: 'Internet', sourceCountry: 'Global',
    destination: 'Windows LDAP clients', destCountry: 'Global',
    severity: 'medium', sectors: ['Enterprise', 'Active Directory environments'],
    summary: 'Unauthenticated crash of Windows LDAP client via malicious LDAP server referral. Can crash domain-joined machines including domain controllers by sending malicious referrals.',
    recommendations: ['Apply December 2024 Windows patches', 'Block outbound LDAP to untrusted servers', 'Monitor LDAP connection anomalies', 'Keep DCs on isolated management VLAN'],
    docLink: 'https://nvd.nist.gov/vuln/detail/CVE-2024-49113',
    cvssScore: 7.5, tags: ['ldap', 'windows', 'dos', 'active-directory'],
  },
]

/* ── Filter constants ────────────────────────────────────────────── */
const ATTACK_TYPES = ['All', 'RCE', 'APT', 'Ransomware', 'Supply Chain', 'DoS', 'SQL Injection', 'Social Engineering', 'Privilege Escalation', 'Exfiltration', 'Initial Access', 'Authentication Bypass', 'NTLM Relay']
const SEVERITIES   = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info']
const SECTORS = ['All', 'Healthcare', 'Finance', 'Government', 'Technology', 'Defense', 'Critical Infrastructure', 'Education', 'Energy', 'Legal', 'Retail', 'Hospitality', 'Media', 'Aerospace']
const COUNTRIES = ['All', 'United States', 'United Kingdom', 'Germany', 'Russia', 'China', 'North Korea', 'France', 'Japan', 'Australia', 'Israel', 'Netherlands', 'Global']

const SEV_COLOR: Record<Severity, string> = {
  critical: 'bg-magenta/15 text-magenta border-magenta/25',
  high:     'bg-threat/15 text-threat border-threat/25',
  medium:   'bg-amber/15 text-amber border-amber/25',
  low:      'bg-safe/15 text-safe border-safe/25',
  info:     'bg-violet/15 text-violet border-violet/25',
}

/* ── Generate "live" random entries ──────────────────────────────── */
const LIVE_POOL: Partial<FeedEntry>[] = [
  { cve: null,  title: 'Brute force SSH login — 847 attempts in 60s',       attackType: 'Brute Force',    severity: 'medium',   sourceCountry: 'China',   destCountry: 'Germany'       },
  { cve: null,  title: 'Shodan fingerprint: exposed Elasticsearch cluster',  attackType: 'Reconnaissance', severity: 'info',     sourceCountry: 'Iran',    destCountry: 'Netherlands'   },
  { cve: null,  title: 'Cobalt Strike beacon C2 callback detected',          attackType: 'C2 Beacon',      severity: 'high',     sourceCountry: 'Russia',  destCountry: 'United States' },
  { cve: null,  title: 'Credential stuffing attack on identity provider',    attackType: 'Credential',     severity: 'medium',   sourceCountry: 'Nigeria', destCountry: 'United Kingdom'},
  { cve: null,  title: 'Mass scan for log4j (CVE-2021-44228) still active',  attackType: 'Reconnaissance', severity: 'low',      sourceCountry: 'Global',  destCountry: 'Global'        },
  { cve: null,  title: 'DarkGate malware delivered via Microsoft Teams',     attackType: 'Phishing',       severity: 'high',     sourceCountry: 'Russia',  destCountry: 'United States' },
  { cve: null,  title: 'Suspicious S3 bucket data exfiltration',             attackType: 'Exfiltration',   severity: 'high',     sourceCountry: 'Unknown', destCountry: 'United States' },
  { cve: null,  title: 'GootLoader JS campaign targeting legal sector',      attackType: 'Initial Access', severity: 'medium',   sourceCountry: 'Russia',  destCountry: 'United States' },
]

let liveCounter = 1000

function generateLiveEntry(): FeedEntry {
  const pool = LIVE_POOL[Math.floor(Math.random() * LIVE_POOL.length)]
  const now = new Date()
  return {
    id: `live-${++liveCounter}`,
    ts: now.toISOString(),
    cve: null,
    source: `${Math.floor(Math.random() * 200 + 50)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
    destination: `10.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
    sectors: ['Enterprise'],
    summary: `Live detection: ${pool.title?.toLowerCase()}. Automated threat correlation in progress.`,
    recommendations: ['Investigate immediately', 'Check SIEM for correlated events', 'Isolate affected endpoint if confirmed'],
    docLink: null,
    cvssScore: null,
    tags: ['live'],
    ...pool,
  } as FeedEntry
}

/* ── Feed Entry Row ──────────────────────────────────────────────── */
function FeedRow({ entry, idx }: { entry: FeedEntry; idx: number }) {
  const [hovered, setHovered] = useState(false)
  const rowRef = useRef<HTMLDivElement>(null)

  const timeAgo = (ts: string) => {
    const diff = (Date.now() - new Date(ts).getTime()) / 1000
    if (diff < 60) return `${Math.floor(diff)}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return `${Math.floor(diff / 3600)}h ago`
  }

  return (
    <div
      ref={rowRef}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className="relative"
    >
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: idx * 0.03, duration: 0.3 }}
        className={cn(
          'grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 items-center px-4 py-3 border-b border-white/4 transition-colors cursor-pointer',
          hovered ? 'bg-white/3' : idx % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.012]',
        )}
      >
        {/* Severity dot */}
        <span
          className="w-2 h-2 rounded-full shrink-0"
          style={{ background: entry.severity === 'critical' ? '#FF2E97' : entry.severity === 'high' ? '#FF4D6D' : entry.severity === 'medium' ? '#FFB23E' : entry.severity === 'low' ? '#34F5C5' : '#7A3CFF' }}
        />

        {/* Title + CVE */}
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {entry.cve && (
              <span className="shrink-0 text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded bg-violet/15 text-violet border border-violet/20">
                {entry.cve}
              </span>
            )}
            <span className="text-xs text-ink-200 truncate">{entry.title}</span>
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-[10px] text-ink-600 font-mono">{entry.source}</span>
            <span className="text-[10px] text-ink-700">→</span>
            <span className="text-[10px] text-ink-600 font-mono">{entry.destination}</span>
          </div>
        </div>

        {/* Attack type */}
        <span className="text-[10px] text-ink-400 whitespace-nowrap">{entry.attackType}</span>

        {/* Countries */}
        <div className="text-[10px] text-ink-500 whitespace-nowrap text-right hidden md:block">
          <div>{entry.sourceCountry}</div>
          <div className="text-ink-700">→ {entry.destCountry}</div>
        </div>

        {/* Severity badge */}
        <span className={cn('text-[9px] font-semibold px-2 py-0.5 rounded-full border uppercase tracking-wide whitespace-nowrap', SEV_COLOR[entry.severity])}>
          {entry.severity}
        </span>

        {/* Time */}
        <span className="text-[10px] text-ink-600 whitespace-nowrap hidden sm:block">{timeAgo(entry.ts)}</span>
      </motion.div>

      {/* Hover detail panel */}
      <AnimatePresence>
        {hovered && (
          <motion.div
            initial={{ opacity: 0, y: 4, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 4, scale: 0.97 }}
            transition={{ duration: 0.15 }}
            className="absolute left-4 right-4 top-full z-50 mt-1 glass border border-white/10 rounded-xl p-4 shadow-[0_8px_40px_rgba(0,0,0,0.6)] overflow-hidden"
          >
            {/* Glow */}
            <div className="absolute inset-0 pointer-events-none"
              style={{ background: 'radial-gradient(ellipse at 0% 0%, rgba(255,46,151,0.06), transparent 60%)' }}
            />

            <div className="relative grid md:grid-cols-2 gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  {entry.cve && (
                    <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-violet/20 text-violet border border-violet/30">
                      {entry.cve}
                    </span>
                  )}
                  {entry.cvssScore && (
                    <span className={cn(
                      'text-[10px] font-mono font-bold px-1.5 py-0.5 rounded',
                      entry.cvssScore >= 9 ? 'bg-magenta/15 text-magenta' :
                      entry.cvssScore >= 7 ? 'bg-threat/15 text-threat' : 'bg-amber/15 text-amber',
                    )}>
                      CVSS {entry.cvssScore}
                    </span>
                  )}
                </div>
                <p className="text-xs text-ink-300 leading-relaxed">{entry.summary}</p>
                <div className="flex flex-wrap gap-1.5 mt-3">
                  {entry.tags.map((t) => (
                    <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-surface-3 text-ink-500 font-mono">{t}</span>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-[10px] font-semibold text-white mb-2 uppercase tracking-wide">Recommended Actions</p>
                <ul className="space-y-1.5">
                  {entry.recommendations.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-ink-300">
                      <Shield className="w-3 h-3 text-safe mt-0.5 shrink-0" />
                      {r}
                    </li>
                  ))}
                </ul>
                {entry.docLink && (
                  <a
                    href={entry.docLink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 mt-3 text-xs text-magenta hover:underline"
                  >
                    <ExternalLink className="w-3 h-3" />
                    Official CVE Documentation
                  </a>
                )}
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {entry.sectors.map((s) => (
                    <span key={s} className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-2 border border-white/8 text-ink-500">{s}</span>
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

/* ── Filters ─────────────────────────────────────────────────────── */
function FilterDropdown({
  label, options, value, onChange,
}: {
  label: string; options: string[]; value: string; onChange: (v: string) => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs border transition-colors',
          value !== 'All'
            ? 'bg-magenta/10 border-magenta/30 text-magenta'
            : 'bg-surface-2 border-white/8 text-ink-400 hover:text-white hover:border-white/15',
        )}
      >
        {label}: <span className="font-medium">{value}</span>
        <ChevronDown className={cn('w-3 h-3 transition-transform', open && 'rotate-180')} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            className="absolute top-full mt-1 left-0 z-50 bg-surface border border-white/10 rounded-xl overflow-hidden shadow-[0_8px_40px_rgba(0,0,0,0.5)] min-w-[160px]"
          >
            {options.map((opt) => (
              <button
                key={opt}
                onClick={() => { onChange(opt); setOpen(false) }}
                className={cn(
                  'w-full text-left px-3 py-2 text-xs transition-colors',
                  opt === value ? 'text-magenta bg-magenta/8' : 'text-ink-300 hover:text-white hover:bg-white/5',
                )}
              >
                {opt}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* ── Stats bar ───────────────────────────────────────────────────── */
function FeedStats({ feeds }: { feeds: FeedEntry[] }) {
  const counts = {
    critical: feeds.filter((f) => f.severity === 'critical').length,
    high:     feeds.filter((f) => f.severity === 'high').length,
    medium:   feeds.filter((f) => f.severity === 'medium').length,
    total:    feeds.length,
  }
  return (
    <div className="flex items-center gap-6 text-xs text-ink-500">
      <span className="font-mono text-white font-semibold">{counts.total} events</span>
      <span className="text-magenta">{counts.critical} critical</span>
      <span className="text-threat">{counts.high} high</span>
      <span className="text-amber">{counts.medium} medium</span>
    </div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function ThreatFeedsPage() {
  const [feeds, setFeeds] = useState<FeedEntry[]>(ALL_FEEDS)
  const [live, setLive] = useState(true)
  const [filterAttack, setFilterAttack] = useState('All')
  const [filterSev, setFilterSev] = useState('All')
  const [filterSector, setFilterSector] = useState('All')
  const [filterCountry, setFilterCountry] = useState('All')
  const [search, setSearch] = useState('')
  const [ticker, setTicker] = useState(0)

  // Live feed update every 3 seconds
  useEffect(() => {
    if (!live) return
    const id = setInterval(() => {
      setFeeds((prev) => [generateLiveEntry(), ...prev.slice(0, 79)])
      setTicker((t) => t + 1)
    }, 3000)
    return () => clearInterval(id)
  }, [live])

  const filtered = feeds.filter((f) => {
    if (filterAttack !== 'All' && f.attackType !== filterAttack) return false
    if (filterSev !== 'All' && f.severity !== filterSev.toLowerCase()) return false
    if (filterSector !== 'All' && !f.sectors.includes(filterSector)) return false
    if (filterCountry !== 'All' && f.sourceCountry !== filterCountry && f.destCountry !== filterCountry) return false
    if (search && !f.title.toLowerCase().includes(search.toLowerCase()) && !(f.cve ?? '').toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const hasFilters = filterAttack !== 'All' || filterSev !== 'All' || filterSector !== 'All' || filterCountry !== 'All' || search

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-5 border-b border-white/5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Threat Intelligence Feeds</h1>
          <p className="text-xs text-ink-500 mt-0.5">Real-time threat feed aggregation · hover any row for details</p>
        </div>
        <div className="flex items-center gap-3">
          {/* Live toggle */}
          <button
            onClick={() => setLive((l) => !l)}
            aria-label={live ? 'Pause live feed' : 'Resume live feed'}
            className={cn(
              'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs border transition-colors',
              live ? 'bg-safe/10 border-safe/25 text-safe' : 'bg-surface-2 border-white/8 text-ink-400',
            )}
          >
            <span className={cn('w-1.5 h-1.5 rounded-full', live && 'animate-pulse bg-safe')} style={!live ? { background: '#665B7D' } : {}} />
            {live ? 'Live' : 'Paused'}
          </button>
          <div className="flex items-center gap-1.5 text-[10px] text-ink-600">
            <RefreshCw className="w-3 h-3" />
            Update #{ticker}
          </div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="px-6 py-3 border-b border-white/4 flex flex-wrap items-center gap-3">
        <Filter className="w-3.5 h-3.5 text-ink-500 shrink-0" />

        {/* Search */}
        <input
          type="text"
          placeholder="Search CVE, title..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-3 py-1.5 rounded-lg text-xs bg-surface-2 border border-white/8 text-ink-200 placeholder-ink-600 focus:outline-none focus:border-magenta/40 w-44"
        />

        <FilterDropdown label="Attack Type" options={ATTACK_TYPES} value={filterAttack} onChange={setFilterAttack} />
        <FilterDropdown label="Severity"    options={SEVERITIES}   value={filterSev}    onChange={setFilterSev}    />
        <FilterDropdown label="Sector"      options={SECTORS}       value={filterSector} onChange={setFilterSector} />
        <FilterDropdown label="Country"     options={COUNTRIES}     value={filterCountry}onChange={setFilterCountry}/>

        {hasFilters && (
          <button
            onClick={() => { setFilterAttack('All'); setFilterSev('All'); setFilterSector('All'); setFilterCountry('All'); setSearch('') }}
            className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs text-threat hover:bg-threat/5 transition-colors border border-threat/20"
          >
            <X className="w-3 h-3" />
            Clear
          </button>
        )}

        <div className="ml-auto">
          <FeedStats feeds={filtered} />
        </div>
      </div>

      {/* Column headers */}
      <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 items-center px-4 py-2 text-[9px] font-semibold uppercase tracking-widest text-ink-600 border-b border-white/4">
        <span className="w-2" />
        <span>Threat / IOC</span>
        <span>Type</span>
        <span className="hidden md:block text-right">Country</span>
        <span>Severity</span>
        <span className="hidden sm:block">Time</span>
      </div>

      {/* Feed rows */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-ink-600">
            <Zap className="w-6 h-6 mb-2" />
            <p className="text-sm">No matching threats</p>
          </div>
        ) : (
          filtered.map((entry, i) => <FeedRow key={entry.id} entry={entry} idx={i} />)
        )}
      </div>
    </div>
  )
}
