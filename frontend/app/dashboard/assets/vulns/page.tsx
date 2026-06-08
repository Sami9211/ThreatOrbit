'use client'

import { useState, useMemo, useEffect } from 'react'
import { fetchVulns, type Asset as ApiAsset } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldAlert, Bug, Search, X, ExternalLink, Crosshair, Clock,
  User, Server, FileText, Wrench, Activity, ChevronRight, Zap, ShieldCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Types ───────────────────────────────────────────────────────── */
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

/* ── Meta ───────────────────────────────────────────────────────── */
const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#FF2E97' },
  high:     { label: 'High',     color: '#FF4D6D' },
  medium:   { label: 'Medium',   color: '#FFB23E' },
  low:      { label: 'Low',      color: '#34F5C5' },
}

const STATUS_META: Record<VulnStatus, { label: string; color: string; bg: string }> = {
  open:          { label: 'Open',          color: '#FF4D6D', bg: 'bg-threat/10' },
  'in-progress': { label: 'In Progress',   color: '#FFB23E', bg: 'bg-amber/10'  },
  patched:       { label: 'Patched',       color: '#34F5C5', bg: 'bg-safe/10'   },
  accepted:      { label: 'Accepted Risk', color: '#7A3CFF', bg: 'bg-violet/10' },
}

const EXPLOIT_META: Record<ExploitMaturity, { label: string; color: string }> = {
  kev:        { label: 'KEV',        color: '#FF2E97' },
  weaponized: { label: 'Weaponized', color: '#FF4D6D' },
  poc:        { label: 'PoC',        color: '#FFB23E' },
  none:       { label: 'None',       color: '#665B7D' },
}

function cvssColor(score: number): string {
  if (score >= 9.0) return '#FF2E97'
  if (score >= 7.0) return '#FF4D6D'
  if (score >= 4.0) return '#FFB23E'
  return '#34F5C5'
}

function severityFromCvss(score: number): Severity {
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  return 'low'
}

/* ── Seed data ──────────────────────────────────────────────────── */
const SEED: Vuln[] = [
  {
    id: 'CVE-2024-3094', cvss: 10.0, title: 'XZ Utils Backdoor (liblzma)',
    description: 'Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file, modifying functions in the liblzma code and allowing a remote attacker with a specific Ed448 key to bypass SSH authentication and gain unauthorized remote code execution.',
    severity: 'critical', status: 'in-progress', exploit: 'kev', kev: true, exploitAvailable: true,
    affectedAssets: ['build-agent-03', 'PROD-API-04', 'edge-node-eu-w'], ageDays: 6, assignee: 'a.patel',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Changed' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.71,
    remediation: ['Downgrade xz/liblzma to a known-good version (≤ 5.4.6).', 'Audit any systems that built or installed xz 5.6.0/5.6.1.', 'Rotate SSH host keys on potentially exposed hosts.', 'Apply distribution security advisories and rebuild affected packages.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094'],
  },
  {
    id: 'CVE-2024-6387', cvss: 8.1, title: 'regreSSHion — OpenSSH Signal Handler RCE',
    description: 'A signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems. If a client does not authenticate within LoginGraceTime, sshd\'s SIGALRM handler is called asynchronously, invoking functions that are not async-signal-safe, leading to memory corruption.',
    severity: 'high', status: 'open', exploit: 'weaponized', kev: false, exploitAvailable: true,
    affectedAssets: ['PROD-API-04', 'jenkins-ci-01', 'bastion-01'], ageDays: 11, assignee: 'r.osei',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'High' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.42,
    remediation: ['Update OpenSSH to 9.8p1 or later.', 'As a temporary mitigation, set LoginGraceTime to 0 in sshd_config.', 'Restrict SSH exposure via firewall / bastion-only access.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-6387'],
  },
  {
    id: 'CVE-2024-21762', cvss: 9.6, title: 'FortiOS SSL VPN Out-of-Bounds Write',
    description: 'An out-of-bounds write vulnerability in FortiOS may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests to the SSL VPN interface.',
    severity: 'critical', status: 'open', exploit: 'kev', kev: true, exploitAvailable: true,
    affectedAssets: ['fw-edge-01', 'fw-edge-02'], ageDays: 4, assignee: null,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.94,
    remediation: ['Upgrade FortiOS to a patched release (7.4.3, 7.2.7, 7.0.14, etc.).', 'Disable SSL VPN if not required until patched.', 'Review VPN logs for signs of exploitation.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21762'],
  },
  {
    id: 'CVE-2024-4577', cvss: 9.8, title: 'PHP CGI Argument Injection RCE',
    description: 'When using PHP in CGI mode on Windows, certain code-page conversions allow attackers to bypass earlier protections (CVE-2012-1823) via argument injection, leading to remote code execution by passing crafted query strings to the PHP interpreter.',
    severity: 'critical', status: 'in-progress', exploit: 'kev', kev: true, exploitAvailable: true,
    affectedAssets: ['web-legacy-01', 'wordpress-mkt'], ageDays: 9, assignee: 'j.chen',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.96,
    remediation: ['Update PHP to 8.3.8 / 8.2.20 / 8.1.29 or later.', 'Migrate away from PHP-CGI to PHP-FPM where possible.', 'Apply WAF rules blocking argument injection patterns.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-4577'],
  },
  {
    id: 'CVE-2024-23897', cvss: 9.8, title: 'Jenkins Arbitrary File Read (args4j)',
    description: 'Jenkins uses the args4j library to parse command arguments in the CLI. A feature that replaces an @ character followed by a file path with the file contents allows unauthenticated attackers to read arbitrary files on the Jenkins controller file system, including secrets that can lead to remote code execution.',
    severity: 'critical', status: 'patched', exploit: 'weaponized', kev: false, exploitAvailable: true,
    affectedAssets: ['jenkins-ci-01'], ageDays: 21, assignee: 'a.patel',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.93,
    remediation: ['Update Jenkins to 2.442 / LTS 2.426.3 or later.', 'Disable CLI access if not needed.', 'Rotate any secrets that may have been exposed.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-23897'],
  },
  {
    id: 'CVE-2024-21413', cvss: 9.8, title: 'Microsoft Outlook MonikerLink RCE',
    description: 'A flaw in Microsoft Outlook\'s handling of hyperlinks ("MonikerLink") allows attackers to bypass Protected View and trigger remote code execution by crafting links using the file:// protocol with an exclamation mark, leaking NTLM credentials and enabling arbitrary code execution.',
    severity: 'critical', status: 'open', exploit: 'poc', kev: false, exploitAvailable: true,
    affectedAssets: ['DESKTOP-FIN-087', 'DESKTOP-HR-012', 'LAPTOP-EXEC-03'], ageDays: 14, assignee: 'alice',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'Required' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.38,
    remediation: ['Apply the February 2024 Patch Tuesday updates for Office/Outlook.', 'Block outbound SMB/NTLM at the perimeter.', 'Educate users on suspicious links.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21413'],
  },
  {
    id: 'CVE-2024-27956', cvss: 9.9, title: 'WordPress Automatic Plugin SQL Injection',
    description: 'An improper neutralization of special elements in the WP Automatic plugin allows unauthenticated SQL injection, enabling attackers to extract sensitive data, create administrator accounts, and ultimately take over affected WordPress sites.',
    severity: 'critical', status: 'open', exploit: 'weaponized', kev: false, exploitAvailable: true,
    affectedAssets: ['wordpress-mkt'], ageDays: 17, assignee: null,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Changed' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.89,
    remediation: ['Update WP Automatic to 3.92.1 or later.', 'Audit the WordPress users table for rogue admin accounts.', 'Review database logs for injection attempts.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-27956'],
  },
  {
    id: 'CVE-2023-34362', cvss: 9.8, title: 'MOVEit Transfer SQL Injection (Cl0p)',
    description: 'A SQL injection vulnerability in Progress MOVEit Transfer allows unauthenticated attackers to access the database, infer its structure, and execute SQL statements that alter or delete database elements — widely exploited by the Cl0p ransomware group for mass data theft.',
    severity: 'critical', status: 'patched', exploit: 'kev', kev: true, exploitAvailable: true,
    affectedAssets: ['moveit-transfer-01'], ageDays: 64, assignee: 'r.osei',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.97,
    remediation: ['Apply MOVEit Transfer patched builds immediately.', 'Hunt for the human2.aspx web shell and indicators of compromise.', 'Notify affected data subjects if exfiltration is confirmed.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-34362'],
  },
  {
    id: 'CVE-2021-44228', cvss: 10.0, title: 'Log4Shell — Apache Log4j2 JNDI RCE',
    description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages can execute arbitrary code loaded from remote servers when message lookup substitution is enabled.',
    severity: 'critical', status: 'patched', exploit: 'kev', kev: true, exploitAvailable: true,
    affectedAssets: ['PROD-API-04', 'search-cluster-02', 'jenkins-ci-01'], ageDays: 120, assignee: 'a.patel',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Changed' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.97,
    remediation: ['Upgrade Log4j2 to 2.17.1 or later.', 'Remove the JndiLookup class from the classpath where upgrade is not possible.', 'Set log4j2.formatMsgNoLookups=true as a stopgap.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
  },
  {
    id: 'CVE-2024-38094', cvss: 7.2, title: 'Microsoft SharePoint Deserialization RCE',
    description: 'A deserialization of untrusted data vulnerability in Microsoft SharePoint Server allows an authenticated attacker with Site Owner permissions to execute arbitrary code on the server.',
    severity: 'high', status: 'in-progress', exploit: 'poc', kev: false, exploitAvailable: true,
    affectedAssets: ['sharepoint-01'], ageDays: 25, assignee: 'j.chen',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'High' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'High' },
      { label: 'Integrity', value: 'High' }, { label: 'Availability', value: 'High' },
    ], epss: 0.55,
    remediation: ['Apply the July 2024 SharePoint security updates.', 'Restrict Site Owner permissions to trusted users.', 'Monitor SharePoint for anomalous code execution.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-38094'],
  },
  {
    id: 'CVE-2024-20353', cvss: 8.6, title: 'Cisco ASA / FTD Web Services DoS',
    description: 'A vulnerability in the management and VPN web servers of Cisco ASA and FTD software could allow an unauthenticated remote attacker to cause the device to reload unexpectedly, resulting in a denial of service — part of the ArcaneDoor campaign.',
    severity: 'high', status: 'open', exploit: 'kev', kev: true, exploitAvailable: true,
    affectedAssets: ['fw-asa-dc-01', 'fw-asa-dc-02'], ageDays: 8, assignee: null,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'None' },
      { label: 'Integrity', value: 'None' }, { label: 'Availability', value: 'High' },
    ], epss: 0.61,
    remediation: ['Upgrade to a fixed Cisco ASA/FTD software release.', 'Restrict access to management web services.', 'Review device logs for ArcaneDoor IoCs.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-20353'],
  },
  {
    id: 'CVE-2024-49113', cvss: 7.5, title: 'LDAP Nightmare — Windows LDAP DoS',
    description: 'A vulnerability in the Windows Lightweight Directory Access Protocol (LDAP) implementation allows an unauthenticated attacker to crash the Local Security Authority Subsystem Service (LSASS) and reboot Domain Controllers via a crafted CLDAP referral response, causing denial of service.',
    severity: 'high', status: 'accepted', exploit: 'poc', kev: false, exploitAvailable: true,
    affectedAssets: ['dc-prod-01', 'dc-prod-02'], ageDays: 31, assignee: 'r.osei',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    vectorBreakdown: [
      { label: 'Attack Vector', value: 'Network' }, { label: 'Attack Complexity', value: 'Low' },
      { label: 'Privileges Req.', value: 'None' }, { label: 'User Interaction', value: 'None' },
      { label: 'Scope', value: 'Unchanged' }, { label: 'Confidentiality', value: 'None' },
      { label: 'Integrity', value: 'None' }, { label: 'Availability', value: 'High' },
    ], epss: 0.18,
    remediation: ['Apply the December 2024 Patch Tuesday updates to Domain Controllers.', 'Restrict inbound CLDAP/LDAP from untrusted networks.', 'Monitor DCs for unexpected LSASS crashes.'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-49113'],
  },
]

/* ── Sub-components ─────────────────────────────────────────────── */
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

/* ── Main page ─────────────────────────────────────────────────── */
export default function VulnsPage() {
  const [vulns, setVulns] = useState<Vuln[]>(SEED)

  useEffect(() => {
    fetchVulns().then((assets: ApiAsset[]) => {
      if (assets.length > 0) {
        const extra: Vuln[] = assets
          .filter((a) => a.cves.critical + a.cves.high > 0)
          .flatMap((a) => {
            const rows: Vuln[] = []
            const totalCritical = a.cves.critical
            const totalHigh = a.cves.high
            if (totalCritical > 0) {
              rows.push({
                id: `CVE-API-${a.id}-C`,
                cvss: 9.5,
                title: `${totalCritical} critical CVE${totalCritical > 1 ? 's' : ''} on ${a.name}`,
                description: `Asset ${a.name} has ${totalCritical} unpatched critical vulnerabilities detected during last scan.`,
                severity: 'critical',
                status: a.status === 'critical' ? 'open' : 'in-progress',
                exploit: 'poc',
                kev: false,
                exploitAvailable: true,
                affectedAssets: [a.name],
                ageDays: a.patchAge,
                assignee: a.owner,
                cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                vectorBreakdown: [{ label: 'Attack Vector', value: 'Network' }],
                epss: 0.5,
                remediation: [`Apply available patches for ${a.name}.`, 'Update OS and software packages.'],
                references: [],
              })
            }
            if (totalHigh > 0) {
              rows.push({
                id: `CVE-API-${a.id}-H`,
                cvss: 7.5,
                title: `${totalHigh} high CVE${totalHigh > 1 ? 's' : ''} on ${a.name}`,
                description: `Asset ${a.name} has ${totalHigh} unpatched high-severity vulnerabilities.`,
                severity: 'high',
                status: 'open',
                exploit: 'poc',
                kev: false,
                exploitAvailable: false,
                affectedAssets: [a.name],
                ageDays: a.patchAge,
                assignee: a.owner,
                cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
                vectorBreakdown: [{ label: 'Attack Vector', value: 'Network' }],
                epss: 0.3,
                remediation: [`Patch high-severity findings on ${a.name}.`],
                references: [],
              })
            }
            return rows
          })
        if (extra.length > 0) {
          setVulns((prev) => {
            const existingIds = new Set(prev.map((v) => v.id))
            const newOnly = extra.filter((v) => !existingIds.has(v.id))
            return newOnly.length > 0 ? [...prev, ...newOnly] : prev
          })
        }
      }
    }).catch(() => {})
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
    { label: 'Total CVEs',        value: '342',     color: 'text-white'  },
    { label: 'Critical',          value: '28',      color: 'text-magenta' },
    { label: 'Actively Exploited', value: '11',     color: 'text-threat' },
    { label: 'Avg Patch Age',     value: '18d',     color: 'text-amber'  },
    { label: 'Exposure Score',    value: '72/100',  color: 'text-threat' },
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
            className="flex-1 bg-transparent text-xs text-white placeholder-ink-600 outline-none" />
          {search && <button onClick={() => setSearch('')}><X className="w-3 h-3 text-ink-500" /></button>}
        </div>

        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as Severity | 'all')}
          className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/10 bg-white/5 text-ink-400 outline-none cursor-pointer">
          <option value="all" className="bg-surface">All Severities</option>
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
            <option key={s} value={s} className="bg-surface">{SEVERITY_META[s].label}</option>
          ))}
        </select>

        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as VulnStatus | 'all')}
          className="appearance-none px-3 py-1.5 rounded-lg text-xs border border-white/10 bg-white/5 text-ink-400 outline-none cursor-pointer">
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
                    i % 2 !== 0 && !isSel && 'bg-white/[0.01]')}>
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
        {filtered.length === 0 && (
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
              className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
            <motion.div
              initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 30, stiffness: 280 }}
              className="fixed right-0 top-0 bottom-0 z-[60] w-full max-w-md bg-surface border-l border-white/10 shadow-2xl overflow-y-auto">
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

                    {/* Quick stats */}
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { label: 'Severity', value: SEVERITY_META[v.severity].label, color: SEVERITY_META[v.severity].color },
                        { label: 'EPSS', value: `${(v.epss * 100).toFixed(0)}%`, color: cvssColor(v.cvss) },
                        { label: 'Patch Age', value: `${v.ageDays}d`, color: v.ageDays > 30 ? '#FF4D6D' : '#FFB23E' },
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

                    {/* CVSS vector */}
                    <div>
                      <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-1.5">CVSS Vector</p>
                      <p className="font-mono text-[10px] text-violet bg-violet/5 border border-violet/15 rounded-lg px-2.5 py-1.5 mb-2 break-all">{v.cvssVector}</p>
                      <div className="grid grid-cols-2 gap-1.5">
                        {v.vectorBreakdown.map((b) => (
                          <div key={b.label} className="flex items-center justify-between text-[10px] py-1 px-2 rounded bg-white/3">
                            <span className="text-ink-500">{b.label}</span>
                            <span className="text-ink-200 font-medium">{b.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>

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
