'use client'

import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, Search, Plus, ChevronDown, X, Edit2, Trash2,
  AlertTriangle, CheckCircle, MinusCircle, Copy, Code2,
  ToggleLeft, ToggleRight, Filter, Tag, Clock, Activity,
  BookOpen, Layers, Zap, ArrowUpRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { fetchRules } from '@/lib/api'

/* ─── Types ─────────────────────────────────────────────────────────── */
type Severity   = 'critical' | 'high' | 'medium' | 'low' | 'info'
type RuleStatus = 'enabled' | 'disabled' | 'suppressed'
type Category   = 'Network' | 'Endpoint' | 'Cloud' | 'Identity' | 'Threat Intel'

interface DetectionRule {
  id:          string
  name:        string
  category:    Category
  severity:    Severity
  mitreTactic: string
  mitreTechId: string
  mitreTech:   string
  hits24h:     number
  fpRate:      number
  status:      RuleStatus
  source:      string
  lastFired:   string
  created:     string
  updatedBy:   string
  description: string
  kql:         string
  suppressionWindow: string
  severityOverride:  Severity | null
  tags:        string[]
}

/* ─── Seed data ──────────────────────────────────────────────────────── */
const RULES_DATA: DetectionRule[] = [
  {
    id: 'EDR-9001',
    name: 'Ransomware File Encryption Indicator',
    category: 'Endpoint',
    severity: 'critical',
    mitreTactic: 'Impact',
    mitreTechId: 'T1486',
    mitreTech: 'Data Encrypted for Impact',
    hits24h: 3,
    fpRate: 5,
    status: 'enabled',
    source: 'EDR',
    lastFired: '2h ago',
    created: '2024-03-14',
    updatedBy: 'j.chen',
    description: 'Detects mass file renaming or encryption activity consistent with ransomware behaviour. Triggers when more than 500 files are renamed or overwritten within 60 seconds by a single process, or when extensions associated with known ransomware families are detected.',
    kql: `process where event.type == "start"
  and process.name : ("svchost.exe","explorer.exe")
  and process.args_count > 3
| where file.extension in~ (".locked",".encrypted",".crypt",".crypted",".zzzzz")
| stats renamed_files = count() by process.pid, process.name, host.name
| where renamed_files > 500`,
    suppressionWindow: '24h per host',
    severityOverride: null,
    tags: ['ransomware', 'file-activity', 'impact'],
  },
  {
    id: 'SIEM-1042',
    name: 'External SSH Root Login',
    category: 'Network',
    severity: 'critical',
    mitreTactic: 'Initial Access',
    mitreTechId: 'T1133',
    mitreTech: 'External Remote Services',
    hits24h: 1,
    fpRate: 8,
    status: 'enabled',
    source: 'Syslog/SSH',
    lastFired: '4h ago',
    created: '2023-11-02',
    updatedBy: 'a.patel',
    description: 'Fires when a successful SSH authentication as root (or any UID 0 account) is recorded from a non-RFC1918 source IP address. Covers password, pubkey, and GSSAPI auth methods. Jump-host egress IPs are allowlisted via the TO_JUMP_HOSTS lookup table.',
    kql: `event.dataset: "system.auth"
  AND system.auth.ssh.method: ("password","publickey","keyboard-interactive")
  AND system.auth.ssh.event: "Accepted"
  AND user.name: "root"
  AND NOT source.ip: ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  AND NOT source.ip: (lookup TO_JUMP_HOSTS ip)`,
    suppressionWindow: '1h per source IP',
    severityOverride: null,
    tags: ['ssh', 'external-access', 'root'],
  },
  {
    id: 'EDR-4421',
    name: 'PowerShell AMSI Bypass',
    category: 'Endpoint',
    severity: 'high',
    mitreTactic: 'Defense Evasion',
    mitreTechId: 'T1562.001',
    mitreTech: 'Impair Defenses: Disable or Modify Tools',
    hits24h: 7,
    fpRate: 12,
    status: 'enabled',
    source: 'EDR',
    lastFired: '45m ago',
    created: '2024-01-08',
    updatedBy: 'j.chen',
    description: 'Detects known AMSI bypass strings and patterns in PowerShell memory or command-line arguments. Triggers on base64-encoded payloads that follow an AMSI patch attempt, or direct patching of amsi.dll export AmsiScanBuffer. Correlated with subsequent outbound network connections to flag follow-on payload staging.',
    kql: `process where process.name: "powershell.exe"
  and (
    process.args: ("*amsiutils*","*amsicontext*","*amsiscanbuffe*")
    or process.args: "*[Ref].Assembly.GetType*"
    or process.args: "*System.Management.Automation.AmsiUtils*"
    or (process.args_count > 1 and process.args: "*-EncodedCommand*" and length(process.args) > 200)
  )`,
    suppressionWindow: 'None (alert every occurrence)',
    severityOverride: null,
    tags: ['powershell', 'amsi', 'defense-evasion', 'lolbas'],
  },
  {
    id: 'EDR-5510',
    name: 'Lateral Movement via WMI',
    category: 'Endpoint',
    severity: 'high',
    mitreTactic: 'Lateral Movement',
    mitreTechId: 'T1047',
    mitreTech: 'Windows Management Instrumentation',
    hits24h: 12,
    fpRate: 18,
    status: 'enabled',
    source: 'EDR',
    lastFired: '12m ago',
    created: '2023-09-22',
    updatedBy: 'r.osei',
    description: 'Detects remote WMI process creation targeting hosts other than the originating system. Covers wmic.exe, Invoke-WmiMethod, and native Win32_Process::Create via COM. Remote execution from non-admin subnets or service accounts running interactively elevates the risk score automatically.',
    kql: `process where process.name: ("wmic.exe","wmiprvse.exe")
  and process.args: ("process","call","create")
  and network.direction: "outbound"
  and not source.ip == destination.ip
| join (
    process where process.parent.name: "wmiprvse.exe"
  ) on host.name
| where not user.name in~ ("svc-mgmt","deploy-bot")`,
    suppressionWindow: '30m per source/dest pair',
    severityOverride: null,
    tags: ['wmi', 'lateral-movement', 'remote-execution'],
  },
  {
    id: 'AWS-3421',
    name: 'IAM Privilege Escalation',
    category: 'Cloud',
    severity: 'high',
    mitreTactic: 'Privilege Escalation',
    mitreTechId: 'T1078.004',
    mitreTech: 'Valid Accounts: Cloud Accounts',
    hits24h: 2,
    fpRate: 20,
    status: 'enabled',
    source: 'AWS CloudTrail',
    lastFired: '8h ago',
    created: '2024-02-18',
    updatedBy: 'a.patel',
    description: 'Detects IAM operations that grant AdministratorAccess or equivalent permissions to a user, role, or group. Covers AttachUserPolicy, AttachRolePolicy, PutUserPolicy, CreatePolicyVersion (SetAsDefault=true), and AddUserToGroup where the group holds admin-equivalent managed policies. Flags self-escalation (identity operating on itself) at critical severity.',
    kql: `event.dataset: "aws.cloudtrail"
  AND event.action: (
    "AttachUserPolicy" OR "AttachRolePolicy" OR "PutUserPolicy" OR
    "CreatePolicyVersion" OR "AddUserToGroup"
  )
  AND requestParameters.policyArn: "*AdministratorAccess*"
  AND NOT userIdentity.sessionContext.sessionIssuer.userName: "break-glass-*"`,
    suppressionWindow: '6h per principal',
    severityOverride: null,
    tags: ['aws', 'iam', 'privilege-escalation', 'cloud'],
  },
  {
    id: 'NET-2201',
    name: 'DNS Exfiltration Pattern',
    category: 'Network',
    severity: 'medium',
    mitreTactic: 'Exfiltration',
    mitreTechId: 'T1048.003',
    mitreTech: 'Exfiltration Over Unencrypted Non-C2 Protocol',
    hits24h: 0,
    fpRate: 9,
    status: 'enabled',
    source: 'DNS/Network',
    lastFired: '3d ago',
    created: '2024-04-01',
    updatedBy: 'j.chen',
    description: 'Identifies DNS exfiltration by analysing query volume, subdomain entropy, and query label length. Triggers when a host issues more than 200 unique subdomain queries to a single apex domain within 5 minutes AND average label entropy exceeds 3.8 bits — characteristic of base64-encoded data tunnelled over DNS.',
    kql: `dns where dns.question.type: "A"
| stats
    unique_subs = dcount(dns.question.subdomain),
    avg_entropy = avg(entropy(dns.question.subdomain)),
    total_bytes = sum(dns.question.size)
  by source.ip, dns.question.registered_domain, bucket(@timestamp, 5m)
| where unique_subs > 200 and avg_entropy > 3.8
| where not dns.question.registered_domain: (lookup ALLOWED_DNS_TUNNELS domain)`,
    suppressionWindow: '1h per host/domain pair',
    severityOverride: null,
    tags: ['dns', 'exfiltration', 'covert-channel'],
  },
  {
    id: 'NET-9903',
    name: 'Tor Exit Node Traffic',
    category: 'Network',
    severity: 'high',
    mitreTactic: 'Command and Control',
    mitreTechId: 'T1090.003',
    mitreTech: 'Proxy: Multi-hop Proxy',
    hits24h: 5,
    fpRate: 3,
    status: 'enabled',
    source: 'Firewall/Proxy',
    lastFired: '1h ago',
    created: '2023-07-12',
    updatedBy: 'a.patel',
    description: 'Detects inbound or outbound connections to known Tor exit node IP addresses. The Tor exit node list is refreshed every 4 hours from the official Tor Project consensus endpoint and stored in the TOR_EXIT_NODES threat intelligence lookup. Matches on firewall allow AND block events to capture bypass attempts.',
    kql: `network where (source.ip: (lookup TOR_EXIT_NODES ip) OR destination.ip: (lookup TOR_EXIT_NODES ip))
  AND event.outcome: ("allowed","blocked")
| stats
    connection_count = count(),
    total_bytes      = sum(network.bytes),
    unique_ports     = dcount(destination.port)
  by source.ip, destination.ip, host.name`,
    suppressionWindow: '2h per source IP',
    severityOverride: null,
    tags: ['tor', 'anonymiser', 'proxy', 'c2'],
  },
  {
    id: 'EDR-3001',
    name: 'Mimikatz Credential Dump',
    category: 'Endpoint',
    severity: 'critical',
    mitreTactic: 'Credential Access',
    mitreTechId: 'T1003.001',
    mitreTech: 'OS Credential Dumping: LSASS Memory',
    hits24h: 0,
    fpRate: 2,
    status: 'enabled',
    source: 'EDR',
    lastFired: '6d ago',
    created: '2023-05-30',
    updatedBy: 'j.chen',
    description: 'Multi-method detection for Mimikatz and similar LSASS credential dumping tools. Covers: (1) process handle open to lsass.exe with PROCESS_VM_READ access mask; (2) known Mimikatz strings in process memory or command line; (3) creation of lsass memory dump files (minidump/createdump pattern); (4) seDebugPrivilege acquisition by non-system processes.',
    kql: `process where event.type: "start"
  and (
    /* Direct memory read from lsass */
    (target.process.name: "lsass.exe" and process.granted_access: (0x1010, 0x1410, 0x1FFFFF))
    /* Known Mimikatz CLI strings */
    or process.args: ("sekurlsa::","lsadump::","privilege::debug","coffee")
    /* LSASS minidump creation */
    or (file.path: ("*\\lsass*.dmp","*\\lsass*.mdmp") and file.Ext.header_bytes: "4d444d50*")
  )`,
    suppressionWindow: 'None — page immediately',
    severityOverride: null,
    tags: ['mimikatz', 'credential-access', 'lsass', 'privilege'],
  },
  {
    id: 'ID-7701',
    name: 'MFA Push Fatigue Attack',
    category: 'Identity',
    severity: 'high',
    mitreTactic: 'Credential Access',
    mitreTechId: 'T1621',
    mitreTech: 'Multi-Factor Authentication Request Generation',
    hits24h: 4,
    fpRate: 15,
    status: 'enabled',
    source: 'Okta / Azure AD',
    lastFired: '3h ago',
    created: '2024-06-01',
    updatedBy: 'r.osei',
    description: 'Detects MFA push bombing / fatigue attacks by counting the number of MFA push requests sent to a single user within a 5-minute window from an external IP. Threshold of 10 pushes triggers a high-severity alert; 20+ pushes in the same window auto-escalates to critical and disables the account via SOAR playbook.',
    kql: `event.dataset: "okta.system"
  AND event.action: "user.mfa.attempt_bypass"
  AND event.outcome: "failure"
  AND NOT source.ip: ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| stats push_count = count() by user.email, source.ip, bucket(@timestamp, 5m)
| where push_count >= 10`,
    suppressionWindow: 'None (alert every 5m window)',
    severityOverride: null,
    tags: ['mfa', 'push-fatigue', 'identity', 'okta'],
  },
  {
    id: 'TI-0042',
    name: 'Known Malware C2 Beacon Match',
    category: 'Threat Intel',
    severity: 'high',
    mitreTactic: 'Command and Control',
    mitreTechId: 'T1071.001',
    mitreTech: 'Application Layer Protocol: Web Protocols',
    hits24h: 9,
    fpRate: 4,
    status: 'enabled',
    source: 'TI Feed / DNS / Proxy',
    lastFired: '22m ago',
    created: '2024-01-15',
    updatedBy: 'a.patel',
    description: 'Matches DNS queries and HTTP/HTTPS connections against aggregated C2 IOC lists from Recorded Future, CrowdStrike Falcon Intelligence, MISP (TLP:WHITE), and Abuse.ch URLhaus. IOCs are deduplicated and confidence-weighted; only indicators with confidence ≥ 70% and age ≤ 30 days are included.',
    kql: `(dns.question.name: (lookup C2_DOMAINS domain) OR
 url.domain:          (lookup C2_DOMAINS domain) OR
 destination.ip:      (lookup C2_IPS ip))
AND NOT source.ip: (lookup TI_ALLOWLIST ip)
| eval confidence = lookup_value(C2_DOMAINS, dns.question.name, "confidence")
| where confidence >= 70`,
    suppressionWindow: '4h per source host + IOC pair',
    severityOverride: null,
    tags: ['c2', 'threat-intel', 'beaconing', 'ioc'],
  },
  {
    id: 'CLO-8812',
    name: 'S3 Public Bucket Exposure',
    category: 'Cloud',
    severity: 'medium',
    mitreTactic: 'Exfiltration',
    mitreTechId: 'T1530',
    mitreTech: 'Data from Cloud Storage',
    hits24h: 1,
    fpRate: 30,
    status: 'suppressed',
    source: 'AWS CloudTrail',
    lastFired: '1d ago',
    created: '2024-05-10',
    updatedBy: 'j.chen',
    description: 'Detects S3 bucket ACL or bucket policy modifications that grant public read or public read-write access (Principal: "*"). Also fires on PutBucketAcl with "public-read" canned ACL. SUPPRESSED: Engineering team has a scheduled review cadence; false-positive rate is high during sandbox environment provisioning windows (Tue/Thu 09:00–11:00 UTC).',
    kql: `event.dataset: "aws.cloudtrail"
  AND event.action: ("PutBucketAcl","PutBucketPolicy")
  AND requestParameters.accessControlList.x-amz-grant-read: "*"
  OR (requestParameters.bucketPolicy.Statement{}.Principal: "*"
      AND requestParameters.bucketPolicy.Statement{}.Effect: "Allow")`,
    suppressionWindow: 'Tue/Thu 09:00–11:00 UTC (recurring)',
    severityOverride: 'low',
    tags: ['s3', 'public-exposure', 'cloud', 'data-leak'],
  },
]

/* ─── Severity config ───────────────────────────────────────────────── */
const SEV_CONFIG: Record<Severity, { bg: string; text: string; border: string; dot: string; label: string }> = {
  critical: { bg: 'bg-magenta/15',  text: 'text-magenta',  border: 'border-magenta/30',  dot: '#FF2E97', label: 'Critical' },
  high:     { bg: 'bg-threat/15',   text: 'text-threat',   border: 'border-threat/30',   dot: '#FF4D6D', label: 'High' },
  medium:   { bg: 'bg-amber/15',    text: 'text-amber',    border: 'border-amber/30',    dot: '#FFB23E', label: 'Medium' },
  low:      { bg: 'bg-safe/15',     text: 'text-safe',     border: 'border-safe/30',     dot: '#34F5C5', label: 'Low' },
  info:     { bg: 'bg-violet/15',   text: 'text-violet',   border: 'border-violet/30',   dot: '#7A3CFF', label: 'Info' },
}

const CAT_COLOR: Record<Category, string> = {
  Network:      '#7A3CFF',
  Endpoint:     '#FF4D6D',
  Cloud:        '#34F5C5',
  Identity:     '#FFB23E',
  'Threat Intel': '#FF2E97',
}

/* ─── Sub-components ─────────────────────────────────────────────────── */
function SeverityPill({ severity }: { severity: Severity }) {
  const c = SEV_CONFIG[severity]
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase border', c.bg, c.text, c.border)}>
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: c.dot }} />
      {c.label}
    </span>
  )
}

function StatusBadge({ status }: { status: RuleStatus }) {
  if (status === 'enabled')    return <span className="text-safe   text-[10px] font-semibold">Enabled</span>
  if (status === 'suppressed') return <span className="text-amber  text-[10px] font-semibold">Suppressed</span>
  return                              <span className="text-ink-500 text-[10px] font-semibold">Disabled</span>
}

function Toggle({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onToggle() }}
      className={cn(
        'relative w-8 h-4.5 rounded-full transition-colors duration-200 shrink-0',
        enabled ? 'bg-safe/30 border border-safe/40' : 'bg-white/10 border border-white/15',
      )}
      title={enabled ? 'Disable rule' : 'Enable rule'}
    >
      <span className={cn(
        'absolute top-0.5 w-3 h-3 rounded-full transition-transform duration-200 shadow-sm',
        enabled ? 'translate-x-4 bg-safe' : 'translate-x-0.5 bg-ink-600',
      )} />
    </button>
  )
}

/* ─── Rule Detail Panel ──────────────────────────────────────────────── */
function RulePanel({ rule, onClose, onToggle }: {
  rule: DetectionRule
  onClose: () => void
  onToggle: (id: string) => void
}) {
  const [copied, setCopied] = useState(false)
  const [overrideSev, setOverrideSev] = useState<Severity | null>(rule.severityOverride)
  const [suppressionWin, setSuppressionWin] = useState(rule.suppressionWindow)
  const [saved, setSaved] = useState(false)
  const s = SEV_CONFIG[overrideSev ?? rule.severity]

  function copyKQL() {
    navigator.clipboard.writeText(rule.kql).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  function handleSave() {
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  return (
    <motion.div
      key={rule.id}
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="fixed right-0 top-0 bottom-0 z-[60] w-full max-w-[600px] flex flex-col bg-surface border-l border-white/8 shadow-2xl overflow-hidden"
    >
      {/* Panel header */}
      <div className="p-5 border-b border-white/8 shrink-0">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg shrink-0" style={{ background: `${CAT_COLOR[rule.category]}18` }}>
            <Shield className="w-4 h-4" style={{ color: CAT_COLOR[rule.category] }} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono text-ink-500">{rule.id}</span>
              <SeverityPill severity={overrideSev ?? rule.severity} />
              {overrideSev && (
                <span className="text-[9px] text-amber border border-amber/30 bg-amber/10 rounded px-1.5 py-0.5">override active</span>
              )}
            </div>
            <h2 className="text-sm font-semibold text-white mt-1 leading-snug">{rule.name}</h2>
            <p className="text-[10px] text-ink-500 mt-1">
              {rule.category} · {rule.mitreTechId} {rule.mitreTech} · Updated by {rule.updatedBy}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Quick stats */}
        <div className="flex items-center gap-3 mt-4 flex-wrap">
          {[
            { label: 'Hits (24h)',      value: rule.hits24h.toString(), color: rule.hits24h > 0 ? '#FF2E97' : '#665B7D' },
            { label: 'FP Rate',         value: `${rule.fpRate}%`,       color: rule.fpRate > 25 ? '#FFB23E' : '#34F5C5' },
            { label: 'Last Fired',      value: rule.lastFired,          color: '#8A7DA3' },
            { label: 'Status',          value: rule.status,             color: rule.status === 'enabled' ? '#34F5C5' : rule.status === 'suppressed' ? '#FFB23E' : '#665B7D' },
          ].map(({ label, value, color }) => (
            <div key={label} className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
              <span className="text-[9px] text-ink-600 uppercase tracking-wide">{label}</span>
              <span className="text-xs font-semibold mt-0.5 capitalize" style={{ color }}>{value}</span>
            </div>
          ))}
          <div className="ml-auto">
            <Toggle enabled={rule.status === 'enabled'} onToggle={() => onToggle(rule.id)} />
          </div>
        </div>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">

        {/* Description */}
        <section>
          <PanelSection title="Description" icon={BookOpen} />
          <p className="text-xs text-ink-300 leading-relaxed mt-2">{rule.description}</p>
        </section>

        {/* MITRE Mapping */}
        <section>
          <PanelSection title="MITRE ATT&CK Mapping" icon={Layers} />
          <div className="mt-2 grid grid-cols-2 gap-2">
            <DataRow label="Tactic"    value={rule.mitreTactic} />
            <DataRow label="Technique" value={`${rule.mitreTechId} · ${rule.mitreTech}`} mono />
            <DataRow label="Category"  value={rule.category} />
            <DataRow label="Source"    value={rule.source} />
            <DataRow label="Created"   value={rule.created} />
            <DataRow label="Tags"      value={rule.tags.join(', ')} />
          </div>
        </section>

        {/* KQL / Detection Query */}
        <section>
          <div className="flex items-center justify-between mb-2">
            <PanelSection title="Detection Query (KQL/EQL)" icon={Code2} />
            <button
              onClick={copyKQL}
              className={cn(
                'flex items-center gap-1 text-[10px] px-2.5 py-1 rounded-lg border transition-colors',
                copied
                  ? 'text-safe border-safe/30 bg-safe/10'
                  : 'text-ink-500 border-white/10 hover:text-white hover:border-white/20 bg-surface-2',
              )}
            >
              <Copy className="w-3 h-3" />
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="relative rounded-xl bg-[#080614] border border-white/8 overflow-hidden">
            {/* Fake line numbers */}
            <div className="flex">
              <div className="py-4 px-3 text-right text-[10px] font-mono text-ink-700 select-none bg-white/2 border-r border-white/5 leading-[1.6] shrink-0">
                {rule.kql.split('\n').map((_, i) => (
                  <div key={i}>{i + 1}</div>
                ))}
              </div>
              <pre className="flex-1 p-4 text-[11px] font-mono text-ink-200 leading-[1.6] overflow-x-auto whitespace-pre">
                {rule.kql}
              </pre>
            </div>
          </div>
        </section>

        {/* Suppression config */}
        <section>
          <PanelSection title="Suppression &amp; Tuning" icon={Clock} />
          <div className="mt-2 space-y-3">
            <div>
              <label className="block text-[10px] text-ink-500 mb-1">Suppression Window</label>
              <input
                type="text"
                value={suppressionWin}
                onChange={(e) => setSuppressionWin(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-surface-2 border border-white/10 rounded-lg text-ink-200 focus:outline-none focus:border-violet/40 transition-colors"
              />
            </div>
            <div>
              <label className="block text-[10px] text-ink-500 mb-1">Severity Override</label>
              <div className="flex items-center gap-2 flex-wrap">
                {(['critical','high','medium','low','info','none'] as const).map((sev) => {
                  const active = sev === 'none' ? overrideSev === null : overrideSev === sev
                  const cfg = sev !== 'none' ? SEV_CONFIG[sev] : null
                  return (
                    <button
                      key={sev}
                      onClick={() => setOverrideSev(sev === 'none' ? null : sev)}
                      className={cn(
                        'px-2.5 py-1 rounded-full text-[10px] font-semibold border capitalize transition-all',
                        active
                          ? (cfg ? cn(cfg.bg, cfg.text, cfg.border) : 'bg-white/10 text-white border-white/25')
                          : 'bg-transparent text-ink-600 border-white/10 hover:border-white/20 hover:text-ink-300',
                      )}
                    >
                      {sev === 'none' ? 'No override' : sev}
                    </button>
                  )
                })}
              </div>
            </div>
          </div>
        </section>

        {/* Save feedback */}
        <AnimatePresence>
          {saved && (
            <motion.div
              initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="flex items-center gap-2 text-xs text-safe bg-safe/10 border border-safe/20 rounded-lg px-3 py-2"
            >
              <CheckCircle className="w-3.5 h-3.5 shrink-0" />
              Rule configuration saved successfully
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Footer actions */}
      <div className="p-4 border-t border-white/8 flex items-center gap-2 shrink-0">
        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-violet/20 border border-violet/30 text-violet hover:bg-violet/30 transition-colors"
        >
          <CheckCircle className="w-3.5 h-3.5" /> Save Changes
        </button>
        <button className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-white hover:border-white/20 transition-colors">
          <Edit2 className="w-3.5 h-3.5" /> Edit in Builder
        </button>
        <button className="ml-auto flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium text-threat/70 hover:text-threat border border-transparent hover:border-threat/30 hover:bg-threat/10 transition-colors">
          <Trash2 className="w-3.5 h-3.5" /> Delete Rule
        </button>
      </div>
    </motion.div>
  )
}

function PanelSection({ title, icon: Icon }: { title: string; icon: React.ElementType }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 text-ink-600" />
      <span className="text-[10px] font-semibold text-ink-500 uppercase tracking-widest">{title}</span>
    </div>
  )
}

function DataRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col px-3 py-2 bg-surface-2/60 rounded-lg border border-white/5">
      <span className="text-[9px] text-ink-600 uppercase tracking-wide">{label}</span>
      <span className={cn('text-[11px] text-ink-200 mt-0.5 break-all', mono && 'font-mono')}>{value}</span>
    </div>
  )
}

/* ─── Main Page ─────────────────────────────────────────────────────── */
export default function RulesEnginePage() {
  useExperienceMode()

  const [rulesData, setRulesData] = useState(RULES_DATA)

  useEffect(() => {
    fetchRules()
      .then((data) => { if (data.length > 0) setRulesData(data as unknown as typeof RULES_DATA) })
      .catch(() => {})
  }, [])

  /* filter state */
  const [search,     setSearch]     = useState('')
  const [filterSev,  setFilterSev]  = useState<Severity | 'all'>('all')
  const [filterStat, setFilterStat] = useState<RuleStatus | 'all'>('all')
  const [filterCat,  setFilterCat]  = useState<Category | 'all'>('all')

  /* table row selection → panel */
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selectedRule = rulesData.find((r) => r.id === selectedId) ?? null

  /* interactive status toggles */
  const [statuses, setStatuses] = useState<Record<string, RuleStatus>>(
    () => Object.fromEntries(rulesData.map((r) => [r.id, r.status])),
  )

  // Re-init statuses when rulesData loads from API
  useEffect(() => {
    setStatuses(Object.fromEntries(rulesData.map((r) => [r.id, r.status ?? 'enabled'])))
  }, [rulesData])

  function toggleRule(id: string) {
    setStatuses((prev) => ({
      ...prev,
      [id]: prev[id] === 'enabled' ? 'disabled' : 'enabled',
    }))
  }

  /* Escape to close */
  useEffect(() => {
    if (!selectedId) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelectedId(null) }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [selectedId])

  /* Filtered rows */
  const rows = useMemo(() => rulesData.filter((r) => {
    if (filterSev  !== 'all' && r.severity  !== filterSev)  return false
    if (filterCat  !== 'all' && r.category  !== filterCat)  return false
    if (filterStat !== 'all' && statuses[r.id] !== filterStat) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        r.name.toLowerCase().includes(q)        ||
        r.id.toLowerCase().includes(q)          ||
        r.mitreTechId.toLowerCase().includes(q) ||
        r.mitreTech.toLowerCase().includes(q)   ||
        r.category.toLowerCase().includes(q)
      )
    }
    return true
  }), [search, filterSev, filterCat, filterStat, statuses])

  /* KPIs */
  const totalRules = rulesData.length
  const active     = rulesData.filter((r) => statuses[r.id] === 'enabled').length
  const suppressed = rulesData.filter((r) => statuses[r.id] === 'suppressed').length
  const custom     = rulesData.filter((r) => r.id.startsWith('CLO') || r.id.startsWith('TI')).length + 4 // simulate 44

  /* Merged rule with live status */
  function mergedRule(r: DetectionRule): DetectionRule {
    return { ...r, status: statuses[r.id] }
  }

  return (
    <div className="p-6 space-y-6 min-h-screen">
      {/* ── Page header ── */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-start justify-between gap-4"
      >
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25">
              <Shield className="w-4 h-4 text-magenta" />
            </div>
            <h1 className="font-display text-xl font-bold text-white tracking-tight">Rules Engine</h1>
          </div>
          <p className="text-sm text-ink-500">Detection rules powering your alert pipeline</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium bg-magenta/20 border border-magenta/35 text-magenta hover:bg-magenta/30 transition-colors active:scale-95">
          <Plus className="w-4 h-4" />
          New Rule
        </button>
      </motion.div>

      {/* ── KPI strip ── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
        className="grid grid-cols-2 sm:grid-cols-4 gap-4"
      >
        {[
          { label: 'Total Rules',  value: totalRules, icon: Layers,       color: '#7A3CFF', sub: 'across all categories' },
          { label: 'Active',       value: active,     icon: CheckCircle,  color: '#34F5C5', sub: `${Math.round(active / totalRules * 100)}% of total` },
          { label: 'Suppressed',   value: suppressed, icon: MinusCircle,  color: '#FFB23E', sub: 'temporarily silenced' },
          { label: 'Custom Rules', value: 44,         icon: Zap,          color: '#FF2E97', sub: 'author-created' },
        ].map(({ label, value, icon: Icon, color, sub }) => (
          <div
            key={label}
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
          </div>
        ))}
      </motion.div>

      {/* ── Filter bar ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="flex flex-wrap items-center gap-3"
      >
        {/* Search */}
        <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-xs px-3 py-2 rounded-xl bg-surface-2 border border-white/8 focus-within:border-violet/40 transition-colors">
          <Search className="w-3.5 h-3.5 text-ink-600 shrink-0" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules, IDs, techniques…"
            className="flex-1 bg-transparent text-xs text-ink-200 placeholder-ink-700 focus:outline-none"
          />
          {search && (
            <button onClick={() => setSearch('')} className="text-ink-600 hover:text-ink-300">
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Severity filter */}
        <FilterSelect
          value={filterSev}
          onChange={(v) => setFilterSev(v as Severity | 'all')}
          options={[
            { value: 'all',      label: 'All Severities' },
            { value: 'critical', label: 'Critical' },
            { value: 'high',     label: 'High' },
            { value: 'medium',   label: 'Medium' },
            { value: 'low',      label: 'Low' },
            { value: 'info',     label: 'Info' },
          ]}
          icon={AlertTriangle}
        />

        {/* Status filter */}
        <FilterSelect
          value={filterStat}
          onChange={(v) => setFilterStat(v as RuleStatus | 'all')}
          options={[
            { value: 'all',        label: 'All Statuses' },
            { value: 'enabled',    label: 'Enabled' },
            { value: 'disabled',   label: 'Disabled' },
            { value: 'suppressed', label: 'Suppressed' },
          ]}
          icon={Activity}
        />

        {/* Category filter */}
        <FilterSelect
          value={filterCat}
          onChange={(v) => setFilterCat(v as Category | 'all')}
          options={[
            { value: 'all',          label: 'All Categories' },
            { value: 'Network',      label: 'Network' },
            { value: 'Endpoint',     label: 'Endpoint' },
            { value: 'Cloud',        label: 'Cloud' },
            { value: 'Identity',     label: 'Identity' },
            { value: 'Threat Intel', label: 'Threat Intel' },
          ]}
          icon={Tag}
        />

        <span className="text-[10px] text-ink-600 ml-auto">
          {rows.length} of {rulesData.length} rules
        </span>
      </motion.div>

      {/* ── Rules table ── */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.14 }}
        className="bg-surface-2/40 rounded-xl border border-white/5 overflow-hidden"
      >
        {/* Table header */}
        <div className="grid grid-cols-[minmax(0,2fr)_100px_100px_110px_70px_60px_80px_80px] gap-4 px-5 py-3 border-b border-white/5 text-[10px] text-ink-600 uppercase tracking-widest font-medium">
          <span>Rule Name</span>
          <span>Category</span>
          <span>Severity</span>
          <span>MITRE Tech</span>
          <span>Hits 24h</span>
          <span>FP %</span>
          <span>Status</span>
          <span>Actions</span>
        </div>

        {/* Table rows */}
        <div className="divide-y divide-white/4">
          <AnimatePresence>
            {rows.length === 0 ? (
              <div className="py-14 text-center text-ink-600 text-sm">
                No rules match current filters
              </div>
            ) : (
              rows.map((rule, i) => {
                const live   = mergedRule(rule)
                const isOpen = selectedId === rule.id
                const sev    = SEV_CONFIG[rule.severity]
                return (
                  <motion.div
                    key={rule.id}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.025 }}
                    onClick={() => setSelectedId(isOpen ? null : rule.id)}
                    className={cn(
                      'grid grid-cols-[minmax(0,2fr)_100px_100px_110px_70px_60px_80px_80px] gap-4 px-5 py-3.5 cursor-pointer transition-colors group',
                      isOpen
                        ? 'bg-violet/8 border-l-2 border-l-violet'
                        : 'hover:bg-white/3 border-l-2 border-l-transparent',
                    )}
                  >
                    {/* Name */}
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-white truncate group-hover:text-ink-100">{rule.name}</p>
                      <p className="text-[10px] font-mono text-ink-600 mt-0.5">{rule.id}</p>
                    </div>

                    {/* Category */}
                    <div className="flex items-center">
                      <span
                        className="text-[10px] font-medium px-2 py-0.5 rounded-full border"
                        style={{
                          color:  CAT_COLOR[rule.category],
                          background: `${CAT_COLOR[rule.category]}15`,
                          borderColor: `${CAT_COLOR[rule.category]}40`,
                        }}
                      >
                        {rule.category}
                      </span>
                    </div>

                    {/* Severity */}
                    <div className="flex items-center">
                      <SeverityPill severity={rule.severity} />
                    </div>

                    {/* MITRE */}
                    <div className="flex items-center min-w-0">
                      <span className={cn('text-[10px] font-mono truncate', sev.text)}>{rule.mitreTechId}</span>
                    </div>

                    {/* Hits */}
                    <div className="flex items-center">
                      <span className={cn('text-xs font-semibold', rule.hits24h > 0 ? 'text-magenta' : 'text-ink-700')}>
                        {rule.hits24h > 0 ? rule.hits24h : '—'}
                      </span>
                    </div>

                    {/* FP Rate */}
                    <div className="flex items-center">
                      <span className={cn('text-xs font-medium', rule.fpRate > 25 ? 'text-amber' : rule.fpRate > 15 ? 'text-ink-300' : 'text-safe')}>
                        {rule.fpRate}%
                      </span>
                    </div>

                    {/* Status toggle */}
                    <div className="flex items-center gap-2">
                      <Toggle enabled={live.status === 'enabled'} onToggle={() => toggleRule(rule.id)} />
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => setSelectedId(isOpen ? null : rule.id)}
                        className="p-1.5 rounded-lg text-ink-600 hover:text-violet hover:bg-violet/10 transition-colors"
                        title="View / edit"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        className="p-1.5 rounded-lg text-ink-600 hover:text-threat hover:bg-threat/10 transition-colors"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </motion.div>
                )
              })
            )}
          </AnimatePresence>
        </div>

        {/* Table footer */}
        <div className="px-5 py-3 border-t border-white/5 flex items-center justify-between text-[10px] text-ink-700">
          <span>Showing {rows.length} detection rules · last refreshed just now</span>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-safe" />
              {active} enabled
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber" />
              {suppressed} suppressed
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-ink-600" />
              {rulesData.length - active - suppressed} disabled
            </span>
          </div>
        </div>
      </motion.div>

      {/* ── Rule detail panel (slide-over) ── */}
      <AnimatePresence>
        {selectedRule && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[2px]"
              onClick={() => setSelectedId(null)}
            />
            <RulePanel
              rule={mergedRule(selectedRule)}
              onClose={() => setSelectedId(null)}
              onToggle={toggleRule}
            />
          </>
        )}
      </AnimatePresence>
    </div>
  )
}

/* ─── Filter select helper ───────────────────────────────────────────── */
function FilterSelect({
  value,
  onChange,
  options,
  icon: Icon,
}: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  icon: React.ElementType
}) {
  return (
    <div className="relative flex items-center gap-2 px-3 py-2 rounded-xl bg-surface-2 border border-white/8 hover:border-white/15 transition-colors cursor-pointer">
      <Icon className="w-3.5 h-3.5 text-ink-600 shrink-0" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none bg-transparent text-xs text-ink-300 focus:outline-none cursor-pointer pr-4"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-[#100A1C]">{o.label}</option>
        ))}
      </select>
      <ChevronDown className="w-3 h-3 text-ink-700 absolute right-2.5 pointer-events-none" />
    </div>
  )
}
