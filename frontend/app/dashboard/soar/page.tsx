'use client'

import { useState, useEffect, useMemo, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Zap, CheckCircle, Clock, AlertTriangle, X, Shield, User,
  FileText, MessageSquare, ChevronDown, Search, Play, RefreshCw,
  BarChart2, ArrowRight, Terminal, Paperclip, Flag, Eye,
  GitBranch, Activity, TrendingUp, TrendingDown, Database,
  ChevronRight, MoreHorizontal, Circle, Lock,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { fadeInUp } from '@/lib/motion'
import ReportButton from '@/components/dashboard/ReportButton'
import AnimatedNumber from '@/components/dashboard/AnimatedNumber'
import { SkeletonRows } from '@/components/dashboard/Skeleton'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { fetchCases, fetchPlaybooks, fetchSoarMetrics, createCase, addCaseNote, patchCaseTask, runPlaybook as apiRunPlaybook, fetchCaseRelated, addCaseEvidence, exportEvidenceBundle, type SoarMetrics, type CaseRelated } from '@/lib/api'
import { tk } from '@/lib/colors'

/* ── Types ────────────────────────────────────────────────────────── */
/* Responsive grid for the case queue. Status (hidden until md) and Owner (hidden
   until lg) would otherwise leave their fixed tracks reserved on smaller screens,
   shifting the remaining columns out of alignment and squashing the row. The
   track count is kept in step with the number of visible cells per breakpoint. */
const CASE_GRID =
  'grid gap-3 items-center ' +
  'grid-cols-[16px_minmax(0,1fr)_auto_auto_auto] ' +     // mobile: dot Case Playbook SLA Created
  'md:grid-cols-[16px_1fr_80px_80px_90px_60px] ' +        // +Status
  'lg:grid-cols-[16px_1fr_80px_90px_80px_90px_60px]'      // +Owner

type Severity = 'critical' | 'high' | 'medium' | 'low'
type CaseStatus = 'new' | 'assigned' | 'in-progress' | 'pending' | 'resolved' | 'closed'
type StepType = 'check' | 'action' | 'decision' | 'notify' | 'human' | 'sub-playbook'
type StepStatus = 'idle' | 'running' | 'completed' | 'failed' | 'skipped'

type CaseRecord = {
  id: string
  title: string
  type: string
  severity: Severity
  status: CaseStatus
  owner: string | null
  playbook: string
  slaHours: number
  created: string
  updated: string
  alertCount: number
  description: string
  entities: { type: string; value: string }[]
  warRoom: { ts: string; actor: string; type: 'auto' | 'manual' | 'system'; content: string }[]
  tasks: { id: string; phase: string; name: string; status: 'pending' | 'in-progress' | 'done' | 'skipped'; assignee: string | null; notes: string }[]
  // Static seeds carry added/by; live API items carry ts/addedBy (+sha256).
  evidence: { name: string; type: string; added?: string; by?: string;
              ts?: string; addedBy?: string; sha256?: string }[]
}

type Playbook = {
  id: string
  name: string
  trigger: string
  description: string
  runs: number
  successRate: number
  avgTime: string
  lastRun: string
  status: 'idle' | 'running' | 'completed' | 'failed'
  steps: { name: string; type: StepType; status: StepStatus; duration?: string }[]
  category: string
}

/* ── Case data ────────────────────────────────────────────────────── */
const CASES: CaseRecord[] = [
  {
    id: 'CASE-0441',
    title: 'Ransomware incident - DESKTOP-FIN-087 (msmith)',
    type: 'Ransomware', severity: 'critical', status: 'in-progress',
    owner: 'j.chen', playbook: 'Endpoint Ransomware Containment',
    slaHours: 4, created: '2024-11-12T14:22:00Z', updated: '2024-11-12T14:35:00Z',
    alertCount: 3,
    description: 'Ransomware detected on Finance workstation DESKTOP-FIN-087. 1,247 files encrypted with .locked extension. Host isolated. Active investigation and recovery in progress.',
    entities: [
      { type: 'Host',    value: 'DESKTOP-FIN-087' },
      { type: 'User',    value: 'msmith (Finance)' },
      { type: 'Process', value: 'svchost.exe (PID 9823)' },
      { type: 'Hash',    value: 'SHA256: 7a8b9c0d...' },
      { type: 'IP',      value: '10.44.0.87 (internal)' },
    ],
    warRoom: [
      { ts: '14:22:01', actor: 'SOAR Engine',  type: 'system', content: 'Case CASE-0441 created from SIEM alert a001 (EDR-9001). Playbook "Endpoint Ransomware Containment" triggered automatically.' },
      { ts: '14:22:04', actor: 'CrowdStrike',  type: 'auto',   content: 'Host DESKTOP-FIN-087 isolated from network via EDR API. Isolation status: CONFIRMED.' },
      { ts: '14:22:09', actor: 'VirusTotal',   type: 'auto',   content: 'Hash 7a8b9c0d: Detection ratio 58/72. Identified as LockBit 3.0 variant. TI confidence: HIGH.' },
      { ts: '14:23:11', actor: 'SOAR Engine',  type: 'auto',   content: 'Memory snapshot initiated on DESKTOP-FIN-087. Estimated completion: 4 minutes. Evidence collection in progress.' },
      { ts: '14:25:18', actor: 'j.chen',       type: 'manual', content: 'Confirmed ransomware - LockBit 3.0. Notified IR team lead and CISO. Checking for lateral spread indicators.' },
      { ts: '14:27:00', actor: 'Jira',         type: 'auto',   content: 'Incident ticket INC-20241112-0441 created in Jira ServiceDesk. Priority: P1. Assigned to IR team.' },
      { ts: '14:29:12', actor: 'j.chen',       type: 'manual', content: 'No lateral movement detected in last 2h based on EDR telemetry. Attack appears contained to single host.' },
      { ts: '14:35:00', actor: 'SOAR Engine',  type: 'auto',   content: 'Memory snapshot complete. Evidence archived to S3://soc-evidence/CASE-0441/. SHA256 hash logged for chain of custody.' },
    ],
    tasks: [
      { id: 't1', phase: 'Containment',  name: 'Isolate affected host from network',         status: 'done',       assignee: 'SOAR (automated)', notes: 'CrowdStrike API call successful' },
      { id: 't2', phase: 'Containment',  name: 'Verify no lateral movement in last 24h',     status: 'done',       assignee: 'j.chen', notes: 'Checked EDR telemetry - clean' },
      { id: 't3', phase: 'Evidence',     name: 'Collect memory snapshot and disk image',     status: 'done',       assignee: 'SOAR (automated)', notes: 'Archived to S3' },
      { id: 't4', phase: 'Evidence',     name: 'Identify patient zero and initial vector',   status: 'in-progress',assignee: 'j.chen', notes: 'Reviewing process tree' },
      { id: 't5', phase: 'Eradication',  name: 'Scan environment for additional IOCs',       status: 'pending',    assignee: null, notes: '' },
      { id: 't6', phase: 'Eradication',  name: 'Patch vulnerable software on all endpoints', status: 'pending',    assignee: null, notes: '' },
      { id: 't7', phase: 'Recovery',     name: 'Restore data from last known-good backup',  status: 'pending',    assignee: null, notes: '' },
      { id: 't8', phase: 'Post-Incident','name': 'Draft incident report and lessons learned', status: 'pending',   assignee: null, notes: '' },
    ],
    evidence: [
      { name: 'DESKTOP-FIN-087_mem.dmp',    type: 'Memory Dump', added: '14:35',  by: 'SOAR (automated)' },
      { name: 'process_tree.json',          type: 'EDR Export',  added: '14:26',  by: 'j.chen' },
      { name: 'network_connections.pcap',   type: 'PCAP',        added: '14:28',  by: 'j.chen' },
      { name: 'locked_file_list.txt',       type: 'File List',   added: '14:22',  by: 'SOAR (automated)' },
    ],
  },
  {
    id: 'CASE-0440',
    title: 'Phishing campaign targeting C-suite (14 recipients)',
    type: 'Phishing', severity: 'high', status: 'in-progress',
    owner: 'a.patel', playbook: 'Phishing Email Response',
    slaHours: 8, created: '2024-11-12T12:30:00Z', updated: '2024-11-12T14:10:00Z',
    alertCount: 2,
    description: 'LockBit-affiliated spearphishing campaign delivered macro-laced Excel file to 14 executives. 3 recipients opened the file. Cobalt Strike stager payload detected and quarantined on 2 of 3 hosts.',
    entities: [
      { type: 'Email',  value: 'noreply@m1crosoft-reports.kz' },
      { type: 'File',   value: 'Q4_Budget_Final.xlsm' },
      { type: 'Hash',   value: 'SHA256: abc123def...' },
      { type: 'Domain', value: 'm1crosoft-reports.kz' },
      { type: 'IP',     value: '185.220.101.42 (DPRK-linked)' },
    ],
    warRoom: [
      { ts: '12:30:05', actor: 'SOAR Engine', type: 'system', content: 'Case CASE-0440 created. 14 recipients identified. Playbook "Phishing Email Response" executing.' },
      { ts: '12:30:12', actor: 'Exchange',    type: 'auto',   content: 'Quarantine executed: 11 of 14 emails quarantined across Exchange Online. 3 emails already opened.' },
      { ts: '12:30:44', actor: 'VirusTotal',  type: 'auto',   content: 'Attachment SHA256 abc123def: 54/72 engines detected. Identified as Cobalt Strike stager (MalwareBytes: "CobaltStrikeStager.xlsm").' },
      { ts: '12:32:10', actor: 'CrowdStrike', type: 'auto',   content: 'Macro execution detected on HOST-EXEC-01 (CEO workstation). Process tree: EXCEL.EXE → cmd.exe → powershell.exe. Host quarantined.' },
      { ts: '12:40:00', actor: 'a.patel',     type: 'manual', content: 'Notified all 14 recipients via secure out-of-band communication. 3 confirmed opening file - conducting interviews.' },
      { ts: '14:10:00', actor: 'a.patel',     type: 'manual', content: 'Two hosts confirmed clean (Cobalt Strike payload blocked by EDR). Third host (CEO) shows C2 beacon - escalating to CASE-0441 investigation scope.' },
    ],
    tasks: [
      { id: 't1', phase: 'Triage',        name: 'Quarantine malicious emails',              status: 'done',       assignee: 'SOAR (automated)', notes: '11/14 quarantined; 3 opened' },
      { id: 't2', phase: 'Analysis',      name: 'Analyze attachment in sandbox',            status: 'done',       assignee: 'SOAR (automated)', notes: 'CobaltStrike stager confirmed' },
      { id: 't3', phase: 'Containment',   name: 'Block sender domain at email gateway',     status: 'done',       assignee: 'SOAR (automated)', notes: 'm1crosoft-reports.kz blocked' },
      { id: 't4', phase: 'Containment',   name: 'Notify affected users',                   status: 'done',       assignee: 'a.patel', notes: 'Out-of-band notification sent' },
      { id: 't5', phase: 'Investigation', name: 'Check 3 machines that opened file',       status: 'in-progress',assignee: 'a.patel', notes: '2 clean, 1 active C2' },
      { id: 't6', phase: 'Eradication',   name: 'Force password reset for affected users', status: 'pending',    assignee: null, notes: '' },
    ],
    evidence: [
      { name: 'Q4_Budget_Final.xlsm',   type: 'Malware Sample', added: '12:31', by: 'SOAR (automated)' },
      { name: 'vt_report_abc123.json',  type: 'TI Report',      added: '12:30', by: 'SOAR (automated)' },
      { name: 'email_headers.txt',      type: 'Email Headers',  added: '12:30', by: 'SOAR (automated)' },
    ],
  },
  {
    id: 'CASE-0439',
    title: 'Credential compromise - alice (impossible travel + MFA fatigue)',
    type: 'Account Compromise', severity: 'high', status: 'pending',
    owner: 'r.osei', playbook: 'Account Compromise Response',
    slaHours: 12, created: '2024-11-12T12:40:00Z', updated: '2024-11-12T13:45:00Z',
    alertCount: 2,
    description: 'User alice shows signs of credential compromise: impossible travel (New York → Singapore in 47 min) and 23 MFA push notifications from Russian IP. Awaiting user interview to confirm.',
    entities: [
      { type: 'User',   value: 'alice@corp.com' },
      { type: 'IP',     value: '103.245.12.44 (Singapore)' },
      { type: 'IP',     value: '91.108.56.0 (Russia)' },
    ],
    warRoom: [
      { ts: '12:40:20', actor: 'SOAR Engine', type: 'system', content: 'Case CASE-0439 created from 2 correlated alerts: impossible travel + MFA fatigue. Auto-correlation confidence: 94%.' },
      { ts: '12:41:00', actor: 'Okta',        type: 'auto',   content: 'User alice active session from SG IP terminated. Forced re-authentication required.' },
      { ts: '12:45:10', actor: 'r.osei',      type: 'manual', content: 'Contacted alice via phone. She confirms she is in New York. No knowledge of Singapore login. Account compromise confirmed.' },
      { ts: '13:00:00', actor: 'SOAR Engine', type: 'auto',   content: 'Emergency password reset token sent to alice recovery email (verified OOB). All active sessions revoked.' },
      { ts: '13:45:00', actor: 'r.osei',      type: 'manual', content: 'Password reset completed. MFA devices re-enrolled. Investigating how credential was obtained - checking for prior phishing.' },
    ],
    tasks: [
      { id: 't1', phase: 'Containment', name: 'Terminate active sessions',      status: 'done',       assignee: 'SOAR (automated)', notes: 'Okta API' },
      { id: 't2', phase: 'Containment', name: 'Force password reset',           status: 'done',       assignee: 'SOAR (automated)', notes: 'Token sent OOB' },
      { id: 't3', phase: 'Analysis',    name: 'Interview affected user',        status: 'done',       assignee: 'r.osei', notes: 'Confirmed compromise from NY' },
      { id: 't4', phase: 'Investigation','name': 'Trace credential theft vector', status: 'in-progress',assignee: 'r.osei', notes: 'Checking email + endpoint logs' },
      { id: 't5', phase: 'Post-Incident','name': 'Re-enroll MFA devices',       status: 'done',       assignee: 'r.osei', notes: 'Completed' },
    ],
    evidence: [],
  },
  {
    id: 'CASE-0438',
    title: 'IAM privilege escalation - lambda-svc (AWS AdministratorAccess)',
    type: 'Cloud Security', severity: 'high', status: 'resolved',
    owner: 'j.chen', playbook: 'Cloud Privilege Escalation',
    slaHours: 8, created: '2024-11-12T14:10:00Z', updated: '2024-11-12T15:20:00Z',
    alertCount: 1,
    description: 'Lambda service account self-escalated to AdministratorAccess. Root cause identified: overly permissive IAM role trust policy. Policy corrected and least-privilege role applied.',
    entities: [
      { type: 'IAM Role', value: 'lambda-svc' },
      { type: 'Policy',   value: 'AdministratorAccess' },
    ],
    warRoom: [
      { ts: '14:10:05', actor: 'SOAR Engine', type: 'system', content: 'Case CASE-0438 created from CloudTrail alert. Policy escalation detected.' },
      { ts: '14:10:11', actor: 'AWS',         type: 'auto',   content: 'AdministratorAccess policy detached from lambda-svc via IAM API. Role permissions reverted to previous state.' },
      { ts: '14:15:00', actor: 'j.chen',      type: 'manual', content: 'Root cause: trust policy allowed lambda-svc to assume any role in account. Fix: restrict assume-role to specific target roles only.' },
      { ts: '15:20:00', actor: 'j.chen',      type: 'manual', content: 'Least-privilege policy applied. Terraform PR raised for permanent fix. Case resolved - no data access occurred during elevated period.' },
    ],
    tasks: [
      { id: 't1', phase: 'Containment',  name: 'Detach escalated policy',       status: 'done', assignee: 'SOAR (automated)', notes: 'Auto-remediated via API' },
      { id: 't2', phase: 'Analysis',     name: 'Review CloudTrail for abuse',   status: 'done', assignee: 'j.chen', notes: 'No data access during window' },
      { id: 't3', phase: 'Eradication',  name: 'Apply least-privilege policy',  status: 'done', assignee: 'j.chen', notes: 'Terraform PR raised' },
    ],
    evidence: [
      { name: 'cloudtrail_export.json', type: 'Cloud Logs', added: '14:11', by: 'SOAR (automated)' },
    ],
  },
  {
    id: 'CASE-0437',
    title: 'SQL injection campaign - 847 attempts, 15 bypass events',
    type: 'Web Attack', severity: 'high', status: 'new',
    owner: null, playbook: 'Web Attack Triage',
    slaHours: 12, created: '2024-11-12T13:10:00Z', updated: '2024-11-12T13:10:00Z',
    alertCount: 1,
    description: 'Iranian IP launched 847 SQL injection attempts against /api/v2/users. WAF blocked 832 but 15 bypassed. Two 200 OK responses suggest partial data exposure. Investigation required.',
    entities: [
      { type: 'IP',       value: '91.92.251.103 (Iran, Stark Industries)' },
      { type: 'Endpoint', value: '/api/v2/users' },
    ],
    warRoom: [
      { ts: '13:10:10', actor: 'SOAR Engine', type: 'system', content: 'Case CASE-0437 auto-created from WAF-2231 alert. 15 bypass events flagged for immediate review.' },
      { ts: '13:10:15', actor: 'SOAR Engine', type: 'auto',   content: 'IP 91.92.251.103 blocked on Palo Alto perimeter firewall (GeoBlock + IP reputation feed). All future requests from ASN44477 blocked.' },
    ],
    tasks: [
      { id: 't1', phase: 'Containment', name: 'Block attacker IP at perimeter',         status: 'done',    assignee: 'SOAR (automated)', notes: 'PA FW API block applied' },
      { id: 't2', phase: 'Analysis',    name: 'Review 15 WAF bypass requests',          status: 'pending', assignee: null, notes: '' },
      { id: 't3', phase: 'Analysis',    name: 'Check DB logs for data exposure',        status: 'pending', assignee: null, notes: '' },
      { id: 't4', phase: 'Eradication', name: 'Patch SQL injection in /api/v2/users',  status: 'pending', assignee: null, notes: '' },
    ],
    evidence: [],
  },
]

/* ── Playbook data ────────────────────────────────────────────────── */
const PLAYBOOKS: Playbook[] = [
  {
    id: 'pb-001', name: 'Endpoint Ransomware Containment', trigger: 'EDR: mass file encryption',
    description: 'Immediate host isolation, memory collection, and IR escalation on ransomware detection.',
    runs: 7, successRate: 100, avgTime: '8m 44s', lastRun: 'Running now', status: 'running', category: 'Endpoint',
    steps: [
      { name: 'Verify detection confidence (EDR)',           type: 'check',       status: 'completed', duration: '2s' },
      { name: 'Isolate host from network',                   type: 'action',      status: 'completed', duration: '3s' },
      { name: 'Capture memory snapshot',                     type: 'action',      status: 'completed', duration: '4m 12s' },
      { name: 'Hash all renamed files',                      type: 'action',      status: 'completed', duration: '22s' },
      { name: 'Submit sample hash to VirusTotal',            type: 'action',      status: 'completed', duration: '8s' },
      { name: 'Known ransomware family?',                    type: 'decision',    status: 'completed', duration: '0s' },
      { name: 'Notify CISO + IR lead (PagerDuty)',           type: 'notify',      status: 'completed', duration: '1s' },
      { name: 'Create Jira P1 incident ticket',              type: 'action',      status: 'running',   duration: undefined },
      { name: 'Identify patient zero (human task)',          type: 'human',       status: 'idle',      duration: undefined },
      { name: 'Recovery plan execution',                     type: 'sub-playbook',status: 'idle',      duration: undefined },
    ],
  },
  {
    id: 'pb-002', name: 'Phishing Email Response', trigger: 'Mail gateway alert',
    description: 'Automated triage, quarantine, and user notification for detected phishing emails.',
    runs: 284, successRate: 97, avgTime: '2m 14s', lastRun: '12m ago', status: 'completed', category: 'Email',
    steps: [
      { name: 'Extract email headers & attachments',        type: 'check',    status: 'completed', duration: '1s' },
      { name: 'Check URLs against threat intel feeds',      type: 'check',    status: 'completed', duration: '4s' },
      { name: 'Submit attachment hash to VirusTotal',       type: 'action',   status: 'completed', duration: '6s' },
      { name: 'Malicious?',                                 type: 'decision', status: 'completed', duration: '0s' },
      { name: 'Quarantine email across all mailboxes',      type: 'action',   status: 'completed', duration: '12s' },
      { name: 'Block sender domain at gateway',             type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Notify affected users',                      type: 'notify',   status: 'completed', duration: '3s' },
      { name: 'Create SIEM investigation case',             type: 'action',   status: 'completed', duration: '1s' },
    ],
  },
  {
    id: 'pb-003', name: 'Account Compromise Response', trigger: 'Impossible travel / MFA fatigue',
    description: 'Automated account lockout, session revocation, and credential reset on suspected identity compromise.',
    runs: 41, successRate: 95, avgTime: '3m 55s', lastRun: '1h 40m ago', status: 'completed', category: 'Identity',
    steps: [
      { name: 'Correlate impossible travel events',         type: 'check',    status: 'completed', duration: '2s' },
      { name: 'Terminate all active user sessions (Okta)',  type: 'action',   status: 'completed', duration: '4s' },
      { name: 'Check recent auth log for other anomalies',  type: 'check',    status: 'completed', duration: '8s' },
      { name: 'High confidence compromise?',                type: 'decision', status: 'completed', duration: '0s' },
      { name: 'Force password reset (OOB notification)',    type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Disable FIDO2 hardware tokens',              type: 'action',   status: 'completed', duration: '1s' },
      { name: 'Notify user and manager via secure channel', type: 'notify',   status: 'completed', duration: '2s' },
      { name: 'Analyst interview + re-enrollment (human)',  type: 'human',    status: 'completed', duration: '45m' },
    ],
  },
  {
    id: 'pb-004', name: 'Cloud Privilege Escalation', trigger: 'CloudTrail: attach admin policy',
    description: 'Detect and automatically remediate IAM privilege escalation events in AWS/Azure.',
    runs: 12, successRate: 100, avgTime: '1m 42s', lastRun: '1h 10m ago', status: 'completed', category: 'Cloud',
    steps: [
      { name: 'Parse CloudTrail event details',             type: 'check',    status: 'completed', duration: '1s' },
      { name: 'Is this an authorized deployment action?',   type: 'decision', status: 'completed', duration: '0s' },
      { name: 'Detach escalated IAM policy via API',        type: 'action',   status: 'completed', duration: '3s' },
      { name: 'Export CloudTrail actions during window',    type: 'action',   status: 'completed', duration: '12s' },
      { name: 'Check for data access during escalation',   type: 'check',    status: 'completed', duration: '15s' },
      { name: 'Create Jira ticket for IAM policy review',  type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Notify cloud security team',                 type: 'notify',   status: 'completed', duration: '1s' },
    ],
  },
  {
    id: 'pb-005', name: 'C2 Beacon Containment', trigger: 'DNS: known C2 domain',
    description: 'Isolate and investigate hosts exhibiting C2 beacon behavior.',
    runs: 33, successRate: 91, avgTime: '5m 20s', lastRun: '3h ago', status: 'idle', category: 'Network',
    steps: [
      { name: 'Verify C2 domain in TI feeds',               type: 'check',    status: 'idle' },
      { name: 'Identify affected hosts via DNS logs',        type: 'check',    status: 'idle' },
      { name: 'Confidence > 90%?',                          type: 'decision', status: 'idle' },
      { name: 'Isolate host via EDR',                       type: 'action',   status: 'idle' },
      { name: 'Block domain/IP on all firewalls',           type: 'action',   status: 'idle' },
      { name: 'Extract process responsible for DNS query',  type: 'check',    status: 'idle' },
      { name: 'Submit to sandbox for full analysis',        type: 'action',   status: 'idle' },
      { name: 'Analyst review of process tree (human)',     type: 'human',    status: 'idle' },
    ],
  },
]

/* ── Metrics (offline fallback only; replaced by live /soar/metrics) ─ */
const SOAR_METRICS = {
  openCases: 5,
  criticalOpen: 1,
  mttr: '2h 17m',
  mttrTrendPct: null as number | null,
  automationRate: 73,
  automationTrendPp: null as number | null,
  timeSavedMonth: 847,
  runsMonth: 312,
  totalRuns: 1243,
  playbooksToday: 1243,
  avgPlaybookTime: '3m 08s',
  casesClosedWeek: 28,
}

/* Format a minutes value as "Xm" or "Hh MMm" for case-level MTTR display. */
function fmtMinsShort(minutes: number): string {
  const m = Math.round(minutes)
  if (m < 60) return `${m}m`
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`
}

/* Format a seconds value as "Xs" or "Mm SSs" for per-run timing display. */
function fmtSecsShort(secs: number): string {
  const s = Math.round(secs)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`
}

/* ── Helpers ──────────────────────────────────────────────────────── */
const SEV_STYLE: Record<Severity, string> = {
  critical: 'text-magenta border-magenta/30 bg-magenta/10',
  high:     'text-threat  border-threat/30  bg-threat/10',
  medium:   'text-amber   border-amber/30   bg-amber/10',
  low:      'text-safe    border-safe/30    bg-safe/10',
}

const STATUS_STYLE: Record<CaseStatus, { label: string; color: string }> = {
  'new':         { label: 'New',         color: 'text-magenta' },
  'assigned':    { label: 'Assigned',    color: 'text-amber' },
  'in-progress': { label: 'In Progress', color: 'text-violet' },
  'pending':     { label: 'Pending',     color: 'text-ink-400' },
  'resolved':    { label: 'Resolved',    color: 'text-safe' },
  'closed':      { label: 'Closed',      color: 'text-ink-600' },
}

const STEP_ICON: Record<StepType, React.ComponentType<any>> = {
  check:          Shield,
  action:         Zap,
  decision:       GitBranch,
  notify:         MessageSquare,
  human:          User,
  'sub-playbook': Activity,
}

const STEP_COLOR: Record<StepType, string> = {
  check:          tk('teal'),
  action:         tk('violet'),
  decision:       tk('amber'),
  notify:         tk('safe'),
  human:          tk('threat'),
  'sub-playbook': tk('magenta'),
}

// War-room timestamps arrive as ISO strings from the API (or HH:MM:SS from
// optimistic local entries). Render both as a compact clock time.
function fmtWarRoomTs(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

function slaPercent(created: string, slaHours: number): number {
  const now = Date.parse('2024-11-12T16:00:00Z')
  const start = new Date(created).getTime()
  const deadline = start + slaHours * 3600 * 1000
  const elapsed = now - start
  const total = deadline - start
  return Math.min(100, Math.max(0, (elapsed / total) * 100))
}

function slaLabel(created: string, slaHours: number): string {
  const now = Date.parse('2024-11-12T16:00:00Z')
  const deadline = new Date(created).getTime() + slaHours * 3600 * 1000
  const left = deadline - now
  if (left <= 0) return 'SLA BREACHED'
  const h = Math.floor(left / 3600000)
  const m = Math.floor((left % 3600000) / 60000)
  return h > 0 ? `${h}h ${m}m left` : `${m}m left`
}

/* ── Case detail panel ────────────────────────────────────────────── */
function CaseDetail({ c, onClose, simplified }: { c: CaseRecord; onClose: () => void; simplified?: boolean }) {
  const [tab, setTab] = useState<'overview' | 'warroom' | 'tasks' | 'evidence'>('overview')
  const [tasks, setTasks] = useState(c.tasks)
  const [warRoom, setWarRoom] = useState(c.warRoom)
  const [evidence, setEvidence] = useState(c.evidence)
  const [note, setNote] = useState('')
  const [related, setRelated] = useState<CaseRelated | null>(null)
  useEffect(() => {
    fetchCaseRelated(c.id).then(setRelated).catch(() => {})
  }, [c.id])
  const st = STATUS_STYLE[c.status]
  const detailTabs = simplified
    ? (['overview', 'tasks'] as const)
    : (['overview', 'warroom', 'tasks', 'evidence'] as const)

  // Advance a task through pending → in-progress → done on click.
  // Optimistic local update, persisted to the API, rolled back on failure.
  function cycleTask(id: string) {
    const task = tasks.find((t) => t.id === id)
    if (!task) return
    const next = task.status === 'done' ? 'pending' : task.status === 'in-progress' ? 'done' : 'in-progress'
    setTasks((prev) => prev.map((t) => (t.id === id ? { ...t, status: next as typeof t.status } : t)))
    patchCaseTask(c.id, id, { status: next }).catch(() => {
      setTasks((prev) => prev.map((t) => (t.id === id ? { ...t, status: task.status } : t)))
    })
  }

  function addNote() {
    const text = note.trim()
    if (!text) return
    const ts = new Date().toISOString()
    setWarRoom((prev) => [...prev, { ts, actor: 'you', type: 'manual', content: text }])
    setNote('')
    addCaseNote(c.id, text).then((updated) => {
      if (updated?.warRoom) setWarRoom(updated.warRoom as typeof warRoom)
    }).catch(() => {})  // keep the optimistic entry when the API is unreachable
  }

  const doneCount = tasks.filter((t) => t.status === 'done').length

  return (
    <motion.div
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 280, damping: 28 }}
      className="fixed right-0 top-0 bottom-0 z-[60] w-full max-w-xl flex flex-col bg-surface border-l border-white/8 shadow-2xl overflow-hidden"
    >
      {/* Header */}
      <div className="p-4 border-b border-white/8">
        <div className="flex items-start gap-3">
          <span className={cn('mt-0.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase border shrink-0', SEV_STYLE[c.severity])}>
            {c.severity}
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-white leading-snug">{c.title}</p>
            <div className="flex items-center gap-3 mt-1 text-[10px] text-ink-500">
              <span className="font-mono text-violet">{c.id}</span>
              <span>·</span>
              <span className={st.color}>{st.label}</span>
              <span>·</span>
              <span>{c.type}</span>
              <span>·</span>
              <span>{c.alertCount} alert{c.alertCount !== 1 ? 's' : ''}</span>
            </div>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <ReportButton kind="incident" label={`Post-Incident · ${c.id}`} caseId={c.id} />
            <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* SLA bar */}
        <div className="mt-3">
          {(() => {
            const pct = slaPercent(c.created, c.slaHours)
            const label = slaLabel(c.created, c.slaHours)
            const barColor = pct > 80 ? tk('magenta') : pct > 60 ? tk('amber') : tk('safe')
            return (
              <div>
                <div className="flex items-center justify-between text-[10px] mb-1">
                  <span className="text-ink-600">SLA ({c.slaHours}h target)</span>
                  <span style={{ color: barColor }} className="font-semibold">{label}</span>
                </div>
                <div className="h-1.5 bg-white/8 rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: barColor }} />
                </div>
              </div>
            )
          })()}
        </div>

        {/* Quick metadata */}
        <div className="flex items-center gap-3 mt-3 text-[10px] text-ink-500">
          <span className="flex items-center gap-1"><User className="w-3 h-3" />{c.owner ?? 'Unassigned'}</span>
          <span className="flex items-center gap-1"><Zap className="w-3 h-3" />{c.playbook}</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-4 px-4 border-b border-white/5 shrink-0">
        {detailTabs.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={cn('py-2.5 text-[11px] border-b-2 transition-colors capitalize',
              tab === t ? 'border-magenta text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}>
            {t === 'warroom' ? 'War Room' : t.charAt(0).toUpperCase() + t.slice(1)}
            {t === 'tasks' && ` (${c.tasks.filter(t => t.status !== 'done').length})`}
            {t === 'evidence' && ` (${c.evidence.length})`}
          </button>
        ))}
      </div>

      {/* keyed on the tab: switching replays a smooth fade-up enter */}
      <motion.div key={tab} variants={fadeInUp} initial="hidden" animate="show"
        className="flex-1 overflow-y-auto p-4 space-y-4">
        {tab === 'overview' && (
          <>
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2">Description</p>
              <p className="text-xs text-ink-300 leading-relaxed">{c.description}</p>
            </div>
            <div>
              <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2">Entities / Observables</p>
              <div className="space-y-1.5">
                {c.entities.map((e, i) => (
                  <div key={i} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5">
                    <span className="text-[10px] text-ink-600 w-20 shrink-0">{e.type}</span>
                    <span className="text-[11px] font-mono text-ink-200 truncate">{e.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Linked evidence - real cross-store linkage via the case entities */}
            {related && (related.alerts.length > 0 || related.runs.length > 0) && (
              <div>
                <p className="text-[10px] text-ink-600 uppercase tracking-widest mb-2">
                  Linked evidence
                  <span className="ml-2 normal-case tracking-normal text-ink-500">
                    {related.alerts.length} alerts · {related.iocs.length} IOCs · {related.runs.length} playbook runs
                  </span>
                </p>
                {related.techniques.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-2">
                    {related.techniques.slice(0, 6).map((t) => (
                      <span key={t.technique} className="text-[10px] px-2 py-0.5 rounded bg-violet/10 text-violet border border-violet/20 font-mono">
                        {t.technique} ×{t.count}
                      </span>
                    ))}
                  </div>
                )}
                <div className="space-y-1.5">
                  {related.alerts.slice(0, 5).map((a) => (
                    <a key={a.id} href={`/dashboard/siem?q=${encodeURIComponent(a.srcIp ?? a.hostname ?? a.title)}`}
                      className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5 hover:border-white/15 transition-colors">
                      <span className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ background: { critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe') }[a.severity] ?? tk('violet') }} />
                      <span className="text-[11px] text-ink-200 truncate flex-1">{a.title}</span>
                      {a.mitreTechId && <span className="text-[9px] font-mono text-violet shrink-0">{a.mitreTechId}</span>}
                      <span className="text-[9px] text-ink-600 shrink-0 capitalize">{a.status}</span>
                    </a>
                  ))}
                  {related.runs.slice(0, 3).map((r) => (
                    <div key={r.id} className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-surface-2/40 border border-white/5">
                      <Zap className="w-3 h-3 text-safe shrink-0" />
                      <span className="text-[11px] text-ink-300 truncate flex-1">{r.playbookName}</span>
                      <span className="text-[9px] text-ink-600 shrink-0">{r.trigger} · {r.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {tab === 'warroom' && (
          <div className="space-y-3">
            {warRoom.map((entry, i) => (
              <div key={i} className={cn('flex gap-3 text-xs',
                entry.type === 'auto' ? 'opacity-80' : '')}>
                <div className="shrink-0 w-12 text-[10px] text-ink-600 font-mono pt-0.5">{fmtWarRoomTs(entry.ts)}</div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={cn('text-[10px] font-semibold',
                      entry.type === 'system' ? 'text-violet' :
                      entry.type === 'auto' ? 'text-safe' : 'text-amber'
                    )}>{entry.actor}</span>
                    <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border',
                      entry.type === 'system' ? 'border-violet/20 text-violet/70 bg-violet/5' :
                      entry.type === 'auto' ? 'border-safe/20 text-safe/70 bg-safe/5' :
                      'border-amber/20 text-amber/70 bg-amber/5')}>
                      {entry.type === 'auto' ? 'automated' : entry.type === 'system' ? 'system' : 'analyst'}
                    </span>
                  </div>
                  <p className="text-ink-300 text-[11px] leading-relaxed">{entry.content}</p>
                </div>
              </div>
            ))}
            <div className="pt-2 border-t border-white/5 flex gap-2">
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') addNote() }}
                placeholder="Add investigation note…"
                className="flex-1 bg-surface-2 border border-white/8 rounded-lg px-3 py-2 text-xs text-ink-200 placeholder-ink-600 focus:outline-none focus:border-white/20"
              />
              <button onClick={addNote}
                className="px-3 py-2 rounded-lg text-xs bg-magenta/15 border border-magenta/30 text-magenta hover:bg-magenta/25 transition-colors shrink-0">
                Post
              </button>
            </div>
          </div>
        )}

        {tab === 'tasks' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between mb-1">
              <p className="text-[10px] text-ink-600">{doneCount} / {tasks.length} tasks complete · click a task to advance it</p>
              <div className="w-24 h-1 bg-white/8 rounded-full overflow-hidden">
                <div className="h-full bg-safe rounded-full transition-all" style={{ width: `${(doneCount / tasks.length) * 100}%` }} />
              </div>
            </div>
            {Object.entries(
              tasks.reduce((acc, t) => {
                if (!acc[t.phase]) acc[t.phase] = []
                acc[t.phase].push(t)
                return acc
              }, {} as Record<string, typeof tasks>)
            ).map(([phase, phaseTasks]) => (
              <div key={phase}>
                <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-1.5">{phase}</p>
                <div className="space-y-1">
                  {phaseTasks.map((task) => (
                    <button key={task.id} onClick={() => cycleTask(task.id)} className={cn(
                      'w-full text-left flex items-center gap-3 px-3 py-2.5 rounded-lg border transition-colors hover:border-white/20',
                      task.status === 'done' ? 'border-safe/15 bg-safe/5' :
                      task.status === 'in-progress' ? 'border-violet/20 bg-violet/5' :
                      'border-white/5 bg-surface-2/30',
                    )}>
                      <div className={cn('w-4 h-4 rounded-full border flex items-center justify-center shrink-0',
                        task.status === 'done' ? 'border-safe bg-safe/20' :
                        task.status === 'in-progress' ? 'border-violet bg-violet/20' :
                        'border-ink-700')}>
                        {task.status === 'done' && <CheckCircle className="w-3 h-3 text-safe" />}
                        {task.status === 'in-progress' && <Circle className="w-2.5 h-2.5 text-violet animate-pulse" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className={cn('text-xs', task.status === 'done' ? 'text-ink-600 line-through' : 'text-ink-200')}>{task.name}</p>
                        {task.assignee && <p className="text-[10px] text-ink-600 mt-0.5">{task.assignee}</p>}
                        {task.notes && <p className="text-[10px] text-safe/70 mt-0.5">{task.notes}</p>}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {tab === 'evidence' && (
          <div>
            {evidence.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-ink-600 text-xs">
                <Paperclip className="w-5 h-5 mb-2 opacity-30" />
                No evidence collected yet
              </div>
            ) : (
              <div className="space-y-2">
                {evidence.map((e, i) => (
                  <div key={i} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-surface-2/40 border border-white/5">
                    <FileText className="w-4 h-4 text-ink-500 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono text-ink-200 truncate">{e.name}</p>
                      <p className="text-[10px] text-ink-600 mt-0.5">
                        {e.type} · Added {e.added ?? (e.ts ? new Date(e.ts).toLocaleString() : '-')} by {e.by ?? e.addedBy ?? '-'}
                      </p>
                      {e.sha256 && (
                        <p className="text-[10px] font-mono text-ink-700 mt-0.5 truncate" title={`SHA-256 ${e.sha256}`}>
                          sha256:{e.sha256.slice(0, 16)}…
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-2">
              <button
                onClick={() => {
                  const name = window.prompt('Evidence name (e.g. "pcap extract", "memory dump ref"):')
                  if (!name?.trim()) return
                  const content = window.prompt('Content / reference (hashed for chain-of-custody):') ?? ''
                  addCaseEvidence(c.id, { name: name.trim(), type: 'file', content })
                    .then((updated) => {
                      const ev = (updated as unknown as CaseRecord)?.evidence
                      if (ev) setEvidence(ev)
                    })
                    .catch(() => {})
                }}
                className="flex items-center justify-center gap-2 py-2 rounded-lg border border-dashed border-white/15 text-xs text-ink-500 hover:text-ink-200 hover:border-white/25 transition-colors">
                <Paperclip className="w-3.5 h-3.5" /> Add evidence
              </button>
              <button
                onClick={() => {
                  exportEvidenceBundle(c.id).then((signed) => {
                    const blob = new Blob([JSON.stringify(signed, null, 2)], { type: 'application/json' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = `evidence-bundle-${c.id}.json`
                    a.click()
                    URL.revokeObjectURL(url)
                  }).catch(() => {})
                }}
                title="Download the case's full record as an HMAC-signed, tamper-evident JSON bundle"
                className="flex items-center justify-center gap-2 py-2 rounded-lg border border-safe/25 bg-safe/5 text-xs text-safe hover:bg-safe/10 transition-colors">
                <Lock className="w-3.5 h-3.5" /> Export signed bundle
              </button>
            </div>
          </div>
        )}
      </motion.div>
    </motion.div>
  )
}

/* ── Normal Mode: Case Kanban Board ──────────────────────────────── */
function NormalSOAR({ cases: casesData, casesPending = false }: { cases: CaseRecord[]; casesPending?: boolean }) {
  const CASES = casesData
  const SEV_COLOR: Record<string, string> = {
    critical: tk('magenta'), high: tk('threat'), medium: tk('amber'), low: tk('safe'),
  }
  const COLS = [
    { id: 'todo',       label: 'New',         statuses: ['new'],                                  color: tk('amber'), border: 'border-amber/25',   header: 'bg-amber/10 text-amber'   },
    { id: 'inprogress', label: 'In Progress',  statuses: ['assigned', 'in-progress', 'pending'],  color: tk('violet'), border: 'border-violet/25',  header: 'bg-violet/10 text-violet' },
    { id: 'done',       label: 'Resolved',     statuses: ['resolved', 'closed'],                  color: tk('safe'), border: 'border-safe/25',    header: 'bg-safe/10 text-safe'     },
  ]
  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between shrink-0">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Case Board</h1>
          <p className="text-xs text-ink-500 mt-0.5">
            {CASES.length} cases · track progress at a glance
          </p>
        </div>
        <span className="flex items-center gap-1.5 text-[10px] px-2.5 py-1.5 rounded-full border border-safe/25 bg-safe/10 text-safe font-medium self-start">
          <Eye className="w-3 h-3" /> Normal mode
        </span>
      </div>

      {/* Board */}
      <div className="flex-1 overflow-y-auto p-6 space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {COLS.map(({ id, label, statuses, color, border, header }) => {
            const colCases = CASES.filter((c) => statuses.includes(c.status))
            return (
              <div key={id} className={cn('glass border rounded-xl overflow-hidden flex flex-col', border)}>
                <div className={cn('flex items-center justify-between px-4 py-3', header)}>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full" style={{ background: color }} />
                    <span className="text-sm font-semibold">{label}</span>
                  </div>
                  <span className="text-sm font-bold">{colCases.length}</span>
                </div>
                <div className="flex-1 overflow-y-auto p-3 space-y-2.5 min-h-[160px]">
                  {colCases.length === 0 ? (
                    casesPending
                      ? <SkeletonRows rows={3} className="px-0" />
                      : <div className="py-10 text-center text-xs text-ink-600">No cases</div>
                  ) : (
                    colCases.map((c) => (
                      <motion.div
                        key={c.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="glass border border-white/5 rounded-lg p-3.5 space-y-2 hover:border-white/10 transition-colors group"
                      >
                        <div className="flex items-start gap-2">
                          <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: SEV_COLOR[c.severity] }} />
                          <p className="text-xs text-ink-100 leading-snug flex-1 group-hover:text-white transition-colors">{c.title}</p>
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-ink-500 font-mono flex-wrap">
                          <span>{c.id}</span>
                          <span>·</span>
                          <span className="text-ink-600">{c.type}</span>
                          {c.owner && <><span>·</span><span>{c.owner}</span></>}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase"
                            style={{ background: `${SEV_COLOR[c.severity]}1a`, color: SEV_COLOR[c.severity] }}>
                            {c.severity}
                          </span>
                          <span className="text-[10px] text-ink-600">
                            {c.alertCount} alert{c.alertCount !== 1 ? 's' : ''}
                          </span>
                          <span className="text-[10px] text-ink-600 ml-auto">
                            SLA {c.slaHours}h
                          </span>
                        </div>
                      </motion.div>
                    ))
                  )}
                </div>
              </div>
            )
          })}
        </div>

        {/* Power mode CTA */}
        <div className="glass border border-white/5 rounded-xl p-4 flex items-center gap-4">
          <div className="p-2 rounded-lg bg-magenta/10 shrink-0">
            <Zap className="w-4 h-4 text-magenta" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-white">Power User mode shows playbooks, automation analytics & war rooms</p>
            <p className="text-[10px] text-ink-400 mt-0.5">Full case investigation, evidence chain, SOAR playbook editor, and automation ROI metrics</p>
          </div>
          <span className="text-[10px] text-ink-500 shrink-0 hidden sm:block">Toggle in top bar →</span>
        </div>
      </div>
    </div>
  )
}

/* ── New case modal ───────────────────────────────────────────────── */
function NewCaseModal({ onClose, onCreate }: {
  onClose: () => void
  onCreate: (body: { title: string; severity: string; type: string; description: string }) => Promise<void>
}) {
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [caseType, setCaseType] = useState('Investigation')
  const [description, setDescription] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!title.trim() || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await onCreate({ title: title.trim(), severity, type: caseType, description: description.trim() })
      onClose()
    } catch {
      setError('Could not create the case. Is the dashboard API running?')
      setSubmitting(false)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 backdrop-blur-sm p-6"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-2xl border border-white/10 bg-surface p-6"
      >
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-magenta/15"><Zap className="w-4 h-4 text-magenta" /></div>
            <h2 className="text-sm font-semibold text-white">New Case</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Title</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Suspicious lateral movement from jump host"
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 placeholder-ink-600" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">Type</label>
              <select value={caseType} onChange={(e) => setCaseType(e.target.value)}
                className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                {['Investigation', 'Phishing', 'Malware', 'Ransomware', 'Account Compromise',
                  'Data Exfiltration', 'Insider Threat', 'Web Attack', 'Misconfiguration'].map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-300 mb-1.5">Description (optional)</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3}
              placeholder="What happened, which assets are affected…"
              className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 placeholder-ink-600 resize-none" />
          </div>

          {error && <p className="px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert">{error}</p>}

          <button type="submit" disabled={!title.trim() || submitting}
            className={cn('w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold transition-all',
              title.trim() && !submitting ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {submitting ? 'Creating…' : 'Create Case'}
          </button>
        </form>
      </motion.div>
    </motion.div>
  )
}

/* ── Main page ────────────────────────────────────────────────────── */
export default function SOARPage() {
  const [mode] = useExperienceMode()
  const isNormal = mode === 'normal'
  const [tab, setTab] = useState<'cases' | 'playbooks' | 'metrics'>('cases')
  // Empty until the API answers — cases/playbooks are the API's to fill. An
  // empty case board on a real deployment is honest; the demo constants are an
  // offline-only fallback (loadedRef gates them to a first-load failure).
  const [cases, setCases] = useState<CaseRecord[]>([])
  // First answer pending → the board shows skeleton rows, not "No cases"
  const [casesPending, setCasesPending] = useState(true)
  const [selectedCase, setSelectedCase] = useState<CaseRecord | null>(null)
  const [selectedPBId, setSelectedPBId] = useState<string | null>(null)
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const loadedRef = useRef({ cases: false, playbooks: false })
  const [soarApi, setSoarApi] = useState<SoarMetrics | null>(null)
  const [showNewCase, setShowNewCase] = useState(false)
  const selectedPB = playbooks.find((p) => p.id === selectedPBId) ?? null

  async function handleCreateCase(body: { title: string; severity: string; type: string; description: string }) {
    const created = await createCase(body)
    setCases((prev) => [created as unknown as CaseRecord, ...prev])
  }

  // Load from API
  useEffect(() => {
    fetchCases()
      .then((data) => { setCases(data as unknown as CaseRecord[]); loadedRef.current.cases = true })
      .catch(() => { if (!loadedRef.current.cases) setCases(CASES) })
      .finally(() => setCasesPending(false))
    fetchPlaybooks()
      .then((data) => { setPlaybooks(data as unknown as Playbook[]); loadedRef.current.playbooks = true })
      .catch(() => { if (!loadedRef.current.playbooks) setPlaybooks(PLAYBOOKS) })
    fetchSoarMetrics().then(setSoarApi).catch(() => {})
  }, [])

  // Prefer live SOAR metrics; fall back to static demo values. Trends are
  // real week-over-week movements from the backend (null = no baseline yet).
  const metrics = useMemo(() => {
    if (!soarApi) return SOAR_METRICS
    return {
      ...SOAR_METRICS,
      openCases: soarApi.openCases,
      criticalOpen: soarApi.criticalOpen,
      mttr: fmtMinsShort(soarApi.mttr),
      mttrTrendPct: soarApi.mttrTrendPct,
      automationRate: Math.round(soarApi.automationRate),
      automationTrendPp: soarApi.automationTrendPp,
      timeSavedMonth: Math.round(soarApi.timeSavedMonth),
      runsMonth: soarApi.runsMonth,
      totalRuns: soarApi.totalRuns,
      playbooksToday: soarApi.playbooksToday,
      avgPlaybookTime: fmtSecsShort(soarApi.avgPlaybookTime),
      casesClosedWeek: soarApi.casesClosedWeek,
    }
  }, [soarApi])

  useEffect(() => { if (isNormal && tab !== 'cases') setTab('cases') }, [isNormal, tab])

  function simulateRun(id: string) {
    const pb = playbooks.find((p) => p.id === id)
    if (!pb || pb.status === 'running') return
    setSelectedPBId(id)
    // Reset steps and mark running while the REAL server-side execution runs.
    setPlaybooks((prev) => prev.map((p) => p.id !== id ? p : {
      ...p, status: 'running',
      steps: p.steps.map((s) => ({ ...s, status: 'running' as StepStatus, duration: undefined })),
    }))
    // Execute for real; the timeline then shows each step's ACTUAL outcome
    // from the run record (success/failed/skipped/awaiting approval) - no
    // fabricated durations.
    apiRunPlaybook(id)
      .then((updated) => {
        const run = (updated as { run?: { status: string; steps: Array<{ idx: number; status: string }> } }).run
        const mapStatus = (s?: string): StepStatus =>
          s === 'success' ? 'completed' : s === 'failed' ? 'failed'
          : s === 'skipped' ? 'skipped' : s === 'pending-approval' ? 'running' : 'completed'
        setPlaybooks((prev) => prev.map((p) => p.id !== id ? p : {
          ...p,
          runs: updated.runs ?? p.runs,
          status: run?.status === 'awaiting-approval' ? 'running' : 'completed',
          steps: p.steps.map((s, j) => ({
            ...s,
            status: mapStatus(run?.steps?.find((r) => r.idx === j)?.status),
          })),
        }))
      })
      .catch(() => {
        // API unreachable - reflect failure honestly instead of pretending success.
        setPlaybooks((prev) => prev.map((p) => p.id !== id ? p : {
          ...p, status: 'failed',
          steps: p.steps.map((s) => ({ ...s, status: 'failed' as StepStatus })),
        }))
      })
  }

  if (isNormal) return <NormalSOAR cases={cases} casesPending={casesPending} />

  return (
    <div className="flex h-full overflow-hidden">
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Page header */}
        <div className="px-6 py-4 border-b border-white/5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between shrink-0">
          <div>
            <h1 className="font-display text-xl font-bold text-white">Security Orchestration, Automation & Response</h1>
            <p className="text-xs text-ink-500 mt-0.5">
              <span className="text-magenta">{metrics.openCases} open cases</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span className="text-safe">{metrics.automationRate}% automation rate</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span>MTTR {metrics.mttr}</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span className="text-safe">{metrics.timeSavedMonth}h saved this month</span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <ReportButton kind="soar" label="SOAR Incident Response" />
            <button
              onClick={() => setShowNewCase(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-magenta/10 border border-magenta/25 text-magenta hover:bg-magenta/15 transition-colors">
              <Zap className="w-3.5 h-3.5" /> New Case
            </button>
          </div>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-0 border-b border-white/5 shrink-0">
          {[
            { label: 'Open Cases',           value: <AnimatedNumber value={metrics.openCases} />, sub: `${metrics.criticalOpen} critical`, color: 'text-magenta', trend: null },
            // Real week-over-week movement; "no baseline" until a prior week exists.
            { label: 'MTTR',                  value: metrics.mttr,
              sub: metrics.mttrTrendPct != null ? `${metrics.mttrTrendPct > 0 ? '+' : ''}${metrics.mttrTrendPct}% vs prior week` : 'no prior-week baseline',
              color: 'text-safe',    trend: metrics.mttrTrendPct == null ? null : metrics.mttrTrendPct < 0 ? 'down' : 'up' },
            { label: 'Automation Rate',       value: <><AnimatedNumber value={metrics.automationRate} />%</>,
              sub: metrics.automationTrendPp != null ? `${metrics.automationTrendPp > 0 ? '+' : ''}${metrics.automationTrendPp}pp vs prior week` : 'no prior-week baseline',
              color: 'text-violet', trend: metrics.automationTrendPp == null ? null : metrics.automationTrendPp > 0 ? 'up' : 'down' },
            { label: 'Time Saved (month)',    value: <><AnimatedNumber value={metrics.timeSavedMonth} />h</>, sub: `from ${metrics.runsMonth.toLocaleString()} runs this month`, color: 'text-amber', trend: null },
            { label: 'Playbooks Today',       value: <AnimatedNumber value={metrics.playbooksToday} />, sub: `avg ${metrics.avgPlaybookTime}/run`, color: 'text-white',   trend: null },
          ].map((k) => (
            <div key={k.label} className="px-4 py-3 border-r border-white/5 last:border-r-0">
              <p className="text-[10px] text-ink-600 uppercase tracking-wide">{k.label}</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                <p className={cn('text-lg font-bold', k.color)}>{k.value}</p>
                {k.trend === 'up' && <TrendingUp className="w-3 h-3 text-safe" />}
                {k.trend === 'down' && <TrendingDown className="w-3 h-3 text-safe" />}
              </div>
              <p className="text-[10px] text-safe/70 mt-0.5">{k.sub}</p>
            </div>
          ))}
        </div>

        {/* Tab bar */}
        <div className="flex gap-6 px-6 border-b border-white/5 shrink-0 items-center">
          {([
            ['cases',     'Case Queue',  FileText],
            ['playbooks', 'Playbooks',   Zap],
            ['metrics',   'Metrics',     BarChart2],
          ] as const)
            .filter(([id]) => !isNormal || id === 'cases')
            .map(([id, label, Icon]) => (
            <button key={id} onClick={() => setTab(id as typeof tab)}
              className={cn('flex items-center gap-2 py-3 text-xs border-b-2 transition-colors',
                tab === id ? 'border-magenta text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}>
              <Icon className="w-3.5 h-3.5" />
              {label}
              {id === 'cases' && (
                <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-magenta/15 text-magenta border border-magenta/25">
                  {metrics.openCases}
                </span>
              )}
            </button>
          ))}
          <span className={cn('ml-auto flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-full border',
            isNormal ? 'border-safe/25 bg-safe/10 text-safe' : 'border-magenta/25 bg-magenta/10 text-magenta')}>
            {isNormal ? <User className="w-3 h-3" /> : <Zap className="w-3 h-3" />}
            {isNormal ? 'Normal mode' : 'Power User'}
          </span>
        </div>

        {/* keyed on the tab: switching replays a smooth fade-up enter */}
        <motion.div key={tab} variants={fadeInUp} initial="hidden" animate="show"
          className="flex-1 overflow-hidden">
          {/* ── CASE QUEUE ─────────────────────────────────────────── */}
          {tab === 'cases' && (
            <div className="flex flex-col h-full">
              <div className={cn(CASE_GRID, 'px-4 py-2 border-b border-white/5 text-[10px] text-ink-600 uppercase tracking-wide shrink-0')}>
                <span />
                <span>Case / Type</span>
                <span className="hidden md:block">Status</span>
                <span className="hidden lg:block">Owner</span>
                <span>Playbook</span>
                <span>SLA</span>
                <span>Created</span>
              </div>
              <div className="flex-1 overflow-y-auto">
                {cases.length === 0 && casesPending && <SkeletonRows rows={8} />}
                {cases.length === 0 && !casesPending && (
                  <div className="flex flex-col items-center justify-center h-32 text-xs text-ink-600">
                    No cases yet — correlated alerts escalate here automatically
                  </div>
                )}
                {cases.map((c, i) => (
                  <CaseRow key={c.id} c={c} idx={i} selected={selectedCase?.id === c.id}
                    onClick={() => setSelectedCase((prev) => prev?.id === c.id ? null : c)} />
                ))}
              </div>
            </div>
          )}

          {/* ── PLAYBOOKS ───────────────────────────────────────────── */}
          {tab === 'playbooks' && (
            <div className="flex h-full overflow-hidden">
              {/* Playbook list */}
              <div className={cn('flex-1 overflow-y-auto p-4 grid gap-3 content-start', selectedPB ? 'hidden lg:grid' : 'grid')}>
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                  {playbooks.map((pb) => (
                    <PlaybookCard key={pb.id} pb={pb} selected={selectedPBId === pb.id}
                      onClick={() => setSelectedPBId((prev) => prev === pb.id ? null : pb.id)}
                      onRun={(e) => { e.stopPropagation(); simulateRun(pb.id) }} />
                  ))}
                </div>
              </div>

              {/* Playbook step detail */}
              {selectedPB && (
                <div className="w-full lg:w-80 xl:w-96 border-l border-white/5 flex flex-col overflow-hidden shrink-0">
                  <div className="p-4 border-b border-white/5 flex items-center justify-between">
                    <p className="text-xs font-semibold text-white truncate">{selectedPB.name}</p>
                    <button onClick={() => setSelectedPBId(null)} className="p-1 text-ink-500 hover:text-white">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <div className="flex-1 overflow-y-auto p-4">
                    <p className="text-[11px] text-ink-400 mb-4">{selectedPB.description}</p>
                    {/* Step flow */}
                    <div className="relative space-y-2">
                      {selectedPB.steps.map((step, i) => {
                        const Icon = STEP_ICON[step.type]
                        const color = STEP_COLOR[step.type]
                        return (
                          <div key={i} className="flex gap-3">
                            {/* Connector line */}
                            <div className="flex flex-col items-center">
                              <div className={cn('w-6 h-6 rounded-full flex items-center justify-center shrink-0',
                                step.status === 'completed' ? 'bg-safe/20 border border-safe/40' :
                                step.status === 'running'   ? 'bg-violet/20 border border-violet/40' :
                                step.status === 'failed'    ? 'bg-threat/20 border border-threat/40' :
                                'bg-surface-2 border border-white/10')}>
                                {step.status === 'completed' ? (
                                  <CheckCircle className="w-3 h-3 text-safe" />
                                ) : step.status === 'running' ? (
                                  <RefreshCw className="w-3 h-3 text-violet animate-spin" />
                                ) : (
                                  <Icon className="w-3 h-3" style={{ color: step.status === 'idle' ? '#4a4463' : color }} />
                                )}
                              </div>
                              {i < selectedPB.steps.length - 1 && (
                                <div className={cn('w-0.5 flex-1 min-h-3 mt-1',
                                  step.status === 'completed' ? 'bg-safe/30' : 'bg-white/8')} />
                              )}
                            </div>
                            <div className="pb-3">
                              <p className={cn('text-[11px] leading-snug',
                                step.status === 'completed' ? 'text-ink-400' :
                                step.status === 'running'   ? 'text-white' :
                                'text-ink-600')}>{step.name}</p>
                              <div className="flex items-center gap-2 mt-0.5">
                                <span className="text-[9px] px-1 py-0.5 rounded" style={{ background: color + '20', color }}>
                                  {step.type}
                                </span>
                                {step.duration && (
                                  <span className="text-[9px] text-ink-700">{step.duration}</span>
                                )}
                              </div>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── METRICS ────────────────────────────────────────────── */}
          {tab === 'metrics' && (
            <div className="overflow-y-auto h-full p-6 space-y-6">
              {/* Cases by type + automation donut row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                  <p className="text-xs font-semibold text-white mb-4">Cases by Type (Last 30 days)</p>
                  {(() => {
                    // Live derivation from the same case list the KPI table
                    // below uses (this block used to be a hardcoded sample —
                    // the last fabrication-sweep miss on this page).
                    const cutoff = Date.now() - 30 * 24 * 3600 * 1000
                    const counts = new Map<string, number>()
                    for (const c of cases) {
                      if (new Date(c.created).getTime() < cutoff) continue
                      const t = c.type?.trim() || 'Uncategorised'
                      counts.set(t, (counts.get(t) ?? 0) + 1)
                    }
                    const palette = [tk('threat'), tk('magenta'), tk('amber'),
                                     tk('violet'), tk('safe'), tk('teal'), '#A78BFA']
                    const rows = [...counts.entries()]
                      .sort((a, b) => b[1] - a[1]).slice(0, 7)
                    const maxN = rows[0]?.[1] ?? 1
                    if (rows.length === 0) return (
                      <p className="text-[11px] text-ink-600 py-6 text-center">
                        No cases opened in the last 30 days.
                      </p>
                    )
                    return rows.map(([type, count], i) => (
                      <div key={type} className="flex items-center gap-3 mb-2">
                        <span className="text-[11px] text-ink-400 w-40 shrink-0 truncate" title={type}>{type}</span>
                        <div className="flex-1 h-2.5 bg-white/5 rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${(count / maxN) * 100}%` }}
                            transition={{ duration: 0.5, delay: i * 0.06 }}
                            className="h-full rounded-full"
                            style={{ background: palette[i % palette.length] }}
                          />
                        </div>
                        <span className="text-[11px] font-mono text-ink-500 w-8 text-right">{count}</span>
                      </div>
                    ))
                  })()}
                </div>

                <div className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                  <p className="text-xs font-semibold text-white mb-4">Automation Metrics</p>
                  <div className="space-y-4">
                    {[
                      { label: 'Playbook Executions', value: playbooks.reduce((s, p) => s + (p.runs || 0), 0).toLocaleString(), sub: `Across ${playbooks.length} playbooks`, color: 'text-white' },
                      { label: 'Automation Rate',     value: soarApi ? `${Math.round(soarApi.automationRate)}%` : '-', sub: 'of closed cases playbook-driven', color: 'text-safe' },
                      { label: 'Analyst Hours Saved', value: soarApi ? `${Math.round(soarApi.timeSavedMonth)}h` : '-', sub: 'this month, from run volume', color: 'text-violet' },
                      { label: 'Cases Closed (week)', value: soarApi ? String(soarApi.casesClosedWeek) : '-', sub: `${soarApi?.openCases ?? 0} still open`, color: 'text-amber' },
                      { label: 'Playbooks Run Today', value: soarApi ? String(soarApi.playbooksToday) : '-', sub: 'with a recorded run', color: 'text-ink-300' },
                    ].map((m) => (
                      <div key={m.label} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                        <p className="text-[11px] text-ink-500">{m.label}</p>
                        <div className="text-right">
                          <p className={cn('text-sm font-bold', m.color)}>{m.value}</p>
                          <p className="text-[10px] text-ink-700">{m.sub}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* KPI table - every row computed from the live API/case data */}
              <div className="bg-surface-2/40 rounded-xl border border-white/5">
                <div className="px-4 py-3 border-b border-white/5">
                  <p className="text-xs font-semibold text-white">SOAR KPI Summary</p>
                </div>
                <div className="divide-y divide-white/5">
                  {(() => {
                    const resolved = cases.filter((c) => ['resolved', 'closed'].includes(c.status)).length
                    const sla = soarApi && soarApi.openCases > 0
                      ? Math.round((1 - (soarApi.slaBreached ?? 0) / soarApi.openCases) * 100)
                      : soarApi ? 100 : null
                    const pbSuccess = playbooks.length
                      ? Math.round(playbooks.reduce((s, p) => s + (p.successRate <= 1 ? p.successRate * 100 : p.successRate), 0) / playbooks.length)
                      : null
                    const fmtMin = (m?: number) => m == null ? '-'
                      : m >= 60 ? `${Math.floor(m / 60)}h ${String(Math.round(m % 60)).padStart(2, '0')}m` : `${m.toFixed(1)}m`
                    return [
                    { metric: 'Mean Time to Respond (MTTR)', value: fmtMin(soarApi?.mttr), target: '< 4h',  status: soarApi && soarApi.mttr < 240 ? 'good' : 'warn' },
                    { metric: 'Cases Created',               value: String(cases.length),   target: '-',     status: 'good' },
                    { metric: 'Cases Resolved',              value: String(resolved),       target: '-',     status: 'good' },
                    { metric: 'SLA Compliance',              value: sla == null ? '-' : `${sla}%`, target: '> 95%', status: sla != null && sla >= 95 ? 'good' : 'warn' },
                    { metric: 'Automation Rate',             value: soarApi ? `${Math.round(soarApi.automationRate)}%` : '-', target: '> 60%', status: soarApi && soarApi.automationRate > 60 ? 'good' : 'warn' },
                    { metric: 'Playbook Success Rate',       value: pbSuccess == null ? '-' : `${pbSuccess}%`, target: '> 90%', status: pbSuccess != null && pbSuccess >= 90 ? 'good' : 'warn' },
                    { metric: 'Avg Playbook Execution Time', value: soarApi ? `${soarApi.avgPlaybookTime}s` : '-', target: '< 10m', status: 'good' },
                  ]})().map((row) => (
                    <div key={row.metric} className="grid grid-cols-3 px-4 py-2.5 text-xs">
                      <span className="text-ink-300">{row.metric}</span>
                      <span className={cn('font-mono', row.status === 'good' ? 'text-safe' : 'text-amber')}>{row.value}</span>
                      <span className="text-ink-600">Target: {row.target}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </motion.div>
      </div>

      {/* Case detail overlay */}
      <AnimatePresence>
        {selectedCase && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm"
              onClick={() => setSelectedCase(null)}
            />
            <CaseDetail key={selectedCase.id} c={selectedCase} onClose={() => setSelectedCase(null)} simplified={isNormal} />
          </>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showNewCase && (
          <NewCaseModal onClose={() => setShowNewCase(false)} onCreate={handleCreateCase} />
        )}
      </AnimatePresence>
    </div>
  )
}

/* ── Case table row ───────────────────────────────────────────────── */
function CaseRow({ c, idx, selected, onClick }: {
  c: CaseRecord; idx: number; selected: boolean; onClick: () => void
}) {
  const st = STATUS_STYLE[c.status]
  const pct = slaPercent(c.created, c.slaHours)
  const slaColor = pct > 80 ? tk('magenta') : pct > 60 ? tk('amber') : tk('safe')

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: idx * 0.04, duration: 0.25 }}
      onClick={onClick}
      className={cn(
        CASE_GRID, 'px-4 py-2.5 border-b border-white/4 cursor-pointer transition-colors',
        selected ? 'bg-magenta/8 border-l-2 border-l-magenta' : 'hover:bg-white/3',
        (c.status === 'closed' || c.status === 'resolved') && 'opacity-50',
      )}
    >
      <span className="w-2 h-2 rounded-full shrink-0"
        style={{ background: c.severity === 'critical' ? tk('magenta') : c.severity === 'high' ? tk('threat') : c.severity === 'medium' ? tk('amber') : tk('safe') }} />

      <div className="min-w-0">
        <p className="text-xs text-ink-200 truncate">{c.title}</p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[10px] font-mono text-violet">{c.id}</span>
          <span className="text-[10px] text-ink-700">·</span>
          <span className="text-[10px] text-ink-600">{c.type}</span>
        </div>
      </div>

      <span className={cn('hidden md:block text-[10px]', st.color)}>{st.label}</span>
      <span className="hidden lg:block text-[11px] text-ink-500 truncate">{c.owner ?? <span className="text-amber">Unassigned</span>}</span>

      <span className="text-[10px] text-ink-600 truncate">{c.playbook.split(' ')[0]}</span>

      {/* SLA */}
      <div className="flex flex-col gap-1">
        <div className="h-1 w-full bg-white/8 rounded-full overflow-hidden">
          <div className="h-full rounded-full" style={{ width: `${pct}%`, background: slaColor }} />
        </div>
        <span className="text-[9px] font-mono" style={{ color: slaColor }}>{slaLabel(c.created, c.slaHours)}</span>
      </div>

      <span suppressHydrationWarning className="text-[10px] text-ink-700">
        {Math.floor((Date.parse('2024-11-12T16:00:00Z') - new Date(c.created).getTime()) / 60000)}m ago
      </span>
    </motion.div>
  )
}

/* ── Playbook card ────────────────────────────────────────────────── */
function PlaybookCard({ pb, selected, onClick, onRun }: {
  pb: Playbook; selected: boolean; onClick: () => void; onRun?: (e: React.MouseEvent) => void
}) {
  const completedSteps = pb.steps.filter((s) => s.status === 'completed').length

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={onClick}
      className={cn(
        'bg-surface-2/40 rounded-xl p-4 border cursor-pointer transition-colors',
        selected ? 'border-magenta/40 bg-magenta/5' : 'border-white/5 hover:border-white/10',
      )}
    >
      <div className="flex items-start gap-3">
        <div className={cn('p-2 rounded-lg shrink-0',
          pb.status === 'running' ? 'bg-violet/15' : pb.status === 'failed' ? 'bg-threat/15' : 'bg-safe/10')}>
          {pb.status === 'running'
            ? <RefreshCw className="w-4 h-4 text-violet animate-spin" />
            : pb.status === 'failed'
            ? <AlertTriangle className="w-4 h-4 text-threat" />
            : <Zap className="w-4 h-4 text-safe" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 justify-between">
            <p className="text-xs font-semibold text-white truncate">{pb.name}</p>
            <span className={cn('text-[9px] px-1.5 py-0.5 rounded font-semibold uppercase shrink-0',
              pb.status === 'running' ? 'bg-violet/15 text-violet' :
              pb.status === 'failed'  ? 'bg-threat/15 text-threat' :
              pb.status === 'idle'    ? 'bg-white/5 text-ink-500' :
              'bg-safe/10 text-safe')}>
              {pb.status === 'running' ? 'Running' : pb.status}
            </span>
          </div>
          <p className="text-[10px] text-ink-600 mt-0.5">{pb.trigger}</p>
        </div>
      </div>

      {/* Progress bar (for running) */}
      {pb.status === 'running' && (
        <div className="mt-3">
          <div className="flex justify-between text-[10px] text-ink-600 mb-1">
            <span>{completedSteps}/{pb.steps.length} steps</span>
            <span className="text-violet">Running…</span>
          </div>
          <div className="h-1.5 bg-white/8 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(completedSteps / pb.steps.length) * 100}%` }}
              className="h-full rounded-full bg-violet"
            />
          </div>
        </div>
      )}

      <div className="flex items-end justify-between mt-3 gap-3">
        <div className="grid grid-cols-3 gap-3 text-[10px] flex-1">
          <div><p className="text-ink-600">Runs</p><p className="text-ink-300 font-mono">{pb.runs}</p></div>
          <div><p className="text-ink-600">Success</p><p className={cn('font-mono', pb.successRate >= 95 ? 'text-safe' : 'text-amber')}>{pb.successRate}%</p></div>
          <div><p className="text-ink-600">Avg Time</p><p className="text-ink-300 font-mono">{pb.avgTime}</p></div>
        </div>
        {pb.status === 'running' ? (
          <span className="flex items-center gap-1 text-[10px] text-violet shrink-0">
            <RefreshCw className="w-3 h-3 animate-spin" /> Running…
          </span>
        ) : onRun ? (
          <button
            onClick={onRun}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] bg-violet/10 border border-violet/25 text-violet hover:bg-violet/20 transition-colors shrink-0 active:scale-95"
          >
            <Play className="w-3 h-3" /> Run
          </button>
        ) : null}
      </div>
    </motion.div>
  )
}
