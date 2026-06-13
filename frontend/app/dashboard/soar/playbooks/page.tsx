'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchPlaybooks, runPlaybook, updatePlaybook, type Playbook as ApiPlaybook } from '@/lib/api'
import PlaybookRunsPanel from '@/components/dashboard/PlaybookRunsPanel'
import PlaybookBuilder from '@/components/dashboard/PlaybookBuilder'
import {
  Zap, CheckCircle, RefreshCw, AlertTriangle, X, Shield, User,
  GitBranch, MessageSquare, Activity, Play, Edit2, Clock,
  ChevronRight, ToggleLeft, ToggleRight, Plus, Search,
  Circle, Network, Cloud, Lock, FileCheck, Globe,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'

/* ── Types ────────────────────────────────────────────────────────── */
type StepType = 'check' | 'action' | 'decision' | 'notify' | 'human' | 'sub-playbook'
type StepStatus = 'idle' | 'running' | 'completed' | 'failed' | 'skipped'
type RunStatus = 'success' | 'failure' | 'running' | 'scheduled' | 'idle'
type FilterCat = 'All' | 'Network' | 'Endpoint' | 'Cloud' | 'Identity' | 'Compliance'

type PlaybookStep = {
  name: string
  type: StepType
  status: StepStatus
  duration?: string
  note?: string
}

type Playbook = {
  id: string
  name: string
  category: string
  trigger: string
  triggerType: 'auto' | 'manual'
  stepsCount: number
  estimatedRuntime: string
  successRate: number
  lastRun: string
  lastRunStatus: RunStatus
  runCount: number
  enabled: boolean
  steps: PlaybookStep[]
}

/* ── Constants ────────────────────────────────────────────────────── */
const STEP_ICON: Record<StepType, React.ElementType> = {
  check:           Shield,
  action:          Zap,
  decision:        GitBranch,
  notify:          MessageSquare,
  human:           User,
  'sub-playbook':  Activity,
}

const STEP_COLOR: Record<StepType, string> = {
  check:           '#7A3CFF',   // violet
  action:          '#FF2E97',   // magenta
  decision:        '#FFB23E',   // amber
  notify:          '#34F5C5',   // safe
  human:           '#FFFFFF',   // white
  'sub-playbook':  '#3B82F6',   // blue
}

const CAT_COLOR: Record<string, string> = {
  Network:    'border-violet/30 bg-violet/10 text-violet',
  Endpoint:   'border-threat/30 bg-threat/10 text-threat',
  Cloud:      'border-safe/30 bg-safe/10 text-safe',
  Identity:   'border-amber/30 bg-amber/10 text-amber',
  Compliance: 'border-magenta/30 bg-magenta/10 text-magenta',
  Intel:      'border-teal/30 bg-teal/10 text-teal',
}

const CAT_ICON: Record<string, React.ElementType> = {
  Network:    Network,
  Endpoint:   Shield,
  Cloud:      Cloud,
  Identity:   Lock,
  Compliance: FileCheck,
  Intel:      Globe,
}

const STATUS_DOT: Record<RunStatus, string> = {
  success:   'bg-safe',
  failure:   'bg-threat',
  running:   'bg-violet animate-pulse',
  scheduled: 'bg-amber',
  idle:      'bg-ink-600',
}

const STATUS_LABEL: Record<RunStatus, string> = {
  success:   'Success',
  failure:   'Failed',
  running:   'Running',
  scheduled: 'Scheduled',
  idle:      'Never run',
}

/* ── Playbook data ────────────────────────────────────────────────── */
const PLAYBOOKS: Playbook[] = [
  {
    id: 'pb-001',
    name: 'Endpoint Ransomware Containment',
    category: 'Endpoint',
    trigger: 'Auto: Critical ransomware indicator (EDR mass-encrypt)',
    triggerType: 'auto',
    stepsCount: 12,
    estimatedRuntime: '8m 44s',
    successRate: 98,
    lastRun: '14m ago',
    lastRunStatus: 'running',
    runCount: 847,
    enabled: true,
    steps: [
      { name: 'Verify detection confidence (EDR score ≥ 90)',       type: 'check',        status: 'completed', duration: '2s' },
      { name: 'Isolate host from network via EDR API',              type: 'action',       status: 'completed', duration: '3s' },
      { name: 'Capture live memory snapshot',                       type: 'action',       status: 'completed', duration: '4m 12s' },
      { name: 'Hash all renamed / encrypted files',                 type: 'action',       status: 'completed', duration: '22s' },
      { name: 'Submit hashes to VirusTotal + IntelMQ',             type: 'action',       status: 'completed', duration: '8s' },
      { name: 'Known ransomware family?',                           type: 'decision',     status: 'completed', duration: '0s', note: 'Yes → continue; No → escalate to analyst' },
      { name: 'Notify CISO + IR lead via PagerDuty',               type: 'notify',       status: 'completed', duration: '1s' },
      { name: 'Create Jira P1 incident ticket',                     type: 'action',       status: 'running',   duration: undefined },
      { name: 'Block C2 IPs on perimeter firewall',                 type: 'action',       status: 'idle' },
      { name: 'Scan environment for additional IOCs',               type: 'action',       status: 'idle' },
      { name: 'Analyst: identify patient zero (human task)',        type: 'human',        status: 'idle' },
      { name: 'Execute Recovery Playbook (sub-playbook)',           type: 'sub-playbook', status: 'idle' },
    ],
  },
  {
    id: 'pb-002',
    name: 'Phishing Email Response',
    category: 'Identity',
    trigger: 'Auto: Phishing detected - mail gateway + URL reputation',
    triggerType: 'auto',
    stepsCount: 8,
    estimatedRuntime: '2m 14s',
    successRate: 96,
    lastRun: '12m ago',
    lastRunStatus: 'success',
    runCount: 2847,
    enabled: true,
    steps: [
      { name: 'Extract email headers and attachments',              type: 'check',    status: 'completed', duration: '1s' },
      { name: 'Check URLs against threat intel feeds',             type: 'check',    status: 'completed', duration: '4s' },
      { name: 'Submit attachment hash to VirusTotal',              type: 'action',   status: 'completed', duration: '6s' },
      { name: 'Malicious verdict?',                                type: 'decision', status: 'completed', duration: '0s', note: 'If ≥ 5 engines: malicious. Else: suspicious → human review' },
      { name: 'Quarantine email across all mailboxes (Exchange)',  type: 'action',   status: 'completed', duration: '12s' },
      { name: 'Block sender domain at email gateway',             type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Notify affected recipients via secure channel',    type: 'notify',   status: 'completed', duration: '3s' },
      { name: 'Create SOAR case and link alert',                  type: 'action',   status: 'completed', duration: '1s' },
    ],
  },
  {
    id: 'pb-003',
    name: 'Brute Force Block',
    category: 'Network',
    trigger: 'Auto: 5+ failed logins from single source within 60s',
    triggerType: 'auto',
    stepsCount: 5,
    estimatedRuntime: '0m 28s',
    successRate: 99,
    lastRun: '3h ago',
    lastRunStatus: 'success',
    runCount: 14203,
    enabled: true,
    steps: [
      { name: 'Aggregate failed login events from SIEM',           type: 'check',    status: 'completed', duration: '1s' },
      { name: 'Threshold exceeded (≥5 fails / 60s)?',             type: 'decision', status: 'completed', duration: '0s', note: 'Yes → block. No → alert only.' },
      { name: 'Block source IP on perimeter firewall (PA)',        type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Notify SOC via Slack #soc-alerts',                 type: 'notify',   status: 'completed', duration: '1s' },
      { name: 'Log IOC to threat intel feed (TIP)',                type: 'action',   status: 'completed', duration: '3s' },
    ],
  },
  {
    id: 'pb-004',
    name: 'C2 Beacon Isolation',
    category: 'Network',
    trigger: 'Auto: C2 IOC match - DNS/HTTP beacon to known C2 domain',
    triggerType: 'auto',
    stepsCount: 10,
    estimatedRuntime: '5m 20s',
    successRate: 97,
    lastRun: '1h ago',
    lastRunStatus: 'success',
    runCount: 412,
    enabled: true,
    steps: [
      { name: 'Cross-reference domain/IP with TI feeds',           type: 'check',    status: 'completed', duration: '3s' },
      { name: 'Identify beaconing hosts from DNS/proxy logs',      type: 'check',    status: 'completed', duration: '8s' },
      { name: 'Confidence ≥ 90% (≥3 TI feeds match)?',            type: 'decision', status: 'completed', duration: '0s', note: 'Yes → auto-isolate. No → analyst decision.' },
      { name: 'Isolate host(s) via EDR API',                       type: 'action',   status: 'completed', duration: '4s' },
      { name: 'Block domain and IPs on all firewalls',             type: 'action',   status: 'completed', duration: '6s' },
      { name: 'Extract process responsible for DNS query',         type: 'check',    status: 'completed', duration: '5s' },
      { name: 'Submit process binary to sandbox',                  type: 'action',   status: 'completed', duration: '3m 40s' },
      { name: 'Notify IR team (PagerDuty P2)',                     type: 'notify',   status: 'completed', duration: '1s' },
      { name: 'Analyst: review process tree and sandbox report',  type: 'human',    status: 'completed', duration: '12m' },
      { name: 'Update threat intel with confirmed IOCs',           type: 'action',   status: 'completed', duration: '2s' },
    ],
  },
  {
    id: 'pb-005',
    name: 'IAM Privilege Escalation Rollback',
    category: 'Cloud',
    trigger: 'Auto: IAM change detected - policy attach with admin scope',
    triggerType: 'auto',
    stepsCount: 7,
    estimatedRuntime: '1m 42s',
    successRate: 91,
    lastRun: '2d ago',
    lastRunStatus: 'success',
    runCount: 94,
    enabled: true,
    steps: [
      { name: 'Parse CloudTrail / Azure AD event details',         type: 'check',    status: 'completed', duration: '1s' },
      { name: 'Authorized deployment action?',                     type: 'decision', status: 'completed', duration: '0s', note: 'Match change-management DB. Yes → close. No → rollback.' },
      { name: 'Detach escalated IAM policy via API',               type: 'action',   status: 'completed', duration: '3s' },
      { name: 'Export CloudTrail log for escalation window',       type: 'action',   status: 'completed', duration: '12s' },
      { name: 'Check for data access during elevated period',      type: 'check',    status: 'completed', duration: '15s' },
      { name: 'Create Jira ticket for IAM policy review',          type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Notify cloud security team (Slack + email)',        type: 'notify',   status: 'completed', duration: '1s' },
    ],
  },
  {
    id: 'pb-006',
    name: 'Malware Sandboxing',
    category: 'Endpoint',
    trigger: 'Manual trigger - analyst submits file for detonation',
    triggerType: 'manual',
    stepsCount: 6,
    estimatedRuntime: '12m 00s',
    successRate: 88,
    lastRun: '6h ago',
    lastRunStatus: 'success',
    runCount: 1289,
    enabled: true,
    steps: [
      { name: 'Receive file hash or URL from analyst',             type: 'check',    status: 'completed', duration: '1s' },
      { name: 'Check VirusTotal cache (last 24h)',                 type: 'check',    status: 'completed', duration: '2s' },
      { name: 'Submit to Cuckoo/Any.run sandbox',                  type: 'action',   status: 'completed', duration: '10m 14s' },
      { name: 'Parse sandbox report - extract IOCs',               type: 'action',   status: 'completed', duration: '30s' },
      { name: 'Malicious verdict?',                                type: 'decision', status: 'completed', duration: '0s', note: 'Yes → push IOCs to SIEM + firewall. No → log benign.' },
      { name: 'Notify requesting analyst with full report',        type: 'notify',   status: 'completed', duration: '1s' },
    ],
  },
  {
    id: 'pb-007',
    name: 'GDPR Incident Notification',
    category: 'Compliance',
    trigger: 'Auto: PII breach indicator - DLP alert + data exfil pattern',
    triggerType: 'auto',
    stepsCount: 9,
    estimatedRuntime: '4m 10s',
    successRate: 95,
    lastRun: '5d ago',
    lastRunStatus: 'success',
    runCount: 23,
    enabled: true,
    steps: [
      { name: 'Identify data classification of affected records',  type: 'check',    status: 'completed', duration: '5s' },
      { name: 'PII or regulated data confirmed?',                  type: 'decision', status: 'completed', duration: '0s', note: 'Yes → GDPR workflow. No → standard IR.' },
      { name: 'Contain data source (revoke access/quarantine)',    type: 'action',   status: 'completed', duration: '20s' },
      { name: 'Estimate scope: number of records affected',        type: 'check',    status: 'completed', duration: '2m' },
      { name: '>250 records? Notify DPA within 72h required',      type: 'decision', status: 'completed', duration: '0s', note: 'Yes → schedule regulatory notification. No → internal report only.' },
      { name: 'Draft breach notification (DPA template)',          type: 'action',   status: 'completed', duration: '45s' },
      { name: 'Human: DPO review and approve notification',        type: 'human',    status: 'completed', duration: '30m' },
      { name: 'Submit notification to supervisory authority',      type: 'action',   status: 'completed', duration: '2s' },
      { name: 'Notify affected data subjects (email template)',    type: 'notify',   status: 'completed', duration: '5s' },
    ],
  },
  {
    id: 'pb-008',
    name: 'Threat Intel Enrichment',
    category: 'Intel',
    trigger: 'Auto: New IOC received - STIX/TAXII feed or manual import',
    triggerType: 'auto',
    stepsCount: 4,
    estimatedRuntime: '0m 45s',
    successRate: 99,
    lastRun: '2m ago',
    lastRunStatus: 'success',
    runCount: 38291,
    enabled: true,
    steps: [
      { name: 'Parse IOC from STIX 2.1 bundle or CSV',             type: 'action',   status: 'completed', duration: '1s' },
      { name: 'Enrich with VirusTotal + AbuseIPDB + Shodan',       type: 'check',    status: 'completed', duration: '8s' },
      { name: 'Confidence ≥ 70%?',                                 type: 'decision', status: 'completed', duration: '0s', note: 'Yes → push to SIEM rules + blocklists. No → watchlist only.' },
      { name: 'Publish enriched IOC to all integrated platforms',  type: 'action',   status: 'completed', duration: '3s' },
    ],
  },
]

/* ── KPI data ─────────────────────────────────────────────────────── */
const KPI = [
  { label: 'Total Playbooks', value: '18',   color: 'text-white',   sub: '8 shown, 10 additional' },
  { label: 'Running Now',     value: '2',    color: 'text-violet',  sub: '1 critical, 1 medium' },
  { label: 'Scheduled',       value: '4',    color: 'text-amber',   sub: 'Next: 17:00 UTC' },
  { label: 'Avg Success Rate',value: '94.2%',color: 'text-safe',    sub: '+1.3% from last month' },
]

const FILTER_CATS: FilterCat[] = ['All', 'Network', 'Endpoint', 'Cloud', 'Identity', 'Compliance']

/* ── Step detail panel ────────────────────────────────────────────── */
function StepDetailPanel({ pb, onClose, onEdit }: { pb: Playbook; onClose: () => void; onEdit?: () => void }) {
  return (
    <motion.div
      key={pb.id}
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 290, damping: 28 }}
      className="fixed right-0 top-0 bottom-0 z-[60] w-full max-w-md flex flex-col bg-surface border-l border-white/8 shadow-2xl overflow-hidden"
    >
      {/* Panel header */}
      <div className="p-4 border-b border-white/8 shrink-0">
        <div className="flex items-start gap-3">
          <div className={cn('p-2 rounded-lg shrink-0', CAT_COLOR[pb.category] || 'bg-white/5 text-ink-400')}>
            {(() => { const Icon = CAT_ICON[pb.category] || Globe; return <Icon className="w-4 h-4" /> })()}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-white leading-snug">{pb.name}</p>
            <p className="text-[10px] text-ink-500 mt-0.5">{pb.trigger}</p>
          </div>
          {onEdit && (
            <button onClick={onEdit}
              className="px-2.5 py-1.5 rounded-lg text-[11px] text-magenta border border-magenta/30 hover:bg-magenta/15 transition-colors shrink-0">
              Edit
            </button>
          )}
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-3 gap-3 mt-4">
          {[
            { label: 'Steps',    value: String(pb.stepsCount) },
            { label: 'Est. Time',value: pb.estimatedRuntime },
            { label: 'Success',  value: `${pb.successRate}%` },
          ].map((s) => (
            <div key={s.label} className="bg-surface-2/60 rounded-lg px-3 py-2 text-center border border-white/5">
              <p className="text-xs font-bold text-white">{s.value}</p>
              <p className="text-[10px] text-ink-600 mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Step legend */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-white/5 shrink-0 flex-wrap">
        {(Object.entries(STEP_COLOR) as [StepType, string][]).map(([type, color]) => {
          const Icon = STEP_ICON[type]
          return (
            <span key={type} className="flex items-center gap-1 text-[9px] text-ink-500">
              <Icon className="w-3 h-3" style={{ color }} />
              {type}
            </span>
          )
        })}
      </div>

      {/* Steps list */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="relative space-y-1">
          {pb.steps.map((step, i) => {
            const Icon = STEP_ICON[step.type]
            const color = STEP_COLOR[step.type]
            const isRunning = step.status === 'running'
            const isDone = step.status === 'completed'

            return (
              <div key={i} className="flex gap-3">
                {/* Icon + connector */}
                <div className="flex flex-col items-center shrink-0">
                  <div className={cn(
                    'w-7 h-7 rounded-full flex items-center justify-center border transition-all',
                    isDone   ? 'bg-safe/15 border-safe/40' :
                    isRunning? 'bg-violet/20 border-violet/50 ring-2 ring-violet/20' :
                    step.status === 'failed' ? 'bg-threat/15 border-threat/40' :
                    'bg-surface-2 border-white/10',
                  )}>
                    {isDone ? (
                      <CheckCircle className="w-3.5 h-3.5 text-safe" />
                    ) : isRunning ? (
                      <RefreshCw className="w-3.5 h-3.5 text-violet animate-spin" />
                    ) : step.status === 'failed' ? (
                      <AlertTriangle className="w-3.5 h-3.5 text-threat" />
                    ) : (
                      <Icon className="w-3 h-3" style={{ color: step.status === 'idle' ? '#4a4463' : color }} />
                    )}
                  </div>
                  {i < pb.steps.length - 1 && (
                    <div className={cn(
                      'w-0.5 flex-1 min-h-4 mt-1 rounded-full',
                      isDone ? 'bg-safe/25' : 'bg-white/6',
                    )} />
                  )}
                </div>

                {/* Content */}
                <div className="pb-3 flex-1 min-w-0">
                  <p className={cn(
                    'text-[11px] leading-snug font-medium',
                    isDone    ? 'text-ink-400' :
                    isRunning ? 'text-white'   :
                    step.status === 'failed' ? 'text-threat' :
                    'text-ink-600',
                  )}>
                    {step.name}
                  </p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <span
                      className="text-[9px] px-1.5 py-0.5 rounded font-semibold uppercase tracking-wide"
                      style={{ background: color + '18', color }}
                    >
                      {step.type}
                    </span>
                    {step.duration && (
                      <span className="text-[9px] text-ink-700 font-mono">{step.duration}</span>
                    )}
                    {isRunning && (
                      <span className="text-[9px] text-violet flex items-center gap-1">
                        <Circle className="w-1.5 h-1.5 fill-violet animate-pulse" /> executing…
                      </span>
                    )}
                  </div>
                  {step.note && (
                    <p className="text-[9px] text-ink-600 mt-1 italic leading-relaxed">{step.note}</p>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </motion.div>
  )
}

/* ── Playbook card ────────────────────────────────────────────────── */
function PlaybookCard({
  pb, selected, running, onClick, onToggle, onRun,
}: {
  pb: Playbook
  selected: boolean
  running: boolean
  onClick: () => void
  onToggle: (e: React.MouseEvent) => void
  onRun: (e: React.MouseEvent) => void
}) {
  const CatIcon = CAT_ICON[pb.category] || Globe

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2 }}
      transition={{ duration: 0.22 }}
      onClick={onClick}
      className={cn(
        'group relative bg-surface-2/50 rounded-xl border cursor-pointer transition-all duration-200 flex flex-col overflow-hidden',
        selected
          ? 'border-magenta/40 bg-magenta/5 shadow-magenta-sm'
          : 'border-white/6 hover:border-white/14 hover:shadow-card',
        !pb.enabled && 'opacity-50',
      )}
    >
      {/* Running shimmer */}
      {pb.lastRunStatus === 'running' && (
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-violet/5 to-transparent animate-gradient-x pointer-events-none" />
      )}

      {/* Card body */}
      <div className="p-4 flex-1">
        {/* Header row */}
        <div className="flex items-start gap-3 mb-3">
          <div className={cn('p-2 rounded-lg shrink-0 border', CAT_COLOR[pb.category] || 'border-white/10 bg-white/5 text-ink-400')}>
            <CatIcon className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 justify-between">
              <p className="text-[13px] font-semibold text-white truncate leading-snug">{pb.name}</p>
              <span className={cn(
                'shrink-0 text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase tracking-wide',
                CAT_COLOR[pb.category] || 'border-white/10 text-ink-500',
              )}>
                {pb.category}
              </span>
            </div>
            <p className="text-[10px] text-ink-500 mt-1 leading-relaxed line-clamp-2">{pb.trigger}</p>
          </div>
        </div>

        {/* Steps + runtime */}
        <div className="flex items-center gap-4 text-[10px] text-ink-500 mb-3">
          <span className="flex items-center gap-1">
            <ChevronRight className="w-3 h-3" />
            {pb.stepsCount} steps
          </span>
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            ~{pb.estimatedRuntime}
          </span>
          <span className={cn('px-1.5 py-0.5 rounded text-[9px] border',
            pb.triggerType === 'auto'
              ? 'border-violet/25 bg-violet/8 text-violet'
              : 'border-amber/25 bg-amber/8 text-amber',
          )}>
            {pb.triggerType === 'auto' ? 'Auto' : 'Manual'}
          </span>
        </div>

        {/* Success rate bar */}
        <div className="mb-3">
          <div className="flex items-center justify-between text-[10px] mb-1">
            <span className="text-ink-600">Success rate</span>
            <span className={cn('font-mono font-semibold',
              pb.successRate >= 95 ? 'text-safe' :
              pb.successRate >= 85 ? 'text-amber' :
              'text-threat',
            )}>
              {pb.successRate}%
            </span>
          </div>
          <div className="h-1.5 bg-white/6 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${pb.successRate}%` }}
              transition={{ duration: 0.6, ease: 'easeOut' }}
              className={cn('h-full rounded-full',
                pb.successRate >= 95 ? 'bg-safe' :
                pb.successRate >= 85 ? 'bg-amber' :
                'bg-threat',
              )}
            />
          </div>
        </div>

        {/* Last run + run count */}
        <div className="flex items-center justify-between text-[10px]">
          <div className="flex items-center gap-1.5">
            <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', STATUS_DOT[pb.lastRunStatus])} />
            <span className="text-ink-500">{STATUS_LABEL[pb.lastRunStatus]}</span>
            <span className="text-ink-700">·</span>
            <span className="text-ink-600">{pb.lastRun}</span>
          </div>
          <span className="text-ink-600 font-mono">{pb.runCount.toLocaleString()} runs</span>
        </div>
      </div>

      {/* Footer: actions */}
      <div className="px-4 py-2.5 border-t border-white/5 flex items-center gap-2 bg-surface-2/30">
        <button
          onClick={(e) => { e.stopPropagation() }}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] bg-white/5 border border-white/8 text-ink-400 hover:text-ink-200 hover:bg-white/8 transition-colors"
        >
          <Edit2 className="w-3 h-3" /> Edit
        </button>
        <button
          onClick={onRun}
          disabled={running || !pb.enabled}
          className={cn(
            'flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[10px] border transition-colors',
            running
              ? 'bg-violet/20 border-violet/40 text-violet cursor-wait'
              : 'bg-violet/10 border-violet/25 text-violet hover:bg-violet/20 disabled:opacity-40 disabled:cursor-not-allowed',
          )}
        >
          <Play className={cn('w-3 h-3', running && 'animate-pulse')} /> {running ? 'Running…' : 'Run'}
        </button>
        <div className="flex-1" />
        {/* Toggle */}
        <button
          onClick={onToggle}
          className="flex items-center gap-1.5 text-[10px] transition-colors"
          title={pb.enabled ? 'Disable playbook' : 'Enable playbook'}
        >
          {pb.enabled ? (
            <>
              <ToggleRight className="w-4 h-4 text-safe" />
              <span className="text-safe hidden sm:inline">On</span>
            </>
          ) : (
            <>
              <ToggleLeft className="w-4 h-4 text-ink-600" />
              <span className="text-ink-600 hidden sm:inline">Off</span>
            </>
          )}
        </button>
      </div>
    </motion.div>
  )
}

/* ── Main page ────────────────────────────────────────────────────── */
export default function PlaybooksPage() {
  const [mode] = useExperienceMode()
  const isPower = mode === 'power'

  const [filter, setFilter] = useState<FilterCat>('All')
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [playbooks, setPlaybooks] = useState(PLAYBOOKS)

  useEffect(() => {
    fetchPlaybooks().then((data: ApiPlaybook[]) => {
      if (data.length > 0) {
        const mapped = data.map((p) => {
          const seed = PLAYBOOKS.find((s) => s.id === p.id || s.name === p.name)
          const apiSteps = (p.steps ?? []).map((s) => ({
            name: s.name, type: (s.type ?? 'action') as StepType,
            status: (s.status ?? 'idle') as StepStatus, duration: `${s.duration ?? 5}s`,
          }))
          return {
            id: p.id,
            name: p.name,
            category: p.category || seed?.category || 'Network',
            trigger: p.trigger,
            triggerType: (p.triggerType === 'manual' ? 'manual' : 'auto') as 'auto' | 'manual',
            stepsCount: p.steps?.length ?? seed?.stepsCount ?? 0,
            estimatedRuntime: `${p.avgTime}s`,
            successRate: p.successRate,
            lastRun: p.lastRun ?? 'Never',
            lastRunStatus: (p.lastRunStatus === 'failure' ? 'failure'
              : p.lastRunStatus === 'running' ? 'running'
              : p.lastRunStatus === 'success' ? 'success' : 'idle') as RunStatus,
            runCount: p.runs,
            enabled: p.enabled === 1,
            steps: apiSteps.length > 0 ? apiSteps : (seed?.steps ?? []),
          }
        })
        setPlaybooks(mapped)
      }
    }).catch(() => {})
  }, [])

  const [runningId, setRunningId] = useState<string | null>(null)
  // null = closed; {} = new; {id,name,steps} = edit. Drives the visual builder.
  const [builder, setBuilder] = useState<{ id?: string; name?: string; steps?: Array<{ kind?: string; name: string; params?: Record<string, unknown> }> } | null>(null)
  // After a builder save/revert, refetch so the new definition is reflected.
  function reloadPlaybooks() {
    if (typeof window !== 'undefined') window.location.reload()
  }

  const selectedPB = playbooks.find((p) => p.id === selectedId) ?? null

  function toggleEnabled(id: string, e: React.MouseEvent) {
    e.stopPropagation()
    const prev = playbooks.find((p) => p.id === id)?.enabled ?? true
    // Optimistic flip, persisted to the backend; revert on failure.
    setPlaybooks((ps) => ps.map((p) => p.id === id ? { ...p, enabled: !prev } : p))
    updatePlaybook(id, { enabled: !prev }).catch(() => {
      setPlaybooks((ps) => ps.map((p) => p.id === id ? { ...p, enabled: prev } : p))
    })
  }

  async function runPlaybookById(id: string, e: React.MouseEvent) {
    e.stopPropagation()
    if (runningId) return
    setRunningId(id)
    try {
      // Real execution: the engine runs every step and records the run -
      // results land in the Run history panel below.
      const updated = await runPlaybook(id)
      const runStatus = updated.run?.status
      setPlaybooks((prev) => prev.map((p) => p.id === id ? {
        ...p,
        runCount: updated.runs,
        lastRun: 'Just now',
        lastRunStatus: (runStatus === 'failed' ? 'failure'
          : runStatus === 'awaiting-approval' ? 'running' : 'success') as RunStatus,
      } : p))
    } catch {
      setPlaybooks((prev) => prev.map((p) => p.id === id ? { ...p, lastRunStatus: 'failure' as RunStatus } : p))
    } finally {
      setRunningId(null)
    }
  }

  const filtered = playbooks.filter((pb) => {
    const matchCat = filter === 'All' || pb.category === filter
    const matchSearch = search === '' || pb.name.toLowerCase().includes(search.toLowerCase())
    return matchCat && matchSearch
  })

  return (
    <div className="flex h-full overflow-hidden">
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* ── Page header ──────────────────────────────────────────── */}
        <div className="px-6 py-4 border-b border-white/5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between shrink-0">
          <div>
            <h1 className="font-display text-xl font-bold text-white">Playbooks</h1>
            <p className="text-xs text-ink-500 mt-0.5 max-w-xl">
              Automated response workflows.{' '}
              <span className="text-ink-400">Each trigger auto-runs when conditions are met.</span>
            </p>
          </div>
          <button onClick={() => setBuilder({})}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs bg-magenta/10 border border-magenta/25 text-magenta hover:bg-magenta/18 transition-colors shrink-0 self-start">
            <Plus className="w-3.5 h-3.5" /> New Playbook
          </button>
        </div>

        {/* ── KPI strip ────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 border-b border-white/5 shrink-0">
          {KPI.map((k, i) => (
            <div key={k.label} className={cn('px-5 py-3 border-r border-white/5 last:border-r-0', i > 1 && 'hidden md:block')}>
              <p className="text-[10px] text-ink-600 uppercase tracking-wide">{k.label}</p>
              <p className={cn('text-xl font-bold mt-0.5', k.color)}>{k.value}</p>
              <p className="text-[10px] text-ink-600 mt-0.5">{k.sub}</p>
            </div>
          ))}
        </div>

        {/* ── Filter bar ───────────────────────────────────────────── */}
        <div className="px-6 py-3 border-b border-white/5 flex items-center gap-4 shrink-0 overflow-x-auto">
          {/* Search */}
          <div className="relative shrink-0">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search playbooks…"
              className="pl-8 pr-3 py-1.5 bg-surface-2/60 border border-white/8 rounded-lg text-xs text-ink-200 placeholder-ink-600 focus:outline-none focus:border-white/20 w-44"
            />
          </div>

          <div className="w-px h-4 bg-white/10 shrink-0" />

          {/* Category tabs */}
          <div className="flex items-center gap-1 shrink-0">
            {FILTER_CATS.map((cat) => (
              <button
                key={cat}
                onClick={() => setFilter(cat)}
                className={cn(
                  'px-3 py-1.5 rounded-lg text-xs transition-colors whitespace-nowrap',
                  filter === cat
                    ? 'bg-magenta/12 border border-magenta/30 text-magenta'
                    : 'text-ink-500 hover:text-ink-300 hover:bg-white/4',
                )}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="ml-auto shrink-0 text-[10px] text-ink-600">
            {filtered.length} of {playbooks.length} playbooks
          </div>
        </div>

        {/* ── Grid ─────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto p-6">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-ink-600 gap-2">
              <Search className="w-8 h-8 opacity-30" />
              <p className="text-sm">No playbooks match your filters</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {filtered.map((pb, i) => (
                <motion.div
                  key={pb.id}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04, duration: 0.25 }}
                >
                  <PlaybookCard
                    pb={pb}
                    selected={selectedId === pb.id}
                    running={runningId === pb.id}
                    onClick={() => setSelectedId((prev) => prev === pb.id ? null : pb.id)}
                    onToggle={(e) => toggleEnabled(pb.id, e)}
                    onRun={(e) => runPlaybookById(pb.id, e)}
                  />
                </motion.div>
              ))}
            </div>
          )}

          {/* ── Run history + approvals (live, per-step audit trail) ── */}
          <div className="mt-6">
            <PlaybookRunsPanel />
          </div>
        </div>
      </div>

      {/* ── Step detail slide-over ────────────────────────────────── */}
      <AnimatePresence>
        {selectedPB && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm"
              onClick={() => setSelectedId(null)}
            />
            <StepDetailPanel
              pb={selectedPB}
              onClose={() => setSelectedId(null)}
              onEdit={() => {
                setBuilder({ id: selectedPB.id, name: selectedPB.name,
                  steps: (selectedPB.steps ?? []).map((s) => ({ kind: (s as { kind?: string }).kind, name: s.name })) })
                setSelectedId(null)
              }}
            />
          </>
        )}
      </AnimatePresence>

      {/* Visual playbook builder (create / edit) */}
      <AnimatePresence>
        {builder && (
          <PlaybookBuilder
            playbook={builder.id ? { id: builder.id, name: builder.name ?? '', steps: builder.steps } : null}
            onClose={() => setBuilder(null)}
            onSaved={reloadPlaybooks}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
