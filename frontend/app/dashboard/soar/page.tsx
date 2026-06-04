'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Zap, Play, Pause, CheckCircle, Clock, AlertTriangle,
  ChevronRight, ArrowRight, GitBranch, Terminal, Shield,
  RefreshCw, XCircle, Loader,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Playbook definitions ────────────────────────────────────────── */
type PBStatus = 'idle' | 'running' | 'completed' | 'failed'

type Playbook = {
  id: string
  name: string
  trigger: string
  description: string
  status: PBStatus
  lastRun: string
  runs: number
  avgTime: string
  steps: { name: string; type: 'check' | 'action' | 'decision' | 'notify'; status: PBStatus }[]
}

const PLAYBOOKS: Playbook[] = [
  {
    id: 'pb-001',
    name: 'Phishing Email Response',
    trigger: 'Mail gateway alert',
    description: 'Automated triage, quarantine, and user notification for detected phishing emails.',
    status: 'completed',
    lastRun: '4m ago',
    runs: 284,
    avgTime: '2m 14s',
    steps: [
      { name: 'Extract email headers & attachments', type: 'check',    status: 'completed' },
      { name: 'Check URLs against threat intel',     type: 'check',    status: 'completed' },
      { name: 'Hash attachments vs malware DB',      type: 'check',    status: 'completed' },
      { name: 'Malicious?',                          type: 'decision', status: 'completed' },
      { name: 'Quarantine email across mailboxes',   type: 'action',   status: 'completed' },
      { name: 'Block sender & domain',               type: 'action',   status: 'completed' },
      { name: 'Notify affected users',               type: 'notify',   status: 'completed' },
      { name: 'Create SIEM incident ticket',         type: 'action',   status: 'completed' },
    ],
  },
  {
    id: 'pb-002',
    name: 'Endpoint Ransomware Containment',
    trigger: 'EDR: encryption pattern',
    description: 'Immediate host isolation, evidence collection, and IR team escalation on ransomware detection.',
    status: 'running',
    lastRun: 'Running now',
    runs: 7,
    avgTime: '8m 44s',
    steps: [
      { name: 'Verify detection confidence',         type: 'check',    status: 'completed' },
      { name: 'Isolate host from network',           type: 'action',   status: 'completed' },
      { name: 'Snapshot memory & disk',              type: 'action',   status: 'completed' },
      { name: 'Collect process tree',                type: 'check',    status: 'completed' },
      { name: 'Submit sample to sandbox',            type: 'check',    status: 'running'   },
      { name: 'Identify lateral movement',           type: 'check',    status: 'idle'      },
      { name: 'Revoke compromised credentials',      type: 'action',   status: 'idle'      },
      { name: 'Page SOC lead (P0 escalation)',       type: 'notify',   status: 'idle'      },
    ],
  },
  {
    id: 'pb-003',
    name: 'Brute Force Account Lockout',
    trigger: 'Auth: 10+ failures / 60s',
    description: 'Block attacking IP, lock account, alert user and SOC, and add to watchlist.',
    status: 'idle',
    lastRun: '1h ago',
    runs: 1204,
    avgTime: '0m 38s',
    steps: [
      { name: 'Validate failure threshold',          type: 'check',    status: 'idle' },
      { name: 'Block source IP at perimeter',        type: 'action',   status: 'idle' },
      { name: 'Temporarily lock user account',       type: 'action',   status: 'idle' },
      { name: 'Notify user via secure channel',      type: 'notify',   status: 'idle' },
      { name: 'Add IP to 30-day watchlist',          type: 'action',   status: 'idle' },
      { name: 'Log to SIEM case',                   type: 'action',   status: 'idle' },
    ],
  },
  {
    id: 'pb-004',
    name: 'Critical CVE Patch Enforcement',
    trigger: 'CVE CVSS ≥ 9.0 published',
    description: 'Assess exposure, initiate emergency patching workflow, and verify remediation.',
    status: 'failed',
    lastRun: '23m ago',
    runs: 42,
    avgTime: '15m 20s',
    steps: [
      { name: 'Identify affected asset inventory',   type: 'check',    status: 'completed' },
      { name: 'Query patch availability',            type: 'check',    status: 'completed' },
      { name: 'Trigger patch deployment pipeline',  type: 'action',   status: 'failed'    },
      { name: 'Verify patch applied',               type: 'check',    status: 'idle'      },
      { name: 'Report remediation status',          type: 'notify',   status: 'idle'      },
    ],
  },
  {
    id: 'pb-005',
    name: 'Cloud IAM Anomaly Response',
    trigger: 'CSPM: privilege escalation',
    description: 'Revoke suspicious IAM permissions, collect CloudTrail evidence, and create case.',
    status: 'idle',
    lastRun: '6h ago',
    runs: 19,
    avgTime: '3m 55s',
    steps: [
      { name: 'Identify suspicious principal',      type: 'check',    status: 'idle' },
      { name: 'Revoke excess permissions',          type: 'action',   status: 'idle' },
      { name: 'Export CloudTrail logs (24h)',        type: 'action',   status: 'idle' },
      { name: 'Check for data access in logs',      type: 'check',    status: 'idle' },
      { name: 'Notify cloud security team',         type: 'notify',   status: 'idle' },
      { name: 'Create SOAR incident',               type: 'action',   status: 'idle' },
    ],
  },
]

/* ── Case queue ──────────────────────────────────────────────────── */
const CASES = [
  { id: 'INC-4421', title: 'Ransomware activity on HOST-44',    priority: 'P0', status: 'In Progress', analyst: 'J. Chen',    pb: 'Ransomware Containment' },
  { id: 'INC-4419', title: 'Phishing campaign — Finance team',  priority: 'P1', status: 'Contained',   analyst: 'A. Patel',   pb: 'Phishing Response' },
  { id: 'INC-4415', title: 'SSH brute force from 45.95.147.0',  priority: 'P2', status: 'Mitigated',   analyst: 'Auto',       pb: 'Brute Force Lockout' },
  { id: 'INC-4412', title: 'CVE-2024-6387 exposure detected',   priority: 'P1', status: 'Patching',    analyst: 'M. Singh',   pb: 'CVE Patch Enforcement' },
  { id: 'INC-4409', title: 'Suspicious IAM role assumption',    priority: 'P2', status: 'Investigating',analyst: 'K. Lee',    pb: 'Cloud IAM Response' },
]

const PRIORITY_COLOR: Record<string, string> = {
  P0: 'bg-magenta/15 text-magenta border-magenta/25',
  P1: 'bg-threat/15 text-threat border-threat/25',
  P2: 'bg-amber/15 text-amber border-amber/25',
  P3: 'bg-violet/15 text-violet border-violet/25',
}

/* ── Step icon ───────────────────────────────────────────────────── */
function StepIcon({ type, status }: { type: string; status: PBStatus }) {
  if (status === 'running') return <Loader className="w-3 h-3 text-safe animate-spin" />
  if (status === 'completed') return <CheckCircle className="w-3 h-3 text-safe" />
  if (status === 'failed') return <XCircle className="w-3 h-3 text-threat" />
  if (type === 'decision') return <GitBranch className="w-3 h-3 text-ink-500" />
  if (type === 'notify')   return <Terminal className="w-3 h-3 text-ink-500" />
  if (type === 'action')   return <Zap className="w-3 h-3 text-ink-500" />
  return <Clock className="w-3 h-3 text-ink-500" />
}

const STATUS_STYLE: Record<PBStatus, string> = {
  idle:      'bg-white/5 border-white/10 text-ink-400',
  running:   'bg-safe/10 border-safe/25 text-safe',
  completed: 'bg-violet/10 border-violet/25 text-violet',
  failed:    'bg-threat/10 border-threat/25 text-threat',
}

/* ── Playbook card ───────────────────────────────────────────────── */
function PlaybookCard({ pb }: { pb: Playbook }) {
  const [expanded, setExpanded] = useState(pb.status === 'running')

  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div
        className="flex items-start gap-4 p-4 cursor-pointer hover:bg-white/2 transition-colors"
        onClick={() => setExpanded((e) => !e)}
      >
        <div className={cn('mt-0.5 w-2 h-2 rounded-full shrink-0',
          pb.status === 'running' ? 'bg-safe animate-pulse' :
          pb.status === 'completed' ? 'bg-violet' :
          pb.status === 'failed' ? 'bg-threat' : 'bg-ink-600',
        )} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-semibold text-white">{pb.name}</span>
            <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border font-semibold uppercase', STATUS_STYLE[pb.status])}>
              {pb.status}
            </span>
          </div>
          <p className="text-xs text-ink-400 mb-2">{pb.description}</p>
          <div className="flex items-center gap-4 text-[10px] text-ink-600">
            <span>Trigger: <span className="text-ink-400">{pb.trigger}</span></span>
            <span>Last: <span className="text-ink-400">{pb.lastRun}</span></span>
            <span>{pb.runs} runs · avg {pb.avgTime}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors">
            {pb.status === 'running' ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>
          <ChevronRight className={cn('w-3.5 h-3.5 text-ink-600 transition-transform', expanded && 'rotate-90')} />
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-white/5"
          >
            <div className="px-4 py-4">
              <p className="text-[9px] font-semibold uppercase tracking-widest text-ink-600 mb-3">Workflow Steps</p>
              <div className="space-y-2">
                {pb.steps.map((step, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <div className="flex flex-col items-center">
                      <StepIcon type={step.type} status={step.status} />
                      {i < pb.steps.length - 1 && <div className="w-px h-4 bg-white/5 mt-1" />}
                    </div>
                    <span className={cn(
                      'text-xs',
                      step.status === 'completed' ? 'text-ink-400 line-through' :
                      step.status === 'running' ? 'text-safe' :
                      step.status === 'failed' ? 'text-threat' : 'text-ink-500',
                    )}>
                      {step.name}
                    </span>
                    {step.type === 'decision' && (
                      <span className="text-[9px] px-1 py-0.5 rounded bg-amber/10 text-amber border border-amber/20 ml-auto">Branch</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function SOARPage() {
  return (
    <div className="p-6 space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Active Cases',       value: '5',     icon: AlertTriangle, color: '#FF2E97' },
          { label: 'Automated Actions',  value: '1,847', icon: Zap,           color: '#7A3CFF' },
          { label: 'MTTD',              value: '4m 12s', icon: Clock,         color: '#FFB23E' },
          { label: 'MTTR',              value: '38m',    icon: RefreshCw,     color: '#2DD4BF' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="glass border border-white/5 rounded-xl p-4 flex items-center gap-4">
            <div className="p-2.5 rounded-xl" style={{ background: `${color}18` }}>
              <Icon className="w-4 h-4" style={{ color }} />
            </div>
            <div>
              <p className="text-xs text-ink-500">{label}</p>
              <p className="font-display text-xl font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Playbooks */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between mb-1">
            <h2 className="text-sm font-semibold text-white">Playbooks</h2>
            <button className="flex items-center gap-1.5 text-xs text-magenta hover:underline">
              <Zap className="w-3 h-3" /> New Playbook
            </button>
          </div>
          {PLAYBOOKS.map((pb) => <PlaybookCard key={pb.id} pb={pb} />)}
        </div>

        {/* Right panel */}
        <div className="space-y-4">
          {/* Case queue */}
          <div className="glass border border-white/5 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
              <h3 className="text-sm font-semibold text-white">Incident Queue</h3>
              <span className="text-[10px] text-ink-500">{CASES.length} open</span>
            </div>
            <div className="divide-y divide-white/4">
              {CASES.map((c) => (
                <div key={c.id} className="px-4 py-3 hover:bg-white/2 transition-colors cursor-pointer">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border font-bold', PRIORITY_COLOR[c.priority])}>
                      {c.priority}
                    </span>
                    <span className="font-mono text-[10px] text-ink-500">{c.id}</span>
                    <span className="text-[10px] text-ink-400 ml-auto">{c.analyst}</span>
                  </div>
                  <p className="text-xs text-ink-200 truncate">{c.title}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[9px] text-ink-600">{c.pb}</span>
                    <ArrowRight className="w-2.5 h-2.5 text-ink-700" />
                    <span className="text-[9px] text-ink-500">{c.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Automation stats */}
          <div className="glass border border-white/5 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4">Automation Coverage</h3>
            {[
              { label: 'Phishing',        pct: 94, color: '#7A3CFF' },
              { label: 'Brute Force',     pct: 99, color: '#2DD4BF' },
              { label: 'Ransomware',      pct: 88, color: '#FF2E97' },
              { label: 'Cloud IAM',       pct: 76, color: '#FFB23E' },
              { label: 'Vulnerability',   pct: 61, color: '#FF4D6D' },
            ].map(({ label, pct, color }) => (
              <div key={label} className="mb-3">
                <div className="flex justify-between mb-1 text-xs">
                  <span className="text-ink-300">{label}</span>
                  <span className="text-ink-500">{pct}%</span>
                </div>
                <div className="h-1.5 bg-surface-3 rounded-full">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.9 }}
                    className="h-full rounded-full"
                    style={{ background: color }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Action log */}
          <div className="glass border border-white/5 rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-white/5">
              <h3 className="text-sm font-semibold text-white">Recent Actions</h3>
            </div>
            <div className="divide-y divide-white/4">
              {[
                { action: 'IP blocked at perimeter',      pb: 'Brute Force',    time: '2m' },
                { action: 'Email quarantined (47 copies)', pb: 'Phishing',      time: '4m' },
                { action: 'Host isolated: WIN-HOST-44',   pb: 'Ransomware',     time: '8m' },
                { action: 'IAM permissions revoked',      pb: 'Cloud IAM',      time: '1h' },
                { action: 'CVE patch deployed to 24 hosts',pb: 'CVE Patch',     time: '2h' },
              ].map(({ action, pb, time }) => (
                <div key={action} className="flex items-center gap-3 px-4 py-2.5">
                  <Shield className="w-3 h-3 text-safe shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] text-ink-200 truncate">{action}</p>
                    <p className="text-[9px] text-ink-600">{pb}</p>
                  </div>
                  <span className="text-[10px] text-ink-600 shrink-0">{time} ago</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
