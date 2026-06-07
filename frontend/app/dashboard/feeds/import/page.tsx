'use client'

import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Upload, ClipboardPaste, FileText, CheckCircle, Tag as TagIcon,
  ShieldAlert, X, Globe, Hash, Link2, Bug, FileJson, FileCheck,
  Wand2,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type ImportMode = 'paste' | 'upload'
type TlpMarking = 'TLP:RED' | 'TLP:AMBER' | 'TLP:GREEN' | 'TLP:CLEAR'
type ConfidenceLevel = 'Low' | 'Medium' | 'High' | 'Confirmed'

interface ParsedIocs {
  ips: string[]
  domains: string[]
  hashes: string[]
  urls: string[]
  cves: string[]
}

interface ImportHistoryEntry {
  id: string
  filename: string
  count: number
  date: string
  user: string
  status: 'completed' | 'partial' | 'failed'
}

const HISTORY: ImportHistoryEntry[] = [
  { id: 'h1', filename: 'apt29_ioc_dump.csv',        count: 1842, date: '2026-06-06 14:22', user: 'm.chen',     status: 'completed' },
  { id: 'h2', filename: 'phishing_campaign.txt',     count: 318,  date: '2026-06-05 09:10', user: 'a.okafor',   status: 'completed' },
  { id: 'h3', filename: 'misp_export_event_4471.json', count: 2204, date: '2026-06-04 17:48', user: 's.ivanova', status: 'partial' },
  { id: 'h4', filename: 'ransomware_hashes.txt',     count: 96,   date: '2026-06-03 11:33', user: 'm.chen',     status: 'completed' },
  { id: 'h5', filename: 'c2_infrastructure.stix',    count: 540,  date: '2026-06-02 08:05', user: 'd.rossi',    status: 'failed' },
]

const TLP_OPTIONS: { value: TlpMarking; color: string }[] = [
  { value: 'TLP:RED',   color: 'text-threat bg-threat/10 border-threat/30' },
  { value: 'TLP:AMBER', color: 'text-amber bg-amber/10 border-amber/30' },
  { value: 'TLP:GREEN', color: 'text-safe bg-safe/10 border-safe/30' },
  { value: 'TLP:CLEAR', color: 'text-ink-200 bg-white/5 border-white/15' },
]

const CONFIDENCE_OPTIONS: ConfidenceLevel[] = ['Low', 'Medium', 'High', 'Confirmed']

const SUPPORTED_FORMATS = [
  { ext: '.csv',  label: 'Comma-separated values', icon: FileText },
  { ext: '.txt',  label: 'Plain-text indicator list', icon: FileText },
  { ext: '.json', label: 'MISP / generic JSON', icon: FileJson },
  { ext: '.stix', label: 'STIX 2.1 bundle', icon: FileCheck },
]

const STATUS_COLOR: Record<ImportHistoryEntry['status'], string> = {
  completed: 'text-safe bg-safe/10 border-safe/20',
  partial:   'text-amber bg-amber/10 border-amber/20',
  failed:    'text-threat bg-threat/10 border-threat/20',
}

// --- Regex IOC parser ---------------------------------------------------------
const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
const RE_SHA256 = /\b[a-fA-F0-9]{64}\b/g
const RE_SHA1 = /\b[a-fA-F0-9]{40}\b/g
const RE_MD5 = /\b[a-fA-F0-9]{32}\b/g
const RE_URL = /\b(?:https?|ftp):\/\/[^\s<>"')]+/gi
const RE_CVE = /\bCVE-\d{4}-\d{4,7}\b/gi
const RE_DOMAIN = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g

function refang(text: string): string {
  return text
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/\[dot\]/gi, '.')
    .replace(/\bhxxp(s?):\/\//gi, 'http$1://')
    .replace(/\bhxxp(s?)\[:\]\/\//gi, 'http$1://')
    .replace(/\[:\]/g, ':')
    .replace(/\[@\]/g, '@')
    .replace(/\[at\]/gi, '@')
}

function uniqMatches(text: string, re: RegExp): string[] {
  const matches = text.match(re)
  if (!matches) return []
  return Array.from(new Set(matches.map(m => m.toLowerCase())))
}

function parseIocs(rawText: string, doRefang: boolean): ParsedIocs {
  const text = doRefang ? refang(rawText) : rawText

  const urls = uniqMatches(text, RE_URL)
  const ips = uniqMatches(text, RE_IPV4)
  const cves = uniqMatches(text, RE_CVE)

  const hashes = Array.from(
    new Set([
      ...uniqMatches(text, RE_SHA256),
      ...uniqMatches(text, RE_SHA1),
      ...uniqMatches(text, RE_MD5),
    ]),
  )

  // Domains: exclude bare IPs and hostnames already captured inside URLs.
  const ipSet = new Set(ips)
  let urlHostBlob = ''
  for (const u of urls) {
    try {
      urlHostBlob += ' ' + new URL(u).hostname.toLowerCase()
    } catch {
      // ignore malformed url for host extraction
    }
  }
  const urlHosts = new Set(uniqMatches(urlHostBlob, RE_DOMAIN))

  const domains = uniqMatches(text, RE_DOMAIN).filter(d => !ipSet.has(d) && !urlHosts.has(d))

  return { ips, domains, hashes, urls, cves }
}

export default function ImportIocsPage() {
  const [mode, setMode] = useState<ImportMode>('paste')
  const [rawText, setRawText] = useState('')
  const [doRefang, setDoRefang] = useState(true)
  const [tags, setTags] = useState<string[]>(['triage'])
  const [tagDraft, setTagDraft] = useState('')
  const [tlp, setTlp] = useState<TlpMarking>('TLP:AMBER')
  const [confidence, setConfidence] = useState<ConfidenceLevel>('Medium')
  const [dragging, setDragging] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [showToast, setShowToast] = useState(false)

  const parsed = useMemo(() => parseIocs(rawText, doRefang), [rawText, doRefang])

  const totalCount =
    parsed.ips.length +
    parsed.domains.length +
    parsed.hashes.length +
    parsed.urls.length +
    parsed.cves.length

  const counts = [
    { label: 'IPs',     value: parsed.ips.length,     icon: Globe, color: 'text-violet' },
    { label: 'Domains', value: parsed.domains.length, icon: Link2, color: 'text-magenta' },
    { label: 'Hashes',  value: parsed.hashes.length,  icon: Hash,  color: 'text-safe' },
    { label: 'URLs',    value: parsed.urls.length,    icon: Bug,   color: 'text-amber' },
    { label: 'CVEs',    value: parsed.cves.length,    icon: ShieldAlert, color: 'text-threat' },
  ]

  const addTag = () => {
    const t = tagDraft.trim().toLowerCase()
    if (t && !tags.includes(t)) setTags(prev => [...prev, t])
    setTagDraft('')
  }

  const removeTag = (t: string) => setTags(prev => prev.filter(x => x !== t))

  const triggerImport = () => {
    if (totalCount === 0) return
    setShowToast(true)
    window.setTimeout(() => setShowToast(false), 3200)
  }

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files?.[0]
    if (f) setFileName(f.name)
  }

  const canImport = mode === 'paste' ? totalCount > 0 : fileName !== null

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-violet" />
            <h1 className="text-lg font-display font-semibold text-white">Import IOCs</h1>
          </div>
          <p className="text-xs text-ink-500 mt-0.5">Bulk import indicators from files or paste</p>
        </div>
        <button
          onClick={triggerImport}
          disabled={!canImport}
          className={cn(
            'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-opacity',
            canImport ? 'bg-plasma text-white' : 'bg-white/5 text-ink-600 cursor-not-allowed',
          )}
        >
          <CheckCircle className="w-3.5 h-3.5" />
          Import {mode === 'paste' ? totalCount : fileName ? '' : 0} indicators
        </button>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-5 divide-x divide-white/5 border-b border-white/5 shrink-0">
        {counts.map(({ label, value, color }) => (
          <div key={label} className="px-5 py-3">
            <div className={cn('text-xl font-bold font-mono', color)}>{value}</div>
            <div className="text-[10px] text-ink-600">{label}</div>
          </div>
        ))}
      </div>

      {/* Mode tabs */}
      <div className="flex items-center gap-2 px-6 py-3 border-b border-white/4 shrink-0">
        {([
          { id: 'paste' as const, label: 'Paste', icon: ClipboardPaste },
          { id: 'upload' as const, label: 'Upload File', icon: Upload },
        ]).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setMode(id)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
              mode === id
                ? 'bg-magenta/20 text-magenta border border-magenta/30'
                : 'bg-white/4 text-ink-500 border border-white/8 hover:text-ink-200',
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Body */}
      <div className="flex-1 overflow-auto px-6 py-5 space-y-6">
        <div className="grid lg:grid-cols-3 gap-5">
          {/* Left: input area */}
          <div className="lg:col-span-2 space-y-4">
            {mode === 'paste' ? (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs text-ink-400 font-medium">Paste indicators (IPs, domains, hashes, URLs, CVEs)</label>
                  <button
                    onClick={() => setDoRefang(v => !v)}
                    className={cn(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border transition-colors',
                      doRefang
                        ? 'text-safe bg-safe/10 border-safe/20'
                        : 'text-ink-500 bg-white/4 border-white/8 hover:text-ink-200',
                    )}
                  >
                    <Wand2 className="w-3 h-3" />
                    {doRefang ? 'Refang: On' : 'Refang: Off'}
                  </button>
                </div>
                <textarea
                  value={rawText}
                  onChange={e => setRawText(e.target.value)}
                  placeholder={'185.220.101.45\nhxxps://malicious[.]example[.]com/payload\n44d88612fea8a8f36de82e1278abb02f\nCVE-2024-3094\nevil-c2[.]net'}
                  spellCheck={false}
                  className="w-full h-80 bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-xs font-mono text-ink-100 placeholder-ink-600 outline-none focus:border-magenta/30 resize-none leading-relaxed"
                />
                <p className="text-[10px] text-ink-600 mt-1.5">
                  Live parsing detects and de-duplicates indicators as you type. Defanged input (hxxp, 1.1.1[.]1) is normalized when Refang is on.
                </p>
              </div>
            ) : (
              <div>
                <div
                  onDragOver={e => { e.preventDefault(); setDragging(true) }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={onDrop}
                  className={cn(
                    'flex flex-col items-center justify-center h-80 rounded-xl border-2 border-dashed transition-colors text-center px-6',
                    dragging ? 'border-magenta/50 bg-magenta/5' : 'border-white/10 bg-white/3',
                  )}
                >
                  <Upload className={cn('w-10 h-10 mb-3', dragging ? 'text-magenta' : 'text-ink-500')} />
                  {fileName ? (
                    <div className="flex items-center gap-2">
                      <FileCheck className="w-4 h-4 text-safe" />
                      <span className="text-sm text-ink-100 font-mono">{fileName}</span>
                      <button onClick={() => setFileName(null)} className="p-1 rounded hover:bg-white/8 text-ink-500">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ) : (
                    <>
                      <p className="text-sm text-ink-200 font-medium">Drag &amp; drop a file here</p>
                      <p className="text-xs text-ink-500 mt-1">or click to browse — .csv .txt .json .stix</p>
                    </>
                  )}
                  <label className="mt-4 px-3 py-1.5 rounded-lg glass border border-white/10 text-xs text-ink-300 hover:text-white cursor-pointer">
                    Choose file
                    <input
                      type="file"
                      accept=".csv,.txt,.json,.stix"
                      className="hidden"
                      onChange={e => {
                        const f = e.target.files?.[0]
                        if (f) setFileName(f.name)
                      }}
                    />
                  </label>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3">
                  {SUPPORTED_FORMATS.map(({ ext, label, icon: Icon }) => (
                    <div key={ext} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/3 border border-white/8">
                      <Icon className="w-4 h-4 text-violet shrink-0" />
                      <div className="min-w-0">
                        <p className="text-xs font-mono text-ink-200">{ext}</p>
                        <p className="text-[10px] text-ink-600 truncate">{label}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right: live preview + metadata */}
          <div className="space-y-4">
            <div className="rounded-xl border border-white/8 bg-white/3 p-4">
              <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-3">Detected Indicators</p>
              <div className="space-y-2.5">
                {counts.map(({ label, value, icon: Icon, color }) => (
                  <div key={label} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon className={cn('w-3.5 h-3.5', color)} />
                      <span className="text-xs text-ink-300">{label}</span>
                    </div>
                    <span className={cn('text-sm font-mono font-bold', value > 0 ? color : 'text-ink-600')}>{value}</span>
                  </div>
                ))}
              </div>
              <div className="mt-3 pt-3 border-t border-white/8 flex items-center justify-between">
                <span className="text-xs text-ink-400 font-medium">Total unique</span>
                <span className="text-base font-mono font-bold text-white">{totalCount}</span>
              </div>
            </div>

            {/* Tags */}
            <div className="rounded-xl border border-white/8 bg-white/3 p-4">
              <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <TagIcon className="w-3 h-3" /> Batch Tags
              </p>
              <div className="flex flex-wrap gap-1.5 mb-2">
                {tags.map(t => (
                  <span key={t} className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-violet/10 text-violet border border-violet/20 font-mono">
                    {t}
                    <button onClick={() => removeTag(t)} className="hover:text-white">
                      <X className="w-2.5 h-2.5" />
                    </button>
                  </span>
                ))}
              </div>
              <input
                value={tagDraft}
                onChange={e => setTagDraft(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag() } }}
                placeholder="Add tag + Enter"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-ink-600 outline-none focus:border-magenta/30"
              />
            </div>

            {/* TLP */}
            <div className="rounded-xl border border-white/8 bg-white/3 p-4">
              <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-2">TLP Marking</p>
              <div className="grid grid-cols-2 gap-1.5">
                {TLP_OPTIONS.map(({ value, color }) => (
                  <button
                    key={value}
                    onClick={() => setTlp(value)}
                    className={cn(
                      'px-2 py-1 rounded-lg border text-[10px] font-bold font-mono transition-all',
                      tlp === value ? color : 'text-ink-500 bg-white/4 border-white/8 hover:text-ink-200',
                    )}
                  >
                    {value}
                  </button>
                ))}
              </div>
            </div>

            {/* Confidence */}
            <div className="rounded-xl border border-white/8 bg-white/3 p-4">
              <p className="text-[10px] text-ink-600 uppercase tracking-wider mb-2">Confidence</p>
              <div className="flex gap-1.5">
                {CONFIDENCE_OPTIONS.map(c => (
                  <button
                    key={c}
                    onClick={() => setConfidence(c)}
                    className={cn(
                      'flex-1 px-2 py-1 rounded-lg border text-[10px] font-medium transition-colors',
                      confidence === c
                        ? 'bg-magenta/20 text-magenta border-magenta/30'
                        : 'text-ink-500 bg-white/4 border-white/8 hover:text-ink-200',
                    )}
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Recent imports history */}
        <div>
          <h2 className="text-xs text-ink-400 font-semibold uppercase tracking-wider mb-2">Recent Imports</h2>
          <div className="rounded-xl border border-white/8 overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-white/3 border-b border-white/8">
                <tr>
                  {['Filename', 'Count', 'Date', 'User', 'Status'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] text-ink-500 font-semibold uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {HISTORY.map((h, i) => (
                  <tr key={h.id} className={cn('border-b border-white/4', i % 2 !== 0 && 'bg-white/[0.01]')}>
                    <td className="px-4 py-3 font-mono text-ink-200">{h.filename}</td>
                    <td className="px-4 py-3 font-mono text-violet text-right">{h.count.toLocaleString()}</td>
                    <td className="px-4 py-3 font-mono text-ink-500 whitespace-nowrap">{h.date}</td>
                    <td className="px-4 py-3 text-ink-400">{h.user}</td>
                    <td className="px-4 py-3">
                      <span className={cn('px-2 py-0.5 rounded-full border text-[10px] font-semibold capitalize', STATUS_COLOR[h.status])}>
                        {h.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Success toast */}
      <AnimatePresence>
        {showToast && (
          <motion.div
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.96 }}
            className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border border-safe/30 bg-surface-2 glass shadow-card"
          >
            <motion.span
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 400, damping: 16 }}
              className="flex items-center justify-center w-8 h-8 rounded-full bg-safe/15"
            >
              <CheckCircle className="w-5 h-5 text-safe" />
            </motion.span>
            <div>
              <p className="text-sm font-semibold text-white">Import queued</p>
              <p className="text-[11px] text-ink-400">
                {totalCount} indicators · {tlp} · {confidence} confidence
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
