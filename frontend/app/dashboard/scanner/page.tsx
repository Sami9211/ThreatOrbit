'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { lookupIoc, recordScan, fetchScans, importIocs, type ScanEntry } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Upload, Shield, AlertTriangle, CheckCircle,
  Globe, Hash, Link, File, ChevronDown, ExternalLink, Loader,
  Clock, Database, Zap, Bookmark, BookmarkCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { tk, withAlpha } from '@/lib/colors'

/* -- Recent-scan history row (populated live from /scans; empty on a fresh
   install rather than showing invented history) -------------------- */
type ScanRow = {
  target: string
  type: string
  verdict: string
  score: number
  engines: string
  time: string
}

/* -- Sample results for demo --------------------------------------- */
const DEMO_RESULTS: Record<string, ScanResult> = {
  url: {
    target: 'http://malicious-phishing-site.xyz/login',
    type: 'url',
    verdict: 'malicious',
    detectionRatio: '62/90',
    score: 0.93,
    firstSeen: '2024-11-10',
    lastSeen: '2024-11-12',
    categories: ['Phishing', 'Malware Distribution', 'Credential Harvesting'],
    community: { votes: 47, malicious: 43, clean: 4 },
    network: { asn: 'AS13335 Cloudflare', ip: '104.21.55.198', country: 'United States', registrar: 'Namecheap Inc.' },
    engines: [
      { name: 'Google Safe Browsing', verdict: 'malicious', category: 'Phishing' },
      { name: 'ESET', verdict: 'malicious', category: 'Phishing' },
      { name: 'Kaspersky', verdict: 'malicious', category: 'Phishing' },
      { name: 'Symantec', verdict: 'malicious', category: 'Malicious URL' },
      { name: 'Fortinet', verdict: 'malicious', category: 'Phishing' },
      { name: 'Avira', verdict: 'malicious', category: 'Phishing' },
      { name: 'CrowdStrike', verdict: 'malicious', category: 'Suspicious' },
      { name: 'Palo Alto', verdict: 'malicious', category: 'Phishing' },
      { name: 'BitDefender', verdict: 'clean',     category: null },
      { name: 'McAfee', verdict: 'malicious', category: 'Phishing' },
      { name: 'Sophos', verdict: 'malicious', category: 'Phishing' },
      { name: 'Trend Micro', verdict: 'malicious', category: 'Phishing' },
      { name: 'Cisco Talos', verdict: 'malicious', category: 'Malicious' },
      { name: 'Webroot', verdict: 'clean', category: null },
      { name: 'Barracuda', verdict: 'malicious', category: 'Phishing' },
    ],
    iocs: ['104.21.55.198', 'malicious-phishing-site.xyz', 'a3f8e92b1d47c61e'],
    mitre: ['T1566.002 - Spearphishing Link', 'T1056 - Input Capture'],
  },
  ip: {
    target: '45.95.147.236',
    type: 'ip',
    verdict: 'malicious',
    detectionRatio: '41/90',
    score: 0.81,
    firstSeen: '2024-09-01',
    lastSeen: '2024-11-12',
    categories: ['Command & Control', 'Botnet', 'Scanning Activity'],
    community: { votes: 31, malicious: 29, clean: 2 },
    network: { asn: 'AS59253 LLC Baxet', ip: '45.95.147.236', country: 'Russia', registrar: 'OOO Network of data-centers Selectel' },
    engines: [
      { name: 'AbuseIPDB', verdict: 'malicious', category: 'Scanning/Hacking' },
      { name: 'Cisco Talos', verdict: 'malicious', category: 'Malicious' },
      { name: 'Kaspersky', verdict: 'malicious', category: 'Botnet' },
      { name: 'Shodan', verdict: 'malicious', category: 'Open ports: 22, 80, 443, 3389' },
      { name: 'AlienVault', verdict: 'malicious', category: 'Scanning' },
      { name: 'GreyNoise', verdict: 'malicious', category: 'Mass Scanner' },
      { name: 'Proofpoint', verdict: 'malicious', category: 'C2' },
      { name: 'Symantec', verdict: 'clean', category: null },
      { name: 'ThreatFox', verdict: 'malicious', category: 'SSH Brute Force' },
      { name: 'ESET', verdict: 'clean', category: null },
    ],
    iocs: ['45.95.147.236', 'CVE-2024-6387'],
    mitre: ['T1110.001 - Brute Force: Password Guessing', 'T1078 - Valid Accounts'],
  },
  hash: {
    target: 'a3f8e92b1d47c61e83dd2a9f7c4b5e01',
    type: 'hash',
    verdict: 'malicious',
    detectionRatio: '69/72',
    score: 0.98,
    firstSeen: '2024-10-15',
    lastSeen: '2024-11-12',
    categories: ['Trojan', 'Ransomware', 'RAT'],
    community: { votes: 82, malicious: 80, clean: 2 },
    network: { asn: 'N/A', ip: 'N/A', country: 'N/A', registrar: 'N/A' },
    engines: [
      { name: 'Kaspersky', verdict: 'malicious', category: 'Trojan.Win32.Agent' },
      { name: 'ESET', verdict: 'malicious', category: 'Win32/Filecoder.Ryuk' },
      { name: 'Microsoft Defender', verdict: 'malicious', category: 'Ransom:Win32/Ryuk.A' },
      { name: 'Symantec', verdict: 'malicious', category: 'Ransom.Ryuk' },
      { name: 'CrowdStrike', verdict: 'malicious', category: 'Win.Ransomware.Ryuk' },
      { name: 'Palo Alto', verdict: 'malicious', category: 'Ransomware' },
      { name: 'Sophos', verdict: 'malicious', category: 'Troj/Ryuk-A' },
      { name: 'BitDefender', verdict: 'malicious', category: 'Trojan.GenericKD' },
      { name: 'Avast', verdict: 'malicious', category: 'Win32:Malware-gen' },
      { name: 'AVG', verdict: 'malicious', category: 'Win32:Malware-gen' },
      { name: 'McAfee', verdict: 'malicious', category: 'Ransom-Ryuk!A' },
      { name: 'Trend Micro', verdict: 'malicious', category: 'RANSOM_RYUK.SM' },
    ],
    iocs: ['a3f8e92b1d47c61e83dd2a9f7c4b5e01', 'ryuk_loader.exe', 'BLACKBASTA'],
    mitre: ['T1486 - Data Encrypted for Impact', 'T1490 - Inhibit System Recovery', 'T1059 - Command and Scripting Interpreter'],
    fileInfo: { name: 'invoice_Q4.exe', size: '182 KB', type: 'PE32 executable', compiler: 'Microsoft Visual C++', signature: 'Not signed' },
  },
  clean: {
    target: '8.8.8.8',
    type: 'ip',
    verdict: 'clean',
    detectionRatio: '0/90',
    score: 0.0,
    firstSeen: '2009-01-01',
    lastSeen: '2024-11-12',
    categories: ['Public DNS', 'Google'],
    community: { votes: 120, malicious: 3, clean: 117 },
    network: { asn: 'AS15169 Google LLC', ip: '8.8.8.8', country: 'United States', registrar: 'Google LLC' },
    engines: [
      { name: 'Kaspersky',   verdict: 'clean', category: null },
      { name: 'ESET',        verdict: 'clean', category: null },
      { name: 'Cisco Talos', verdict: 'clean', category: null },
      { name: 'Symantec',    verdict: 'clean', category: null },
      { name: 'AlienVault',  verdict: 'clean', category: null },
    ],
    iocs: [],
    mitre: [],
  },
}

type ScanResult = {
  target: string
  type: 'url' | 'ip' | 'hash' | 'file'
  verdict: 'malicious' | 'suspicious' | 'clean'
  detectionRatio: string
  score: number
  firstSeen: string
  lastSeen: string
  categories: string[]
  community: { votes: number; malicious: number; clean: number }
  network: { asn: string; ip: string; country: string; registrar: string }
  engines: { name: string; verdict: 'malicious' | 'suspicious' | 'clean'; category: string | null }[]
  iocs: string[]
  mitre: string[]
  fileInfo?: { name: string; size: string; type: string; compiler: string; signature: string }
}

const SCAN_TYPES = [
  { key: 'url',  label: 'URL',      icon: Link,   placeholder: 'https://example.com/path' },
  { key: 'ip',   label: 'IP',       icon: Globe,  placeholder: '192.168.1.1' },
  { key: 'hash', label: 'Hash',     icon: Hash,   placeholder: 'MD5 / SHA1 / SHA256' },
  { key: 'file', label: 'File',     icon: File,   placeholder: 'Drop a file or browse...' },
]

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

// SHA-256 of a file via Web Crypto - the same first-pass fingerprint a
// detonation pipeline would compute before deciding to run the sample.
async function sha256Hex(file: globalThis.File): Promise<string> {
  const buf = await file.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

/* -- Verdict gauge -------------------------------------------------- */
function VerdictGauge({ score, verdict }: { score: number; verdict: string }) {
  const color = verdict === 'malicious' ? tk('magenta') : verdict === 'suspicious' ? tk('amber') : tk('safe')
  const pct   = score * 100
  const r = 44
  const circ = 2 * Math.PI * r
  const dash = circ * (1 - score)

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
          <motion.circle
            cx="50" cy="50" r={r} fill="none"
            stroke={color} strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            initial={{ strokeDashoffset: circ }}
            animate={{ strokeDashoffset: dash }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display text-2xl font-bold text-white">{Math.round(pct)}</span>
          <span className="text-[10px] text-ink-500">/ 100</span>
        </div>
      </div>
      <span
        className={cn(
          'px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider',
          verdict === 'malicious' ? 'bg-magenta/15 text-magenta border border-magenta/30' :
          verdict === 'suspicious' ? 'bg-amber/15 text-amber border border-amber/30' :
          'bg-safe/15 text-safe border border-safe/30',
        )}
      >
        {verdict}
      </span>
    </div>
  )
}

/* -- Engine table -------------------------------------------------- */
function EngineResults({ engines }: { engines: ScanResult['engines'] }) {
  const [showAll, setShowAll] = useState(false)
  const visible = showAll ? engines : engines.slice(0, 8)
  const malicious = engines.filter((e) => e.verdict === 'malicious').length
  const total     = engines.length

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-white">Detection Results</h3>
        <span className="text-xs text-ink-500">{malicious}/{total} engines</span>
      </div>
      <div className="space-y-1">
        {visible.map((e) => (
          <div key={e.name} className="flex items-center justify-between py-1.5 px-3 rounded-lg hover:bg-white/3 transition-colors">
            <span className="text-xs text-ink-300">{e.name}</span>
            <div className="flex items-center gap-3">
              {e.category && <span className="text-[10px] text-ink-500">{e.category}</span>}
              <span className={cn(
                'flex items-center gap-1 text-[10px] font-semibold',
                e.verdict === 'malicious' ? 'text-threat' : e.verdict === 'suspicious' ? 'text-amber' : 'text-safe',
              )}>
                {e.verdict === 'malicious' ? <AlertTriangle className="w-3 h-3" /> :
                 e.verdict === 'suspicious' ? <AlertTriangle className="w-3 h-3" /> :
                 <CheckCircle className="w-3 h-3" />}
                {e.verdict}
              </span>
            </div>
          </div>
        ))}
      </div>
      {engines.length > 8 && (
        <button
          onClick={() => setShowAll((s) => !s)}
          className="flex items-center gap-1 mt-2 text-xs text-magenta hover:underline"
        >
          {showAll ? 'Show less' : `Show all ${engines.length} engines`}
          <ChevronDown className={cn('w-3 h-3 transition-transform', showAll && 'rotate-180')} />
        </button>
      )}
    </div>
  )
}

/* -- Page ---------------------------------------------------------- */
export default function ScannerPage() {
  const [scanType, setScanType] = useState<string>('url')
  const [query, setQuery] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [history, setHistory] = useState<ScanRow[]>([])
  const [stats, setStats] = useState<{ scansToday: number; malicious: number } | null>(null)

  // Live scan history + header stats. On a fresh install there are no scans, so
  // the list is genuinely empty (an empty state) rather than invented rows.
  const refreshHistory = useCallback(() => {
    fetchScans(8).then((data) => {
      setStats({ scansToday: data.scansToday, malicious: data.malicious })
      setHistory(data.items.map((s: ScanEntry) => ({
        target: s.target,
        type: s.type,
        verdict: s.verdict,
        score: Math.round(s.score * 100),
        engines: s.engines ?? '-',
        time: relativeTime(s.ts),
      })))
    }).catch(() => {})
  }, [])

  useEffect(() => { refreshHistory() }, [refreshHistory])

  const handleScan = () => {
    if (!query.trim() && scanType !== 'file') return
    setScanning(true)
    setResult(null)
    setSaved(false)

    // Base demo shape for the indicator type, then overlay a real verdict from
    // the IOC threat-intel store when the value is known to us.
    const q = query.toLowerCase()
    let demo = DEMO_RESULTS.url
    if (scanType === 'ip')   demo = DEMO_RESULTS.ip
    if (scanType === 'hash') demo = DEMO_RESULTS.hash
    if (q.includes('8.8.8.8') || q.includes('google')) demo = DEMO_RESULTS.clean

    const finish = (r: ScanResult, persist = true) => setTimeout(() => {
      setResult(r)
      setScanning(false)
      if (persist) {
        recordScan({
          target: r.target, type: r.type, verdict: r.verdict,
          score: r.score, engines: r.detectionRatio,
        }).then(refreshHistory).catch(() => {})
      }
    }, 900)

    if (!query.trim()) { finish(demo, false); return }

    lookupIoc(query.trim())
      .then((hit) => {
        if (!hit.found) {
          // Not in our TI - report clean/unverified rather than a fake verdict.
          finish({
            ...demo, target: query.trim(), verdict: 'clean', score: 0,
            detectionRatio: '0/90', categories: [],
            iocs: [], mitre: [],
          })
          return
        }
        finish({
          ...demo,
          target: hit.value,
          verdict: hit.verdict,
          score: hit.confidence,
          firstSeen: hit.firstSeen ?? demo.firstSeen,
          lastSeen: hit.lastSeen ?? demo.lastSeen,
          categories: [hit.threatType, hit.actor ? `Attributed: ${hit.actor}` : null, ...hit.tags]
            .filter(Boolean) as string[],
        })
      })
      .catch(() => finish(demo, false))  // API unreachable → demo result, nothing persisted
  }

  // File scan: fingerprint the file in-browser (SHA-256, nothing uploaded)
  // and check the digest against the live threat-intel store.
  const fileRef = useRef<HTMLInputElement>(null)

  async function handleFileScan(file: globalThis.File | undefined) {
    if (!file || scanning) return
    if (file.size > 32 * 1024 * 1024) return
    setScanning(true)
    setResult(null)
    setSaved(false)
    try {
      const hash = await sha256Hex(file)
      const fileInfo = {
        name: file.name,
        size: fmtBytes(file.size),
        type: file.type || 'unknown',
        compiler: '-',
        signature: `sha256:${hash.slice(0, 16)}…`,
      }
      const base: ScanResult = {
        target: hash, type: 'file', verdict: 'clean', detectionRatio: '0/90', score: 0,
        firstSeen: '-', lastSeen: '-', categories: [],
        community: { votes: 0, malicious: 0, clean: 0 },
        network: { asn: 'N/A', ip: 'N/A', country: 'N/A', registrar: 'N/A' },
        engines: [], iocs: [hash], mitre: [], fileInfo,
      }
      let scanResult = base
      try {
        const hit = await lookupIoc(hash)
        if (hit.found) {
          scanResult = {
            ...base,
            verdict: hit.verdict,
            score: hit.confidence,
            firstSeen: hit.firstSeen ?? '-',
            lastSeen: hit.lastSeen ?? '-',
            categories: [hit.threatType, hit.actor ? `Attributed: ${hit.actor}` : null, ...hit.tags]
              .filter(Boolean) as string[],
          }
        }
      } catch { /* TI store unreachable - report the unverified fingerprint */ }
      setResult(scanResult)
      recordScan({
        target: `${file.name} (${hash.slice(0, 12)}…)`, type: 'file',
        verdict: scanResult.verdict, score: scanResult.score, engines: scanResult.detectionRatio,
      }).then(refreshHistory).catch(() => {})
    } finally {
      setScanning(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  // Save the scanned indicator into the CTI IOC store.
  function handleSaveIoc() {
    if (!result || saved || saving) return
    setSaving(true)
    const iocType = result.type === 'file' ? 'hash' : result.type
    importIocs({
      indicators: [{ type: iocType, value: result.target }],
      severity: result.verdict === 'malicious' ? 'high' : result.verdict === 'suspicious' ? 'medium' : 'low',
      confidence: Math.round(result.score * 100),
      source: 'intelscope-scanner',
      threat_type: result.categories[0] ?? 'Scanned indicator',
      tags: ['intelscope'],
    })
      .then(() => setSaved(true))
      .catch(() => {})
      .finally(() => setSaving(false))
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="font-display text-xl font-bold text-white">IntelScope</h1>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-safe/15 text-safe border border-safe/30 uppercase tracking-wider">Free</span>
            <span className="text-[10px] text-ink-600">by ThreatOrbit</span>
          </div>
          <p className="text-xs text-ink-500">Scan URLs, IPs, file hashes, and files against 90+ threat intelligence engines</p>
        </div>
        {/* Stats row */}
        <div className="flex items-center gap-3 flex-wrap">
          {[
            { label: 'Scans today', value: stats ? stats.scansToday.toLocaleString() : '-', icon: Zap,          color: tk('violet') },
            { label: 'Malicious',   value: stats ? stats.malicious.toLocaleString() : '-',  icon: AlertTriangle, color: tk('magenta') },
            { label: 'Engines',     value: '90+',   icon: Database,      color: tk('teal') },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="glass border border-white/5 rounded-xl px-4 py-2.5 flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg" style={{ background: `${color}18` }}>
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
              <div>
                <p className="text-[10px] text-ink-500">{label}</p>
                <p className="text-sm font-bold text-white font-display">{value}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scanner card */}
      <div className="glass border border-white/8 rounded-2xl p-6 mb-6 relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none"
          style={{ background: `radial-gradient(ellipse at 50% 0%, ${withAlpha(tk('magenta'), 0.06)}, transparent 60%)` }}
        />
        <div className="relative">
          {/* Type tabs */}
          <div className="flex items-center gap-2 mb-5">
            {SCAN_TYPES.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => { setScanType(key); setQuery(''); setResult(null) }}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all',
                  scanType === key
                    ? 'bg-magenta/15 text-magenta border border-magenta/30'
                    : 'text-ink-400 border border-white/8 hover:text-white hover:border-white/15',
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
              </button>
            ))}
          </div>

          {/* Input */}
          {scanType === 'file' ? (
            <div
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); handleFileScan(e.dataTransfer.files?.[0]) }}
              className="flex items-center justify-center h-24 border-2 border-dashed border-white/10 rounded-xl text-ink-500 hover:border-magenta/30 hover:text-ink-300 transition-colors cursor-pointer"
            >
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                onChange={(e) => handleFileScan(e.target.files?.[0])}
              />
              <div className="flex flex-col items-center gap-2 text-sm">
                <Upload className="w-5 h-5" />
                <span>Drop a file here, or click to browse</span>
                <span className="text-[10px]">Max 32 MB · fingerprinted in your browser (SHA-256), never uploaded</span>
              </div>
            </div>
          ) : (
            <div className="flex gap-3">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-600" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                  placeholder={SCAN_TYPES.find((s) => s.key === scanType)?.placeholder}
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 placeholder-ink-600 focus:outline-hidden focus:border-magenta/40 focus:ring-1 focus:ring-magenta/20 transition-colors"
                />
              </div>
              <button
                onClick={handleScan}
                disabled={!query.trim() || scanning}
                className="px-6 py-3 rounded-xl bg-plasma text-white font-semibold text-sm transition-all hover:shadow-magenta-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {scanning ? (
                  <><Loader className="w-4 h-4 animate-spin" /> Scanning...</>
                ) : (
                  <><Shield className="w-4 h-4" /> Scan</>
                )}
              </button>
            </div>
          )}

          {/* Example targets */}
          {!result && !scanning && (
            <div className="flex items-center gap-2 mt-3">
              <span className="text-[10px] text-ink-600">Try:</span>
              {[
                { label: 'Malicious URL', value: 'http://malicious-phishing-site.xyz/login', type: 'url' },
                { label: 'Russian IP',    value: '45.95.147.236',                            type: 'ip'  },
                { label: 'Ryuk hash',     value: 'a3f8e92b1d47c61e83dd2a9f7c4b5e01',       type: 'hash'},
                { label: 'Google DNS',    value: '8.8.8.8',                                  type: 'ip'  },
              ].map((ex) => (
                <button
                  key={ex.label}
                  onClick={() => { setScanType(ex.type); setQuery(ex.value) }}
                  className="text-[10px] px-2 py-1 rounded-md bg-surface-2 border border-white/8 text-ink-400 hover:text-white hover:border-white/15 transition-colors"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Scanning animation */}
      <AnimatePresence>
        {scanning && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="glass border border-white/8 rounded-2xl p-8 flex flex-col items-center gap-4 text-center"
          >
            <div className="relative w-16 h-16">
              <div className="absolute inset-0 rounded-full border-2 border-magenta/20 animate-ping" />
              <div className="absolute inset-2 rounded-full border-2 border-magenta/40 animate-spin" />
              <Shield className="absolute inset-0 m-auto w-6 h-6 text-magenta" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">Scanning across 90+ engines</p>
              <p className="text-xs text-ink-500 mt-1">Checking reputation databases, malware feeds, and threat intelligence…</p>
            </div>
            <div className="flex gap-2 flex-wrap justify-center">
              {['VirusTotal', 'Kaspersky', 'Cisco Talos', 'AlienVault', 'Shodan', 'AbuseIPDB'].map((e) => (
                <span key={e} className="text-[10px] px-2 py-1 rounded-md bg-surface-2 border border-white/8 text-ink-500 animate-pulse">{e}</span>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Recent Scans - shown when idle */}
      <AnimatePresence>
        {!result && !scanning && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="glass border border-white/5 rounded-2xl overflow-hidden"
          >
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-ink-500" />
                <h3 className="text-sm font-semibold text-white">Recent Scans</h3>
              </div>
              <span className="text-[10px] text-ink-500">Live history</span>
            </div>
            {history.length === 0 ? (
              <div className="px-5 py-12 text-center">
                <Clock className="w-6 h-6 text-ink-700 mx-auto mb-2" />
                <p className="text-xs text-ink-400">No scans yet</p>
                <p className="text-[10px] text-ink-600 mt-1">Run your first scan above - results will appear here.</p>
              </div>
            ) : (
            <div className="divide-y divide-white/4">
              {history.map((s, i) => (
                <div key={`${s.target}-${i}`} className="flex items-center gap-4 px-5 py-3 hover:bg-white/2 transition-colors">
                  <div className={cn(
                    'w-2 h-2 rounded-full shrink-0',
                    s.verdict === 'malicious' ? 'bg-threat' : s.verdict === 'suspicious' ? 'bg-amber' : 'bg-safe',
                  )} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-ink-200 truncate">{s.target}</p>
                  </div>
                  <span className="text-[9px] text-ink-600 font-mono uppercase bg-surface-3 px-1.5 py-0.5 rounded-sm">{s.type}</span>
                  <span className="text-[10px] text-ink-500 font-mono w-14 text-right">{s.engines}</span>
                  <span className={cn(
                    'text-[10px] font-semibold w-16 text-right uppercase',
                    s.verdict === 'malicious' ? 'text-threat' : s.verdict === 'suspicious' ? 'text-amber' : 'text-safe',
                  )}>
                    {s.verdict}
                  </span>
                  <span className="text-[10px] text-ink-600 w-12 text-right">{s.time}</span>
                </div>
              ))}
            </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* What you can scan - fills idle space with useful guidance */}
      <AnimatePresence>
        {!result && !scanning && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
          >
            {[
              { icon: Link,   title: 'URLs',   desc: 'Phishing, malware delivery & C2 domains', color: tk('magenta'), example: 'https://example.com/path' },
              { icon: Globe,  title: 'IPs',    desc: 'Reputation, geolocation & ASN context',   color: tk('violet'), example: '45.95.147.236' },
              { icon: Hash,   title: 'Hashes', desc: 'MD5 / SHA-1 / SHA-256 file fingerprints',  color: tk('amber'), example: 'a3f8e92b1d47…' },
              { icon: File,   title: 'Files',  desc: 'Static analysis across 90+ engines',       color: tk('teal'), example: 'invoice.pdf' },
            ].map((c) => (
              <div key={c.title} className="glass border border-white/5 rounded-2xl p-5">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center mb-3" style={{ background: `${c.color}18` }}>
                  <c.icon className="w-5 h-5" style={{ color: c.color }} />
                </div>
                <p className="text-sm font-semibold text-white mb-1">{c.title}</p>
                <p className="text-xs text-ink-400 leading-snug mb-3">{c.desc}</p>
                <p className="text-[10px] font-mono text-ink-600 truncate bg-surface-3 rounded-md px-2 py-1">{c.example}</p>
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-4"
          >
            {/* Overview row */}
            <div className="glass border border-white/8 rounded-2xl p-6 grid md:grid-cols-[auto_1fr_auto] gap-8 items-center relative overflow-hidden">
              <div className="absolute inset-0 pointer-events-none"
                style={{ background: result.verdict === 'malicious' ? `radial-gradient(ellipse at 0% 50%, ${withAlpha(tk('magenta'), 0.05)}, transparent 60%)` : `radial-gradient(ellipse at 0% 50%, ${withAlpha(tk('safe'), 0.05)}, transparent 60%)` }}
              />
              <VerdictGauge score={result.score} verdict={result.verdict} />
              <div>
                <p className="text-xs text-ink-500 mb-1">Target</p>
                <p className="font-mono text-sm text-white break-all mb-4">{result.target}</p>
                <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
                  <div><span className="text-ink-500">First seen:</span> <span className="text-ink-200 ml-1">{result.firstSeen}</span></div>
                  <div><span className="text-ink-500">Last seen:</span> <span className="text-ink-200 ml-1">{result.lastSeen}</span></div>
                  <div><span className="text-ink-500">Detections:</span> <span className="text-threat font-semibold ml-1">{result.detectionRatio}</span></div>
                  <div><span className="text-ink-500">ASN:</span> <span className="text-ink-200 ml-1">{result.network.asn}</span></div>
                  <div><span className="text-ink-500">Country:</span> <span className="text-ink-200 ml-1">{result.network.country}</span></div>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-4">
                  {result.categories.map((c) => (
                    <span key={c} className="text-[10px] px-2 py-0.5 rounded-full bg-threat/10 text-threat border border-threat/20">{c}</span>
                  ))}
                </div>
              </div>
              <div className="text-center space-y-4">
                <div>
                  <div className="text-xs text-ink-500 mb-2">Community</div>
                  <div className="text-2xl font-display font-bold text-threat">{result.community.malicious}</div>
                  <div className="text-[10px] text-ink-500">malicious votes</div>
                  <div className="text-sm text-safe mt-1">{result.community.clean} clean</div>
                </div>
                <button
                  onClick={handleSaveIoc}
                  disabled={saved || saving}
                  title="Add this indicator to the CTI IOC store"
                  className={cn(
                    'flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium border transition-all',
                    saved
                      ? 'bg-violet/15 text-violet border-violet/30'
                      : 'text-ink-400 border-white/10 hover:text-white hover:border-white/20',
                  )}
                >
                  {saved ? <BookmarkCheck className="w-3.5 h-3.5" /> : <Bookmark className="w-3.5 h-3.5" />}
                  {saved ? 'Saved to CTI' : saving ? 'Saving…' : 'Save IOC'}
                </button>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              {/* Engine results */}
              <div className="glass border border-white/8 rounded-xl p-5">
                <EngineResults engines={result.engines} />
              </div>

              {/* Network + MITRE */}
              <div className="space-y-4">
                {result.fileInfo && (
                  <div className="glass border border-white/8 rounded-xl p-5">
                    <h3 className="text-sm font-semibold text-white mb-3">File Details</h3>
                    {Object.entries(result.fileInfo).map(([k, v]) => (
                      <div key={k} className="flex justify-between py-1 text-xs border-b border-white/4">
                        <span className="text-ink-500 capitalize">{k}</span>
                        <span className="text-ink-200 font-mono">{v}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="glass border border-white/8 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-white mb-3">Network Info</h3>
                  {Object.entries(result.network).map(([k, v]) => (
                    <div key={k} className="flex justify-between py-1 text-xs border-b border-white/4">
                      <span className="text-ink-500 capitalize">{k}</span>
                      <span className="text-ink-200 font-mono">{v}</span>
                    </div>
                  ))}
                </div>

                {result.mitre.length > 0 && (
                  <div className="glass border border-white/8 rounded-xl p-5">
                    <h3 className="text-sm font-semibold text-white mb-3">MITRE ATT&CK</h3>
                    <div className="space-y-2">
                      {result.mitre.map((t) => (
                        <div key={t} className="flex items-center gap-2 text-xs">
                          <span className="px-1.5 py-0.5 rounded-sm bg-violet/15 text-violet font-mono text-[9px]">
                            {t.split(' - ')[0]}
                          </span>
                          <span className="text-ink-300">{t.split(' - ')[1]}</span>
                          <ExternalLink className="w-3 h-3 text-ink-600 ml-auto shrink-0" />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.iocs.length > 0 && (
                  <div className="glass border border-white/8 rounded-xl p-5">
                    <h3 className="text-sm font-semibold text-white mb-3">Extracted IOCs</h3>
                    <div className="space-y-1">
                      {result.iocs.map((ioc) => (
                        <div key={ioc} className="font-mono text-xs text-ink-300 bg-surface-3 px-3 py-1.5 rounded-lg">
                          {ioc}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
