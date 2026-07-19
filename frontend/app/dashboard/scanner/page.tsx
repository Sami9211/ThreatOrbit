'use client'

import { useState, useEffect, useCallback, useRef, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { lookupIoc, recordScan, fetchScans, importIocs, fetchScanEnrich, fetchEnrichers,
  fetchScanContext, type ScanEntry, type EnrichProvider, type ScanContext,
  type IocLookup } from '@/lib/api'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Upload, Shield, AlertTriangle, CheckCircle,
  Globe, Hash, Link, File, ChevronDown, ExternalLink, Loader,
  Clock, Database, Zap, Bookmark, BookmarkCheck, Layers, Network, Users,
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
  verdict: string
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
  /** Live results carry real provenance instead of the demo blocks. */
  source?: string | null            // which feed knew the indicator
  providers?: EnrichProvider[]      // real enrichment pipeline rows
  lookup?: IocLookup | null         // the raw TI-store record (Details tab)
  context?: ScanContext | null      // real relations from our own stores
  demo?: boolean                    // API unreachable - sample result, labeled
}

type ResultTab = 'details' | 'relations' | 'community' | 'sources'

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
  const color = verdict === 'malicious' ? tk('magenta')
    : verdict === 'suspicious' ? tk('amber')
    : verdict === 'unverified' || verdict === 'expired' ? tk('violet')
    : tk('safe')   // clean / benign
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
          verdict === 'unverified' || verdict === 'expired'
            ? 'bg-violet/15 text-violet border border-violet/30' :
          'bg-safe/15 text-safe border border-safe/30',
        )}
      >
        {verdict}
      </span>
    </div>
  )
}

/* -- Provider results (the honest engine panel) --------------------- */
const PROVIDER_LABEL: Record<string, string> = {
  internal: 'Internal telemetry',
  indicator: 'Indicator heuristics',
  rdap: 'RDAP registry',
  otx: 'AlienVault OTX',
  virustotal: 'VirusTotal',
  greynoise: 'GreyNoise',
  shodan: 'Shodan',
  whois: 'WHOIS',
}

function ProviderResults({ providers, unknown }: { providers: EnrichProvider[]; unknown: boolean }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-white">Intelligence Sources</h3>
        <span className="text-xs text-ink-500">
          {providers.filter((p) => p.available).length + 1} consulted
        </span>
      </div>
      <div className="space-y-1">
        {/* The TI store itself is always consulted first. */}
        <div className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-white/2">
          <span className="text-xs text-ink-300">ThreatOrbit TI store</span>
          <span className={cn('text-[10px] font-semibold', unknown ? 'text-ink-500' : 'text-threat')}>
            {unknown ? 'no record' : 'known indicator'}
          </span>
        </div>
        {providers.map((p) => (
          <div key={p.provider} className="flex items-center justify-between py-1.5 px-3 rounded-lg hover:bg-white/3 transition-colors">
            <span className={cn('text-xs', p.available ? 'text-ink-300' : 'text-ink-600')}>
              {PROVIDER_LABEL[p.provider] ?? p.provider}
              {p.cached && <span className="text-ink-600 ml-1.5 text-[9px]">cached</span>}
            </span>
            {p.available ? (
              <span className={cn(
                'flex items-center gap-1 text-[10px] font-semibold',
                p.verdict === 'malicious' ? 'text-threat'
                  : p.verdict === 'suspicious' ? 'text-amber'
                  : p.verdict === 'clean' || p.verdict === 'benign' ? 'text-safe' : 'text-ink-500',
              )}>
                {(p.verdict === 'malicious' || p.verdict === 'suspicious')
                  ? <AlertTriangle className="w-3 h-3" /> : <CheckCircle className="w-3 h-3" />}
                {p.verdict ?? 'no verdict'}
              </span>
            ) : (
              <span className="text-[10px] text-ink-600">not configured</span>
            )}
          </div>
        ))}
      </div>
      {providers.some((p) => p.available && p.summary) && (
        <div className="mt-3 space-y-1.5 border-t border-white/5 pt-3">
          {providers.filter((p) => p.available && p.summary).map((p) => (
            <p key={p.provider} className="text-[11px] text-ink-400 leading-snug">
              <span className="text-ink-200 font-medium">{PROVIDER_LABEL[p.provider] ?? p.provider}:</span>{' '}
              {p.summary}
            </p>
          ))}
        </div>
      )}
      <p className="text-[10px] text-ink-600 mt-3 leading-relaxed">
        Every row above is a source that actually ran. External providers
        without API keys report &quot;not configured&quot; - nothing here is invented.
      </p>
    </div>
  )
}

/* -- Engine table (demo results only - clearly labeled sample data) -- */
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

/* -- Shared result-tab primitives ----------------------------------- */

function KV({ k, v, mono = true }: { k: string; v: string | number | null | undefined; mono?: boolean }) {
  if (v === null || v === undefined || v === '') return null
  return (
    <div className="flex justify-between gap-4 py-1 text-xs border-b border-white/4 last:border-0">
      <span className="text-ink-500 shrink-0">{k}</span>
      <span className={cn('text-ink-200 text-right break-all', mono && 'font-mono')}>{String(v)}</span>
    </div>
  )
}

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={cn(
      'text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-sm shrink-0',
      sev === 'critical' ? 'bg-magenta/15 text-magenta'
        : sev === 'high' ? 'bg-threat/15 text-threat'
        : sev === 'medium' ? 'bg-amber/15 text-amber' : 'bg-surface-3 text-ink-400',
    )}>{sev}</span>
  )
}

function Card({ title, right, children }: { title: string; right?: ReactNode; children: ReactNode }) {
  return (
    <div className="glass border border-white/8 rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        {right}
      </div>
      {children}
    </div>
  )
}

/* Classify an indicator's source so engine-derived intel never reads as an
   authoritative external feed or NVD record - keeps provenance honest at a
   glance and stops the "engine-generated vs feed/NVD" skew. */
function provClass(source: string | null | undefined):
    { label: string; cls: string; hint: string } | null {
  if (!source) return null
  const s = source.toLowerCase()
  if (s.startsWith('engine:'))
    return { label: 'Engine-derived', cls: 'bg-violet/15 text-violet border-violet/25',
      hint: 'Derived by this deployment’s correlation engine from local telemetry - internal intelligence, not an external feed.' }
  if (s === 'nvd' || s.includes('nvd'))
    return { label: 'NVD (official)', cls: 'bg-safe/15 text-safe border-safe/25',
      hint: 'National Vulnerability Database - authoritative CVE record.' }
  if (s === 'manual' || s.startsWith('import'))
    return { label: 'Analyst / import', cls: 'bg-amber/15 text-amber border-amber/25',
      hint: 'Added by an analyst or a one-off import, not a live feed.' }
  return { label: 'External feed', cls: 'bg-surface-3 text-ink-300 border-white/10',
    hint: 'Pulled from an external threat-intel feed connector.' }
}

function EmptyNote({ text }: { text: string }) {
  return <p className="text-xs text-ink-500 leading-relaxed">{text}</p>
}

const providerOf = (r: ScanResult, name: string): EnrichProvider | undefined =>
  (r.providers ?? []).find((p) => p.provider === name)

/* -- Details tab: the full record behind the verdict ----------------- */
function DetailsTab({ result }: { result: ScanResult }) {
  const lu = result.lookup
  const rdap = providerOf(result, 'rdap')
  const heur = providerOf(result, 'indicator')
  const rd = (rdap?.data ?? {}) as Record<string, unknown>
  const rdFound = rdap?.available && rd.found === true
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <Card title="Threat-Intel Record"
        right={lu?.found ? <SevBadge sev={String(lu.severity)} /> : undefined}>
        {lu?.found ? (
          <div>
            <KV k="Threat type" v={lu.threatType} mono={false} />
            <KV k="Attributed actor" v={lu.actor} mono={false} />
            <KV k="Feed source" v={lu.source} mono={false} />
            {(() => {
              const p = provClass(lu.source)
              return p ? (
                <div className="flex justify-between gap-4 py-1 text-xs border-b border-white/4">
                  <span className="text-ink-500 shrink-0">Provenance</span>
                  <span title={p.hint} className={cn('text-[10px] px-2 py-0.5 rounded-full border cursor-help', p.cls)}>{p.label}</span>
                </div>
              ) : null
            })()}
            <KV k="Confidence" v={`${lu.confidence}${lu.effectiveConfidence != null && lu.effectiveConfidence !== lu.confidence ? ` (effective ${lu.effectiveConfidence} after decay)` : ''}`} />
            <KV k="Sightings" v={lu.sightings} />
            <KV k="Lifecycle" v={lu.status} mono={false} />
            <KV k="First seen" v={lu.firstSeen} />
            <KV k="Last seen" v={lu.lastSeen} />
            {lu.knownGood && (
              <p className="text-[11px] text-safe mt-2">Marked known-good by an analyst - it reads back benign and stops matching.</p>
            )}
            {lu.tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {lu.tags.map((t) => (
                  <span key={t} className="text-[10px] px-2 py-0.5 rounded-full bg-surface-3 text-ink-400">{t}</span>
                ))}
              </div>
            )}
          </div>
        ) : result.demo ? (
          <EmptyNote text="Demo result - the live TI store was not consulted." />
        ) : (
          <EmptyNote text="Not present in the ThreatOrbit intelligence store. No feed this deployment ingests has published this indicator." />
        )}
      </Card>

      <Card title="Registry (RDAP)"
        right={rdap?.cached ? <span className="text-[9px] text-ink-600">cached</span> : undefined}>
        {rdFound ? (
          <div>
            {/* Domain record */}
            <KV k="Registrar" v={rd.registrar as string} mono={false} />
            <KV k="Registered" v={rd.registered as string} />
            <KV k="Domain age" v={rd.ageDays != null ? `${rd.ageDays} days` : null} />
            <KV k="Expires" v={rd.expires as string} />
            <KV k="Last changed" v={rd.lastChanged as string} />
            {/* IP network record */}
            <KV k="Network" v={(rd.name ?? rd.handle) as string} />
            <KV k="Organisation" v={rd.org as string} mono={false} />
            <KV k="Country" v={rd.country as string} />
            <KV k="Address range" v={rd.range as string} />
            <KV k="Allocation" v={rd.allocationType as string} mono={false} />
            {Array.isArray(rd.nameservers) && rd.nameservers.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-ink-500 mb-1">Nameservers</p>
                <div className="flex flex-wrap gap-1.5">
                  {(rd.nameservers as string[]).map((ns) => (
                    <span key={ns} className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-surface-3 text-ink-300">{ns}</span>
                  ))}
                </div>
              </div>
            )}
            {rdap?.summary && <p className="text-[11px] text-ink-400 mt-3">{rdap.summary}</p>}
          </div>
        ) : rdap?.available ? (
          <EmptyNote text={rdap.summary || 'No registry record for this value.'} />
        ) : (
          <EmptyNote text={`Registry lookup did not run: ${rdap?.reason ?? 'not applicable for this indicator type'}. RDAP is the registries' own public data - nothing is substituted when it is unreachable.`} />
        )}
      </Card>

      {heur?.available && heur.data && Object.keys(heur.data).length > 1 && (
        <Card title="Indicator Analysis">
          {Object.entries(heur.data as Record<string, unknown>)
            .filter(([k]) => k !== 'type')
            .map(([k, v]) => (
              <KV key={k} k={k.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase())}
                v={typeof v === 'boolean' ? (v ? 'yes' : 'no') : (v as string | number)} />
            ))}
          {heur.summary && <p className="text-[11px] text-ink-400 mt-3">{heur.summary}</p>}
        </Card>
      )}

      {result.fileInfo && (
        <Card title="File Details">
          {Object.entries(result.fileInfo).map(([k, v]) => (
            <KV key={k} k={k.charAt(0).toUpperCase() + k.slice(1)} v={v} />
          ))}
        </Card>
      )}

      {result.demo && (
        <Card title="Network Info (sample)">
          {Object.entries(result.network).map(([k, v]) => (
            <KV key={k} k={k.toUpperCase()} v={v} />
          ))}
        </Card>
      )}

      {result.demo && result.mitre.length > 0 && (
        <Card title="MITRE ATT&CK (sample)">
          <div className="space-y-2">
            {result.mitre.map((t) => (
              <div key={t} className="flex items-center gap-2 text-xs">
                <span className="px-1.5 py-0.5 rounded-sm bg-violet/15 text-violet font-mono text-[9px]">{t.split(' - ')[0]}</span>
                <span className="text-ink-300">{t.split(' - ')[1]}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

/* -- Relations tab: real records around the indicator ---------------- */
function RelationsTab({ result, onOpenAlert, onOpenCase, onPivot }: {
  result: ScanResult
  onOpenAlert: (id: string) => void
  onOpenCase: (id: string) => void
  onPivot: (value: string, type: string) => void
}) {
  const cx = result.context
  if (result.demo || !cx) {
    return <EmptyNote text="Live relations are unavailable - the dashboard API could not be reached. Relations always come from this deployment's own alert, case, dark-web and asset stores; they are never invented." />
  }
  const entityGroups: Array<{ label: string; values: string[]; pivotType?: string }> = [
    { label: 'IPs', values: cx.relatedEntities.ips, pivotType: 'ip' },
    { label: 'Hostnames', values: cx.relatedEntities.hostnames },
    { label: 'Usernames', values: cx.relatedEntities.usernames },
    { label: 'Emails', values: cx.relatedEntities.emails },
  ].filter((g) => g.values.length > 0)
  const nothing = cx.alerts.total === 0 && cx.cases.length === 0 && cx.relatedIocs.length === 0
    && cx.darkWeb.total === 0 && cx.assets.length === 0 && cx.events.count === 0
    && entityGroups.length === 0 && !cx.graph?.length
  if (nothing) {
    return (
      <Card title="No Recorded Relations">
        <EmptyNote text="No SIEM alert, SOAR case, dark-web finding, asset or raw event in this deployment references this indicator, and it has no intelligence-graph neighbours. That is a real answer from your own data - not a gap being papered over." />
      </Card>
    )
  }
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <Card title="SIEM Alerts" right={<span className="text-xs text-ink-500">{cx.alerts.total} total</span>}>
        {cx.alerts.items.length === 0 ? <EmptyNote text="No alert references this indicator." /> : (
          <div className="space-y-1">
            {cx.alerts.items.map((a) => (
              <button key={a.id} onClick={() => onOpenAlert(a.id)}
                className="w-full flex items-center gap-2.5 py-1.5 px-3 rounded-lg hover:bg-white/4 transition-colors text-left group">
                <SevBadge sev={a.severity} />
                <span className="text-xs text-ink-200 truncate flex-1">{a.title}</span>
                <span className="text-[10px] text-ink-600 shrink-0">{relativeTime(a.ts)}</span>
                <ExternalLink className="w-3 h-3 text-ink-600 group-hover:text-magenta shrink-0" />
              </button>
            ))}
            {cx.alerts.total > cx.alerts.items.length && (
              <p className="text-[10px] text-ink-600 px-3 pt-1">Showing {cx.alerts.items.length} of {cx.alerts.total} - open one to triage in the SIEM.</p>
            )}
          </div>
        )}
      </Card>

      <Card title="SOAR Cases">
        {cx.cases.length === 0 ? <EmptyNote text="No case holds this indicator as an entity." /> : (
          <div className="space-y-1">
            {cx.cases.map((c) => (
              <button key={c.id} onClick={() => onOpenCase(c.id)}
                className="w-full flex items-center gap-2.5 py-1.5 px-3 rounded-lg hover:bg-white/4 transition-colors text-left group">
                <SevBadge sev={c.severity} />
                <span className="text-xs text-ink-200 truncate flex-1">{c.title}</span>
                <span className="text-[10px] text-ink-600 uppercase shrink-0">{c.status}</span>
                <ExternalLink className="w-3 h-3 text-ink-600 group-hover:text-magenta shrink-0" />
              </button>
            ))}
          </div>
        )}
      </Card>

      <Card title="Related Indicators">
        {cx.relatedIocs.length === 0 ? <EmptyNote text="No sibling indicators (same actor or same host)." /> : (
          <div className="space-y-1">
            {cx.relatedIocs.map((i) => (
              <div key={i.id} className="flex items-center gap-2.5 py-1.5 px-3 rounded-lg hover:bg-white/3 transition-colors">
                <span className="text-[9px] text-ink-600 font-mono uppercase bg-surface-3 px-1.5 py-0.5 rounded-sm shrink-0">{i.type}</span>
                <span className="text-xs font-mono text-ink-200 truncate flex-1">{i.value}</span>
                {i.actor && <span className="text-[10px] text-violet shrink-0">{i.actor}</span>}
                <SevBadge sev={i.severity} />
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Dark-Web Mentions" right={<span className="text-xs text-ink-500">{cx.darkWeb.total} total</span>}>
        {cx.darkWeb.items.length === 0 ? <EmptyNote text="No monitored forum, market or paste mentions this indicator." /> : (
          <div className="space-y-1">
            {cx.darkWeb.items.map((f) => (
              <div key={f.id} className="flex items-center gap-2.5 py-1.5 px-3 rounded-lg hover:bg-white/3 transition-colors">
                <SevBadge sev={f.severity} />
                <span className="text-xs text-ink-200 truncate flex-1">{f.title}</span>
                <span className="text-[10px] text-ink-600 shrink-0">{f.source ?? f.category}</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      {cx.assets.length > 0 && (
        <Card title="Your Assets">
          <div className="space-y-1">
            {cx.assets.map((a) => (
              <div key={a.id} className="flex items-center gap-2.5 py-1.5 px-3 rounded-lg hover:bg-white/3 transition-colors">
                <SevBadge sev={a.criticality} />
                <span className="text-xs text-ink-200 truncate flex-1">{a.name}</span>
                <span className="text-[10px] font-mono text-ink-500 shrink-0">{a.value}</span>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-amber mt-2">This indicator matches an asset in your inventory - treat detections against it with care.</p>
        </Card>
      )}

      <Card title="Raw Event Volume">
        <p className="font-display text-2xl font-bold text-white">
          {cx.events.count}{cx.events.capped ? '+' : ''}
        </p>
        <p className="text-[11px] text-ink-500 mt-1">
          ingested events reference this indicator{cx.events.capped ? ' (count capped at 500)' : ''} - pivot to the SIEM event explorer for the full stream.
        </p>
      </Card>

      {entityGroups.length > 0 && (
        <Card title="Co-observed Entities">
          <div className="space-y-3">
            {entityGroups.map((g) => (
              <div key={g.label}>
                <p className="text-[10px] text-ink-500 mb-1.5">{g.label}</p>
                <div className="flex flex-wrap gap-1.5">
                  {g.values.map((v) => g.pivotType ? (
                    <button key={v} onClick={() => onPivot(v, g.pivotType!)}
                      title={`Scan ${v}`}
                      className="text-[10px] font-mono px-2 py-1 rounded-md bg-surface-2 border border-white/8 text-ink-300 hover:text-white hover:border-magenta/40 transition-colors">
                      {v}
                    </button>
                  ) : (
                    <span key={v} className="text-[10px] font-mono px-2 py-1 rounded-md bg-surface-3 text-ink-400">{v}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-ink-600 mt-3">Seen in the same alerts as this indicator. Click an IP to pivot the scan onto it.</p>
        </Card>
      )}

      {cx.graph && cx.graph.length > 0 && (
        <Card title="Intelligence Graph">
          <div className="flex flex-wrap gap-1.5">
            {cx.graph.slice(0, 12).map((n) => (
              <span key={n.id} className="text-[10px] px-2 py-1 rounded-md bg-violet/10 text-violet border border-violet/20">
                {n.label} <span className="text-ink-600">({n.group})</span>
              </span>
            ))}
          </div>
          <p className="text-[10px] text-ink-600 mt-2">One-hop neighbours in the CTI relationship graph.</p>
        </Card>
      )}
    </div>
  )
}

/* -- Community tab: real analyst signal, honest external state -------- */
function CommunityTab({ result }: { result: ScanResult }) {
  const cx = result.context
  const lu = result.lookup
  const vt = providerOf(result, 'virustotal')
  if (result.demo) {
    return (
      <Card title="Community (sample)">
        <div className="flex items-end gap-6">
          <div>
            <p className="font-display text-2xl font-bold text-threat">{result.community.malicious}</p>
            <p className="text-[10px] text-ink-500">malicious votes</p>
          </div>
          <div>
            <p className="font-display text-2xl font-bold text-safe">{result.community.clean}</p>
            <p className="text-[10px] text-ink-500">clean votes</p>
          </div>
        </div>
        <p className="text-[10px] text-amber mt-3">Sample data - the dashboard API is unreachable.</p>
      </Card>
    )
  }
  const tally = cx?.analystActivity
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <Card title="Your Analysts">
        {tally && tally.scans > 0 ? (
          <div>
            <p className="text-xs text-ink-300 mb-3">
              Scanned <span className="font-bold text-white">{tally.scans}</span> time{tally.scans === 1 ? '' : 's'} by this SOC
              {tally.lastScan && <span className="text-ink-500"> - last {relativeTime(tally.lastScan)}</span>}
            </p>
            {Object.entries(tally.byVerdict).map(([v, n]) => (
              <div key={v} className="flex items-center justify-between py-1 text-xs border-b border-white/4 last:border-0">
                <span className={cn('font-semibold uppercase text-[10px]',
                  v === 'malicious' ? 'text-threat' : v === 'suspicious' ? 'text-amber'
                    : v === 'unverified' ? 'text-violet' : 'text-safe')}>{v}</span>
                <span className="text-ink-200 font-mono">{n}</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyNote text="No analyst on this deployment has scanned this exact value before. This panel reflects your own team's history - not invented votes." />
        )}
        {lu?.found && (
          <div className="mt-3 pt-3 border-t border-white/5">
            <KV k="Feed sightings" v={lu.sightings} />
            {lu.knownGood && <p className="text-[11px] text-safe mt-1">Whitelisted (known-good) by an analyst.</p>}
          </div>
        )}
      </Card>
      <Card title="External Community">
        {vt?.available ? (
          <div>
            <p className="text-xs text-ink-300">{vt.summary || 'VirusTotal responded with no additional detail.'}</p>
            <p className="text-[10px] text-ink-600 mt-2">Live VirusTotal result for this indicator.</p>
          </div>
        ) : (
          <EmptyNote text="External community reputation (VirusTotal votes, GreyNoise sightings) appears here once the provider API keys are configured in Settings. Until then this panel stays empty rather than showing invented numbers." />
        )}
      </Card>
    </div>
  )
}

/* -- Page ---------------------------------------------------------- */
export default function ScannerPage() {
  const router = useRouter()
  const [scanType, setScanType] = useState<string>('url')
  const [query, setQuery] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [activeTab, setActiveTab] = useState<ResultTab>('details')
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [history, setHistory] = useState<ScanRow[]>([])
  const [stats, setStats] = useState<{ scansToday: number; malicious: number } | null>(null)
  // Real source count for the header tile: the TI store + available enrichers.
  const [sources, setSources] = useState<number | null>(null)
  useEffect(() => {
    fetchEnrichers().then((rows) => {
      setSources(1 + rows.filter((r) => r.available).length)
    }).catch(() => {})
  }, [])

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

  // `pivotValue`/`pivotType` let Relations-tab entity chips re-scan a related
  // value directly (state updates land too late for the same call otherwise).
  const handleScan = (pivotValue?: string, pivotType?: string) => {
    const target = (pivotValue ?? query).trim()
    const typ = pivotType ?? scanType
    if (pivotValue) {
      setQuery(pivotValue)
      // Only known UI tabs get selected; other backend types (cve, domain)
      // still scan under their real type via `typ`.
      if (pivotType && SCAN_TYPES.some((s) => s.key === pivotType)) setScanType(pivotType)
    }
    if (!target && typ !== 'file') return
    setScanning(true)
    setResult(null)
    setSaved(false)
    setActiveTab('details')

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

    const demoOf = () => {
      const d = typ === 'ip' ? DEMO_RESULTS.ip
        : typ === 'hash' ? DEMO_RESULTS.hash : DEMO_RESULTS.url
      return { ...d, demo: true }
    }
    if (!target) { finish(demoOf(), false); return }

    // Three real sources, in parallel: our TI store (verdict + feed
    // provenance), the enrichment pipeline (per-provider results with honest
    // availability) and the relations context (alerts/cases/dark-web around
    // the indicator). Nothing else is shown - no invented vendor tables.
    Promise.allSettled([lookupIoc(target), fetchScanEnrich(target, typ),
      fetchScanContext(target)])
      .then(([lu, en, cx]) => {
        if (lu.status === 'rejected') {
          // API unreachable → clearly-labeled sample result, never persisted.
          finish(demoOf(), false)
          return
        }
        const hit = lu.value
        const enr = en.status === 'fulfilled' ? en.value : null
        const providers = enr?.providers ?? []
        const consulted = providers.filter((p) => p.available)
        const flagged = consulted.filter((p) => p.verdict === 'malicious' || p.verdict === 'suspicious')
        // Verdict precedence: our TI store, then the enrichment consensus,
        // else "unverified" - absence of evidence is not a clean bill.
        const verdict = hit.found ? hit.verdict
          : (enr && enr.verdict !== 'unknown' ? enr.verdict : 'unverified')
        finish({
          target: hit.found ? hit.value : target,
          type: typ as ScanResult['type'],
          verdict,
          // Lookup confidence is 0-100; the gauge/score scale is 0-1.
          score: hit.found ? hit.confidence / 100 : 0,
          detectionRatio: `${flagged.length}/${consulted.length + 1}`,  // +1 = TI store itself
          firstSeen: hit.firstSeen ?? '-',
          lastSeen: hit.lastSeen ?? '-',
          categories: hit.found
            ? ([hit.threatType, hit.actor ? `Attributed: ${hit.actor}` : null, ...hit.tags]
                .filter(Boolean) as string[])
            : [],
          community: { votes: 0, malicious: 0, clean: 0 },
          network: { asn: '-', ip: '-', country: '-', registrar: '-' },
          engines: [], iocs: [], mitre: [],
          source: hit.found ? hit.source : null,
          providers,
          lookup: hit,
          context: cx.status === 'fulfilled' ? cx.value : null,
        })
      })
  }

  // Hand-off deep link: /dashboard/scanner?value=<v>&type=<t>&run=1 arrives
  // pre-populated from CVE/IOC/threat-map actions elsewhere in the app -
  // the user never re-types data the platform already knows. `run=1`
  // starts the scan immediately; otherwise it is one click away.
  const deepLinked = useRef(false)
  useEffect(() => {
    if (deepLinked.current) return
    deepLinked.current = true
    const params = new URLSearchParams(window.location.search)
    const v = (params.get('value') ?? '').trim()
    if (!v) return
    const t = (params.get('type') ?? '').trim().toLowerCase()
    setQuery(v)
    if (SCAN_TYPES.some((s) => s.key === t)) setScanType(t)
    if (params.get('run') === '1') handleScan(v, t || undefined)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once on mount
  }, [])

  // File scan: fingerprint the file in-browser (SHA-256, nothing uploaded)
  // and check the digest against the live threat-intel store.
  const fileRef = useRef<HTMLInputElement>(null)

  async function handleFileScan(file: globalThis.File | undefined) {
    if (!file || scanning) return
    if (file.size > 32 * 1024 * 1024) return
    setScanning(true)
    setResult(null)
    setSaved(false)
    setActiveTab('details')
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
        target: hash, type: 'file', verdict: 'unverified', detectionRatio: '0/1', score: 0,
        firstSeen: '-', lastSeen: '-', categories: [],
        community: { votes: 0, malicious: 0, clean: 0 },
        network: { asn: '-', ip: '-', country: '-', registrar: '-' },
        engines: [], iocs: [hash], mitre: [], fileInfo,
      }
      let scanResult = base
      try {
        const [lu, en, cx] = await Promise.allSettled([
          lookupIoc(hash), fetchScanEnrich(hash, 'hash'), fetchScanContext(hash)])
        const hit = lu.status === 'fulfilled' ? lu.value : null
        const enr = en.status === 'fulfilled' ? en.value : null
        const providers = enr?.providers ?? []
        const consulted = providers.filter((p) => p.available)
        const flagged = consulted.filter((p) => p.verdict === 'malicious' || p.verdict === 'suspicious')
        scanResult = {
          ...base,
          verdict: hit?.found ? hit.verdict
            : (enr && enr.verdict !== 'unknown' ? enr.verdict : 'unverified'),
          score: hit?.found ? hit.confidence / 100 : 0,
          detectionRatio: `${flagged.length}/${consulted.length + 1}`,
          firstSeen: hit?.firstSeen ?? '-',
          lastSeen: hit?.lastSeen ?? '-',
          categories: hit?.found
            ? ([hit.threatType, hit.actor ? `Attributed: ${hit.actor}` : null, ...hit.tags]
                .filter(Boolean) as string[])
            : [],
          source: hit?.found ? hit.source : null,
          providers,
          lookup: hit,
          context: cx.status === 'fulfilled' ? cx.value : null,
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
          <p className="text-xs text-ink-500">Scan URLs, IPs, file hashes, and files against the ThreatOrbit intelligence store and every configured enricher</p>
        </div>
        {/* Stats row */}
        <div className="flex items-center gap-3 flex-wrap">
          {[
            { label: 'Scans today', value: stats ? stats.scansToday.toLocaleString() : '-', icon: Zap,          color: tk('violet') },
            { label: 'Malicious',   value: stats ? stats.malicious.toLocaleString() : '-',  icon: AlertTriangle, color: tk('magenta') },
            { label: 'Sources',     value: sources != null ? String(sources) : '-',   icon: Database,      color: tk('teal') },
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
                onClick={() => handleScan()}
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
              <p className="text-sm font-semibold text-white">Checking configured intelligence sources</p>
              <p className="text-xs text-ink-500 mt-1">The ThreatOrbit TI store plus every enricher this deployment has configured…</p>
            </div>
            <div className="flex gap-2 flex-wrap justify-center">
              {['ThreatOrbit TI', 'Internal telemetry', 'Indicator heuristics', 'RDAP registry', 'VirusTotal'].map((e) => (
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
                    s.verdict === 'malicious' ? 'bg-threat' : s.verdict === 'suspicious' ? 'bg-amber'
                      : s.verdict === 'unverified' ? 'bg-violet' : 'bg-safe',
                  )} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-ink-200 truncate">{s.target}</p>
                  </div>
                  <span className="text-[9px] text-ink-600 font-mono uppercase bg-surface-3 px-1.5 py-0.5 rounded-sm">{s.type}</span>
                  <span className="text-[10px] text-ink-500 font-mono w-14 text-right">{s.engines}</span>
                  <span className={cn(
                    'text-[10px] font-semibold w-16 text-right uppercase',
                    s.verdict === 'malicious' ? 'text-threat' : s.verdict === 'suspicious' ? 'text-amber'
                      : s.verdict === 'unverified' ? 'text-violet' : 'text-safe',
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
              { icon: File,   title: 'Files',  desc: 'SHA-256 fingerprint checked against TI',   color: tk('teal'), example: 'invoice.pdf' },
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
            {result.demo && (
              <div className="flex items-center gap-2.5 px-4 py-3 rounded-xl border border-amber/30 bg-amber/10">
                <AlertTriangle className="w-4 h-4 text-amber shrink-0" />
                <p className="text-xs text-amber">
                  <span className="font-bold">Demo result.</span> The dashboard API is
                  unreachable, so this is illustrative sample data - nothing below is
                  live intelligence, and it is not saved to history.
                </p>
              </div>
            )}

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
                  <div><span className="text-ink-500">Detections:</span> <span className={cn('font-semibold ml-1', result.detectionRatio.startsWith('0/') ? 'text-ink-200' : 'text-threat')}>{result.detectionRatio}</span></div>
                  {!result.demo && (
                    <div><span className="text-ink-500">Feed source:</span> <span className="text-ink-200 ml-1">{result.source ?? 'none'}</span></div>
                  )}
                  {result.demo && (
                    <>
                      <div><span className="text-ink-500">ASN:</span> <span className="text-ink-200 ml-1">{result.network.asn}</span></div>
                      <div><span className="text-ink-500">Country:</span> <span className="text-ink-200 ml-1">{result.network.country}</span></div>
                    </>
                  )}
                </div>
                {result.verdict === 'unverified' && (
                  <p className="text-[11px] text-ink-500 mt-3 leading-snug max-w-md">
                    Not present in the ThreatOrbit intelligence store and no configured
                    enricher flagged it. Unverified means <span className="text-ink-300">unknown</span> -
                    not proven clean.
                  </p>
                )}
                <div className="flex flex-wrap gap-1.5 mt-4">
                  {result.categories.map((c) => (
                    <span key={c} className="text-[10px] px-2 py-0.5 rounded-full bg-threat/10 text-threat border border-threat/20">{c}</span>
                  ))}
                </div>
              </div>
              <div className="text-center space-y-4">
                {result.demo && (
                  <div>
                    <div className="text-xs text-ink-500 mb-2">Community</div>
                    <div className="text-2xl font-display font-bold text-threat">{result.community.malicious}</div>
                    <div className="text-[10px] text-ink-500">malicious votes</div>
                    <div className="text-sm text-safe mt-1">{result.community.clean} clean</div>
                  </div>
                )}
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

            {/* Result tabs: Details / Relations / Community / Sources */}
            <div className="flex items-center gap-2 flex-wrap" role="tablist" aria-label="Scan result sections">
              {([
                { key: 'details', label: 'Details', icon: Layers },
                { key: 'relations', label: 'Relations', icon: Network,
                  badge: result.context
                    ? result.context.alerts.total + result.context.cases.length
                      + result.context.relatedIocs.length + result.context.darkWeb.total
                      + result.context.assets.length
                    : 0 },
                { key: 'community', label: 'Community', icon: Users },
                { key: 'sources', label: 'Sources', icon: Database,
                  badge: (result.providers ?? []).filter((p) => p.available).length + 1 },
              ] as Array<{ key: ResultTab; label: string; icon: typeof Layers; badge?: number }>).map(({ key, label, icon: Icon, badge }) => (
                <button
                  key={key}
                  role="tab"
                  aria-selected={activeTab === key}
                  onClick={() => setActiveTab(key)}
                  className={cn(
                    'flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all',
                    activeTab === key
                      ? 'bg-violet/15 text-violet border border-violet/30'
                      : 'text-ink-400 border border-white/8 hover:text-white hover:border-white/15',
                  )}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                  {badge != null && badge > 0 && (
                    <span className={cn('text-[9px] font-bold px-1.5 py-0.5 rounded-full',
                      activeTab === key ? 'bg-violet/20' : 'bg-surface-3 text-ink-500')}>
                      {badge}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {activeTab === 'details' && <DetailsTab result={result} />}
            {activeTab === 'relations' && (
              <RelationsTab
                result={result}
                onOpenAlert={(id) => router.push(`/dashboard/siem?alert=${encodeURIComponent(id)}`)}
                onOpenCase={(id) => router.push(`/dashboard/soar?case=${encodeURIComponent(id)}`)}
                onPivot={(v, t) => handleScan(v, t)}
              />
            )}
            {activeTab === 'community' && <CommunityTab result={result} />}
            {activeTab === 'sources' && (
              <div className="grid md:grid-cols-2 gap-4">
                <div className="glass border border-white/8 rounded-xl p-5">
                  {result.demo
                    ? <EngineResults engines={result.engines} />
                    : <ProviderResults providers={result.providers ?? []}
                        unknown={result.source == null} />}
                </div>
                {result.iocs.length > 0 && (
                  <Card title={result.demo ? 'Extracted IOCs (sample)' : 'Scanned Indicator'}>
                    <div className="space-y-1">
                      {result.iocs.map((ioc) => (
                        <div key={ioc} className="font-mono text-xs text-ink-300 bg-surface-3 px-3 py-1.5 rounded-lg break-all">
                          {ioc}
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
