'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { Terminal, Loader2, ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ingestLogs } from '@/lib/api'

const SAMPLE = `Jan 10 03:22:01 web01 sshd[2451]: Failed password for root from 45.9.1.2 port 51110
Jan 10 03:22:03 web01 sshd[2452]: Failed password for root from 45.9.1.2 port 51120
192.0.2.55 - admin [10/Jan/2025:03:22:05] "GET /p?id=1' OR 1=1-- HTTP/1.1" 200
{"event_type":"beacon","src_ip":"10.0.0.9","dest_ip":"185.2.3.4","dest_port":443}`

/**
 * Native log collector — paste raw log lines (syslog / Apache / JSON / key=value)
 * and the SIEM parses them into events, runs detection rules + threat-intel
 * matching, and raises real alerts. This is the "production logs stream in" path
 * (an agent/forwarder POSTs the same way to /siem/ingest).
 */
export default function LogCollectorPanel() {
  const [text, setText] = useState('')
  const [format, setFormat] = useState('auto')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ parsed: number; alerts: number; tiMatches: number } | null>(null)
  const [error, setError] = useState<string | null>(null)

  function send() {
    const lines = text.split('\n').map((l) => l.trim()).filter(Boolean)
    if (lines.length === 0 || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    ingestLogs(lines, format)
      .then((r) => setResult(r))
      .catch(() => setError('Ingestion failed — is the dashboard API running?'))
      .finally(() => setBusy(false))
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25 shrink-0">
          <Terminal className="w-4 h-4 text-magenta" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Log Collector</h3>
          <p className="text-[10px] text-ink-500">Paste raw logs → parsed → rules + threat-intel fire → real alerts</p>
        </div>
        <select value={format} onChange={(e) => setFormat(e.target.value)}
          className="ml-auto px-2.5 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-none focus:border-magenta/40">
          {['auto', 'syslog', 'apache', 'json', 'kv'].map((f) => <option key={f} value={f}>{f}</option>)}
        </select>
      </div>

      <div className="p-4 space-y-3">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          placeholder="Paste log lines here (syslog, Apache/Nginx, JSON, or key=value)…"
          className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-[11px] font-mono text-ink-100 focus:outline-none focus:border-magenta/40 placeholder-ink-600 resize-none"
        />
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={send} disabled={busy || !text.trim()}
            className={cn('flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold transition-all',
              text.trim() && !busy ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5" />}
            {busy ? 'Ingesting…' : 'Ingest & detect'}
          </button>
          <button onClick={() => setText(SAMPLE)} className="text-[11px] text-ink-500 hover:text-ink-200">load sample</button>
          {result && (
            <a href="/dashboard/siem" className="flex items-center gap-1.5 ml-auto text-[11px] text-magenta hover:underline">
              <ShieldAlert className="w-3.5 h-3.5" />
              {result.parsed} parsed · <b>{result.alerts}</b> alerts{result.tiMatches > 0 ? ` (${result.tiMatches} TI)` : ''} → open SIEM
            </a>
          )}
          {error && <span className="text-[11px] text-threat ml-auto">{error}</span>}
        </div>
      </div>
    </motion.div>
  )
}
