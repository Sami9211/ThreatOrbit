'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FileSearch, Upload, Loader2, CheckCircle, XCircle, AlertTriangle, ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { analyseLogFile, fetchServicesStatus, type LogAnalysisResult } from '@/lib/api'

const FORMATS = [
  { value: 'apache', label: 'Apache access log' },
  { value: 'syslog', label: 'Syslog' },
  { value: 'windows_event', label: 'Windows Event' },
  { value: 'generic', label: 'Generic / unknown' },
]

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#FF2E97', HIGH: '#FF4D6D', MEDIUM: '#FFB23E', LOW: '#2DD4BF',
}

/**
 * Live bridge to the Log API anomaly engine (log_api, :8001).
 * Upload a log file; four detector engines (pattern, statistical, ML,
 * temporal) analyse it server-side and the findings render here.
 */
export default function LogAnalysisPanel() {
  const [available, setAvailable] = useState<boolean | null>(null)
  const [format, setFormat] = useState('apache')
  const [analysing, setAnalysing] = useState(false)
  const [result, setResult] = useState<LogAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    fetchServicesStatus()
      .then((s) => setAvailable(s.logApi.available))
      .catch(() => setAvailable(false))
  }, [])

  async function handleFile(file: File | undefined) {
    if (!file || analysing) return
    setAnalysing(true)
    setError(null)
    setResult(null)
    try {
      setResult(await analyseLogFile(file, format))
    } catch (e) {
      setError(e instanceof Error && e.message.includes('unreachable')
        ? 'Log API is offline — start it on :8001 to analyse logs.'
        : e instanceof Error ? e.message : 'Analysis failed.')
    } finally {
      setAnalysing(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const findings = (result?.findings ?? []) as Array<{
    detector?: string; description?: string; severity?: string
    severityScore?: number; sourceIp?: string | null; count?: number
  }>
  const summary = (result?.summary ?? {}) as Record<string, number>

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
          <FileSearch className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Log Anomaly Analysis</h3>
          <p className="text-[10px] text-ink-500">Log API — pattern, statistical, ML & temporal detectors</p>
        </div>
        <span className={cn('flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full border font-semibold ml-auto',
          available ? 'bg-safe/10 text-safe border-safe/25' : 'bg-white/5 text-ink-500 border-white/10')}>
          {available ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
          {available === null ? 'Checking…' : available ? 'Connected' : 'Offline'}
        </span>
      </div>

      <div className="px-5 py-4 space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            className="px-3 py-2 rounded-xl bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-none focus:border-magenta/40"
          >
            {FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
          <input
            ref={fileRef}
            type="file"
            accept=".log,.txt,.json"
            className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0])}
          />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={analysing}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-plasma text-white hover:shadow-magenta-sm transition-all disabled:opacity-50"
          >
            {analysing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
            {analysing ? 'Analysing…' : 'Upload & Analyse'}
          </button>
          <span className="text-[10px] text-ink-600">Max 16 MB · processed server-side, nothing stored in the browser</span>
        </div>

        {error && (
          <p className="flex items-center gap-2 px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> {error}
          </p>
        )}

        <AnimatePresence>
          {result && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
              {/* Real detection pipeline: findings became SIEM alerts */}
              {Number(result.alertsCreated ?? 0) > 0 && (
                <a href="/dashboard/siem"
                  className="flex items-center gap-2 mb-3 px-3 py-2 rounded-lg bg-magenta/10 border border-magenta/25 text-[11px] text-magenta hover:bg-magenta/15 transition-colors">
                  <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                  <span><b>{Number(result.alertsCreated)}</b> real SIEM alert{Number(result.alertsCreated) === 1 ? '' : 's'} raised from this analysis — open SIEM →</span>
                </a>
              )}
              {/* Summary strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
                <div className="px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5">
                  <p className="text-[9px] text-ink-600 uppercase">Lines parsed</p>
                  <p className="text-sm font-bold text-white font-mono">
                    {Number(result.parsedLines ?? 0).toLocaleString()} / {Number(result.totalLines ?? 0).toLocaleString()}
                  </p>
                </div>
                <div className="px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5">
                  <p className="text-[9px] text-ink-600 uppercase">Findings</p>
                  <p className="text-sm font-bold text-magenta font-mono">{findings.length}</p>
                </div>
                <div className="px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5">
                  <p className="text-[9px] text-ink-600 uppercase">Detectors</p>
                  <p className="text-sm font-bold text-violet font-mono">{(result.detectorsUsed as string[] | undefined)?.length ?? 4}</p>
                </div>
                <div className="px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5">
                  <p className="text-[9px] text-ink-600 uppercase">Duration</p>
                  <p className="text-sm font-bold text-safe font-mono">{Number(result.analysisDurationSeconds ?? 0).toFixed(2)}s</p>
                </div>
              </div>

              {/* Severity summary chips */}
              {Object.keys(summary).length > 0 && (
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {Object.entries(summary).map(([sev, count]) => (
                    <span key={sev} className="text-[10px] px-2 py-0.5 rounded-full border font-semibold"
                      style={{ color: SEV_COLOR[sev] ?? '#8A7DA3', borderColor: `${SEV_COLOR[sev] ?? '#8A7DA3'}40`, background: `${SEV_COLOR[sev] ?? '#8A7DA3'}14` }}>
                      {sev}: {count}
                    </span>
                  ))}
                </div>
              )}

              {/* Findings list */}
              {findings.length === 0 ? (
                <p className="text-xs text-safe py-2">No anomalies detected in this file.</p>
              ) : (
                <div className="space-y-1.5 max-h-72 overflow-y-auto">
                  {findings.map((f, i) => (
                    <div key={i} className="flex items-start gap-3 px-3 py-2 rounded-lg bg-surface-2/40 border border-white/5">
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0 mt-0.5"
                        style={{ color: SEV_COLOR[f.severity ?? 'LOW'] ?? '#2DD4BF', background: `${SEV_COLOR[f.severity ?? 'LOW'] ?? '#2DD4BF'}18` }}>
                        {f.severity ?? 'LOW'}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] text-ink-200 leading-snug">{f.description}</p>
                        <p className="text-[9px] text-ink-600 mt-0.5">
                          {f.detector} · score {f.severityScore ?? 0}
                          {f.sourceIp ? ` · src ${f.sourceIp}` : ''}
                          {f.count && f.count > 1 ? ` · ×${f.count}` : ''}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}
