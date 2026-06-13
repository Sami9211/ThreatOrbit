'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Satellite, RefreshCw, Download, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchServicesStatus, fetchThreatSourceHealth, triggerThreatFetch, syncThreatIocs,
  type ServicesStatus,
} from '@/lib/api'

/**
 * Live bridge to the Threat API ingestion engine (threat_api, :8000).
 * Shows reachability + per-source fetch health, can trigger an ingestion run,
 * and pulls the engine's indicators into the dashboard CTI store.
 */
export default function IngestionEnginePanel() {
  const [status, setStatus] = useState<ServicesStatus | null>(null)
  const [sources, setSources] = useState<Array<{ name: string; ok: boolean; detail: string }>>([])
  const [fetching, setFetching] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    fetchServicesStatus().then(setStatus).catch(() => setStatus(null))
    fetchThreatSourceHealth().then((data) => {
      if (!data.available) return
      const raw = data.sources
      // /source-health returns a per-source map or list depending on version.
      const entries = Array.isArray(raw)
        ? raw.map((s) => [String((s as { source?: string }).source ?? 'source'), s] as const)
        : Object.entries(raw as Record<string, unknown>)
      setSources(entries.map(([name, v]) => {
        const o = (v ?? {}) as Record<string, unknown>
        const failures = Number(o.consecutiveFailures ?? o.consecutive_failures ?? 0)
        const ok = (o.status ? String(o.status) === 'healthy' : failures === 0)
        const last = String(o.lastSuccess ?? o.last_success ?? o.lastError ?? o.last_error ?? '')
        return { name, ok, detail: last ? new Date(last).toLocaleString() : '-' }
      }))
    }).catch(() => {})
  }, [])

  const available = status?.threatApi.available ?? false

  function flash(msg: string) {
    setMessage(msg)
    setTimeout(() => setMessage(null), 5000)
  }

  function runFetch() {
    if (fetching) return
    setFetching(true)
    triggerThreatFetch()
      .then((out) => flash(`Ingestion job started (${out.jobId ?? out.job_id ?? 'queued'})`))
      .catch((e) => flash(e instanceof Error && e.message.includes('unreachable')
        ? 'Threat API is offline - start it on :8000 to ingest feeds.'
        : 'Could not start ingestion (admin role required).'))
      .finally(() => setFetching(false))
  }

  function runSync() {
    if (syncing) return
    setSyncing(true)
    syncThreatIocs()
      .then((out) => flash(`Synced ${out.imported} new indicators into CTI (${out.duplicates} already known)`))
      .catch((e) => flash(e instanceof Error && e.message.includes('unreachable')
        ? 'Threat API is offline - start it on :8000 to sync indicators.'
        : 'Sync failed (admin role required).'))
      .finally(() => setSyncing(false))
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25 shrink-0">
          <Satellite className="w-4 h-4 text-magenta" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Ingestion Engine</h3>
          <p className="text-[10px] text-ink-500">Threat API - OTX, abuse.ch, RSS, dark-web & social OSINT</p>
        </div>
        <span className={cn('flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full border font-semibold ml-auto',
          available ? 'bg-safe/10 text-safe border-safe/25' : 'bg-white/5 text-ink-500 border-white/10')}>
          {available ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
          {available ? 'Connected' : 'Offline'}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={runFetch}
            disabled={fetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-magenta/10 border border-magenta/25 text-magenta hover:bg-magenta/20 transition-colors disabled:opacity-50"
          >
            {fetching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Trigger Fetch
          </button>
          <button
            onClick={runSync}
            disabled={syncing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-violet/10 border border-violet/25 text-violet hover:bg-violet/20 transition-colors disabled:opacity-50"
          >
            {syncing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            Sync IOCs to CTI
          </button>
        </div>
      </div>

      {message && (
        <div className="px-5 py-2 text-[11px] text-safe bg-safe/5 border-b border-safe/15" role="status">{message}</div>
      )}

      <div className="px-5 py-3">
        {!available && (
          <p className="text-xs text-ink-600 py-3 text-center">
            The ingestion engine is not reachable from the dashboard API.
            Start <code className="font-mono text-ink-400">threat_api</code> on :8000 and set
            <code className="font-mono text-ink-400"> SERVICES_API_KEY</code> to bridge live OSINT feeds in.
          </p>
        )}
        {available && sources.length === 0 && (
          <p className="text-xs text-ink-600 py-3 text-center">Connected - no fetch runs recorded yet. Trigger a fetch to populate source health.</p>
        )}
        {available && sources.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {sources.map((s) => (
              <div key={s.name} className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-surface-2/60 border border-white/5">
                <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', s.ok ? 'bg-safe' : 'bg-threat')} />
                <div className="min-w-0">
                  <p className="text-[11px] text-ink-200 truncate capitalize">{s.name.replace(/_/g, ' ')}</p>
                  <p className="text-[9px] text-ink-600 truncate">{s.detail}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  )
}
