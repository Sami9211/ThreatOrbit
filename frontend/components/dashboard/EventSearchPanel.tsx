'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { SearchCode, Loader2, Play, BarChart3, Hash } from 'lucide-react'
import { cn } from '@/lib/utils'
import { eventSearch, type EventSearchResult } from '@/lib/api'

const RANGES = ['1h', '6h', '24h', '7d']
const EXAMPLES = [
  'event_type=failed_login',
  'src_ip=10.0.0.5 bytes_out>=104857600',
  'event_type=beacon | stats count by dest_ip',
  'username in svc-backup,svc-deploy',
  'source.ip=10.0.0.5',          // ECS field names resolve too
  'raw~"OR 1=1"',
  // cross-source join: successful logins from IPs that also failed
  'event_type=login_success | join src_ip event_type=failed_login',
]

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h` : `${Math.floor(h / 24)}d`
}

/**
 * Event-stream search - a real field-operator query language over the raw
 * telemetry the SIEM ingests (engine + native log collector). Supports
 * `field=value`, `!= > < >= <=`, `~regex`, `:contains`, `field in a,b,c`,
 * bare full-text tokens, `| stats count by <field>`, and cross-source
 * correlation with `| join <field> <subquery>` (keep rows whose field value
 * also matches the subquery). This is what hunting actually is: searching
 * raw events, not just stored alerts.
 */
export default function EventSearchPanel() {
  const [query, setQuery] = useState('')
  const [range, setRange] = useState('24h')
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<EventSearchResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  function run(q = query) {
    if (busy) return
    setBusy(true)
    setError(null)
    eventSearch(q, range)
      .then((r) => setRes(r))
      .catch((e) => setError(e?.message || 'Search failed - is the dashboard API running?'))
      .finally(() => setBusy(false))
  }

  const maxGroup = res?.stats ? Math.max(1, ...res.stats.groups.map((g) => g.count)) : 1

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
          <SearchCode className="w-4 h-4 text-violet" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Event-stream search</h3>
          <p className="text-[10px] text-ink-500">Field operators + <span className="font-mono">| stats count by</span> over raw telemetry</p>
        </div>
        <select value={range} onChange={(e) => setRange(e.target.value)}
          className="ml-auto px-2.5 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-[11px] text-ink-200 focus:outline-none focus:border-violet/40">
          {RANGES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>

      <div className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-xl bg-[#080614] border border-white/8 focus-within:border-violet/40 transition-colors">
            <span className="text-violet font-mono text-xs select-none">›</span>
            <input value={query} onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') run() }}
              placeholder='event_type=failed_login src_ip=10.0.0.5 | stats count by src_ip'
              className="flex-1 bg-transparent text-[12px] font-mono text-ink-100 focus:outline-none placeholder-ink-700" />
          </div>
          <button onClick={() => run()} disabled={busy}
            className={cn('flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold transition-all',
              !busy ? 'bg-violet/20 border border-violet/35 text-violet hover:bg-violet/30' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Search
          </button>
        </div>

        {/* Example chips */}
        {!res && (
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-ink-600">try:</span>
            {EXAMPLES.map((ex) => (
              <button key={ex} onClick={() => { setQuery(ex); run(ex) }}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-2 border border-white/8 text-ink-400 hover:text-violet hover:border-violet/30 transition-colors">
                {ex}
              </button>
            ))}
          </div>
        )}

        {error && <p className="text-[11px] text-threat">{error}</p>}

        {/* Interpreted-as */}
        {res && (res.interpreted.conditions.length > 0 || res.interpreted.freetext.length > 0 || res.interpreted.stats) && (
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-ink-600">interpreted:</span>
            {res.interpreted.conditions.map((c, i) => (
              <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet/10 text-violet border border-violet/20">
                {c.field} {c.op} {c.value}
              </span>
            ))}
            {res.interpreted.freetext.map((f, i) => (
              <span key={`f${i}`} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-2 text-ink-300 border border-white/10">
                raw~“{f}”
              </span>
            ))}
            {res.interpreted.stats && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber/10 text-amber border border-amber/20 flex items-center gap-1">
                <BarChart3 className="w-3 h-3" /> count by {res.interpreted.stats.by}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Results */}
      {res && (
        <div className="border-t border-white/5">
          <div className="px-5 py-2 flex items-center gap-3 text-[10px] text-ink-500 border-b border-white/5">
            <span><b className="text-white font-mono">{res.hits}</b> hits</span>
            <span>scanned <span className="font-mono text-ink-300">{res.scanned}</span></span>
            {res.stats && <span><span className="font-mono text-ink-300">{res.groupCount}</span> groups</span>}
            <span className="ml-auto font-mono">{res.elapsedMs} ms</span>
          </div>

          {/* Aggregated stats view */}
          {res.stats ? (
            <div className="p-4 space-y-1.5 max-h-72 overflow-y-auto">
              {res.stats.groups.length === 0 && <p className="text-[11px] text-ink-600 text-center py-6">No matching events.</p>}
              {res.stats.groups.map((g) => (
                <div key={g.value} className="flex items-center gap-3">
                  <span className="w-40 shrink-0 text-[11px] font-mono text-ink-200 truncate" title={g.value}>{g.value}</span>
                  <div className="flex-1 h-4 rounded bg-white/5 overflow-hidden">
                    <div className="h-full rounded bg-violet/50" style={{ width: `${(g.count / maxGroup) * 100}%` }} />
                  </div>
                  <span className="w-10 text-right text-[11px] font-mono text-violet">{g.count}</span>
                </div>
              ))}
            </div>
          ) : (
            /* Raw event rows */
            <div className="divide-y divide-white/4 max-h-72 overflow-y-auto">
              {res.results.length === 0 && <p className="text-[11px] text-ink-600 text-center py-6">No matching events.</p>}
              {res.results.map((e) => (
                <div key={e.id} className="px-5 py-2.5">
                  <div className="flex items-center gap-2 flex-wrap text-[10px]">
                    <span className="font-mono text-ink-600 flex items-center gap-1"><Hash className="w-2.5 h-2.5" />{relTime(e.ts)}</span>
                    {e.eventType && <span className="px-1.5 py-0.5 rounded bg-magenta/10 text-magenta font-mono">{e.eventType}</span>}
                    {e.srcIp && <span className="font-mono text-ink-300">src={e.srcIp}</span>}
                    {e.destIp && <span className="font-mono text-ink-300">dst={e.destIp}{e.destPort ? `:${e.destPort}` : ''}</span>}
                    {e.username && <span className="font-mono text-ink-400">user={e.username}</span>}
                    {e.hostname && <span className="font-mono text-ink-400">host={e.hostname}</span>}
                    {e.mitreTechId && <span className="px-1.5 py-0.5 rounded bg-violet/10 text-violet font-mono">{e.mitreTechId}</span>}
                  </div>
                  {e.raw && <p className="text-[10px] font-mono text-ink-500 mt-1 truncate">{e.raw}</p>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </motion.div>
  )
}
