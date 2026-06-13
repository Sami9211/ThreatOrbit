'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Radar, Globe, UserPlus, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchExposure, fetchDiscoveredAssets, promoteDiscoveredAsset,
  type ExposureItem, type DiscoveredAsset,
} from '@/lib/api'

const BAND_CLS: Record<string, string> = {
  critical: 'text-magenta bg-magenta/12', high: 'text-threat bg-threat/12',
  medium: 'text-amber bg-amber/12', low: 'text-safe bg-safe/12',
}

function relTime(iso: string | null): string {
  if (!iso) return '-'
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

/**
 * Attack surface - the live exposure inventory (factor-based scoring over the
 * managed fleet, internet-facing flagged) plus passive discovery: unmanaged
 * hostnames observed in real telemetry, promotable into the inventory in one
 * click. All data comes from `/assets/exposure` and `/assets/discovered`.
 */
export default function AttackSurfacePanel({ onPromoted }: { onPromoted?: () => void }) {
  const [exposure, setExposure] = useState<{ items: ExposureItem[]
    summary: { assets: number; internetFacing: number; criticalExposure: number
      avgExposure: number; topFactor: string | null } } | null>(null)
  const [discovered, setDiscovered] = useState<DiscoveredAsset[] | null>(null)
  const [promoting, setPromoting] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  const load = useCallback(() => {
    fetchExposure().then(setExposure).catch(() => {})
    fetchDiscoveredAssets().then((d) => setDiscovered(d.items)).catch(() => {})
  }, [])
  useEffect(() => { load() }, [load])

  function promote(host: string) {
    setPromoting(host)
    promoteDiscoveredAsset(host)
      .then(() => {
        setDiscovered((xs) => (xs ?? []).filter((x) => x.hostname !== host))
        setMsg(`${host} registered into the managed inventory`)
        onPromoted?.()
        load()
      })
      .catch((e) => setMsg(e instanceof Error && e.message.includes('already')
        ? `${host} is already in the inventory`
        : 'Could not promote the host.'))
      .finally(() => { setPromoting(null); setTimeout(() => setMsg(null), 4000) })
  }

  const sum = exposure?.summary
  const facing = (exposure?.items ?? []).filter((i) => i.internetFacing)

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/8 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5 flex-wrap">
        <div className="p-1.5 rounded-lg bg-threat/15 border border-threat/25 shrink-0">
          <Radar className="w-4 h-4 text-threat" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">Attack surface</h3>
          <p className="text-[10px] text-ink-500">Exposure scoring over the fleet + unmanaged hosts discovered in real telemetry</p>
        </div>
        {sum && (
          <div className="ml-auto flex items-center gap-3 text-[10px] flex-wrap">
            <span className="text-ink-500"><b className="text-white font-mono">{sum.internetFacing}</b> internet-facing</span>
            <span className="text-ink-500"><b className="text-magenta font-mono">{sum.criticalExposure}</b> critical exposure</span>
            <span className="text-ink-500">avg <b className="text-amber font-mono">{sum.avgExposure}</b></span>
            {sum.topFactor && <span className="text-ink-500">top driver <b className="text-violet">{sum.topFactor}</b></span>}
          </div>
        )}
      </div>

      <div className="grid lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-white/5">
        {/* Internet-facing exposure inventory */}
        <div className="p-4">
          <p className="text-[10px] font-semibold text-ink-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
            <Globe className="w-3 h-3" /> Internet-facing inventory
          </p>
          {exposure === null ? (
            <p className="text-[11px] text-ink-600 py-4 animate-pulse">Loading exposure…</p>
          ) : facing.length === 0 ? (
            <p className="text-[11px] text-ink-600 py-4">No internet-facing assets in the inventory.</p>
          ) : (
            <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
              {facing.map((i) => (
                <div key={i.id} className="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-white/3 border border-white/6">
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] font-mono text-ink-200 truncate">{i.name}</p>
                    <p className="text-[10px] text-ink-600 truncate"
                      title={i.factors.map((f) => `${f.factor} (+${f.weight})`).join(', ')}>
                      {i.factors.slice(0, 3).map((f) => f.factor).join(' · ') || i.value}
                    </p>
                  </div>
                  <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold uppercase',
                    BAND_CLS[i.band] ?? BAND_CLS.medium)}>{i.band}</span>
                  <span className="text-xs font-bold font-mono text-amber w-8 text-right">{i.score}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Passive discovery → promotion */}
        <div className="p-4">
          <p className="text-[10px] font-semibold text-ink-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
            <UserPlus className="w-3 h-3" /> Discovered (unmanaged) hosts
          </p>
          {discovered === null ? (
            <p className="text-[11px] text-ink-600 py-4 animate-pulse">Scanning telemetry…</p>
          ) : discovered.length === 0 ? (
            <p className="text-[11px] text-ink-600 py-4">
              No unmanaged hosts observed - every hostname in the event stream is already inventoried.
            </p>
          ) : (
            <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
              {discovered.map((d) => (
                <div key={d.hostname} className="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-white/3 border border-white/6 group">
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] font-mono text-ink-200 truncate">{d.hostname}</p>
                    <p className="text-[10px] text-ink-600">
                      {d.events} events · {d.alerts} alerts · last seen {relTime(d.lastSeen)}
                    </p>
                  </div>
                  <button onClick={() => promote(d.hostname)} disabled={promoting === d.hostname}
                    title="Register this host into the managed inventory"
                    className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-medium bg-safe/10 border border-safe/25 text-safe hover:bg-safe/20 disabled:opacity-50 transition-colors">
                    {promoting === d.hostname
                      ? <Loader2 className="w-3 h-3 animate-spin" />
                      : <UserPlus className="w-3 h-3" />}
                    Promote
                  </button>
                </div>
              ))}
            </div>
          )}
          {msg && <p className="text-[10px] text-safe mt-2" role="status">{msg}</p>}
        </div>
      </div>
    </motion.div>
  )
}
