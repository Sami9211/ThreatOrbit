'use client'

import { useState, useEffect } from 'react'
import { Check, KeyRound } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchEnrichmentProviders, setEnrichmentProviderKey, type EnrichmentProvider,
} from '@/lib/api'

/**
 * Configure the external IOC-enrichment providers (VirusTotal, GreyNoise,
 * Shodan, WHOIS). These are per-indicator lookup services, distinct from feed
 * connectors. The API key is stored encrypted server-side and never returned;
 * this panel only shows whether one is set and lets an admin set/clear it, so
 * wiring VirusTotal is a paste-and-save, not an env var + redeploy.
 */
function ProviderRow({ p, onChanged }: { p: EnrichmentProvider; onChanged: () => void }) {
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)

  async function save() {
    if (!key.trim() || busy) return
    setBusy(true); setMsg(null)
    try { await setEnrichmentProviderKey(p.provider, key.trim()); setKey(''); setMsg('Saved'); onChanged() }
    catch { setMsg('Could not save') }
    finally { setBusy(false) }
  }
  async function clear() {
    if (busy) return
    setBusy(true); setMsg(null)
    try { await setEnrichmentProviderKey(p.provider, ''); setKey(''); setMsg('Cleared'); onChanged() }
    catch { setMsg('Could not clear') }
    finally { setBusy(false) }
  }

  const badge = p.source === 'ui'
    ? { text: 'Configured', cls: 'text-safe bg-safe/12' }
    : p.source === 'env'
    ? { text: `via ${p.envVar}`, cls: 'text-violet bg-violet/12' }
    : { text: 'Not configured', cls: 'text-ink-500 bg-white/6' }

  return (
    <div className="p-4 rounded-xl border border-white/8 bg-surface-2/40">
      <div className="flex items-center gap-2 mb-2">
        <KeyRound className="w-3.5 h-3.5 text-ink-400" />
        <p className="text-xs font-semibold text-white">{p.label}</p>
        <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-semibold inline-flex items-center gap-1', badge.cls)}>
          {p.configured && p.source === 'ui' && <Check className="w-2.5 h-2.5" />}{badge.text}
        </span>
      </div>
      <div className="flex flex-wrap gap-2 items-center">
        <input
          type="password" value={key} onChange={(e) => setKey(e.target.value)}
          placeholder={p.configured ? 'Enter a new key to replace' : `${p.label} API key`}
          className="flex-1 min-w-[180px] px-3 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-hidden focus:border-amber/40 placeholder-ink-600"
          autoComplete="off" />
        <button onClick={save} disabled={busy || !key.trim()}
          className="px-3 py-2 rounded-lg text-xs font-medium bg-amber/15 border border-amber/30 text-amber hover:bg-amber/20 disabled:opacity-40 transition-colors">Save</button>
        {p.source === 'ui' && (
          <button onClick={clear} disabled={busy}
            className="px-3 py-2 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-400 hover:text-threat disabled:opacity-40 transition-colors">Clear</button>
        )}
        {msg && <span className="text-[11px] text-ink-500">{msg}</span>}
      </div>
    </div>
  )
}

export default function EnrichmentProvidersPanel() {
  const [providers, setProviders] = useState<EnrichmentProvider[] | null>(null)
  const [error, setError] = useState(false)
  const load = () => fetchEnrichmentProviders().then(setProviders).catch(() => setError(true))
  useEffect(() => { load() }, [])

  if (error) return <p className="text-[11px] text-ink-500">Enrichment configuration is unavailable (admin permission required).</p>
  if (!providers) return <p className="text-[11px] text-ink-600">Loading providers…</p>
  return (
    <div className="space-y-3">
      <p className="text-[11px] text-ink-500">
        External lookup providers used to enrich indicators in IntelScope and the CTI store. Keys are
        stored encrypted and never displayed again. A key set here takes precedence over an environment variable.
      </p>
      {providers.map((p) => <ProviderRow key={p.provider} p={p} onChanged={load} />)}
    </div>
  )
}
