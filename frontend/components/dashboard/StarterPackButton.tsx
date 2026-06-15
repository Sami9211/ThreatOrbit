'use client'

import { useState } from 'react'
import { PackageOpen, Loader2, CheckCircle2 } from 'lucide-react'
import { loadDetectionPack } from '@/lib/api'

/**
 * One-click load of the curated starter detection pack - real Sigma rules
 * mapped to the platform's own event stream. Idempotent: rules already present
 * are skipped, so it's safe to click more than once.
 */
export default function StarterPackButton({ onLoaded }: { onLoaded?: () => void }) {
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)

  function load() {
    if (busy) return
    setBusy(true)
    setMsg(null)
    loadDetectionPack()
      .then((r) => {
        const c = r.created.length
        const s = r.skipped.length
        setMsg(c > 0 ? `Loaded ${c} rule${c !== 1 ? 's' : ''}${s ? `, ${s} already present` : ''}.` : 'Starter pack already loaded.')
        onLoaded?.()
      })
      .catch(() => setMsg('Could not load the starter pack.'))
      .finally(() => { setBusy(false); setTimeout(() => setMsg(null), 4000) })
  }

  return (
    <div className="relative">
      <button onClick={load} disabled={busy}
        title="Load a curated pack of real Sigma detections (idempotent)"
        className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors active:scale-95 disabled:opacity-50">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <PackageOpen className="w-4 h-4" />}
        Starter pack
      </button>
      {msg && (
        <span className="absolute top-full left-0 mt-1 flex items-center gap-1 text-[11px] text-safe whitespace-nowrap">
          <CheckCircle2 className="w-3 h-3 shrink-0" /> {msg}
        </span>
      )}
    </div>
  )
}
