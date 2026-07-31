'use client'
import { CloudOff } from 'lucide-react'
import { tk } from '@/lib/colors'

/**
 * What a page shows when it could not reach the API.
 *
 * The alternative it replaces was worse than nothing: several pages fell back to
 * a hardcoded demo dataset on a first-load failure, rendered exactly like real
 * records. On a live deployment, an expired token or a restarting backend
 * produced a SIEM queue of fabricated critical alerts - a ransomware detection
 * against a host that does not exist, attributed to a country nobody had
 * observed - with nothing on screen marking it as fiction.
 *
 * "We could not ask" and "there is nothing" are different answers, and a
 * security console must never present the first as the second, or as a finding.
 */
export default function ApiUnavailable(
  { what, onRetry, compact }:
  { what: string; onRetry?: () => void; compact?: boolean },
) {
  return (
    <div className={compact ? 'py-6 text-center' : 'py-12 text-center'}>
      <CloudOff className="w-5 h-5 mx-auto mb-2" style={{ color: tk('amber') }} />
      <p className="text-[12px] text-ink-300">Could not load {what}.</p>
      <p className="text-[11px] text-ink-600 mt-1.5 max-w-md mx-auto leading-relaxed">
        This is a connection problem, not a result. Nothing here should be read
        as &ldquo;nothing found&rdquo; — the question was never asked.
      </p>
      {onRetry && (
        <button onClick={onRetry}
          className="mt-3 px-3 py-1.5 rounded-lg text-[11px] border border-white/12
                     text-ink-300 hover:text-white hover:border-white/25 transition-colors">
          Try again
        </button>
      )}
    </div>
  )
}
