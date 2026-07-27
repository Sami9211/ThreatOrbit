import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`
  return n.toString()
}

/**
 * Indicator provenance. The Live Processing Engine writes SIMULATED indicators
 * (randomly generated IPs/hashes from `engine.py`) tagged `engine:*`, so the
 * pipeline has something to act on before real logs are forwarded. They are
 * genuinely useful for exercising detection/correlation, but they are NOT
 * observed threat intelligence and must never be presented as if they were.
 *
 * Everything else - OTX, NVD, TAXII, abuse.ch, custom connectors, manual
 * imports - is real, externally sourced data.
 */
export function isSimulatedSource(source?: string | null): boolean {
  return !!source && source.toLowerCase().startsWith('engine:')
}

/** Short provenance label for an indicator's source. */
export function provenanceLabel(source?: string | null): 'Simulated' | 'Real feed' {
  return isSimulatedSource(source) ? 'Simulated' : 'Real feed'
}

/** Render a cadence in SECONDS as a compact human label (45s / 5m / 2h).
 *  Sub-minute cadences are supported end to end, so anything that formats one
 *  must not divide by 60 and round - that turned a saved 1s interval into "0m"
 *  and made a working connector look misconfigured. */
export function formatEvery(secs: number): string {
  if (!Number.isFinite(secs) || secs <= 0) return '-'
  if (secs < 60) return `${Math.round(secs)}s`
  if (secs < 3600) return secs % 60 ? `${Math.floor(secs / 60)}m ${secs % 60}s` : `${secs / 60}m`
  return secs % 3600 ? `${Math.floor(secs / 3600)}h ${Math.round((secs % 3600) / 60)}m` : `${secs / 3600}h`
}
