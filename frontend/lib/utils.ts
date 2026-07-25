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
