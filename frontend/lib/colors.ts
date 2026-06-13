/**
 * Semantic color mappings - the single source of truth for severity, status,
 * and categorical chart colors across the dashboard. Values mirror the token
 * palette in tailwind.config.ts / globals.css.
 *
 *   critical → magenta   high → threat   medium → amber
 *   low → safe           info → violet
 */

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF2E97',
  high: '#FF4D6D',
  medium: '#FFB23E',
  low: '#34F5C5',
  info: '#7A3CFF',
}

export const STATUS_COLORS: Record<string, string> = {
  // open/unresolved work
  open: '#FF4D6D',
  active: '#FF2E97',
  new: '#FF2E97',
  triaged: '#FFB23E',
  'in-progress': '#FFB23E',
  pending: '#FFB23E',
  // resolved work
  resolved: '#34F5C5',
  closed: '#34F5C5',
  patched: '#34F5C5',
  // special
  accepted: '#7A3CFF',
}

/** Categorical palette for charts (MITRE tactics, case types, …). Keeps the
 * extra hues the charts need without scattering raw hexes through pages. */
export const CHART_PALETTE = {
  magenta: '#FF2E97',
  red: '#FF4D6D',
  amber: '#FFB23E',
  orange: '#FF9B2E',
  violet: '#7A3CFF',
  lavender: '#A78BFA',
  teal: '#2DD4BF',
  mint: '#34F5C5',
} as const
