/**
 * Theme-aware semantic colours - the single source of truth for severity,
 * status and categorical chart colours across the dashboard.
 *
 * Values are `rgb(var(--token))`, NOT hardcoded hex, so they follow whichever
 * `[data-theme]` the user picks (globals.css redefines the tokens per theme).
 * A hardcoded "#FF2E97" would stay Plasma-Noir pink in every theme - that's why
 * some surfaces "don't respect the palette". Use these in inline `style`/SVG
 * (which can't take Tailwind classes); use Tailwind tokens (text-magenta, …) in
 * className.
 *
 *   critical → magenta   high → threat   medium → amber
 *   low → safe           info → violet
 */
export type ThemeToken = 'magenta' | 'violet' | 'amber' | 'teal' | 'threat' | 'safe' | 'ink'

const VAR: Record<ThemeToken, string> = {
  magenta: '--magenta', violet: '--violet', amber: '--amber', teal: '--teal',
  threat: '--threat', safe: '--safe', ink: '--ink-400',
}

/** Solid theme colour, e.g. `tk('magenta')` → "rgb(var(--magenta))". */
export const tk = (name: ThemeToken): string => `rgb(var(${VAR[name]}))`

/**
 * Add alpha to a colour string. Supports both `rgb(var(--x))` tokens (→ the
 * modern `rgb(var(--x) / a)` form) and plain hex (→ #rrggbbaa), so existing
 * `${color}NN` call sites convert cleanly regardless of the source colour.
 */
export function withAlpha(color: string, a: number): string {
  const m = color.match(/^rgb\(\s*(var\(--[\w-]+\))\s*\)$/)
  if (m) return `rgb(${m[1]} / ${a})`
  const hex = color.replace('#', '')
  if (/^[0-9a-fA-F]{6}$/.test(hex)) {
    const aa = Math.round(Math.max(0, Math.min(1, a)) * 255).toString(16).padStart(2, '0')
    return `#${hex}${aa}`
  }
  return color
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: tk('magenta'),
  high: tk('threat'),
  medium: tk('amber'),
  low: tk('safe'),
  info: tk('violet'),
}
/** Singular alias - many components use the name `SEV_COLOR` locally. */
export const SEVERITY_COLOR = SEVERITY_COLORS

export const STATUS_COLORS: Record<string, string> = {
  // open / unresolved work
  open: tk('threat'),
  active: tk('magenta'),
  new: tk('magenta'),
  triaged: tk('amber'),
  'in-progress': tk('amber'),
  pending: tk('amber'),
  // resolved work
  resolved: tk('safe'),
  closed: tk('safe'),
  patched: tk('safe'),
  // special
  accepted: tk('violet'),
}

/** Categorical palette for charts (MITRE tactics, case types, …). The core hues
 * map to theme tokens; two extra hues stay fixed so multi-series charts keep
 * enough distinct colours. */
export const CHART_PALETTE = {
  magenta: tk('magenta'),
  red: tk('threat'),
  amber: tk('amber'),
  orange: '#FF9B2E',
  violet: tk('violet'),
  lavender: '#A78BFA',
  teal: tk('teal'),
  mint: tk('safe'),
} as const
