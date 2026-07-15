'use client'

import { useEffect, useState, useCallback } from 'react'

/**
 * Dashboard colour scheme. Applied via a `data-theme` attribute on the
 * dashboard wrapper only (see components/dashboard/ThemeScope.tsx), so the
 * public marketing site always keeps the default Plasma Noir palette. The
 * actual colour values live in app/globals.css under [data-theme="…"].
 *
 * Persisted to localStorage and synced across mounted components (custom
 * event) and across tabs (storage event). Renders deterministically on first
 * paint as 'plasma' to avoid hydration mismatch; the stored value is applied
 * after mount.
 */
export type DashboardTheme =
  | 'plasma' | 'mono' | 'arctic' | 'matrix' | 'solar' | 'crimson'
  | 'nebula' | 'oceanic' | 'cyber' | 'slate' | 'ember'

export const THEMES: {
  id: DashboardTheme
  label: string
  desc: string
  /** Swatch colours for the picker - [bg, primary, secondary, tertiary] */
  swatch: [string, string, string, string]
}[] = [
  { id: 'plasma',  label: 'Plasma Noir', desc: 'Magenta · violet · amber',  swatch: ['#0A0612', '#FF2E97', '#7A3CFF', '#FFB23E'] },
  { id: 'mono',    label: 'Monochrome',  desc: 'Black & white graphite',    swatch: ['#0A0A0B', '#FAFAFA', '#B8B8C0', '#71717A'] },
  { id: 'arctic',  label: 'Arctic',      desc: 'Sky · indigo · cyan',       swatch: ['#060B12', '#38BDF8', '#6366F1', '#22D3EE'] },
  { id: 'matrix',  label: 'Matrix',      desc: 'Terminal green',            swatch: ['#050A05', '#34D058', '#16A34A', '#A3E635'] },
  { id: 'solar',   label: 'Solar Flare', desc: 'Amber · orange warmth',     swatch: ['#120B05', '#FB923C', '#F59E0B', '#FBBF24'] },
  { id: 'crimson', label: 'Crimson',     desc: 'Rose · red threat tone',    swatch: ['#0F0608', '#F43F5E', '#DC2626', '#FB7185'] },
  { id: 'nebula',  label: 'Nebula',      desc: 'Violet · fuchsia · cyan',   swatch: ['#0B0818', '#C084FC', '#818CF8', '#22D3EE'] },
  { id: 'oceanic', label: 'Oceanic',     desc: 'Cyan · aqua on deep teal',  swatch: ['#050E14', '#22D3EE', '#38BDF8', '#5EEAD4'] },
  { id: 'cyber',   label: 'Cyberpunk',   desc: 'Neon cyan · magenta · lime', swatch: ['#06060A', '#00F5D4', '#FF0099', '#BEF264'] },
  { id: 'slate',   label: 'Slate',       desc: 'Cool professional blue-grey', swatch: ['#090C12', '#60A5FA', '#818CF8', '#94A3B8'] },
  { id: 'ember',   label: 'Ember',       desc: 'Warm rose · gold on charcoal', swatch: ['#0E0A09', '#FB923C', '#F472B6', '#FACC15'] },
]

/* -- Detailed customization knobs (layered on top of the chosen theme) ------
   Persisted separately and applied by ThemeScope: a custom accent (overrides
   the theme's primary), a UI scale (zoom), reduced motion, and compact
   density. Synced cross-tab like the theme. */
export interface DashboardPrefs {
  accent: string | null   // hex like "#FF2E97" - overrides the theme primary
  scale: number           // 0.9 .. 1.4 (UI zoom, applied as CSS zoom)
  motion: 'full' | 'reduced'
  density: 'comfortable' | 'compact'
}

export const DEFAULT_PREFS: DashboardPrefs = {
  accent: null, scale: 1, motion: 'full', density: 'comfortable',
}

/** Suggested accent swatches for quick selection in the picker. */
export const ACCENT_PRESETS = [
  '#FF2E97', '#7A3CFF', '#FB923C', '#34D058', '#38BDF8', '#22D3EE',
  '#F43F5E', '#FACC15', '#C084FC', '#FF0099', '#00F5D4', '#60A5FA',
]

const PREFS_KEY = 'to-dashboard-prefs'
const PREFS_EVT = 'to-dashboard-prefs-change'

function clamp(n: number, lo: number, hi: number) {
  return Math.min(hi, Math.max(lo, n))
}

function sanitizePrefs(raw: unknown): DashboardPrefs {
  const p = (raw && typeof raw === 'object') ? raw as Record<string, unknown> : {}
  const accent = typeof p.accent === 'string' && /^#[0-9a-fA-F]{6}$/.test(p.accent) ? p.accent : null
  const scale = typeof p.scale === 'number' ? clamp(p.scale, 0.9, 1.4) : 1
  const motion = p.motion === 'reduced' ? 'reduced' : 'full'
  const density = p.density === 'compact' ? 'compact' : 'comfortable'
  return { accent, scale, motion, density }
}

export function useDashboardPrefs(): [DashboardPrefs, (patch: Partial<DashboardPrefs>) => void] {
  const [prefs, setPrefs] = useState<DashboardPrefs>(DEFAULT_PREFS)

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(PREFS_KEY)
      if (stored) setPrefs(sanitizePrefs(JSON.parse(stored)))
    } catch { /* ignore */ }

    const onCustom = (e: Event) => setPrefs(sanitizePrefs((e as CustomEvent).detail))
    const onStorage = (e: StorageEvent) => {
      if (e.key === PREFS_KEY && e.newValue) {
        try { setPrefs(sanitizePrefs(JSON.parse(e.newValue))) } catch { /* ignore */ }
      }
    }
    window.addEventListener(PREFS_EVT, onCustom)
    window.addEventListener('storage', onStorage)
    return () => {
      window.removeEventListener(PREFS_EVT, onCustom)
      window.removeEventListener('storage', onStorage)
    }
  }, [])

  const update = useCallback((patch: Partial<DashboardPrefs>) => {
    setPrefs((prev) => {
      const next = sanitizePrefs({ ...prev, ...patch })
      try { window.localStorage.setItem(PREFS_KEY, JSON.stringify(next)) } catch { /* ignore */ }
      window.dispatchEvent(new CustomEvent(PREFS_EVT, { detail: next }))
      return next
    })
  }, [])

  return [prefs, update]
}

/** Convert "#RRGGBB" -> "r g b" for a CSS custom property. */
export function hexToRgbTriplet(hex: string): string | null {
  const m = /^#([0-9a-fA-F]{6})$/.exec(hex)
  if (!m) return null
  const n = parseInt(m[1], 16)
  return `${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255}`
}

const KEY = 'to-dashboard-theme'
const EVT = 'to-dashboard-theme-change'
const VALID: DashboardTheme[] = THEMES.map((t) => t.id)

function isTheme(v: unknown): v is DashboardTheme {
  return typeof v === 'string' && (VALID as string[]).includes(v)
}

export function useDashboardTheme(): [DashboardTheme, (t: DashboardTheme) => void] {
  const [theme, setThemeState] = useState<DashboardTheme>('plasma')

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(KEY)
      if (isTheme(stored)) setThemeState(stored)
    } catch { /* ignore */ }

    const onCustom = (e: Event) => {
      const next = (e as CustomEvent<DashboardTheme>).detail
      if (isTheme(next)) setThemeState(next)
    }
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY && isTheme(e.newValue)) setThemeState(e.newValue)
    }
    window.addEventListener(EVT, onCustom)
    window.addEventListener('storage', onStorage)
    return () => {
      window.removeEventListener(EVT, onCustom)
      window.removeEventListener('storage', onStorage)
    }
  }, [])

  const setTheme = useCallback((t: DashboardTheme) => {
    setThemeState(t)
    try { window.localStorage.setItem(KEY, t) } catch { /* ignore */ }
    window.dispatchEvent(new CustomEvent<DashboardTheme>(EVT, { detail: t }))
  }, [])

  return [theme, setTheme]
}
