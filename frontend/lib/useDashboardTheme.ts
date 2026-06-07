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
export type DashboardTheme = 'plasma' | 'mono' | 'arctic' | 'matrix' | 'solar' | 'crimson'

export const THEMES: {
  id: DashboardTheme
  label: string
  desc: string
  /** Swatch colours for the picker — [bg, primary, secondary, tertiary] */
  swatch: [string, string, string, string]
}[] = [
  { id: 'plasma',  label: 'Plasma Noir', desc: 'Magenta · violet · amber',  swatch: ['#0A0612', '#FF2E97', '#7A3CFF', '#FFB23E'] },
  { id: 'mono',    label: 'Monochrome',  desc: 'Black & white graphite',    swatch: ['#0A0A0B', '#FAFAFA', '#B8B8C0', '#71717A'] },
  { id: 'arctic',  label: 'Arctic',      desc: 'Sky · indigo · cyan',       swatch: ['#060B12', '#38BDF8', '#6366F1', '#22D3EE'] },
  { id: 'matrix',  label: 'Matrix',      desc: 'Terminal green',            swatch: ['#050A05', '#34D058', '#16A34A', '#A3E635'] },
  { id: 'solar',   label: 'Solar Flare', desc: 'Amber · orange warmth',     swatch: ['#120B05', '#FB923C', '#F59E0B', '#FBBF24'] },
  { id: 'crimson', label: 'Crimson',     desc: 'Rose · red threat tone',    swatch: ['#0F0608', '#F43F5E', '#DC2626', '#FB7185'] },
]

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
