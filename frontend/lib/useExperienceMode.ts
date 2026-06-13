'use client'

import { useEffect, useState, useCallback } from 'react'

/**
 * Global "experience mode" - Normal (simplified) vs Power User (full detail).
 * Persisted to localStorage and synced across all mounted components on the
 * same page (custom event) and across tabs (storage event). Defaults to
 * 'normal' and renders deterministically on first paint to avoid hydration
 * mismatch (the persisted value is applied after mount).
 */
export type ExperienceMode = 'normal' | 'power'

const KEY = 'to-experience-mode'
const EVT = 'to-experience-mode-change'

export function useExperienceMode(): [ExperienceMode, (m: ExperienceMode) => void] {
  const [mode, setModeState] = useState<ExperienceMode>('normal')

  // Hydrate from localStorage after mount (deterministic SSR default = 'normal')
  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(KEY)
      if (stored === 'power' || stored === 'normal') setModeState(stored)
    } catch { /* ignore */ }

    const onCustom = (e: Event) => {
      const next = (e as CustomEvent<ExperienceMode>).detail
      if (next === 'power' || next === 'normal') setModeState(next)
    }
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY && (e.newValue === 'power' || e.newValue === 'normal')) {
        setModeState(e.newValue)
      }
    }
    window.addEventListener(EVT, onCustom)
    window.addEventListener('storage', onStorage)
    return () => {
      window.removeEventListener(EVT, onCustom)
      window.removeEventListener('storage', onStorage)
    }
  }, [])

  const setMode = useCallback((m: ExperienceMode) => {
    setModeState(m)
    try { window.localStorage.setItem(KEY, m) } catch { /* ignore */ }
    window.dispatchEvent(new CustomEvent<ExperienceMode>(EVT, { detail: m }))
  }, [])

  return [mode, setMode]
}
