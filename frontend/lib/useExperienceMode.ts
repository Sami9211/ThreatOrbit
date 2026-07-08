'use client'

import { useEffect, useState, useCallback } from 'react'
import { fetchOrgMode, setOrgMode } from '@/lib/api'

/**
 * Global "experience mode" - Normal (simplified) vs Power User (full detail).
 * Persisted to localStorage (instant, offline-friendly first paint) AND
 * synced with the backend org mode (`GET`/`PUT /config/mode` - 'simple' on
 * the wire, 'normal' in this UI) so the choice follows the org across
 * devices/sessions. Synced across mounted components on the same page
 * (custom event) and across tabs (storage event). Defaults to 'normal' and
 * renders deterministically on first paint to avoid hydration mismatch (both
 * the local and backend values are applied after mount).
 *
 * The backend sync is best-effort and fails open: if it's unreachable, the
 * toggle still works instantly from localStorage - this is a UI preference,
 * never a gate on functionality.
 */
export type ExperienceMode = 'normal' | 'power'

const KEY = 'to-experience-mode'
const EVT = 'to-experience-mode-change'
const EVT_FEATURES = 'to-experience-features-change'

const toWire   = (m: ExperienceMode): 'simple' | 'power' => (m === 'normal' ? 'simple' : 'power')
const fromWire = (m: string): ExperienceMode => (m === 'simple' ? 'normal' : 'power')

// Module-level so every mounted instance of the hook shares one backend fetch
// per page load (mirrors usePermissions' cache), rather than each component
// (TopBar, Sidebar, ...) independently hitting /config/mode.
let _backendSynced = false
// The authoritative feature-area list from the backend (which nav areas to
// surface). `null` = not yet known / a failed round-trip - callers (e.g. the
// Sidebar) must treat that as "show everything" (fail open; a UI-curation
// preference must never hide functionality it isn't certain about).
let _featuresCache: string[] | null = null

function broadcastFeatures(features: string[] | null) {
  _featuresCache = features
  window.dispatchEvent(new CustomEvent<string[] | null>(EVT_FEATURES, { detail: features }))
}

/** The org's current feature-area allowlist (null = unrestricted/unknown - show
 * everything). Shares the single backend fetch `useExperienceMode` performs. */
export function useOrgFeatures(): string[] | null {
  const [features, setFeatures] = useState<string[] | null>(_featuresCache)
  useEffect(() => {
    const onFeatures = (e: Event) => setFeatures((e as CustomEvent<string[] | null>).detail)
    window.addEventListener(EVT_FEATURES, onFeatures)
    return () => window.removeEventListener(EVT_FEATURES, onFeatures)
  }, [])
  return features
}

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

    // One-time backend sync per page load. Only an EXPLICITLY-chosen org mode
    // overrides the local value: `useExperienceMode` predates this backend
    // setting as a plain client-side preference (already defaulting to
    // 'normal' and already driving real page UI - e.g. the SIEM alert queue's
    // card density / inline triage actions). The backend's un-set fallback is
    // 'power', so treating every response as authoritative would silently
    // flip that pre-existing 'normal' default to 'power' for every org that
    // has never explicitly touched this setting - a real behaviour change,
    // not just a nav-curation preference. `features` is safe to always adopt
    // (the un-set default already resolves to "every feature", matching the
    // fail-open unrestricted state Sidebar uses when nothing is known yet).
    if (!_backendSynced) {
      _backendSynced = true
      fetchOrgMode()
        .then(({ mode: wireMode, features, explicit }) => {
          if (explicit) {
            const resolved = fromWire(wireMode)
            try { window.localStorage.setItem(KEY, resolved) } catch { /* ignore */ }
            window.dispatchEvent(new CustomEvent<ExperienceMode>(EVT, { detail: resolved }))
          }
          broadcastFeatures(features)
        })
        .catch(() => { /* offline / not yet authenticated - keep the local value, features stay unrestricted */ })
    }

    return () => {
      window.removeEventListener(EVT, onCustom)
      window.removeEventListener('storage', onStorage)
    }
  }, [])

  const setMode = useCallback((m: ExperienceMode) => {
    setModeState(m)
    try { window.localStorage.setItem(KEY, m) } catch { /* ignore */ }
    window.dispatchEvent(new CustomEvent<ExperienceMode>(EVT, { detail: m }))
    // Switching to Power is always "show everything" - correct immediately,
    // no need to wait on the network. Switching to Normal needs the backend's
    // curated feature list, so nav stays unrestricted (fail open) until the
    // PUT resolves rather than guess-and-hide.
    if (m === 'power') broadcastFeatures(null)
    // Best-effort persist; a failed PUT never blocks the (already-applied) local toggle.
    setOrgMode(toWire(m))
      .then(({ features }) => broadcastFeatures(features))
      .catch(() => { /* offline - leave whatever feature set was last known */ })
  }, [])

  return [mode, setMode]
}
