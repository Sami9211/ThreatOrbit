'use client'

import { useEffect } from 'react'
import { useDashboardTheme, useDashboardPrefs, hexToRgbTriplet } from '@/lib/useDashboardTheme'

/**
 * Wraps the dashboard and applies the selected colour scheme plus the
 * personal customization prefs. Everything is scoped here (rather than on
 * <html>) so the public marketing site is never affected:
 *
 *   data-theme   - colour palette (11 presets, values in globals.css)
 *   --magenta    - optional custom accent, overrides the theme's primary
 *   data-motion  - 'reduced' kills animations/transitions (CSS in globals.css)
 *   data-density - 'compact' is reflected as a tighter rem baseline (below)
 *   scale        - UI zoom, also applied through the rem baseline
 *
 * Scale + density both act on the root font-size so every rem-based spacing
 * and text token scales together (a genuine zoom / density change, not a
 * cosmetic flag). It is restored on unmount, so leaving the dashboard returns
 * the document to its default sizing.
 */
export default function ThemeScope({ children }: { children: React.ReactNode }) {
  const [theme] = useDashboardTheme()
  const [prefs] = useDashboardPrefs()

  useEffect(() => {
    const px = 16 * prefs.scale * (prefs.density === 'compact' ? 0.92 : 1)
    const prev = document.documentElement.style.fontSize
    document.documentElement.style.fontSize = `${px.toFixed(2)}px`
    return () => { document.documentElement.style.fontSize = prev }
  }, [prefs.scale, prefs.density])

  const accent = prefs.accent ? hexToRgbTriplet(prefs.accent) : null
  const style = accent ? ({ ['--magenta']: accent } as React.CSSProperties) : undefined

  return (
    <div
      data-theme={theme}
      data-motion={prefs.motion}
      data-density={prefs.density}
      style={style}
      className="flex min-h-screen bg-bg"
    >
      {children}
    </div>
  )
}
