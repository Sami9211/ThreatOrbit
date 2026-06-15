'use client'

import { useDashboardTheme, useDashboardPrefs, hexToRgbTriplet } from '@/lib/useDashboardTheme'

/**
 * Wraps the dashboard and applies the selected colour scheme plus the
 * personal customization prefs. Everything is scoped here (rather than on
 * <html>) so the public marketing site is never affected:
 *
 *   data-theme   - colour palette (11 presets, values in globals.css)
 *   --magenta    - optional custom accent, overrides the theme's primary
 *   data-motion  - 'reduced' kills animations/transitions (CSS in globals.css)
 *   data-density - 'compact' tightens spacing (folded into the zoom below)
 *   scale        - UI zoom
 *
 * Scale + density are applied as CSS `zoom` on this wrapper. Unlike the old
 * rem-baseline trick, zoom scales EVERYTHING in the subtree - including the
 * dashboard's many pixel-pinned sizes (text-[10px], w-[120px], …) - and the
 * browser RE-FLOWS at the zoomed size, so the layout grows proportionally
 * without overlap (a genuine zoom, not a cosmetic flag). Default scale 1 ->
 * zoom 1 -> no change. Scoped here so the public marketing site is untouched.
 */
export default function ThemeScope({ children }: { children: React.ReactNode }) {
  const [theme] = useDashboardTheme()
  const [prefs] = useDashboardPrefs()

  const zoom = prefs.scale * (prefs.density === 'compact' ? 0.92 : 1)
  const accent = prefs.accent ? hexToRgbTriplet(prefs.accent) : null
  const style: React.CSSProperties = {
    ...(accent ? { ['--magenta']: accent } : {}),
    ...(zoom !== 1 ? { zoom } : {}),
  }

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
