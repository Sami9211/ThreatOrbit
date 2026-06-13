'use client'

import { useDashboardTheme } from '@/lib/useDashboardTheme'

/**
 * Wraps the dashboard and applies the selected colour scheme via a
 * `data-theme` attribute. Scoping the attribute here (rather than on <html>)
 * keeps the theme confined to the dashboard - the public site is unaffected.
 */
export default function ThemeScope({ children }: { children: React.ReactNode }) {
  const [theme] = useDashboardTheme()
  return (
    <div data-theme={theme} className="flex min-h-screen bg-bg">
      {children}
    </div>
  )
}
