'use client'

import { usePathname } from 'next/navigation'

/**
 * The Overview page was designed at a dense, information-rich scale that reads
 * well on a laptop. The other dashboard pages were authored a touch larger, so
 * on laptop/desktop they feel "zoomed in" by comparison. Rather than hand-tuning
 * every type and spacing token across seven pages, we tag non-overview routes so
 * the `.page-scale[data-zoom="out"]` rule in globals.css scales the whole subtree
 * down to Overview's effective density. The zoom is gated to md+ via media query
 * (mobile layouts already stack, so shrinking them would only hurt legibility),
 * and the TopBar/Sidebar live outside this wrapper so the chrome stays constant.
 */
export default function PageScale({ children }: { children: React.ReactNode }) {
  const raw = usePathname() ?? '/dashboard'
  const path = raw.length > 1 ? raw.replace(/\/$/, '') : raw
  const isOverview = path === '/dashboard'

  return (
    <div className="page-scale h-full" data-zoom={isOverview ? 'in' : 'out'}>
      {children}
    </div>
  )
}
