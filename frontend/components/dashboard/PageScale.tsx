'use client'

import { usePathname } from 'next/navigation'
import { motion } from 'framer-motion'
import { pageEnter } from '@/lib/motion'

/**
 * The Overview page was designed at a dense, information-rich scale that reads
 * well on a laptop. The other dashboard pages were authored a touch larger, so
 * on laptop/desktop they feel "zoomed in" by comparison. Rather than hand-tuning
 * every type and spacing token across seven pages, we tag non-overview routes so
 * the `.page-scale[data-zoom="out"]` rule in globals.css scales the whole subtree
 * down to Overview's effective density. The zoom is gated to md+ via media query
 * (mobile layouts already stack, so shrinking them would only hurt legibility),
 * and the TopBar/Sidebar live outside this wrapper so the chrome stays constant.
 *
 * It also hosts the per-route page transition: keying the motion element on the
 * pathname remounts it on every navigation, so the `pageEnter` variant replays
 * as a smooth fade-up. Keyed remount (rather than AnimatePresence exit) is the
 * robust App-Router pattern - no exit flash. Reduced-motion users get a still
 * fade with no upward slide (the app-root MotionConfig drops the transform,
 * keeps the opacity), verified in a browser under emulated reduce-motion.
 */
export default function PageScale({ children }: { children: React.ReactNode }) {
  const raw = usePathname() ?? '/dashboard'
  const path = raw.length > 1 ? raw.replace(/\/$/, '') : raw
  const isOverview = path === '/dashboard'

  return (
    <motion.div
      key={path}
      variants={pageEnter}
      initial="hidden"
      animate="show"
      className="page-scale h-full"
      data-zoom={isOverview ? 'in' : 'out'}
    >
      {children}
    </motion.div>
  )
}
