'use client'

import { useState } from 'react'
import { usePathname } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Globe, Search, Activity, Zap, Brain, Radio, Settings, Home,
  ChevronRight, AlertTriangle, Wifi,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'

const NAV = [
  {
    section: null,
    items: [{ href: '/dashboard', label: 'Overview', icon: Globe }],
  },
  {
    section: 'Intelligence',
    items: [
      { href: '/dashboard/feeds', label: 'Threat Feeds', icon: Radio },
      { href: '/dashboard/scanner', label: 'Threat Scanner', icon: Search },
      { href: '/dashboard/cti', label: 'CTI Intelligence', icon: Brain },
    ],
  },
  {
    section: 'Operations',
    items: [
      { href: '/dashboard/siem', label: 'SIEM', icon: Activity },
      { href: '/dashboard/soar', label: 'SOAR', icon: Zap },
    ],
  },
  {
    section: 'System',
    items: [{ href: '/dashboard/config', label: 'Configuration', icon: Settings }],
  },
]

export default function Sidebar() {
  const pathname = usePathname()
  const [expanded, setExpanded] = useState(false)

  return (
    <motion.aside
      className="fixed left-0 top-0 bottom-0 z-40 flex flex-col bg-[#0D0920] border-r border-white/5 overflow-hidden select-none"
      animate={{ width: expanded ? 232 : 56 }}
      transition={{ type: 'spring', stiffness: 320, damping: 32 }}
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
    >
      {/* Logo row */}
      <div className="h-14 flex items-center px-3.5 border-b border-white/5 shrink-0">
        <Logo size={26} className="shrink-0" />
        <AnimatePresence>
          {expanded && (
            <motion.div
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -6 }}
              transition={{ duration: 0.14 }}
              className="ml-2.5 whitespace-nowrap overflow-hidden"
            >
              <span className="font-display font-bold text-sm text-white">Threat</span>
              <span className="font-display font-bold text-sm text-gradient-magenta">Orbit</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Live status chip */}
      <div className="px-3 pt-3 pb-1">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-safe/5 border border-safe/15">
          <Wifi className="w-3 h-3 text-safe shrink-0" />
          <AnimatePresence>
            {expanded && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-[10px] font-medium text-safe whitespace-nowrap"
              >
                Feeds Live
              </motion.span>
            )}
          </AnimatePresence>
          {!expanded && <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />}
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-2 space-y-0.5">
        {NAV.map(({ section, items }) => (
          <div key={section ?? '__root'}>
            <AnimatePresence>
              {expanded && section && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="px-4 pt-4 pb-1"
                >
                  <span className="text-[9px] font-semibold tracking-widest uppercase text-ink-600">
                    {section}
                  </span>
                </motion.div>
              )}
            </AnimatePresence>
            {items.map(({ href, label, icon: Icon }) => {
              const active =
                href === '/dashboard'
                  ? pathname === '/dashboard' || pathname === '/dashboard/'
                  : pathname?.startsWith(href)
              return (
                <a
                  key={href}
                  href={href}
                  title={label}
                  className={cn(
                    'relative flex items-center gap-3 mx-2 px-2.5 py-2.5 rounded-lg transition-colors duration-150',
                    active
                      ? 'bg-magenta/10 text-magenta'
                      : 'text-ink-400 hover:text-white hover:bg-white/5',
                  )}
                >
                  {active && (
                    <motion.span
                      layoutId="sidebar-active"
                      className="absolute inset-0 rounded-lg border border-magenta/25 bg-magenta/8"
                      transition={{ type: 'spring', stiffness: 380, damping: 32 }}
                    />
                  )}
                  <Icon className="w-4 h-4 shrink-0 relative" />
                  <AnimatePresence>
                    {expanded && (
                      <motion.span
                        initial={{ opacity: 0, x: -6 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -6 }}
                        transition={{ duration: 0.12 }}
                        className="text-xs font-medium whitespace-nowrap relative"
                      >
                        {label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                  {active && expanded && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="ml-auto relative"
                    >
                      <ChevronRight className="w-3 h-3 text-magenta/60" />
                    </motion.span>
                  )}
                </a>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Alerts badge */}
      <div className="px-2 pb-2">
        <a
          href="/dashboard/siem"
          title="Active Alerts"
          className="flex items-center gap-3 px-2.5 py-2 rounded-lg text-amber hover:bg-amber/5 transition-colors"
        >
          <div className="relative shrink-0">
            <AlertTriangle className="w-4 h-4" />
            <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-threat text-[8px] font-bold text-white flex items-center justify-center">
              7
            </span>
          </div>
          <AnimatePresence>
            {expanded && (
              <motion.span
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -6 }}
                className="text-xs whitespace-nowrap"
              >
                7 Active Alerts
              </motion.span>
            )}
          </AnimatePresence>
        </a>
      </div>

      {/* Back to landing */}
      <div className="border-t border-white/5 px-2 py-2">
        <a
          href="/"
          title="Back to Landing"
          className="flex items-center gap-3 px-2.5 py-2 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors"
        >
          <Home className="w-4 h-4 shrink-0" />
          <AnimatePresence>
            {expanded && (
              <motion.span
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -6 }}
                className="text-xs whitespace-nowrap"
              >
                Landing Page
              </motion.span>
            )}
          </AnimatePresence>
        </a>
      </div>
    </motion.aside>
  )
}
