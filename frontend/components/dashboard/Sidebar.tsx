'use client'

import { useState, useEffect } from 'react'
import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Globe, Search, Activity, Zap, Brain, Radio, Settings, Home,
  ChevronRight, AlertTriangle, Wifi, Server, EyeOff,
  PanelLeftOpen, PanelLeftClose, X, ChevronDown, Gauge,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'

type SubItem = { href: string; label: string }

type NavItem = {
  href: string
  label: string
  icon: React.ComponentType<any>
  sub?: SubItem[]
}

type NavGroup = {
  section: string | null
  items: NavItem[]
}

const NAV: NavGroup[] = [
  {
    section: null,
    items: [
      { href: '/dashboard', label: 'Overview', icon: Globe },
      { href: '/dashboard/soc', label: 'SOC Console', icon: Gauge },
    ],
  },
  {
    section: 'Intelligence',
    items: [
      {
        href: '/dashboard/feeds',
        label: 'Threat Feeds',
        icon: Radio,
        sub: [
          { href: '/dashboard/feeds',         label: 'Live Feed' },
          { href: '/dashboard/feeds/sources',  label: 'Sources' },
          { href: '/dashboard/feeds/import',   label: 'Import IOCs' },
        ],
      },
      { href: '/dashboard/scanner', label: 'IntelScope', icon: Search },
      {
        href: '/dashboard/cti',
        label: 'CTI Intelligence',
        icon: Brain,
        sub: [
          { href: '/dashboard/cti',        label: 'Overview' },
          { href: '/dashboard/cti/hunt',   label: 'Threat Hunt' },
          { href: '/dashboard/cti/actors', label: 'Actor Profiles' },
        ],
      },
      { href: '/dashboard/darkweb', label: 'Dark Web', icon: EyeOff },
    ],
  },
  {
    section: 'Operations',
    items: [
      {
        href: '/dashboard/assets',
        label: 'Asset Surface',
        icon: Server,
        sub: [
          { href: '/dashboard/assets',         label: 'Inventory' },
          { href: '/dashboard/assets/vulns',   label: 'Vulnerabilities' },
          { href: '/dashboard/assets/network', label: 'Network Map' },
        ],
      },
      {
        href: '/dashboard/siem',
        label: 'SIEM',
        icon: Activity,
        sub: [
          { href: '/dashboard/siem',         label: 'Alert Queue' },
          { href: '/dashboard/siem/rules',   label: 'Rules Engine' },
          { href: '/dashboard/siem/attack',  label: 'ATT&CK Navigator' },
          { href: '/dashboard/siem/entities', label: 'Entity Risk' },
          { href: '/dashboard/siem/sources', label: 'Log Sources' },
          { href: '/dashboard/siem/hunt',    label: 'Threat Hunt' },
        ],
      },
      {
        href: '/dashboard/soar',
        label: 'SOAR',
        icon: Zap,
        sub: [
          { href: '/dashboard/soar',              label: 'Cases' },
          { href: '/dashboard/soar/playbooks',    label: 'Playbooks' },
          { href: '/dashboard/soar/integrations', label: 'Integrations' },
          { href: '/dashboard/soar/metrics',      label: 'SOC Metrics' },
        ],
      },
    ],
  },
  {
    section: 'System',
    items: [
      {
        href: '/dashboard/config',
        label: 'Configuration',
        icon: Settings,
        sub: [
          { href: '/dashboard/config',         label: 'General' },
          { href: '/dashboard/config/sources', label: 'Data Sources' },
          { href: '/dashboard/config/users',   label: 'Users & Roles' },
          { href: '/dashboard/config/api',     label: 'API Keys' },
        ],
      },
    ],
  },
]

export default function Sidebar() {
  const pathname = usePathname()
  const [hovered, setHovered] = useState(false)
  const [pinned, setPinned] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  // Manually expanded sections (in addition to auto-expand for active)
  const [manualExpanded, setManualExpanded] = useState<Set<string>>(new Set())

  // Track viewport. The collapse-to-icon (width) behaviour is desktop-only -
  // on mobile the sidebar is always full width and visibility is controlled
  // purely by the slide (translate) on the wrapper. This prevents the width
  // from collapsing while the drawer slides away (the "flicker" on close).
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 767px)')
    const update = () => setIsMobile(mq.matches)
    update()
    mq.addEventListener('change', update)
    return () => mq.removeEventListener('change', update)
  }, [])

  const expanded = isMobile || pinned || hovered || mobileOpen

  // Close mobile sidebar on route change
  useEffect(() => { setMobileOpen(false) }, [pathname])

  // Lock body scroll while the mobile drawer is open
  useEffect(() => {
    if (!mobileOpen) return
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = '' }
  }, [mobileOpen])

  // Listen for mobile toggle event dispatched from TopBar
  useEffect(() => {
    function handler() { setMobileOpen((o) => !o) }
    window.addEventListener('sidebar-mobile-toggle', handler)
    return () => window.removeEventListener('sidebar-mobile-toggle', handler)
  }, [])

  // Determine if a nav item's sub section should be shown
  function isSubVisible(item: NavItem) {
    if (!item.sub?.length) return false
    const parentActive = item.href === '/dashboard'
      ? pathname === '/dashboard' || pathname === '/dashboard/'
      : pathname?.startsWith(item.href)
    return parentActive || manualExpanded.has(item.href)
  }

  function toggleManual(href: string) {
    setManualExpanded(prev => {
      const next = new Set(prev)
      if (next.has(href)) next.delete(href)
      else next.add(href)
      return next
    })
  }

  return (
    <>
      {/* Mobile backdrop */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm md:hidden"
            onClick={() => setMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar wrapper */}
      <div
        className={cn(
          'fixed left-0 top-0 bottom-0 z-40 transition-transform duration-300 ease-in-out',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
        )}
      >
        <motion.aside
          className="h-full flex flex-col bg-surface border-r border-white/5 overflow-hidden select-none"
          animate={{ width: expanded ? 232 : 56 }}
          transition={{ type: 'spring', stiffness: 320, damping: 32 }}
          onMouseEnter={() => { if (!pinned) setHovered(true) }}
          onMouseLeave={() => { if (!pinned) setHovered(false) }}
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
                  className="ml-2.5 flex-1 flex items-center justify-between whitespace-nowrap overflow-hidden"
                >
                  <div>
                    <span className="font-display font-bold text-sm text-white">Threat</span>
                    <span className="font-display font-bold text-sm text-gradient-magenta">Orbit</span>
                  </div>
                  <div className="flex items-center gap-0.5 ml-2 shrink-0">
                    <button
                      className="hidden md:flex p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/8 transition-colors"
                      onClick={() => setPinned((p) => !p)}
                      title={pinned ? 'Unpin sidebar' : 'Pin sidebar open'}
                    >
                      {pinned
                        ? <PanelLeftClose className="w-3.5 h-3.5 text-magenta" />
                        : <PanelLeftOpen  className="w-3.5 h-3.5" />}
                    </button>
                    <button
                      className="md:hidden p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/8 transition-colors"
                      onClick={() => setMobileOpen(false)}
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
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
                <AnimatePresence initial={false}>
                  {expanded && section && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                      className="px-4 pt-4 pb-1 overflow-hidden"
                    >
                      <span className="text-[9px] font-semibold tracking-widest uppercase text-ink-600">
                        {section}
                      </span>
                    </motion.div>
                  )}
                </AnimatePresence>

                {items.map((navItem) => {
                  const { href, label, icon: Icon, sub } = navItem
                  const active = href === '/dashboard'
                    ? pathname === '/dashboard' || pathname === '/dashboard/'
                    : pathname?.startsWith(href)
                  const hasSub = !!sub?.length
                  const subOpen = isSubVisible(navItem)

                  return (
                    <div key={href}>
                      {/* Parent item */}
                      <div className="relative flex items-center mx-2">
                        <Link
                          href={href}
                          title={label}
                          onClick={() => { if (isMobile) setMobileOpen(false) }}
                          className={cn(
                            'flex-1 flex items-center gap-3 px-2.5 py-2.5 rounded-lg transition-colors duration-150',
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
                                className="text-xs font-medium whitespace-nowrap relative flex-1"
                              >
                                {label}
                              </motion.span>
                            )}
                          </AnimatePresence>
                        </Link>

                        {/* Expand toggle for sub-items */}
                        {hasSub && expanded && (
                          <button
                            onClick={() => toggleManual(href)}
                            className={cn(
                              'relative p-1.5 rounded-md transition-colors mr-0.5',
                              active ? 'text-magenta/60 hover:text-magenta' : 'text-ink-600 hover:text-ink-300',
                            )}
                          >
                            <motion.div
                              animate={{ rotate: subOpen ? 180 : 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <ChevronDown className="w-3 h-3" />
                            </motion.div>
                          </button>
                        )}
                      </div>

                      {/* Sub-items */}
                      <AnimatePresence initial={false}>
                        {hasSub && subOpen && expanded && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                            className="overflow-hidden"
                          >
                            <div className="ml-4 mr-2 mb-1 border-l border-white/8 pl-3 space-y-0.5">
                              {sub!.map((subItem) => {
                                const subActive = subItem.href === href
                                  ? pathname === href || pathname === href + '/'
                                  : pathname?.startsWith(subItem.href) && subItem.href !== href
                                    ? true
                                    : pathname === subItem.href
                                return (
                                  <Link
                                    key={subItem.href}
                                    href={subItem.href}
                                    onClick={() => { if (isMobile) setMobileOpen(false) }}
                                    className={cn(
                                      'flex items-center gap-2 px-2.5 py-1.5 rounded-md text-[11px] transition-colors duration-150',
                                      subActive
                                        ? 'text-magenta bg-magenta/8'
                                        : 'text-ink-500 hover:text-ink-200 hover:bg-white/4',
                                    )}
                                  >
                                    <span
                                      className={cn(
                                        'w-1 h-1 rounded-full shrink-0',
                                        subActive ? 'bg-magenta' : 'bg-ink-600',
                                      )}
                                    />
                                    {subItem.label}
                                  </Link>
                                )
                              })}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )
                })}
              </div>
            ))}
          </nav>

          {/* Alerts badge */}
          <div className="px-2 pb-2">
            <Link
              href="/dashboard/siem"
              title="Active Alerts"
              onClick={() => { if (isMobile) setMobileOpen(false) }}
              className="flex items-center gap-3 px-2.5 py-2 rounded-lg text-amber hover:bg-amber/5 transition-colors"
            >
              <div className="relative shrink-0">
                <AlertTriangle className="w-4 h-4" />
                <span className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full bg-threat text-[8px] font-bold text-white flex items-center justify-center ring-2 ring-surface">
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
            </Link>
          </div>

          {/* Back to landing */}
          <div className="border-t border-white/5 px-2 py-2">
            <Link
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
            </Link>
          </div>
        </motion.aside>
      </div>
    </>
  )
}
