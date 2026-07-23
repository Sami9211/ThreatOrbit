'use client'

import { useState, useEffect } from 'react'
import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Globe, Search, Activity, Zap, Brain, Radio, Settings, Home,
  AlertTriangle, Wifi, Server, EyeOff, ShieldCheck,
  PanelLeftOpen, PanelLeftClose, X, ChevronDown, Gauge,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useCoarsePointer } from '@/lib/usePointer'
import { useOrgFeatures } from '@/lib/useExperienceMode'
import { fetchSiemAlerts } from '@/lib/api'
import Logo from '@/components/ui/Logo'

type SubItem = { href: string; label: string; feature: string }

type NavItem = {
  href: string
  label: string
  icon: React.ComponentType<any>
  /** Feature-area id (dashboard_api/modes.py FEATURES) gating this item in
   * Simple mode; `null` = always shown (core navigation, not mode-gated). */
  feature: string | null
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
      { href: '/dashboard', label: 'Overview', icon: Globe, feature: 'overview' },
      { href: '/dashboard/soc', label: 'SOC Console', icon: Gauge, feature: 'soc' },
    ],
  },
  {
    section: 'Intelligence',
    items: [
      {
        href: '/dashboard/feeds',
        label: 'Threat Feeds',
        icon: Radio,
        feature: 'feeds',
        sub: [
          { href: '/dashboard/feeds',         label: 'Live Feed',   feature: 'feeds' },
          { href: '/dashboard/feeds/sources',  label: 'Sources',     feature: 'feeds' },
          { href: '/dashboard/feeds/imports',  label: 'Imports',     feature: 'feeds' },
          { href: '/dashboard/feeds/import',   label: 'Import IOCs', feature: 'feeds' },
        ],
      },
      { href: '/dashboard/scanner', label: 'IntelScope', icon: Search, feature: 'scanner' },
      {
        href: '/dashboard/cti',
        label: 'CTI Intelligence',
        icon: Brain,
        feature: 'cti.overview',
        sub: [
          { href: '/dashboard/cti',        label: 'Overview',       feature: 'cti.overview' },
          { href: '/dashboard/cti/hunt',   label: 'Threat Hunt',    feature: 'cti.hunt' },
          { href: '/dashboard/cti/actors', label: 'Actor Profiles', feature: 'cti.actors' },
        ],
      },
      { href: '/dashboard/darkweb', label: 'Dark Web', icon: EyeOff, feature: 'darkweb' },
    ],
  },
  {
    section: 'Operations',
    items: [
      {
        href: '/dashboard/assets',
        label: 'Asset Surface',
        icon: Server,
        feature: 'assets.inventory',
        sub: [
          { href: '/dashboard/assets',         label: 'Inventory',       feature: 'assets.inventory' },
          { href: '/dashboard/assets/vulns',   label: 'Vulnerabilities', feature: 'assets.vulns' },
          { href: '/dashboard/assets/network', label: 'Network Map',    feature: 'assets.network' },
        ],
      },
      {
        href: '/dashboard/siem',
        label: 'SIEM',
        icon: Activity,
        feature: 'siem.alerts',
        sub: [
          { href: '/dashboard/siem',         label: 'Alert Queue',        feature: 'siem.alerts' },
          { href: '/dashboard/siem/rules',   label: 'Rules Engine',       feature: 'siem.rules' },
          { href: '/dashboard/siem/attack',  label: 'ATT&CK Navigator',   feature: 'siem.attack' },
          { href: '/dashboard/siem/entities', label: 'Entity Risk',       feature: 'siem.entities' },
          { href: '/dashboard/siem/sources', label: 'Log Sources',        feature: 'siem.sources' },
          { href: '/dashboard/siem/hunt',    label: 'Threat Hunt',        feature: 'siem.hunt' },
        ],
      },
      {
        href: '/dashboard/soar',
        label: 'SOAR',
        icon: Zap,
        feature: 'soar.cases',
        sub: [
          { href: '/dashboard/soar',              label: 'Cases',        feature: 'soar.cases' },
          { href: '/dashboard/soar/playbooks',    label: 'Playbooks',    feature: 'soar.playbooks' },
          { href: '/dashboard/soar/integrations', label: 'Integrations', feature: 'soar.integrations' },
          { href: '/dashboard/soar/metrics',      label: 'SOC Metrics',  feature: 'soar.metrics' },
        ],
      },
    ],
  },
  {
    section: 'System',
    items: [
      { href: '/dashboard/admin', label: 'Admin Console', icon: ShieldCheck, feature: 'config' },
      {
        href: '/dashboard/config',
        label: 'Configuration',
        icon: Settings,
        feature: 'config',
        sub: [
          { href: '/dashboard/config',         label: 'General',      feature: 'config' },
          { href: '/dashboard/config/sources', label: 'Data Sources', feature: 'connectors' },
          { href: '/dashboard/config/users',   label: 'Users & Roles', feature: 'config' },
          { href: '/dashboard/config/api',     label: 'API Keys',     feature: 'config' },
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
  // Touch devices have no real hover, so a hover-to-expand rail behaves
  // erratically (a tap fires a sticky synthetic mouseenter with no leave).
  // On coarse pointers we disable hover-expand and switch to an explicit
  // tap-to-toggle instead (see the logo row + pin button below).
  const isCoarse = useCoarsePointer()
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

  // Simple-mode nav curation: `null` (unrestricted/not-yet-loaded) shows
  // everything, fail-open - this is a UI preference, never a functionality
  // gate (the backend enforces real RBAC regardless of what's hidden here).
  const orgFeatures = useOrgFeatures()
  const visible = (feature: string | null) => orgFeatures === null || feature === null || orgFeatures.includes(feature)
  const nav = NAV
    .map((group) => ({
      ...group,
      items: group.items
        .filter((item) => visible(item.feature))
        .map((item) => ({
          ...item,
          sub: item.sub?.filter((s) => visible(s.feature)),
        })),
    }))
    .filter((group) => group.items.length > 0)

  // Real, live count of alerts actually needing attention (new + investigating -
  // i.e. not yet resolved/closed) - never a placeholder number.
  const [activeAlerts, setActiveAlerts] = useState<number | null>(null)
  useEffect(() => {
    let active = true
    Promise.all([
      fetchSiemAlerts({ status: 'new', limit: '1' }),
      fetchSiemAlerts({ status: 'investigating', limit: '1' }),
    ])
      .then(([a, b]) => { if (active) setActiveAlerts(a.total + b.total) })
      .catch(() => { /* leave as null - badge simply doesn't render */ })
    return () => { active = false }
  }, [])

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

  // After navigating, close the drawer (mobile) or collapse the rail (touch
  // tablet, which stays open via `pinned` since there's no mouse-leave) so the
  // panel doesn't sit on top of the content. With a real mouse the rail
  // collapses on its own when the pointer leaves, so we leave it alone.
  function closeNav() {
    if (isMobile) setMobileOpen(false)
    else if (isCoarse) setPinned(false)
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
            className="fixed inset-0 z-30 bg-black/60 backdrop-blur-xs md:hidden"
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
          // A symmetric eased tween, not a spring: the spring's velocity/overshoot
          // differed by direction, so collapse (pointer-leave) read as abrupt and
          // uneven next to a smooth expand. One easing curve both ways = identical,
          // predictable motion on open and close.
          transition={{ duration: 0.26, ease: [0.22, 1, 0.36, 1] }}
          onMouseEnter={() => { if (!pinned && !isCoarse) setHovered(true) }}
          onMouseLeave={() => { if (!pinned && !isCoarse) setHovered(false) }}
        >
          {/* Logo row */}
          <div className="relative h-14 flex items-center px-3.5 border-b border-white/5 shrink-0">
            <Logo size={26} className="shrink-0" />
            {/* Touch devices have no hover, so tapping the collapsed rail reveals
                the labels (the pin button collapses it again when expanded). */}
            {!expanded && isCoarse && !isMobile && (
              <button
                onClick={() => setPinned(true)}
                aria-label="Expand navigation"
                className="absolute inset-0 z-10"
              />
            )}
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
                      aria-label="Close navigation"
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
          <nav aria-label="Main navigation" className="flex-1 overflow-y-auto overflow-x-hidden py-2 space-y-1">
            {nav.map(({ section, items }) => (
              // space-y-1 between rows: they used to stack flush (0px), which
              // read as cramped/overlapping at real-world zoom levels.
              <div key={section ?? '__root'} className="space-y-1">
                <AnimatePresence initial={false}>
                  {expanded && section && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                      className="px-4 pt-5 pb-1.5 overflow-hidden"
                    >
                      <span className="block text-[10px] leading-none font-semibold tracking-widest uppercase text-ink-600">
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
                          onClick={closeNav}
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
                            aria-label={`${subOpen ? 'Collapse' : 'Expand'} ${label} section`}
                            aria-expanded={subOpen}
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
                            <div className="ml-4 mr-2 mt-1 mb-2 border-l border-white/8 pl-3 space-y-1">
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
                                    onClick={closeNav}
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

          {/* Alerts badge - real open-alert count (new + investigating); no
              badge at all until it loads, and none when there's nothing open. */}
          {!!activeAlerts && (
            <div className="px-2 pb-2">
              <Link
                href="/dashboard/siem"
                title="Active Alerts"
                onClick={closeNav}
                className="flex items-center gap-3 px-2.5 py-2 rounded-lg text-amber hover:bg-amber/5 transition-colors"
              >
                <div className="relative shrink-0">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="absolute -top-1.5 -right-1.5 min-w-[16px] h-4 px-0.5 rounded-full bg-threat text-[8px] font-bold text-[#0a0a0b] flex items-center justify-center ring-2 ring-surface">
                    {activeAlerts > 99 ? '99+' : activeAlerts}
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
                      {activeAlerts} Active Alert{activeAlerts === 1 ? '' : 's'}
                    </motion.span>
                  )}
                </AnimatePresence>
              </Link>
            </div>
          )}

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
