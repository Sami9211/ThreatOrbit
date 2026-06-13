'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard, Home, Info, DollarSign, BookOpen,
  Activity, ChevronRight, Globe, X,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'

const LINKS = [
  { label: 'Home',          href: '#',            icon: Home           },
  { label: 'Platform',      href: '#features',    icon: Activity       },
  { label: 'Threat Intel',  href: '#threat-intel',icon: Globe          },
  { label: 'Pricing',       href: '#pricing',     icon: DollarSign     },
  { label: 'About',         href: '#about',        icon: Info           },
  { label: 'Docs',          href: '/docs',         icon: BookOpen       },
  { label: 'Dashboard',     href: '/dashboard',    icon: LayoutDashboard},
]

export default function LandingSidebar() {
  const [open, setOpen] = useState(false)

  return (
    <>
      {/* Desktop hover trigger strip. (Mobile navigation is handled by the
          Navbar's menu button, which opens the full-screen MegaMenu - a
          second hamburger here would overlap the Navbar logo on phones.) */}
      <div
        className="hidden md:block fixed left-0 top-0 bottom-0 z-50 w-4 cursor-pointer"
        onMouseEnter={() => setOpen(true)}
      />

      {/* Sidebar panel */}
      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm"
              onMouseEnter={() => setOpen(false)}
            />

            {/* Panel */}
            <motion.aside
              initial={{ x: -240 }}
              animate={{ x: 0 }}
              exit={{ x: -240 }}
              transition={{ type: 'spring', stiffness: 320, damping: 32 }}
              className="fixed left-0 top-0 bottom-0 z-50 w-56 flex flex-col bg-[#0D0920] border-r border-white/8 shadow-[4px_0_40px_rgba(0,0,0,0.6)]"
              onMouseLeave={() => setOpen(false)}
            >
              {/* Logo + close */}
              <div className="h-14 flex items-center px-5 border-b border-white/5">
                <Logo size={24} />
                <span className="ml-2.5 font-display font-bold text-sm flex-1">
                  <span className="text-white">Threat</span>
                  <span className="text-gradient-magenta">Orbit</span>
                </span>
                <button
                  onClick={() => setOpen(false)}
                  className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors"
                  aria-label="Close navigation"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Navigation */}
              <nav className="flex-1 py-4 space-y-0.5 px-2">
                {LINKS.map(({ label, href, icon: Icon }) => (
                  <a
                    key={href}
                    href={href}
                    onClick={() => setOpen(false)}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-colors',
                      label === 'Dashboard'
                        ? 'text-magenta hover:bg-magenta/8 border border-magenta/15'
                        : 'text-ink-400 hover:text-white hover:bg-white/5',
                    )}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    {label}
                    {label === 'Dashboard' && (
                      <ChevronRight className="w-3.5 h-3.5 ml-auto text-magenta/60" />
                    )}
                  </a>
                ))}
              </nav>

              {/* Tab handle (visible hint) */}
              <div className="absolute -right-0 top-1/2 -translate-y-1/2 w-1 h-16 rounded-r-full bg-magenta/40" />
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
