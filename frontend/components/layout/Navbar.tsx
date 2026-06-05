'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Menu, ChevronRight, LayoutDashboard } from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'
import MegaMenu from '@/components/layout/MegaMenu'

const NAV_LINKS = [
  { label: 'Platform', href: '#features' },
  { label: 'Products', href: '#pricing' },
  { label: 'Threat Intel', href: '#threat-intel' },
  { label: 'About', href: '#about' },
  { label: 'Docs', href: '/docs' },
]

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [active, setActive] = useState<string>('')

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', fn, { passive: true })
    return () => window.removeEventListener('scroll', fn)
  }, [])

  // Scroll-spy: highlight the nav link whose section is centred in the viewport
  useEffect(() => {
    const ids = NAV_LINKS.map((l) => l.href).filter((h) => h.startsWith('#')).map((h) => h.slice(1))
    const els = ids.map((id) => document.getElementById(id)).filter(Boolean) as HTMLElement[]
    if (!els.length) return
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) setActive('#' + e.target.id)
        })
      },
      { rootMargin: '-45% 0px -45% 0px', threshold: 0 },
    )
    els.forEach((el) => io.observe(el))
    return () => io.disconnect()
  }, [])

  return (
    <>
      <motion.header
        initial={{ y: -80, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        className={cn(
          'fixed top-0 left-0 right-0 z-50 transition-all duration-500',
          scrolled
            ? 'py-3 bg-[#0A0612]/80 backdrop-blur-xl border-b border-white/5 shadow-[0_1px_0_rgba(255,46,151,0.08)]'
            : 'py-5 bg-transparent'
        )}
      >
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <a href="/" className="flex items-center gap-2.5 group">
            <Logo size={30} className="transition-transform duration-500 group-hover:scale-110" />
            <span className="font-display font-semibold text-lg tracking-tight">
              <span className="text-white">Threat</span>
              <span className="text-gradient-magenta">Orbit</span>
            </span>
          </a>

          <nav className="hidden md:flex items-center gap-1">
            {NAV_LINKS.map((link) => {
              const isActive = active === link.href
              return (
                <a
                  key={link.href}
                  href={link.href}
                  className={cn(
                    'relative px-3.5 py-2 text-sm transition-colors duration-200 rounded-lg',
                    isActive ? 'text-white' : 'text-ink-400 hover:text-white hover:bg-white/5',
                  )}
                >
                  {isActive && (
                    <motion.span
                      layoutId="nav-active"
                      className="absolute inset-0 rounded-lg bg-white/8 border border-white/10"
                      transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                    />
                  )}
                  <span className="relative z-10">{link.label}</span>
                </a>
              )
            })}
          </nav>

          <div className="flex items-center gap-2.5">
            {/* Dashboard — always visible (incl. mobile), prominent gradient */}
            <a
              href="/dashboard"
              className="group flex items-center gap-1.5 px-3.5 sm:px-4 py-2 rounded-lg bg-plasma text-white font-semibold text-sm shadow-magenta-sm transition-all duration-300 hover:shadow-magenta hover:scale-[1.03]"
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Dashboard</span>
              <ChevronRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-0.5" />
            </a>
            <a
              href="#cta"
              className="hidden sm:flex items-center gap-1.5 px-4 py-2 rounded-lg border border-white/12 text-ink-200 font-medium text-sm transition-all duration-300 hover:border-magenta/30 hover:text-white"
            >
              Get Started
            </a>
            <button
              onClick={() => setMenuOpen(true)}
              className="flex items-center gap-2 p-2.5 rounded-lg border border-white/10 text-ink-200 hover:text-white hover:border-magenta/30 transition-colors"
              aria-label="Open menu"
            >
              <Menu className="w-5 h-5" />
              <span className="hidden sm:inline text-xs font-medium pr-1">Menu</span>
            </button>
          </div>
        </div>
      </motion.header>

      <MegaMenu open={menuOpen} onClose={() => setMenuOpen(false)} />
    </>
  )
}
