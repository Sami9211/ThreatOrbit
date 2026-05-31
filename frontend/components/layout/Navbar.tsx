'use client'

import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Menu, X, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'

const NAV_LINKS = [
  { label: 'Platform', href: '#features' },
  { label: 'Threat Intel', href: '#threat-intel' },
  { label: 'Log Analysis', href: '#log-analysis' },
  { label: 'OpenCTI', href: '#opencti' },
  { label: 'Docs', href: '#docs' },
]

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', fn, { passive: true })
    return () => window.removeEventListener('scroll', fn)
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
          {/* Logo */}
          <a href="#" className="flex items-center gap-2.5 group">
            <Logo size={30} className="transition-transform duration-500 group-hover:scale-110" />
            <span className="font-display font-semibold text-lg tracking-tight">
              <span className="text-white">Threat</span>
              <span className="text-gradient-magenta">Orbit</span>
            </span>
          </a>

          {/* Desktop nav */}
          <nav className="hidden md:flex items-center gap-1">
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="px-3.5 py-2 text-sm text-ink-400 hover:text-white transition-colors duration-200 rounded-lg hover:bg-white/5"
              >
                {link.label}
              </a>
            ))}
          </nav>

          {/* CTA */}
          <div className="hidden md:flex items-center gap-3">
            <a
              href="#docs"
              className="text-sm text-ink-400 hover:text-white transition-colors duration-200"
            >
              API Docs
            </a>
            <a
              href="#cta"
              className="group flex items-center gap-1.5 px-4 py-2 rounded-lg bg-plasma text-white font-medium text-sm transition-all duration-300 hover:shadow-magenta-sm"
            >
              Get Started
              <ChevronRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-0.5" />
            </a>
          </div>

          {/* Mobile toggle */}
          <button
            onClick={() => setMobileOpen((v) => !v)}
            className="md:hidden p-2 text-ink-400 hover:text-white transition-colors"
            aria-label="Toggle menu"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </motion.header>

      {/* Mobile drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.25 }}
            className="fixed inset-x-0 top-[60px] z-40 bg-[#0A0612]/95 backdrop-blur-xl border-b border-white/5 px-6 py-4 md:hidden"
          >
            <nav className="flex flex-col gap-1">
              {NAV_LINKS.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileOpen(false)}
                  className="px-3 py-2.5 text-sm text-ink-200 hover:text-white rounded-lg hover:bg-white/5 transition-colors"
                >
                  {link.label}
                </a>
              ))}
              <a
                href="#cta"
                onClick={() => setMobileOpen(false)}
                className="mt-2 px-3 py-2.5 text-sm font-medium text-white bg-plasma rounded-lg text-center"
              >
                Get Started
              </a>
            </nav>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
