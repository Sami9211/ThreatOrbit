'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Plus, Minus, ArrowUpRight } from 'lucide-react'
import Logo from '@/components/ui/Logo'

type MenuGroup = {
  heading: string
  items: { label: string; href: string; desc?: string }[]
}

const PRIMARY = [
  { label: 'Home', href: '#' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'About', href: '#about' },
  { label: 'Contact', href: '#contact' },
]

const GROUPS: MenuGroup[] = [
  {
    heading: 'Products',
    items: [
      { label: 'Super SOC', href: '#pricing', desc: 'CTI + SIEM + SOAR, unified' },
      { label: 'CTI Library', href: '#threat-intel', desc: 'Threat intelligence ingestion' },
      { label: 'SIEM', href: '#log-analysis', desc: 'Log analysis and detection' },
      { label: 'SOAR', href: '#how-it-works', desc: 'Automated response pipeline' },
    ],
  },
  {
    heading: 'Platform',
    items: [
      { label: 'OpenCTI Integration', href: '#opencti' },
      { label: 'STIX 2.1 Export', href: '#features' },
      { label: 'Dashboard', href: '#features' },
      { label: 'Capabilities', href: '#features' },
    ],
  },
  {
    heading: 'Developers',
    items: [
      { label: 'API Docs', href: '#docs' },
      { label: 'Quick Start', href: '#docs' },
      { label: 'Authentication', href: '#docs' },
      { label: 'Docker Deploy', href: '#docs' },
    ],
  },
  {
    heading: 'Company',
    items: [
      { label: 'About ThreatOrbit', href: '#about' },
      { label: 'Contact Sales', href: '#contact' },
      { label: 'Security', href: '#' },
      { label: 'Careers', href: '#' },
    ],
  },
]

const overlay = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { duration: 0.3, when: 'beforeChildren', staggerChildren: 0.05 } },
  exit: { opacity: 0, transition: { duration: 0.25, when: 'afterChildren' } },
}
const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: 10 },
}

export default function MegaMenu({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [expanded, setExpanded] = useState<string | null>('Products')

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          variants={overlay}
          initial="hidden"
          animate="show"
          exit="exit"
          className="fixed inset-0 z-[70] overflow-y-auto bg-[#0A0612]/95 backdrop-blur-2xl"
        >
          {/* Plasma ambience */}
          <div className="absolute inset-0 plasma-mesh opacity-60 pointer-events-none" />
          <div className="absolute inset-0 bg-grid-dim opacity-30 pointer-events-none" />

          <div className="relative max-w-7xl mx-auto px-6 py-6">
            {/* Top bar */}
            <div className="flex items-center justify-between mb-12">
              <a href="#" onClick={onClose} className="flex items-center gap-2.5">
                <Logo size={30} />
                <span className="font-display font-semibold text-lg">
                  <span className="text-white">Threat</span>
                  <span className="text-gradient-magenta">Orbit</span>
                </span>
              </a>
              <button
                onClick={onClose}
                className="p-2.5 rounded-lg border border-white/10 text-ink-300 hover:text-white hover:border-magenta/30 transition-colors"
                aria-label="Close menu"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid lg:grid-cols-[1.2fr_2fr] gap-12">
              {/* Primary links (big) */}
              <motion.nav variants={item} className="flex flex-col gap-2">
                {PRIMARY.map((link) => (
                  <a
                    key={link.label}
                    href={link.href}
                    onClick={onClose}
                    className="group flex items-center gap-3 font-display text-4xl md:text-5xl font-bold text-white/90 hover:text-white transition-colors"
                  >
                    <span className="text-gradient-animate bg-clip-text">{link.label}</span>
                    <ArrowUpRight className="w-6 h-6 text-magenta opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
                  </a>
                ))}

                <div className="flex items-center gap-3 mt-8">
                  <a
                    href="#contact"
                    onClick={onClose}
                    className="px-5 py-2.5 rounded-xl bg-plasma text-white font-medium text-sm hover:shadow-magenta-md transition-shadow"
                  >
                    Get Started
                  </a>
                  <a
                    href="#docs"
                    onClick={onClose}
                    className="px-5 py-2.5 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:text-white transition-colors"
                  >
                    Log In
                  </a>
                </div>
              </motion.nav>

              {/* Collapsible groups */}
              <motion.div variants={item} className="grid sm:grid-cols-2 gap-x-8 gap-y-2">
                {GROUPS.map((group) => {
                  const isOpen = expanded === group.heading
                  return (
                    <div key={group.heading} className="border-b border-white/8 py-4">
                      <button
                        onClick={() => setExpanded(isOpen ? null : group.heading)}
                        className="w-full flex items-center justify-between text-left"
                      >
                        <span className="font-display font-semibold text-white text-lg">
                          {group.heading}
                        </span>
                        {isOpen ? (
                          <Minus className="w-4 h-4 text-magenta" />
                        ) : (
                          <Plus className="w-4 h-4 text-ink-400" />
                        )}
                      </button>
                      <AnimatePresence initial={false}>
                        {isOpen && (
                          <motion.ul
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                            className="overflow-hidden"
                          >
                            <div className="pt-3 space-y-2.5">
                              {group.items.map((it) => (
                                <li key={it.label}>
                                  <a
                                    href={it.href}
                                    onClick={onClose}
                                    className="group flex flex-col"
                                  >
                                    <span className="text-sm text-ink-200 group-hover:text-magenta transition-colors">
                                      {it.label}
                                    </span>
                                    {it.desc && (
                                      <span className="text-[11px] text-ink-500">{it.desc}</span>
                                    )}
                                  </a>
                                </li>
                              ))}
                            </div>
                          </motion.ul>
                        )}
                      </AnimatePresence>
                    </div>
                  )
                })}
              </motion.div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
