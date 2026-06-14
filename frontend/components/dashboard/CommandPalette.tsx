'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Globe, Radio, Server, Activity, Zap,
  Brain, Settings, ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type Item = {
  label: string
  description: string
  href: string
  icon: React.ComponentType<any>
  color: string
  keys?: string[]
}

const ITEMS: Item[] = [
  { label: 'Overview',       description: 'Dashboard home & threat map', href: '/dashboard/',         icon: Globe,    color: '#7A3CFF', keys: ['G', 'O'] },
  { label: 'Threat Feeds',   description: 'Live OSINT threat intelligence', href: '/dashboard/feeds/',  icon: Radio,    color: '#FF2E97', keys: ['G', 'F'] },
  { label: 'Threat Scanner', description: 'Scan URLs, IPs, and hashes',   href: '/dashboard/scanner/', icon: Search,   color: '#FFB23E', keys: ['G', 'S'] },
  { label: 'Asset Surface',  description: 'Manage and scan your assets',  href: '/dashboard/assets/',  icon: Server,   color: '#2DD4BF', keys: ['G', 'A'] },
  { label: 'SIEM Dashboard', description: 'Live event log & alert rules',  href: '/dashboard/siem/',    icon: Activity, color: '#FF4D6D', keys: ['G', 'L'] },
  { label: 'SOAR Dashboard', description: 'Playbooks & incident queue',   href: '/dashboard/soar/',    icon: Zap,      color: '#34F5C5', keys: ['G', 'R'] },
  { label: 'CTI Intelligence',description:'Threat actors & MITRE heatmap',href: '/dashboard/cti/',     icon: Brain,    color: '#FF2E97', keys: ['G', 'C'] },
  { label: 'Configuration',  description: 'API keys, feeds, integrations', href: '/dashboard/config/',  icon: Settings, color: '#665B7D', keys: ['G', ','] },
]

export default function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const [results, setResults] = useState<import('@/lib/api').SearchResult[]>([])
  const inputRef = useRef<HTMLInputElement>(null)

  // Live global search across alerts, IOCs, assets, cases, actors, dark web.
  useEffect(() => {
    const q = query.trim()
    if (q.length < 2) { setResults([]); return }
    const t = setTimeout(() => {
      import('@/lib/api').then(({ globalSearch }) =>
        globalSearch(q).then((d) => setResults(d.results)).catch(() => setResults([])))
    }, 220)
    return () => clearTimeout(t)
  }, [query])

  const filtered = query.trim()
    ? ITEMS.filter((i) =>
        i.label.toLowerCase().includes(query.toLowerCase()) ||
        i.description.toLowerCase().includes(query.toLowerCase()),
      )
    : ITEMS

  const close = useCallback(() => { setOpen(false); setQuery('') }, [])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen((o) => { if (!o) setActiveIdx(0); return !o })
      }
      if (e.key === 'Escape') close()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [close])

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 50)
  }, [open])

  useEffect(() => { setActiveIdx(0) }, [query])

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx((i) => (i + 1) % filtered.length) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setActiveIdx((i) => (i - 1 + filtered.length) % filtered.length) }
    if (e.key === 'Enter' && filtered[activeIdx]) {
      window.location.href = filtered[activeIdx].href
      close()
    }
  }

  return (
    <>
      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-sm"
              onClick={close}
            />

            {/* Palette */}
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: -12 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: -12 }}
              transition={{ duration: 0.15, ease: [0.22, 1, 0.36, 1] }}
              className="fixed left-1/2 top-[20%] -translate-x-1/2 z-[101] w-full max-w-lg"
            >
              <div className="bg-[#100A1C] border border-white/10 rounded-2xl shadow-2xl overflow-hidden">
                {/* Input */}
                <div className="flex items-center gap-3 px-4 py-3.5 border-b border-white/8">
                  <Search className="w-4 h-4 text-ink-500 shrink-0" />
                  <input
                    ref={inputRef}
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Search pages and actions…"
                    className="flex-1 bg-transparent text-sm text-ink-100 placeholder-ink-600 focus:outline-none"
                  />
                  <kbd className="text-[9px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-ink-500">ESC</kbd>
                </div>

                {/* Results */}
                <div className="py-2 max-h-72 overflow-y-auto">
                  {/* Live search hits across the data */}
                  {results.length > 0 && (
                    <>
                      <p className="text-[9px] uppercase tracking-widest text-ink-600 px-4 pt-1 pb-1.5">Results</p>
                      {results.map((r, i) => (
                        <a key={`${r.kind}-${i}`} href={r.link} onClick={close}
                          className="flex items-center gap-3 mx-2 px-3 py-2 rounded-xl hover:bg-white/4 transition-colors">
                          <span className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-violet/15 text-violet shrink-0 w-16 text-center">{r.kind}</span>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs text-ink-100 truncate">{r.label}</p>
                            {r.sub && <p className="text-[10px] text-ink-600 truncate font-mono">{r.sub}</p>}
                          </div>
                        </a>
                      ))}
                      <div className="h-px bg-white/5 mx-3 my-2" />
                    </>
                  )}
                  {filtered.length === 0 && results.length === 0 ? (
                    <p className="text-xs text-ink-600 text-center py-6">No results</p>
                  ) : (
                    filtered.map((item, i) => (
                      <a
                        key={item.href}
                        href={item.href}
                        onClick={close}
                        onMouseEnter={() => setActiveIdx(i)}
                        className={cn(
                          'flex items-center gap-3 mx-2 px-3 py-2.5 rounded-xl transition-colors cursor-pointer',
                          i === activeIdx ? 'bg-white/6' : 'hover:bg-white/4',
                        )}
                      >
                        <div className="p-2 rounded-lg shrink-0" style={{ background: `${item.color}18` }}>
                          <item.icon className="w-4 h-4" style={{ color: item.color }} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium text-ink-100">{item.label}</p>
                          <p className="text-[10px] text-ink-600 truncate">{item.description}</p>
                        </div>
                        {i === activeIdx && (
                          <ChevronRight className="w-3.5 h-3.5 text-ink-600 shrink-0" />
                        )}
                      </a>
                    ))
                  )}
                </div>

                <div className="px-4 py-2.5 border-t border-white/5 flex items-center gap-4 text-[9px] text-ink-700">
                  <span className="flex items-center gap-1"><kbd className="px-1 py-0.5 rounded bg-white/5 border border-white/10">↑↓</kbd> navigate</span>
                  <span className="flex items-center gap-1"><kbd className="px-1 py-0.5 rounded bg-white/5 border border-white/10">↵</kbd> go</span>
                  <span className="flex items-center gap-1"><kbd className="px-1 py-0.5 rounded bg-white/5 border border-white/10">ESC</kbd> close</span>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
