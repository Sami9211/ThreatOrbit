'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { usePathname } from 'next/navigation'
import { Bell, RefreshCw, User, AlertTriangle, X, Search, Command, Menu } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'

const LABELS: Record<string, string> = {
  '/dashboard': 'Overview',
  '/dashboard/feeds': 'Threat Feeds',
  '/dashboard/scanner': 'Threat Scanner',
  '/dashboard/assets': 'Asset Surface',
  '/dashboard/siem': 'SIEM Dashboard',
  '/dashboard/soar': 'SOAR Dashboard',
  '/dashboard/cti': 'CTI Intelligence',
  '/dashboard/config': 'Configuration',
}

const NOTIFS = [
  { id: 1, title: 'CVE-2024-6387 RCE attempt blocked',      severity: 'critical', src: '45.95.147.236',  time: '2m ago'  },
  { id: 2, title: 'Lazarus Group C2 beacon detected',        severity: 'critical', src: '185.220.101.42', time: '7m ago'  },
  { id: 3, title: 'SQL Injection on /api/users',             severity: 'high',     src: '192.168.10.44',  time: '12m ago' },
  { id: 4, title: 'Large data exfiltration (4.2 GB)',        severity: 'critical', src: '172.16.0.44',    time: '24m ago' },
  { id: 5, title: 'Brute-force SSH from 14 IPs',            severity: 'medium',   src: 'Multiple',       time: '31m ago' },
  { id: 6, title: 'MISP feed sync failed',                   severity: 'medium',   src: 'Integrations',   time: '1h ago'  },
  { id: 7, title: 'Playbook "Ransomware" triggered',         severity: 'high',     src: 'SOAR Engine',    time: '1h ago'  },
]

const SEV_COLOR: Record<string, string> = {
  critical: '#FF2E97',
  high:     '#FF4D6D',
  medium:   '#FFB23E',
  low:      '#2DD4BF',
}

export default function TopBar() {
  const raw = usePathname() ?? '/dashboard'
  // trailingSlash:true means usePathname() can return "/dashboard/siem/" —
  // normalise so the label lookup matches regardless of trailing slash.
  const pathname = raw.length > 1 ? raw.replace(/\/$/, '') : raw
  const label = LABELS[pathname] ?? LABELS['/dashboard']

  const [notifOpen, setNotifOpen] = useState(false)
  const [dismissed, setDismissed] = useState<Set<number>>(new Set())
  const [refreshing, setRefreshing] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)

  // Close dropdown when clicking outside
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  function handleRefresh() {
    if (refreshing) return
    setRefreshing(true)
    setTimeout(() => setRefreshing(false), 1500)
  }

  const visible = NOTIFS.filter((n) => !dismissed.has(n.id))
  const unread = visible.length

  return (
    <header className="h-14 border-b border-white/5 flex items-center justify-between px-4 md:px-6 bg-[#0D0920]/60 backdrop-blur-sm sticky top-0 z-30">
      <div className="flex items-center gap-2 text-sm">
        {/* Mobile hamburger — dispatches event to Sidebar */}
        <button
          className="md:hidden p-1.5 -ml-1 mr-1 rounded-lg text-ink-400 hover:text-white hover:bg-white/8 transition-colors"
          onClick={() => window.dispatchEvent(new CustomEvent('sidebar-mobile-toggle'))}
          aria-label="Open navigation"
        >
          <Menu className="w-4 h-4" />
        </button>
        <span className="text-ink-500">ThreatOrbit</span>
        <span className="text-ink-600">/</span>
        <span className="text-white font-medium">{label}</span>
      </div>

      <div className="flex items-center gap-2">
        {/* Command palette trigger */}
        <button
          onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true }))}
          aria-label="Open command palette"
          className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/8 text-ink-500 hover:text-ink-200 hover:border-white/15 transition-colors text-xs"
        >
          <Search className="w-3 h-3" />
          <span>Jump to…</span>
          <kbd className="flex items-center gap-0.5 ml-1 text-[9px] px-1 py-0.5 rounded bg-white/5 border border-white/10">
            <Command className="w-2.5 h-2.5" />K
          </kbd>
        </button>

        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button
            aria-label="Notifications"
            aria-expanded={notifOpen}
            onClick={() => setNotifOpen((o) => !o)}
            className={cn(
              'relative p-2 rounded-lg transition-colors',
              notifOpen ? 'text-white bg-white/8' : 'text-ink-400 hover:text-white hover:bg-white/5',
            )}
          >
            <Bell className="w-4 h-4" aria-hidden="true" />
            {unread > 0 && (
              <span className="absolute top-1 right-1 min-w-[14px] h-[14px] rounded-full bg-threat text-[8px] font-bold text-white flex items-center justify-center px-0.5" aria-hidden="true">
                {unread > 9 ? '9+' : unread}
              </span>
            )}
          </button>

          <AnimatePresence>
            {notifOpen && (
              <motion.div
                initial={{ opacity: 0, y: -6, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -6, scale: 0.97 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-full mt-2 w-80 bg-[#100A1C] border border-white/8 rounded-xl shadow-2xl overflow-hidden z-50"
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-threat" />
                    <span className="text-xs font-semibold text-white">Notifications</span>
                    {unread > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-threat/15 text-threat border border-threat/25 font-semibold">
                        {unread} new
                      </span>
                    )}
                  </div>
                  <button
                    onClick={() => { const s = new Set<number>(); NOTIFS.forEach((n) => s.add(n.id)); setDismissed(s) }}
                    className="text-[10px] text-ink-500 hover:text-magenta transition-colors"
                  >
                    Clear all
                  </button>
                </div>

                <div className="max-h-72 overflow-y-auto">
                  <AnimatePresence initial={false}>
                    {visible.length === 0 ? (
                      <div className="py-8 text-center text-xs text-ink-600">No new notifications</div>
                    ) : (
                      visible.map((n) => (
                        <motion.div
                          key={n.id}
                          initial={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          className="flex items-start gap-3 px-4 py-3 border-b border-white/4 hover:bg-white/3 group transition-colors"
                        >
                          <span
                            className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                            style={{ background: SEV_COLOR[n.severity] }}
                          />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs text-ink-200 truncate">{n.title}</p>
                            <p className="text-[10px] text-ink-600 font-mono mt-0.5">{n.src} · {n.time}</p>
                          </div>
                          <button
                            onClick={() => setDismissed((d) => { const s = new Set(d); s.add(n.id); return s })}
                            aria-label="Dismiss"
                            className="p-0.5 text-ink-700 hover:text-ink-300 opacity-0 group-hover:opacity-100 transition-all shrink-0"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </motion.div>
                      ))
                    )}
                  </AnimatePresence>
                </div>

                <div className="px-4 py-2.5 border-t border-white/5">
                  <a href="/dashboard/siem" className="text-[10px] text-magenta hover:underline">
                    View all alerts in SIEM →
                  </a>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Refresh */}
        <button
          aria-label="Refresh data"
          onClick={handleRefresh}
          className="p-2 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors"
        >
          <RefreshCw className={cn('w-4 h-4', refreshing && 'animate-spin text-safe')} aria-hidden="true" />
        </button>

        {/* User */}
        <div className="flex items-center gap-2 pl-2 border-l border-white/8">
          <div className="w-7 h-7 rounded-lg bg-plasma flex items-center justify-center">
            <User className="w-3.5 h-3.5 text-white" />
          </div>
          <div className="hidden sm:block">
            <div className="text-xs font-medium text-white">Admin</div>
            <div className="text-[10px] text-ink-500">SOC Analyst</div>
          </div>
        </div>
      </div>
    </header>
  )
}
