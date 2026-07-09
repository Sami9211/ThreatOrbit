'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { Bell, RefreshCw, AlertTriangle, X, Search, Command, Menu, Zap, LogOut, Settings } from 'lucide-react'
import { fetchNotifications, markNotificationRead, type Notification } from '@/lib/api'
import { useAuth } from '@/lib/auth-context'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { useLiveStream } from '@/lib/useLiveStream'
import { SEVERITY_COLOR as SEV_COLOR } from '@/lib/colors'

/* Compact segmented Normal/Power toggle - surfaces the experience mode so the
   difference is one tap away (it was previously buried in Configuration). */
function ModeToggle() {
  const [mode, setMode] = useExperienceMode()
  return (
    <div className="flex items-center p-0.5 rounded-lg bg-surface-2 border border-white/8" role="group" aria-label="Experience mode">
      {(['normal', 'power'] as const).map((m) => {
        const active = mode === m
        return (
          <button
            key={m}
            onClick={() => setMode(m)}
            aria-pressed={active}
            className="relative px-2 sm:px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors"
          >
            {active && (
              <motion.span
                layoutId="mode-toggle-pill"
                className={cn('absolute inset-0 rounded-md', m === 'power' ? 'bg-magenta/15 border border-magenta/30' : 'bg-white/8 border border-white/12')}
                transition={{ type: 'spring', stiffness: 400, damping: 32 }}
              />
            )}
            <span className={cn('relative z-10 flex items-center gap-1', active ? (m === 'power' ? 'text-magenta' : 'text-white') : 'text-ink-500')}>
              {m === 'power' && <Zap className="w-2.5 h-2.5" />}
              {m === 'power' ? 'Power' : 'Normal'}
            </span>
          </button>
        )
      })}
    </div>
  )
}

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


function relTime(iso: string): string {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60); return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`
}

export default function TopBar() {
  const raw = usePathname() ?? '/dashboard'
  // trailingSlash:true means usePathname() can return "/dashboard/siem/" -
  // normalise so the label lookup matches regardless of trailing slash.
  const pathname = raw.length > 1 ? raw.replace(/\/$/, '') : raw
  const label = LABELS[pathname] ?? LABELS['/dashboard']

  const router = useRouter()
  const [notifOpen, setNotifOpen] = useState(false)
  const [notifs, setNotifs] = useState<Notification[]>([])
  const [unread, setUnread] = useState(0)
  const [refreshing, setRefreshing] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)
  const [userOpen, setUserOpen] = useState(false)
  const userRef = useRef<HTMLDivElement>(null)
  const { user, logout } = useAuth()

  const loadNotifs = useCallback(() => {
    fetchNotifications().then((d) => { setNotifs(d.items); setUnread(d.unread) }).catch(() => {})
  }, [])
  // Real-time push: refresh the bell the instant the server emits a
  // notification; keep a slow poll as a safety net if the stream drops.
  useLiveStream((e) => { if (e.type === 'notification') loadNotifs() })
  useEffect(() => {
    loadNotifs()
    const t = setInterval(loadNotifs, 30000)
    return () => clearInterval(t)
  }, [loadNotifs])

  function openNotif(n: Notification) {
    markNotificationRead(n.id).then(loadNotifs).catch(() => {})
    setNotifOpen(false)
    if (n.link) router.push(n.link)
  }
  function clearAllNotifs() {
    markNotificationRead().then(loadNotifs).catch(() => {})
  }

  // Close dropdown when clicking outside
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false)
      }
      if (userRef.current && !userRef.current.contains(e.target as Node)) {
        setUserOpen(false)
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

  const visible = notifs

  return (
    <header className="h-14 border-b border-white/5 flex items-center justify-between px-4 md:px-6 bg-surface/60 backdrop-blur-sm sticky top-0 z-30">
      <div className="flex items-center gap-2 text-sm min-w-0">
        {/* Mobile hamburger - dispatches event to Sidebar */}
        <button
          className="md:hidden p-1.5 -ml-1 mr-0.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/8 transition-colors shrink-0"
          onClick={() => window.dispatchEvent(new CustomEvent('sidebar-mobile-toggle'))}
          aria-label="Open navigation"
        >
          <Menu className="w-4 h-4" />
        </button>
        {/* Breadcrumb prefix hidden on mobile to make room for the controls */}
        <span className="hidden sm:inline text-ink-500">ThreatOrbit</span>
        <span className="hidden sm:inline text-ink-600">/</span>
        <span className="text-white font-medium truncate">{label}</span>
      </div>

      <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
        {/* Experience mode toggle */}
        <ModeToggle />

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
              <span className="absolute top-1 right-1 min-w-[14px] h-[14px] rounded-full bg-threat text-[8px] font-bold text-[#0a0a0b] flex items-center justify-center px-0.5" aria-hidden="true">
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
                    onClick={clearAllNotifs}
                    className="text-[10px] text-ink-500 hover:text-magenta transition-colors"
                  >
                    Mark all read
                  </button>
                </div>

                <div className="max-h-72 overflow-y-auto">
                  <AnimatePresence initial={false}>
                    {visible.length === 0 ? (
                      <div className="py-8 text-center text-xs text-ink-600">No notifications yet</div>
                    ) : (
                      visible.map((n) => (
                        <motion.button
                          key={n.id}
                          initial={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          onClick={() => openNotif(n)}
                          className={cn('w-full text-left flex items-start gap-3 px-4 py-3 border-b border-white/4 hover:bg-white/3 transition-colors',
                            n.read ? 'opacity-60' : '')}
                        >
                          <span
                            className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                            style={{ background: SEV_COLOR[n.severity ?? 'info'] }}
                          />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs text-ink-200 truncate">{n.title}</p>
                            <p className="text-[10px] text-ink-600 font-mono mt-0.5 capitalize">{n.type} · {relTime(n.ts)}</p>
                          </div>
                          {!n.read && <span className="mt-1 w-1.5 h-1.5 rounded-full bg-magenta shrink-0" />}
                        </motion.button>
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

        {/* Refresh - hidden on mobile to save space */}
        <button
          aria-label="Refresh data"
          onClick={handleRefresh}
          className="hidden sm:block p-2 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors"
        >
          <RefreshCw className={cn('w-4 h-4', refreshing && 'animate-spin text-safe')} aria-hidden="true" />
        </button>

        {/* User menu */}
        <div className="relative sm:pl-2 sm:border-l border-white/8" ref={userRef}>
          <button
            aria-label="Account menu"
            aria-expanded={userOpen}
            onClick={() => setUserOpen((o) => !o)}
            className="flex items-center gap-2 rounded-lg px-1 py-1 hover:bg-white/5 transition-colors"
          >
            <div className="w-7 h-7 rounded-lg bg-plasma flex items-center justify-center shrink-0">
              <span className="text-xs font-bold text-white">
                {(user?.name?.[0] ?? user?.email?.[0] ?? 'U').toUpperCase()}
              </span>
            </div>
            <div className="hidden sm:block text-left">
              <div className="text-xs font-medium text-white truncate max-w-[120px]">{user?.name ?? 'Account'}</div>
              <div className="text-[10px] text-ink-500 capitalize">{user?.role ?? ''}</div>
            </div>
          </button>

          <AnimatePresence>
            {userOpen && (
              <motion.div
                initial={{ opacity: 0, y: -6, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -6, scale: 0.97 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-full mt-2 w-56 bg-[#100A1C] border border-white/8 rounded-xl shadow-2xl overflow-hidden z-50"
              >
                <div className="px-4 py-3 border-b border-white/5">
                  <div className="text-xs font-semibold text-white truncate">{user?.name ?? 'Account'}</div>
                  <div className="text-[10px] text-ink-500 truncate">{user?.email ?? ''}</div>
                </div>
                <button
                  onClick={() => { setUserOpen(false); router.push('/dashboard/config') }}
                  className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs text-ink-200 hover:bg-white/5 transition-colors"
                >
                  <Settings className="w-3.5 h-3.5 text-ink-400" aria-hidden="true" /> Profile &amp; settings
                </button>
                <button
                  onClick={() => { setUserOpen(false); logout(); router.push('/login') }}
                  className="w-full flex items-center gap-2.5 px-4 py-2.5 text-xs text-threat hover:bg-threat/10 transition-colors border-t border-white/5"
                >
                  <LogOut className="w-3.5 h-3.5" aria-hidden="true" /> Sign out
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  )
}
