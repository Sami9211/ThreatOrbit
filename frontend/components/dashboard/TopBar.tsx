'use client'

import { usePathname } from 'next/navigation'
import { Bell, RefreshCw, User } from 'lucide-react'

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

export default function TopBar() {
  const raw = usePathname() ?? '/dashboard'
  // trailingSlash:true means usePathname() can return "/dashboard/siem/" —
  // normalise so the label lookup matches regardless of trailing slash.
  const pathname = raw.length > 1 ? raw.replace(/\/$/, '') : raw
  const label = LABELS[pathname] ?? LABELS['/dashboard']

  return (
    <header className="h-14 border-b border-white/5 flex items-center justify-between px-6 bg-[#0D0920]/60 backdrop-blur-sm sticky top-0 z-30">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-ink-500">ThreatOrbit</span>
        <span className="text-ink-600">/</span>
        <span className="text-white font-medium">{label}</span>
      </div>

      <div className="flex items-center gap-2">
        <button aria-label="Notifications" className="relative p-2 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors">
          <Bell className="w-4 h-4" aria-hidden="true" />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-threat" aria-hidden="true" />
        </button>
        <button aria-label="Refresh data" className="p-2 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors">
          <RefreshCw className="w-4 h-4" aria-hidden="true" />
        </button>
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
