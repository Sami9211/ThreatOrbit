import type { Metadata } from 'next'
import Sidebar from '@/components/dashboard/Sidebar'
import TopBar from '@/components/dashboard/TopBar'
import CommandPalette from '@/components/dashboard/CommandPalette'

export const metadata: Metadata = {
  title: {
    default: 'Dashboard · ThreatOrbit',
    template: '%s · ThreatOrbit',
  },
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-bg">
      <Sidebar />
      <div className="flex-1 ml-14 flex flex-col min-h-screen">
        <TopBar />
        <main className="flex-1 overflow-x-hidden">
          {children}
        </main>
      </div>
      <CommandPalette />
    </div>
  )
}
