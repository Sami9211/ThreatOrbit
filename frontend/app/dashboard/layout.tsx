import type { Metadata } from 'next'
import Sidebar from '@/components/dashboard/Sidebar'
import TopBar from '@/components/dashboard/TopBar'
import CommandPalette from '@/components/dashboard/CommandPalette'
import DetailDrawer from '@/components/dashboard/DetailDrawer'
import ThemeScope from '@/components/dashboard/ThemeScope'
import PageScale from '@/components/dashboard/PageScale'
import CursorParticles from '@/components/effects/CursorParticles'
import AuthGuard from '@/components/dashboard/AuthGuard'
import AssistantWidget from '@/components/dashboard/AssistantWidget'

export const metadata: Metadata = {
  title: {
    default: 'Dashboard · ThreatOrbit',
    template: '%s · ThreatOrbit',
  },
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <ThemeScope>
        <Sidebar />
        <div className="flex-1 min-w-0 ml-0 md:ml-14 flex flex-col min-h-screen">
          <TopBar />
          <main id="main-content" tabIndex={-1} className="flex-1 overflow-x-hidden focus:outline-hidden">
            <PageScale>{children}</PageScale>
          </main>
        </div>
        <CommandPalette />
        <DetailDrawer />
        <CursorParticles />
        <AssistantWidget />
      </ThemeScope>
    </AuthGuard>
  )
}
