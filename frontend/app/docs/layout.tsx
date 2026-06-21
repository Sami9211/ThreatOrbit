import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'
import { ChevronRight, BookOpen, Zap, KeyRound, Terminal, Container, GitFork } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Docs · ThreatOrbit',
  description: 'ThreatOrbit developer documentation - quick start, authentication, REST API reference, Docker deployment, and changelog.',
}

const NAV = [
  {
    heading: 'Getting Started',
    items: [
      { label: 'Overview', href: '/docs', icon: BookOpen },
      { label: 'Quick Start', href: '/docs/quick-start', icon: Zap },
    ],
  },
  {
    heading: 'API Reference',
    items: [
      { label: 'Authentication', href: '/docs/authentication', icon: KeyRound },
      { label: 'REST API', href: '/docs/rest-api', icon: Terminal },
    ],
  },
  {
    heading: 'Deployment',
    items: [
      { label: 'Docker Deploy', href: '/docs/docker-deploy', icon: Container },
    ],
  },
  {
    heading: 'Project',
    items: [
      { label: 'Changelog', href: '/docs/changelog', icon: GitFork },
    ],
  },
]

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-bg">
      {/* Top bar */}
      <header className="sticky top-0 z-50 border-b border-white/5 bg-bg/80 backdrop-blur-xl">
        <div className="site-container h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo size={22} />
            <span className="font-display font-semibold text-sm">
              <span className="text-white">Threat</span>
              <span className="text-gradient-magenta">Orbit</span>
            </span>
            <ChevronRight className="w-3.5 h-3.5 text-ink-600" />
            <span className="text-sm text-ink-400">Docs</span>
          </Link>
          <Link
            href="/"
            className="text-xs text-ink-400 hover:text-white transition-colors"
          >
            Back to site
          </Link>
        </div>
      </header>

      <div className="site-container flex gap-10 py-10">
        {/* Sidebar */}
        <aside className="hidden md:block w-56 shrink-0">
          <nav className="sticky top-24 space-y-6">
            {NAV.map((group) => (
              <div key={group.heading}>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-ink-500 mb-2.5 px-2">
                  {group.heading}
                </p>
                <ul className="space-y-0.5">
                  {group.items.map(({ label, href, icon: Icon }) => (
                    <li key={href}>
                      <Link
                        href={href}
                        className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg text-sm text-ink-400 hover:text-white hover:bg-white/4 transition-colors"
                      >
                        <Icon className="w-3.5 h-3.5 shrink-0" strokeWidth={1.5} />
                        {label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </aside>

        {/* Main content */}
        <main className="flex-1 min-w-0">
          {children}
        </main>
      </div>
    </div>
  )
}
