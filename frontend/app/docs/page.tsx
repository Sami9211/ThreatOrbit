import Link from 'next/link'
import { Zap, KeyRound, Terminal, Container, GitFork, ArrowRight } from 'lucide-react'

const CARDS = [
  {
    icon: Zap,
    title: 'Quick Start',
    desc: 'Deploy ThreatOrbit and make your first API call in under five minutes.',
    href: '/docs/quick-start',
    accent: '#FF2E97',
  },
  {
    icon: KeyRound,
    title: 'Authentication',
    desc: 'Understand the dual API key model: standard user keys and admin write keys.',
    href: '/docs/authentication',
    accent: '#7A3CFF',
  },
  {
    icon: Terminal,
    title: 'REST API Reference',
    desc: 'Every endpoint across both services, with request/response examples.',
    href: '/docs/rest-api',
    accent: '#FFB23E',
  },
  {
    icon: Container,
    title: 'Docker Deploy',
    desc: 'Self-host both APIs with a single docker compose command. Full configuration guide.',
    href: '/docs/docker-deploy',
    accent: '#2DD4BF',
  },
  {
    icon: GitFork,
    title: 'Changelog',
    desc: 'Release notes and version history for the ThreatOrbit platform.',
    href: '/docs/changelog',
    accent: '#FF2E97',
  },
]

export default function DocsPage() {
  return (
    <div className="max-w-3xl">
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-magenta" />
          <span className="text-xs text-ink-300 tracking-wide">Developer Documentation</span>
        </div>
        <h1 className="font-display text-4xl font-bold text-white mb-4">ThreatOrbit Docs</h1>
        <p className="text-lg text-ink-400 leading-relaxed">
          Everything you need to integrate, deploy, and extend ThreatOrbit. Start with the Quick
          Start guide or dive into a specific section below.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-4">
        {CARDS.map(({ icon: Icon, title, desc, href, accent }) => (
          <Link
            key={href}
            href={href}
            className="group relative rounded-2xl p-6 glass border border-white/6 hover:border-white/15 transition-colors"
          >
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center mb-4 border"
              style={{ color: accent, backgroundColor: `${accent}1a`, borderColor: `${accent}33` }}
            >
              <Icon className="w-4 h-4" strokeWidth={1.5} />
            </div>
            <h3 className="font-display font-semibold text-white text-sm mb-1.5">{title}</h3>
            <p className="text-[13px] text-ink-400 leading-relaxed mb-4">{desc}</p>
            <span className="flex items-center gap-1 text-xs font-medium" style={{ color: accent }}>
              Read guide
              <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
            </span>
          </Link>
        ))}
      </div>

      <div className="mt-12 p-6 rounded-2xl border border-magenta/15 bg-magenta/5">
        <h3 className="font-display font-semibold text-white mb-2">Need help?</h3>
        <p className="text-sm text-ink-400 mb-3">
          Can&apos;t find what you are looking for? Reach out via the contact form and we will
          respond within one business day.
        </p>
        <Link
          href="/#contact"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-magenta hover:underline"
        >
          Contact us <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  )
}
