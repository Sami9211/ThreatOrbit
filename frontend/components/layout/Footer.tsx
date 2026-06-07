import Link from 'next/link'
import { Github, ExternalLink } from 'lucide-react'
import Logo from '@/components/ui/Logo'

const LINKS = {
  Platform: [
    { label: 'Threat Intelligence', href: '/platform/threat-intelligence' },
    { label: 'Log Analysis',        href: '/platform/log-analysis' },
    { label: 'OpenCTI Integration', href: '/platform/opencti' },
    { label: 'STIX Export',         href: '/platform/opencti' },
    { label: 'API Reference',       href: '/docs/rest-api' },
  ],
  Products: [
    { label: 'Super SOC',           href: '/products/super-soc' },
    { label: 'CTI Library',         href: '/products/cti-library' },
    { label: 'SIEM + SOAR',         href: '/products/siem-soar' },
    { label: 'Pricing',             href: '/#pricing' },
  ],
  Developers: [
    { label: 'Quick Start',    href: '/docs/quick-start' },
    { label: 'Authentication', href: '/docs/authentication' },
    { label: 'REST API',       href: '/docs/rest-api' },
    { label: 'Docker Deploy',  href: '/docs/docker-deploy' },
    { label: 'Changelog',      href: '/docs/changelog' },
  ],
  Company: [
    { label: 'About',           href: '/#about' },
    { label: 'Security',        href: '/security' },
    { label: 'Privacy Policy',  href: '/privacy' },
    { label: 'Terms of Service',href: '/terms' },
    { label: 'Contact',         href: '/#contact' },
  ],
}

export default function Footer() {
  return (
    <footer className="relative border-t border-white/5 bg-surface pt-16 pb-8 overflow-hidden">
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[600px] h-[200px] bg-magenta/5 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-10 mb-14">
          <div className="col-span-2">
            <Link href="/" className="flex items-center gap-2.5 mb-4 group w-fit">
              <Logo size={26} />
              <span className="font-display font-semibold text-base">
                <span className="text-white">Threat</span>
                <span className="text-gradient-magenta">Orbit</span>
              </span>
            </Link>
            <p className="text-sm text-ink-500 leading-relaxed max-w-xs">
              Enterprise threat intelligence ingestion, log anomaly detection, and OpenCTI
              integration — built for the modern security team.
            </p>
            <div className="flex items-center gap-3 mt-5">
              <a
                href="https://github.com/Sami9211/ThreatOrbit-V2"
                target="_blank"
                rel="noreferrer"
                className="p-2 rounded-lg border border-white/8 text-ink-500 hover:text-white hover:border-magenta/30 transition-all duration-200"
                aria-label="GitHub"
              >
                <Github className="w-4 h-4" />
              </a>
              <Link
                href="/docs"
                className="p-2 rounded-lg border border-white/8 text-ink-500 hover:text-white hover:border-magenta/30 transition-all duration-200"
                aria-label="Documentation"
              >
                <ExternalLink className="w-4 h-4" />
              </Link>
            </div>
          </div>

          {Object.entries(LINKS).map(([title, items]) => (
            <div key={title}>
              <h4 className="text-xs font-semibold text-ink-400 uppercase tracking-widest mb-4">{title}</h4>
              <ul className="space-y-2.5">
                {items.map((item) => (
                  <li key={item.label}>
                    <Link href={item.href} className="group inline-flex items-center text-sm text-ink-500 hover:text-ink-200 transition-colors duration-200">
                      <span className="w-0 group-hover:w-2.5 h-px bg-magenta mr-0 group-hover:mr-1.5 transition-all duration-300" />
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-6 border-t border-white/5">
          <p className="text-xs text-ink-600">
            © {new Date().getFullYear()} ThreatOrbit. All rights reserved.
          </p>
          <div className="flex items-center gap-1.5 text-xs text-ink-600">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
            All systems operational
          </div>
        </div>
      </div>
    </footer>
  )
}
