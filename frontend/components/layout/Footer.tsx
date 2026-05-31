import { Github, ExternalLink } from 'lucide-react'
import Logo from '@/components/ui/Logo'

const LINKS = {
  Platform: ['Threat Intelligence', 'Log Analysis', 'OpenCTI Integration', 'STIX Export', 'API Reference'],
  Developers: ['Quick Start', 'Authentication', 'REST API', 'Docker Deploy', 'Changelog'],
  Company: ['About', 'Security', 'Privacy Policy', 'Terms of Service', 'Contact'],
}

export default function Footer() {
  return (
    <footer className="relative border-t border-white/5 bg-surface pt-16 pb-8 overflow-hidden">
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[600px] h-[200px] bg-magenta/5 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-10 mb-14">
          <div className="col-span-2">
            <a href="#" className="flex items-center gap-2.5 mb-4 group w-fit">
              <Logo size={26} />
              <span className="font-display font-semibold text-base">
                <span className="text-white">Threat</span>
                <span className="text-gradient-magenta">Orbit</span>
              </span>
            </a>
            <p className="text-sm text-ink-500 leading-relaxed max-w-xs">
              Enterprise threat intelligence ingestion, log anomaly detection, and OpenCTI
              integration, built for the modern security team.
            </p>
            <div className="flex items-center gap-3 mt-5">
              <a
                href="https://github.com"
                target="_blank"
                rel="noreferrer"
                className="p-2 rounded-lg border border-white/8 text-ink-500 hover:text-white hover:border-magenta/30 transition-all duration-200"
                aria-label="GitHub"
              >
                <Github className="w-4 h-4" />
              </a>
              <a
                href="#docs"
                className="p-2 rounded-lg border border-white/8 text-ink-500 hover:text-white hover:border-magenta/30 transition-all duration-200"
                aria-label="Documentation"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
          </div>

          {Object.entries(LINKS).map(([title, items]) => (
            <div key={title}>
              <h4 className="text-xs font-semibold text-ink-400 uppercase tracking-widest mb-4">{title}</h4>
              <ul className="space-y-2.5">
                {items.map((item) => (
                  <li key={item}>
                    <a href="#" className="text-sm text-ink-500 hover:text-ink-200 transition-colors duration-200">
                      {item}
                    </a>
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
