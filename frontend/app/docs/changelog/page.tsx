import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'

export const metadata: Metadata = { title: 'Changelog · ThreatOrbit Docs' }

const RELEASES = [
  {
    version: '2.0.0',
    date: '2025-06-01',
    badge: 'Latest',
    badgeColor: '#34F5C5',
    changes: [
      { type: 'feature', text: 'Full platform launch: CTI Library, SIEM, and SOAR in one unified API surface.' },
      { type: 'feature', text: 'Dual API key authentication: standard read key and admin write key.' },
      { type: 'feature', text: 'Four-layer ML anomaly detection pipeline for log analysis.' },
      { type: 'feature', text: 'Automated STIX 2.1 bundle generation and OpenCTI push on detection.' },
      { type: 'feature', text: 'Async job pipeline: POST to /fetch returns job_id immediately, no blocking.' },
      { type: 'feature', text: 'WAL-mode SQLite for both services with shared data volume.' },
      { type: 'feature', text: 'HTML trend reports for log analysis results.' },
      { type: 'improvement', text: 'VirusTotal enrichment uses connection pooling to avoid rate limit errors.' },
      { type: 'improvement', text: 'OpenCTI push retries with exponential back-off on transient failures.' },
    ],
  },
  {
    version: '1.2.0',
    date: '2025-03-15',
    badge: null,
    badgeColor: null,
    changes: [
      { type: 'feature', text: 'Added abuse.ch malware hash feed connector.' },
      { type: 'feature', text: 'Added RSS threat feed ingestion with configurable sources.' },
      { type: 'improvement', text: 'Parallel OSINT fetch with ThreadPoolExecutor for 4x throughput.' },
      { type: 'fix', text: 'Fixed STIX bundle IDs colliding when multiple fetches ran in quick succession.' },
    ],
  },
  {
    version: '1.1.0',
    date: '2025-01-20',
    badge: null,
    badgeColor: null,
    changes: [
      { type: 'feature', text: 'OpenCTI read integration: query indicators and check connection health.' },
      { type: 'feature', text: 'Windows Event log XML parser added to log analysis pipeline.' },
      { type: 'improvement', text: 'Statistical anomaly detector now maintains a rolling baseline window.' },
      { type: 'fix', text: 'Resolved memory leak in the temporal correlation engine on long-running jobs.' },
    ],
  },
  {
    version: '1.0.0',
    date: '2024-11-05',
    badge: null,
    badgeColor: null,
    changes: [
      { type: 'feature', text: 'Initial release of the Threat API with OTX connector and indicator storage.' },
      { type: 'feature', text: 'Initial release of the Log API with Apache and syslog parsers.' },
      { type: 'feature', text: 'Basic STIX 2.1 export for indicators.' },
      { type: 'feature', text: 'Docker Compose deployment with shared data volume.' },
    ],
  },
]

const TYPE_STYLES: Record<string, string> = {
  feature:     'text-safe bg-safe/10 border-safe/20',
  improvement: 'text-violet bg-violet/10 border-violet/20',
  fix:         'text-amber bg-amber/10 border-amber/20',
}

export default function ChangelogPage() {
  return (
    <article className="prose-docs max-w-2xl">
      <Breadcrumb items={[{ label: 'Docs', href: '/docs' }, { label: 'Changelog' }]} />

      <h1>Changelog</h1>
      <p className="lead">Release notes for ThreatOrbit. All changes are documented here.</p>

      <div className="not-prose space-y-10 mt-8">
        {RELEASES.map((release) => (
          <div key={release.version} className="relative pl-6 border-l border-white/8">
            <div className="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-magenta" />
            <div className="flex items-center gap-3 mb-4">
              <span className="font-display font-bold text-white text-xl">v{release.version}</span>
              {release.badge && (
                <span
                  className="text-[10px] font-semibold px-2 py-0.5 rounded-full border"
                  style={{ color: release.badgeColor ?? '', borderColor: `${release.badgeColor}33`, backgroundColor: `${release.badgeColor}15` }}
                >
                  {release.badge}
                </span>
              )}
              <span className="text-xs text-ink-500 ml-auto">{release.date}</span>
            </div>
            <ul className="space-y-2">
              {release.changes.map((c, i) => (
                <li key={i} className="flex items-start gap-2.5">
                  <span className={`shrink-0 mt-0.5 text-[10px] font-medium px-1.5 py-0.5 rounded border ${TYPE_STYLES[c.type]}`}>
                    {c.type}
                  </span>
                  <span className="text-sm text-ink-300">{c.text}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </article>
  )
}

function Breadcrumb({ items }: { items: { label: string; href?: string }[] }) {
  return (
    <nav className="flex items-center gap-1.5 text-xs text-ink-500 mb-8">
      {items.map((item, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <ArrowRight className="w-3 h-3" />}
          {item.href ? (
            <Link href={item.href} className="hover:text-ink-300 transition-colors">{item.label}</Link>
          ) : (
            <span className="text-ink-300">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
