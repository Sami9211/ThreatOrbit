import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'

export const metadata: Metadata = {
  title: 'CTI Library · ThreatOrbit',
  description:
    'Free, self-hosted threat intelligence library. Pull from 5 OSINT sources, enrich with VirusTotal, export STIX 2.1 - no cloud required.',
}

const sources = [
  {
    name: 'AlienVault OTX',
    tag: 'OSINT',
    desc: 'Subscribes to OTX pulse subscriptions for real-time indicators of compromise across IP, domain, hash, and URL types.',
    color: '#FF2E97',
  },
  {
    name: 'abuse.ch Feeds',
    tag: 'OSINT',
    desc: 'Ingests MalwareBazaar, URLhaus, and ThreatFox exports. Malware hashes and malicious URLs land in your local library within minutes of publication.',
    color: '#7A3CFF',
  },
  {
    name: 'RSS / ATOM Feeds',
    tag: 'OSINT',
    desc: 'Any publicly accessible RSS or ATOM feed can be registered as a source. Titles and descriptions are parsed for indicator patterns using regex extraction.',
    color: '#FFB23E',
  },
  {
    name: 'Dark-Web Monitors',
    tag: 'Extended',
    desc: 'Tor-accessible paste sites and dark-web threat-intel boards are polled on a configurable interval. Indicators are extracted and trust-scored before storage.',
    color: '#2DD4BF',
  },
  {
    name: 'Social Intelligence',
    tag: 'Extended',
    desc: 'Public threat-intel accounts and hashtag streams (X/Twitter, Mastodon) are monitored. IOCs mentioned in analyst posts are extracted and correlated with existing library entries.',
    color: '#34F5C5',
  },
]

const enrichment = [
  { label: 'Positives', desc: 'VT detection count from 70+ AV engines' },
  { label: 'Total scans', desc: 'Full scan coverage, not just positives' },
  { label: 'Scan date', desc: 'Timestamp of the most recent VT analysis' },
  { label: 'Permalink', desc: 'Direct link to the VT report for analysts' },
  { label: 'Trust score', desc: 'Composite: source confidence × VT positives / total' },
]

export default function CTILibraryPage() {
  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-white/5 bg-bg/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo size={22} />
            <span className="font-display font-semibold text-sm">
              <span className="text-white">Threat</span>
              <span className="text-gradient-magenta">Orbit</span>
            </span>
          </Link>
          <Link href="/" className="text-xs text-ink-400 hover:text-white transition-colors">Back to site</Link>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-16">
        {/* Hero */}
        <div className="mb-16 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-teal/20 bg-teal/5 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-teal" />
            <span className="text-xs text-teal tracking-wide font-medium">Free Tier · Self-Hosted</span>
          </div>
          <h1 className="font-display text-5xl font-bold text-white mb-5 leading-tight">
            CTI Library -{' '}
            <span className="text-gradient-magenta">open-source</span>
            <br />threat intelligence
          </h1>
          <p className="text-lg text-ink-400 leading-relaxed">
            ThreatOrbit’s CTI Library is the open-core tier: a self-hosted threat intelligence
            aggregator that pulls from five OSINT sources, enriches every indicator against
            VirusTotal, and exports clean STIX 2.1 JSON. No cloud dependency, no per-indicator
            billing, no SaaS lock-in - just a WAL-mode SQLite database that lives on your
            infrastructure.
          </p>
        </div>

        {/* OSINT Sources */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">OSINT Sources</h2>
          <p className="text-sm text-ink-500 mb-8">Five connectors ship in the free tier. All are configurable via environment variables.</p>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {sources.map(({ name, tag, desc, color }) => (
              <div
                key={name}
                className="rounded-2xl border border-white/6 p-5 glass"
              >
                <div className="flex items-center justify-between mb-3">
                  <span
                    className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-full border"
                    style={{ color, backgroundColor: `${color}18`, borderColor: `${color}33` }}
                  >
                    {tag}
                  </span>
                </div>
                <h3 className="font-display font-semibold text-white text-sm mb-2">{name}</h3>
                <p className="text-[13px] text-ink-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* VirusTotal Enrichment */}
        <div className="glass rounded-2xl border border-amber/20 p-6 mb-16">
          <div className="flex items-start gap-4 mb-5">
            <div className="w-10 h-10 rounded-xl border border-amber/30 bg-amber/5 flex items-center justify-center shrink-0">
              <span className="text-sm font-mono font-bold text-amber">VT</span>
            </div>
            <div>
              <h2 className="font-display text-lg font-bold text-white mb-1">VirusTotal Enrichment</h2>
              <p className="text-[13px] text-ink-400">Every stored indicator is sent to the VT API for a reputation check. Results are cached and merged into the indicator record.</p>
            </div>
          </div>
          <div className="grid sm:grid-cols-2 gap-3">
            {enrichment.map(({ label, desc }) => (
              <div key={label} className="flex gap-3 text-[13px]">
                <span className="text-amber w-28 shrink-0 font-medium">{label}</span>
                <span className="text-ink-400">{desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Indicator Schema */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">Indicator Schema</h2>
          <p className="text-sm text-ink-500 mb-6">Every indicator stored in the library carries these fields.</p>
          <div className="rounded-2xl border border-white/6 overflow-hidden">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-white/5">
                  <th className="text-left px-5 py-3 text-ink-500 font-medium">Field</th>
                  <th className="text-left px-5 py-3 text-ink-500 font-medium">Type</th>
                  <th className="text-left px-5 py-3 text-ink-500 font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {[
                  ['id', 'UUID', 'Deterministic v5 UUID derived from type + value'],
                  ['type', 'enum', 'ip · domain · url · hash · email'],
                  ['value', 'string', 'The raw indicator value'],
                  ['source', 'string', 'Originating feed name'],
                  ['trust_score', 'float 0-1', 'Composite confidence score'],
                  ['vt_positives', 'integer', 'VirusTotal detection count'],
                  ['first_seen', 'ISO 8601', 'When the indicator was first ingested'],
                  ['last_seen', 'ISO 8601', 'Most recent observation timestamp'],
                  ['stix_id', 'string', 'STIX 2.1 object ID for export'],
                ].map(([field, type, desc]) => (
                  <tr key={field} className="hover:bg-white/2 transition-colors">
                    <td className="px-5 py-3 font-mono text-magenta">{field}</td>
                    <td className="px-5 py-3 text-ink-500">{type}</td>
                    <td className="px-5 py-3 text-ink-400">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Export & Storage */}
        <div className="grid sm:grid-cols-2 gap-4 mb-16">
          <div className="glass rounded-2xl border border-white/6 p-5">
            <h3 className="font-display font-semibold text-white text-sm mb-3">STIX 2.1 Export</h3>
            <p className="text-[13px] text-ink-400 leading-relaxed mb-3">
              Call <span className="font-mono text-magenta">GET /indicators/export/stix</span> to
              receive a full STIX 2.1 Bundle containing all indicators as Indicator SCOs. IDs are
              deterministic - the same indicator always produces the same STIX ID, making bundles
              safe to import into OpenCTI multiple times without duplication.
            </p>
            <ul className="text-[13px] text-ink-400 space-y-1.5 list-disc pl-4">
              <li>Spec-compliant STIX 2.1 JSON</li>
              <li>Deterministic object IDs (UUIDv5)</li>
              <li>Supports filtering by type, score, or date range</li>
            </ul>
          </div>
          <div className="glass rounded-2xl border border-white/6 p-5">
            <h3 className="font-display font-semibold text-white text-sm mb-3">WAL SQLite Storage</h3>
            <p className="text-[13px] text-ink-400 leading-relaxed mb-3">
              The library uses SQLite in Write-Ahead Log mode for concurrent read access and
              crash-safe writes. Backups are as simple as copying a single file. The enterprise tier
              swaps the storage layer for Postgres with zero API changes.
            </p>
            <ul className="text-[13px] text-ink-400 space-y-1.5 list-disc pl-4">
              <li>Zero-dependency local storage</li>
              <li>WAL mode for concurrent readers</li>
              <li>Single-file backup and restore</li>
            </ul>
          </div>
        </div>

        {/* CTA */}
        <div className="text-center rounded-2xl border border-teal/20 bg-teal/5 p-10">
          <h2 className="font-display text-2xl font-bold text-white mb-3">
            Start collecting threat intelligence today
          </h2>
          <p className="text-sm text-ink-400 mb-6 max-w-md mx-auto">
            Self-host the CTI Library for free or get early access to the full Super SOC platform.
          </p>
          <Link
            href="/#contact"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-magenta text-white text-sm font-semibold hover:bg-magenta/90 transition-colors"
          >
            Get early access
          </Link>
        </div>
      </main>
    </div>
  )
}
