import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'

export const metadata: Metadata = {
  title: 'Threat Intelligence Pipeline · ThreatOrbit',
  description:
    'Deep-dive into the CTI pipeline: OSINT connectors, the ingestion flow, VirusTotal enrichment, the indicator schema, and export options.',
}

const connectors = [
  {
    name: 'AlienVault OTX',
    endpoint: 'otx.alienvault.com/api/v1',
    types: 'IP, Domain, URL, Hash, Email',
    cadence: 'Configurable poll interval (default 15 min)',
    color: '#FF2E97',
    desc: 'Subscribes to your OTX pulse subscriptions and fetches all indicators added since the last high-water mark. Pulse metadata — adversary, malware family, ATT&CK tags — is preserved in the indicator record.',
  },
  {
    name: 'abuse.ch',
    endpoint: 'bazaar / urlhaus / threatfox APIs',
    types: 'Hash, URL, Domain, IP',
    cadence: 'Hourly batch pull',
    color: '#7A3CFF',
    desc: 'Pulls the latest samples from MalwareBazaar, malicious URLs from URLhaus, and IOC dumps from ThreatFox. Each export is deduplicated against the existing library before storage.',
  },
  {
    name: 'RSS / ATOM Feeds',
    endpoint: 'Any public RSS or ATOM URL',
    types: 'IP, Domain, URL, Hash (regex-extracted)',
    cadence: 'Configurable per-feed interval',
    color: '#FFB23E',
    desc: 'Vendor blogs, government CERT advisories, and community feeds are polled. Indicator patterns are extracted from titles and descriptions using a configurable regex set and normalised before scoring.',
  },
  {
    name: 'Dark-Web Monitors',
    endpoint: 'Tor .onion paste / forum APIs',
    types: 'IP, Domain, Hash, Credential',
    cadence: 'Configurable, default 30 min via Tor proxy',
    color: '#2DD4BF',
    desc: 'Routes requests through a local Tor proxy. Paste sites and threat-actor boards are scraped for newly posted IOCs. Extracted indicators receive a lower initial trust score pending VT enrichment.',
  },
  {
    name: 'Social Intelligence',
    endpoint: 'X / Mastodon public APIs',
    types: 'IP, Domain, URL, Hash',
    cadence: 'Stream or 5-min poll',
    color: '#34F5C5',
    desc: 'Follows configured threat-intel accounts and hashtag streams. IOCs extracted from analyst posts are tagged with the originating account for provenance tracking and trust-weighting.',
  },
]

const pipelineSteps = [
  { n: '01', title: 'Fetch', body: 'Each connector runs on its own async schedule. Raw indicator records are fetched and placed into a staging queue. The connector records a high-water mark so reruns never re-fetch old data.' },
  { n: '02', title: 'Normalise', body: 'Staging records are parsed into a canonical schema: type, value, source, source_confidence. Type inference handles edge cases — an IPv6 address is not misclassified as a domain.' },
  { n: '03', title: 'Deduplicate', body: 'A UUIDv5 deterministic ID is derived from (type, value). If an indicator already exists, the record is merged: source list extended, last_seen updated, trust score recalculated.' },
  { n: '04', title: 'Trust-Score', body: 'Initial trust score = source_confidence weight. After VirusTotal enrichment, the score is updated: (source_confidence × 0.6) + (vt_positives / vt_total × 0.4). Scores range 0.0–1.0.' },
  { n: '05', title: 'Store', body: 'Scored indicators land in the WAL-mode SQLite library. Indexes on type, trust_score, and last_seen ensure sub-millisecond lookups during real-time log analysis.' },
]

export default function ThreatIntelligencePage() {
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
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-magenta/20 bg-magenta/5 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-magenta" />
            <span className="text-xs text-magenta tracking-wide font-medium">Platform · Threat Intelligence</span>
          </div>
          <h1 className="font-display text-5xl font-bold text-white mb-5 leading-tight">
            From raw OSINT{' '}
            <span className="text-gradient-magenta">to scored</span>
            <br />indicators in seconds
          </h1>
          <p className="text-lg text-ink-400 leading-relaxed">
            The ThreatOrbit CTI pipeline is a five-stage assembly line: fetch from five OSINT
            sources, normalise to a canonical schema, deduplicate against the existing library,
            calculate a composite trust score, then store in a WAL-mode SQLite database ready for
            real-time log matching. Every indicator is VirusTotal-enriched before being committed
            to the library.
          </p>
        </div>

        {/* Ingestion Flow */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">Ingestion Flow</h2>
          <p className="text-sm text-ink-500 mb-8">Five stages, fully asynchronous, with automatic deduplication and scoring.</p>
          <div className="space-y-0">
            {pipelineSteps.map(({ n, title, body }, i) => (
              <div key={n} className="flex gap-5">
                <div className="flex flex-col items-center">
                  <div className="w-9 h-9 rounded-xl border border-magenta/30 bg-magenta/5 flex items-center justify-center shrink-0">
                    <span className="text-[11px] font-mono font-bold text-magenta">{n}</span>
                  </div>
                  {i < pipelineSteps.length - 1 && <div className="w-px flex-1 my-1 bg-white/5" />}
                </div>
                <div className="pb-8">
                  <h3 className="font-display font-semibold text-white text-sm mb-1">{title}</h3>
                  <p className="text-[13px] text-ink-400 leading-relaxed">{body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Source Connectors */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">OSINT Source Connectors</h2>
          <p className="text-sm text-ink-500 mb-8">Each connector is independently scheduled and fault-isolated — one source going down never stalls the others.</p>
          <div className="space-y-3">
            {connectors.map(({ name, endpoint, types, cadence, color, desc }) => (
              <div key={name} className="glass rounded-2xl border border-white/6 p-5">
                <div className="flex items-start gap-4">
                  <div
                    className="w-2 h-2 rounded-full mt-1.5 shrink-0"
                    style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}88` }}
                  />
                  <div className="flex-1 min-w-0">
                    <h3 className="font-display font-semibold text-white text-sm mb-1">{name}</h3>
                    <p className="text-[13px] text-ink-400 leading-relaxed mb-3">{desc}</p>
                    <div className="flex flex-wrap gap-x-6 gap-y-1.5 text-[12px]">
                      <span><span className="text-ink-500">Endpoint </span><span className="font-mono text-ink-300">{endpoint}</span></span>
                      <span><span className="text-ink-500">Types </span><span className="text-ink-300">{types}</span></span>
                      <span><span className="text-ink-500">Cadence </span><span className="text-ink-300">{cadence}</span></span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Indicator Schema */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">Indicator Schema</h2>
          <p className="text-sm text-ink-500 mb-6">The canonical record every indicator is normalised into before storage.</p>
          <div className="rounded-2xl border border-white/6 overflow-hidden">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-white/5">
                  <th className="text-left px-5 py-3 text-ink-500 font-medium">Field</th>
                  <th className="text-left px-5 py-3 text-ink-500 font-medium">Type</th>
                  <th className="text-left px-5 py-3 text-ink-500 font-medium">Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {[
                  ['id', 'UUIDv5', 'Deterministic — derived from (type, value)'],
                  ['type', 'enum', 'ip · domain · url · hash · email'],
                  ['value', 'string', 'Canonical form — IP normalised, domain lowercased'],
                  ['source', 'string[]', 'All feeds that have reported this indicator'],
                  ['source_confidence', 'float 0–1', 'Weighted average of originating source weights'],
                  ['trust_score', 'float 0–1', 'Composite: source_confidence + VT enrichment'],
                  ['vt_positives', 'integer', 'VirusTotal positive detection count'],
                  ['vt_total', 'integer', 'Total VT scanner count for normalisation'],
                  ['first_seen', 'ISO 8601', 'Timestamp of first ingestion'],
                  ['last_seen', 'ISO 8601', 'Timestamp of most recent observation'],
                  ['stix_id', 'string', 'STIX 2.1 Indicator object ID for export'],
                  ['tags', 'string[]', 'ATT&CK tactics, malware family, analyst labels'],
                ].map(([field, type, notes]) => (
                  <tr key={field} className="hover:bg-white/2 transition-colors">
                    <td className="px-5 py-3 font-mono text-magenta">{field}</td>
                    <td className="px-5 py-3 text-ink-500">{type}</td>
                    <td className="px-5 py-3 text-ink-400">{notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Export Options */}
        <div className="glass rounded-2xl border border-white/6 p-6 mb-16">
          <h2 className="font-display text-lg font-bold text-white mb-4">Export Options</h2>
          <div className="grid sm:grid-cols-3 gap-4">
            {[
              { label: 'STIX 2.1 Bundle', endpoint: 'GET /indicators/export/stix', detail: 'Full spec-compliant STIX 2.1 JSON with deterministic Indicator SCO IDs. Supports ?type=, ?min_score=, and date range filters.' },
              { label: 'CSV Export', endpoint: 'GET /indicators/export/csv', detail: 'Flat CSV for analyst tooling and spreadsheet workflows. Same filter params as the STIX export endpoint.' },
              { label: 'Live JSON', endpoint: 'GET /indicators', detail: 'Paginated JSON API with cursor pagination. Filter by type, trust score, source, and time range. Suitable for pipeline ingestion.' },
            ].map(({ label, endpoint, detail }) => (
              <div key={label}>
                <p className="text-[11px] font-mono text-magenta mb-1">{endpoint}</p>
                <p className="font-semibold text-white text-sm mb-1.5">{label}</p>
                <p className="text-[13px] text-ink-400 leading-relaxed">{detail}</p>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="text-center rounded-2xl border border-magenta/20 bg-magenta/5 p-10">
          <h2 className="font-display text-2xl font-bold text-white mb-3">
            Build your threat library today
          </h2>
          <p className="text-sm text-ink-400 mb-6 max-w-md mx-auto">
            The CTI pipeline is open-core and self-hosted. Start with the free tier or get early access to the full platform.
          </p>
          <Link
            href="/#contact"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-magenta text-white text-sm font-semibold hover:bg-magenta/90 transition-colors"
          >
            Get in touch
          </Link>
        </div>
      </main>
    </div>
  )
}
