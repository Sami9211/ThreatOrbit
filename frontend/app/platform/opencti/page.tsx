import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'
import { GitMerge, Shield, RefreshCw, CheckCircle, AlertCircle, ArrowRight, Layers } from 'lucide-react'

export const metadata: Metadata = {
  title: 'OpenCTI Integration · ThreatOrbit Platform',
  description: 'Native OpenCTI integration via GraphQL API. Push enriched STIX 2.1 bundles, query indicators, and monitor sync health.',
}

const CAPABILITIES = [
  {
    icon: GitMerge,
    color: '#FFB23E',
    title: 'STIX 2.1 Push',
    desc: 'Exports enriched indicators as standards-compliant STIX 2.1 Bundles and pushes them to OpenCTI over its GraphQL API. Every push is idempotent: deterministic UUIDs mean re-pushing the same indicator is safe.',
  },
  {
    icon: RefreshCw,
    color: '#FF2E97',
    title: 'Indicator Queries',
    desc: 'Read existing OpenCTI indicators directly from ThreatOrbit via GET /opencti/indicators. Supports filtering by type, confidence range, and created-after timestamp — no need to open the OpenCTI UI for routine queries.',
  },
  {
    icon: CheckCircle,
    color: '#34F5C5',
    title: 'Connection Health',
    desc: 'GET /opencti/status returns connection health, OpenCTI version, last-push timestamp, and indicator count. Wire this into your monitoring stack to alert when sync falls more than N minutes behind.',
  },
  {
    icon: Layers,
    color: '#7A3CFF',
    title: 'Automatic SOAR Trigger',
    desc: 'When the log analysis pipeline detects anomalies, the SOAR module automatically bundles the findings as STIX 2.1 ObservedData and pushes them to OpenCTI — detection becomes response without manual steps.',
  },
]

const STEPS = [
  { n: '01', title: 'Configure connection', desc: 'Set OPENCTI_URL and OPENCTI_TOKEN in your .env file. ThreatOrbit establishes a long-lived GraphQL session on startup and re-authenticates automatically on token expiry.' },
  { n: '02', title: 'Ingest and enrich',   desc: 'Run a threat intelligence fetch. Indicators are ingested from OSINT sources and enriched with VirusTotal scores. Each IOC is stored locally with full metadata.' },
  { n: '03', title: 'Export STIX bundle',  desc: 'POST /export/stix builds a STIX 2.1 Bundle: Indicator SDOs for each IOC, RelationshipSROs linking them to a ThreatActor identity, and a source Identity SDO.' },
  { n: '04', title: 'Push to OpenCTI',    desc: 'POST /opencti/push uploads the bundle. ThreatOrbit handles rate limiting, chunking for large bundles, and retries with exponential back-off on 5xx responses.' },
  { n: '05', title: 'Verify in OpenCTI',  desc: 'Open OpenCTI and check the Indicators view. All pushed IOCs appear with their confidence scores, tags, and a source reference back to ThreatOrbit.' },
]

export default function OpenCTIPage() {
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

      <main className="max-w-5xl mx-auto px-6 py-16 space-y-20">
        {/* Hero */}
        <section>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-amber/20 bg-amber/5 mb-6">
            <GitMerge className="w-3 h-3 text-amber" />
            <span className="text-xs text-amber tracking-wide">SOAR · OpenCTI</span>
          </div>
          <h1 className="font-display text-5xl md:text-6xl font-bold text-white leading-tight mb-6">
            Detection becomes<br />
            <span className="text-gradient-magenta">response, automatically.</span>
          </h1>
          <p className="text-xl text-ink-300 max-w-2xl leading-relaxed mb-8">
            ThreatOrbit integrates natively with OpenCTI via its GraphQL API. Enriched STIX 2.1
            bundles are pushed on every detection cycle — no scripts, no manual export, no seams.
          </p>
          <div className="flex gap-4 flex-wrap">
            <Link href="/docs/docker-deploy" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-amber/15 border border-amber/25 text-amber text-sm font-medium hover:bg-amber/25 transition-colors">
              Deployment guide <ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/docs/rest-api" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl glass border border-white/10 text-ink-200 text-sm hover:border-white/25 transition-colors">
              API Reference
            </Link>
          </div>
        </section>

        {/* Capabilities */}
        <section>
          <h2 className="font-display text-3xl font-bold text-white mb-8">What ThreatOrbit does with OpenCTI</h2>
          <div className="grid md:grid-cols-2 gap-5">
            {CAPABILITIES.map(({ icon: Icon, color, title, desc }) => (
              <div key={title} className="rounded-2xl glass border border-white/6 p-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-xl flex items-center justify-center border"
                    style={{ color, backgroundColor: `${color}1a`, borderColor: `${color}33` }}>
                    <Icon className="w-5 h-5" strokeWidth={1.5} />
                  </div>
                  <h3 className="font-display font-semibold text-white">{title}</h3>
                </div>
                <p className="text-sm text-ink-300 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* STIX detail */}
        <section>
          <h2 className="font-display text-3xl font-bold text-white mb-2">STIX 2.1 bundle structure</h2>
          <p className="text-ink-400 mb-6">Every pushed bundle is standards-compliant and can be consumed by any TAXII-compatible platform.</p>
          <div className="rounded-xl border border-white/6 bg-surface p-5 font-mono text-xs text-ink-300 overflow-x-auto">
            <pre>{`{
  "type": "bundle",
  "id": "bundle--<deterministic-uuid>",
  "objects": [
    {
      "type": "indicator",           // Indicator SDO
      "id": "indicator--<uuid>",     // deterministic from IOC value
      "name": "Malicious IP 1.2.3.4",
      "pattern": "[ipv4-addr:value = '1.2.3.4']",
      "pattern_type": "stix",
      "confidence": 87,              // VirusTotal score
      "labels": ["malicious-activity", "c2"],
      "valid_from": "2025-06-01T00:00:00Z"
    },
    {
      "type": "relationship",        // RelationshipSRO
      "relationship_type": "indicates",
      "source_ref": "indicator--...",
      "target_ref": "threat-actor--..."
    },
    {
      "type": "identity",            // Source identity
      "name": "ThreatOrbit",
      "identity_class": "system"
    }
  ]
}`}</pre>
          </div>
        </section>

        {/* Setup steps */}
        <section>
          <h2 className="font-display text-3xl font-bold text-white mb-8">Setup in five steps</h2>
          <div className="space-y-5">
            {STEPS.map(({ n, title, desc }) => (
              <div key={n} className="flex gap-5 items-start">
                <div className="shrink-0 w-9 h-9 rounded-full flex items-center justify-center border border-amber/30 bg-amber/10 font-mono text-sm font-bold text-amber">{n}</div>
                <div className="pt-1">
                  <p className="font-display font-semibold text-white mb-1">{title}</p>
                  <p className="text-sm text-ink-400 leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Roadmap */}
        <section className="rounded-2xl border border-white/6 bg-white/2 p-6">
          <h3 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber" strokeWidth={1.5} />
            On the roadmap
          </h3>
          <ul className="space-y-2 text-sm text-ink-400">
            <li className="flex items-start gap-2"><Shield className="w-3.5 h-3.5 text-ink-600 mt-0.5 shrink-0" /> TAXII 2.1 server endpoint for consuming indicators from any TAXII-compatible client</li>
            <li className="flex items-start gap-2"><Shield className="w-3.5 h-3.5 text-ink-600 mt-0.5 shrink-0" /> MISP export format support alongside STIX 2.1</li>
            <li className="flex items-start gap-2"><Shield className="w-3.5 h-3.5 text-ink-600 mt-0.5 shrink-0" /> Webhook trigger on OpenCTI push completion</li>
            <li className="flex items-start gap-2"><Shield className="w-3.5 h-3.5 text-ink-600 mt-0.5 shrink-0" /> Two-way sync: pull new OpenCTI indicators back into the ThreatOrbit store</li>
          </ul>
        </section>

        {/* CTA */}
        <section className="rounded-3xl border border-amber/15 bg-amber/5 p-10 text-center">
          <h2 className="font-display text-3xl font-bold text-white mb-3">Connect to OpenCTI today</h2>
          <p className="text-ink-400 mb-6 max-w-xl mx-auto">Two environment variables and your OSINT pipeline is pushing to OpenCTI automatically.</p>
          <div className="flex gap-4 justify-center flex-wrap">
            <Link href="/docs/docker-deploy" className="px-6 py-3 rounded-xl bg-amber/15 border border-amber/25 text-amber font-semibold text-sm hover:bg-amber/25 transition-colors">
              Deploy with Docker
            </Link>
            <Link href="/#contact" className="px-6 py-3 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:border-white/25 transition-colors">
              Talk to sales
            </Link>
          </div>
        </section>
      </main>
    </div>
  )
}
