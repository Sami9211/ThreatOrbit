import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'

export const metadata: Metadata = {
  title: 'Super SOC · ThreatOrbit',
  description:
    'One unified CTI + SIEM + SOAR platform. A single API surface, single source of truth, and a continuous pipeline from raw threat intelligence to automated response.',
}

const features = [
  {
    title: 'Unified API Surface',
    desc: 'Two purpose-built APIs - Threat API (port 8000) and Log API (port 8001) - share a common auth model and response envelope. One SDK, two attack surfaces covered.',
    color: '#FF2E97',
  },
  {
    title: 'Dual Key Authentication',
    desc: 'Separate read-key and write-key tiers enforce least-privilege by design. Read-only consumers never touch your ingestion pipeline, and write keys are never exposed to dashboards.',
    color: '#7A3CFF',
  },
  {
    title: 'The Three Orbits',
    desc: 'CTI collects and scores indicators. SIEM detects anomalies in live log streams. SOAR wraps detections in STIX 2.1 and pushes them to OpenCTI automatically - all in one runtime.',
    color: '#FFB23E',
  },
  {
    title: 'Async Job Pipeline',
    desc: 'Heavy work - indicator enrichment, ML model runs, report generation - is queued asynchronously. Poll /jobs/{id} for progress or stream server-sent events for real-time status.',
    color: '#2DD4BF',
  },
  {
    title: 'OpenCTI as Output Layer',
    desc: 'Every detection and enriched indicator flows into your OpenCTI instance as a deterministic STIX 2.1 bundle. Push is idempotent - re-running a job never creates duplicate objects.',
    color: '#34F5C5',
  },
  {
    title: 'Enterprise Deployment',
    desc: 'Ship the entire stack as a single Docker Compose file. Override with environment variables for Kubernetes. Persistent WAL-mode SQLite out of the box; swap for Postgres in enterprise tier.',
    color: '#FF2E97',
  },
]

const steps = [
  { n: '01', title: 'Ingest', body: 'OTX, abuse.ch, RSS feeds, dark-web monitors, and social signals are continuously polled. Raw indicators land in a staging table before scoring.' },
  { n: '02', title: 'Enrich', body: 'Staged indicators are sent to VirusTotal for reputation scoring. The combined trust score (source confidence × VT positives) determines storage priority.' },
  { n: '03', title: 'Detect', body: 'Incoming logs are matched against live indicators and passed through four detection engines: pattern, statistical, IsolationForest ML, and temporal correlation.' },
  { n: '04', title: 'Respond', body: 'Confirmed anomalies are wrapped in STIX 2.1 Incident objects. OpenCTI receives the bundle via GraphQL. An HTML report is generated and stored for human review.' },
  { n: '05', title: 'Iterate', body: 'Analyst feedback updates indicator trust scores. False-positive rate feeds back into the ML models. Each orbit tightens with every cycle.' },
]

export default function SuperSOCPage() {
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
            <span className="text-xs text-magenta tracking-wide font-medium">Product</span>
          </div>
          <h1 className="font-display text-5xl font-bold text-white mb-5 leading-tight">
            Super SOC -{' '}
            <span className="text-gradient-magenta">one platform,</span>
            <br />three disciplines
          </h1>
          <p className="text-lg text-ink-400 leading-relaxed">
            ThreatOrbit's Super SOC collapses CTI, SIEM, and SOAR into a single deployable unit. No
            stitching vendor APIs together, no alert fatigue from disconnected toolchains. A unified
            async pipeline carries every raw signal from open-source intel feeds all the way to an
            actionable STIX 2.1 bundle in your OpenCTI instance - automatically.
          </p>
        </div>

        {/* Feature Cards */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-16">
          {features.map(({ title, desc, color }) => (
            <div
              key={title}
              className="rounded-2xl border border-white/6 p-5 glass"
            >
              <div
                className="w-2 h-2 rounded-full mb-4"
                style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}88` }}
              />
              <h3 className="font-display font-semibold text-white text-sm mb-2">{title}</h3>
              <p className="text-[13px] text-ink-400 leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>

        {/* How It Works */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">How It Works</h2>
          <p className="text-sm text-ink-500 mb-8">The continuous orbit - from raw signal to closed loop.</p>
          <div className="space-y-0">
            {steps.map(({ n, title, body }, i) => (
              <div key={n} className="flex gap-5 group">
                <div className="flex flex-col items-center">
                  <div className="w-9 h-9 rounded-xl border border-magenta/30 bg-magenta/5 flex items-center justify-center shrink-0">
                    <span className="text-[11px] font-mono font-bold text-magenta">{n}</span>
                  </div>
                  {i < steps.length - 1 && (
                    <div className="w-px flex-1 my-1 bg-white/5" />
                  )}
                </div>
                <div className="pb-8">
                  <h3 className="font-display font-semibold text-white text-sm mb-1">{title}</h3>
                  <p className="text-[13px] text-ink-400 leading-relaxed">{body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Tech Specs */}
        <div className="glass rounded-2xl border border-white/6 p-6 mb-16">
          <h2 className="font-display text-lg font-bold text-white mb-4">Technical Specifications</h2>
          <div className="grid sm:grid-cols-2 gap-x-10 gap-y-3">
            {[
              ['Runtime', 'Python 3.11, FastAPI, asyncio'],
              ['Storage', 'WAL-mode SQLite (Postgres in enterprise)'],
              ['Auth', 'Dual API keys - read + write scopes'],
              ['Job queue', 'In-process asyncio task queue, SSE streaming'],
              ['Export', 'STIX 2.1 JSON bundles (deterministic UUIDs)'],
              ['Deployment', 'Docker Compose; single-command `docker compose up`'],
              ['Port map', 'Threat API :8000 · Log API :8001'],
              ['OpenCTI', 'GraphQL push, idempotent bundle import'],
            ].map(([k, v]) => (
              <div key={k} className="flex gap-3 text-[13px]">
                <span className="text-ink-500 w-28 shrink-0">{k}</span>
                <span className="text-ink-300">{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="text-center rounded-2xl border border-magenta/20 bg-magenta/5 p-10">
          <h2 className="font-display text-2xl font-bold text-white mb-3">
            Ready to collapse your SOC stack?
          </h2>
          <p className="text-sm text-ink-400 mb-6 max-w-md mx-auto">
            Get early access, request a demo, or deploy the open-core version today.
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
