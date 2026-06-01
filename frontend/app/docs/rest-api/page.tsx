import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'

export const metadata: Metadata = { title: 'REST API · ThreatOrbit Docs' }

const ENDPOINTS = [
  {
    service: 'Threat API',
    port: 8000,
    color: '#FF2E97',
    routes: [
      { method: 'GET',  path: '/health',               auth: 'none',     desc: 'Service health check.' },
      { method: 'GET',  path: '/indicators',           auth: 'standard', desc: 'List all stored IOCs. Supports ?limit and ?offset.' },
      { method: 'GET',  path: '/indicators/{id}',      auth: 'standard', desc: 'Get a single indicator by ID.' },
      { method: 'POST', path: '/fetch',                auth: 'admin',    desc: 'Trigger an async OSINT ingestion pipeline. Returns job_id.' },
      { method: 'GET',  path: '/jobs/{job_id}',        auth: 'standard', desc: 'Poll async job status: pending | running | complete | failed.' },
      { method: 'POST', path: '/export/stix',          auth: 'admin',    desc: 'Export current indicators as a STIX 2.1 bundle.' },
      { method: 'GET',  path: '/opencti/status',       auth: 'standard', desc: 'Check OpenCTI connection health.' },
      { method: 'GET',  path: '/opencti/indicators',   auth: 'standard', desc: 'Query indicators directly from OpenCTI.' },
      { method: 'POST', path: '/opencti/push',         auth: 'admin',    desc: 'Push enriched STIX bundle to OpenCTI.' },
    ],
  },
  {
    service: 'Log API',
    port: 8001,
    color: '#7A3CFF',
    routes: [
      { method: 'GET',  path: '/health',               auth: 'none',     desc: 'Service health check.' },
      { method: 'POST', path: '/analyze',              auth: 'admin',    desc: 'Submit log content for anomaly detection. Accepts raw text or JSON.' },
      { method: 'GET',  path: '/results/{job_id}',     auth: 'standard', desc: 'Retrieve analysis results: anomaly scores, flagged lines, and report.' },
      { method: 'GET',  path: '/results',              auth: 'standard', desc: 'List all completed analysis results with pagination.' },
      { method: 'GET',  path: '/report/{job_id}',      auth: 'standard', desc: 'Download a formatted HTML analysis report.' },
    ],
  },
]

const METHOD_STYLES: Record<string, string> = {
  GET:  'text-safe bg-safe/10 border-safe/20',
  POST: 'text-amber bg-amber/10 border-amber/20',
}

const AUTH_STYLES: Record<string, string> = {
  none:     'text-ink-500 bg-white/3 border-white/10',
  standard: 'text-magenta bg-magenta/10 border-magenta/20',
  admin:    'text-amber bg-amber/10 border-amber/20',
}

export default function RestApiPage() {
  return (
    <article className="prose-docs max-w-3xl">
      <Breadcrumb items={[{ label: 'Docs', href: '/docs' }, { label: 'REST API' }]} />

      <h1>REST API Reference</h1>
      <p className="lead">
        ThreatOrbit exposes two independent HTTP services. All responses are JSON.
        All authenticated endpoints require an <code>X-API-Key</code> header.
      </p>

      <div className="not-prose flex gap-3 my-6 flex-wrap">
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] border ${AUTH_STYLES.standard}`}>Standard key</span>
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] border ${AUTH_STYLES.admin}`}>Admin key required</span>
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] border ${AUTH_STYLES.none}`}>No auth</span>
      </div>

      {ENDPOINTS.map(({ service, port, color, routes }) => (
        <div key={service} className="not-prose mb-10">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-2 h-6 rounded-full" style={{ background: color }} />
            <div>
              <h2 className="text-lg font-display font-bold text-white">{service}</h2>
              <p className="text-xs text-ink-500">localhost:{port}</p>
            </div>
          </div>
          <div className="space-y-2">
            {routes.map((r) => (
              <div key={r.path} className="rounded-xl border border-white/6 bg-white/2 p-4 flex flex-wrap gap-3 items-start">
                <span className={`shrink-0 text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${METHOD_STYLES[r.method] ?? ''}`}>
                  {r.method}
                </span>
                <code className="flex-1 min-w-0 text-sm text-ink-200 font-mono">{r.path}</code>
                <span className={`shrink-0 text-[10px] px-2 py-0.5 rounded-full border ${AUTH_STYLES[r.auth]}`}>
                  {r.auth === 'none' ? 'public' : r.auth}
                </span>
                <p className="w-full text-sm text-ink-400 mt-1 pl-0">{r.desc}</p>
              </div>
            ))}
          </div>
        </div>
      ))}

      <h2>Base URLs</h2>
      <p>In a local Docker Compose deployment:</p>
      <CodeBlock>{`# Threat API
http://localhost:8000

# Log API
http://localhost:8001`}</CodeBlock>

      <h2>Common response shapes</h2>
      <CodeBlock>{`// Job response (async endpoints)
{
  "job_id": "3f4a...",
  "status": "pending" | "running" | "complete" | "failed",
  "created_at": "2025-01-01T00:00:00Z",
  "result": null | { ... }
}

// Indicator
{
  "id": "indicator--...",
  "type": "ip" | "domain" | "hash" | "url",
  "value": "1.2.3.4",
  "source": "otx",
  "score": 87,
  "created_at": "2025-01-01T00:00:00Z"
}`}</CodeBlock>

      <div className="callout">
        New to the API? Start with the <Link href="/docs/quick-start">Quick Start guide</Link>.
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

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="bg-surface rounded-xl border border-white/6 p-4 overflow-x-auto text-sm font-mono text-ink-200 my-4">
      <code>{children}</code>
    </pre>
  )
}
