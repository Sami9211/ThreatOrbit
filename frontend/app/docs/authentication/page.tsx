import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'

export const metadata: Metadata = { title: 'Authentication · ThreatOrbit Docs' }

export default function AuthenticationPage() {
  return (
    <article className="prose-docs max-w-2xl">
      <Breadcrumb items={[{ label: 'Docs', href: '/docs' }, { label: 'Authentication' }]} />

      <h1>Authentication</h1>
      <p className="lead">
        ThreatOrbit uses a dual API key model. Every request must include an
        <code>X-API-Key</code> header.
      </p>

      <h2>Key types</h2>

      <div className="grid sm:grid-cols-2 gap-4 not-prose my-6">
        <div className="rounded-xl border border-white/8 p-5 bg-white/2">
          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-magenta/10 border border-magenta/20 text-magenta text-[11px] font-medium mb-3">Standard key</div>
          <p className="text-sm text-ink-300 leading-relaxed">Read-only access. List indicators, query jobs, check OpenCTI status, and view analysis results.</p>
          <p className="text-[11px] text-ink-500 mt-2">Set as <code className="text-ink-300">APP_API_KEY</code> in .env</p>
        </div>
        <div className="rounded-xl border border-amber/20 p-5 bg-amber/5">
          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-amber/10 border border-amber/20 text-amber text-[11px] font-medium mb-3">Admin key</div>
          <p className="text-sm text-ink-300 leading-relaxed">Write access. Trigger OSINT fetches, export STIX bundles, push to OpenCTI, and submit logs for analysis.</p>
          <p className="text-[11px] text-ink-500 mt-2">Set as <code className="text-ink-300">ADMIN_API_KEY</code> in .env</p>
        </div>
      </div>

      <h2>Using the header</h2>
      <p>Include your key in every request as an HTTP header:</p>
      <CodeBlock>{`curl http://localhost:8000/indicators \\
  -H "X-API-Key: your_api_key_here"`}</CodeBlock>

      <h2>Single-key setups</h2>
      <p>
        If you only set <code>APP_API_KEY</code> and leave <code>ADMIN_API_KEY</code> blank,
        the admin key automatically falls back to the standard key. This lets you run a single-key
        setup with full access, suitable for personal or development deployments.
      </p>

      <h2>Security recommendations</h2>
      <ul>
        <li>Use different keys in production for read vs. write operations</li>
        <li>Store keys in environment variables, never hard-code them</li>
        <li>Rotate keys by updating the environment and restarting the containers</li>
        <li>Keep <code>ADMIN_API_KEY</code> out of client-side code entirely</li>
      </ul>

      <h2>Error responses</h2>
      <p>
        A missing or invalid key returns <code>401 Unauthorized</code>. An attempt to use a
        standard key on a write endpoint returns <code>403 Forbidden</code>.
      </p>
      <CodeBlock>{`// Missing key
{ "detail": "API key required" }

// Wrong key
{ "detail": "Invalid API key" }

// Insufficient privileges
{ "detail": "Admin key required for this endpoint" }`}</CodeBlock>

      <div className="callout">
        See all available endpoints in the{' '}
        <Link href="/docs/rest-api">REST API reference</Link>.
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
