import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'

export const metadata: Metadata = { title: 'Quick Start · ThreatOrbit Docs' }

export default function QuickStartPage() {
  return (
    <article className="prose-docs max-w-2xl">
      <Breadcrumb items={[{ label: 'Docs', href: '/docs' }, { label: 'Quick Start' }]} />

      <h1>Quick Start</h1>
      <p className="lead">
        Get ThreatOrbit running locally in under five minutes using Docker Compose.
      </p>

      <h2>Prerequisites</h2>
      <ul>
        <li>Docker and Docker Compose installed</li>
        <li>An OTX AlienVault API key (free at otx.alienvault.com)</li>
        <li>Optional: VirusTotal API key for enrichment</li>
      </ul>

      <h2>1. Clone the repository</h2>
      <CodeBlock>{`git clone https://github.com/Sami9211/ThreatOrbit-V2.git
cd ThreatOrbit-V2`}</CodeBlock>

      <h2>2. Configure environment variables</h2>
      <p>Copy the example file and fill in your keys:</p>
      <CodeBlock>{`cp .env.example .env`}</CodeBlock>
      <p>Open <code>.env</code> and set at minimum:</p>
      <CodeBlock>{`APP_API_KEY=your_read_key_here
ADMIN_API_KEY=your_admin_key_here
OTX_API_KEY=your_otx_api_key`}</CodeBlock>

      <h2>3. Start the platform</h2>
      <CodeBlock>{`docker compose up -d`}</CodeBlock>
      <p>This brings up two services:</p>
      <ul>
        <li><strong>Threat API</strong> on port <code>8000</code> (OSINT ingestion and CTI)</li>
        <li><strong>Log API</strong> on port <code>8001</code> (anomaly detection and SOAR)</li>
      </ul>

      <h2>4. Verify both services are healthy</h2>
      <CodeBlock>{`curl http://localhost:8000/health
curl http://localhost:8001/health`}</CodeBlock>
      <p>Both should return <code>{"{ \"status\": \"healthy\" }"}</code>.</p>

      <h2>5. Trigger your first threat intelligence fetch</h2>
      <CodeBlock>{`curl -X POST http://localhost:8000/fetch \\
  -H "X-API-Key: your_admin_key_here"`}</CodeBlock>
      <p>
        The endpoint returns a <code>job_id</code> immediately. The full OSINT pipeline runs
        asynchronously in the background.
      </p>

      <h2>6. Check job status</h2>
      <CodeBlock>{`curl http://localhost:8000/jobs/{job_id} \\
  -H "X-API-Key: your_read_key_here"`}</CodeBlock>

      <h2>7. List ingested indicators</h2>
      <CodeBlock>{`curl "http://localhost:8000/indicators?limit=20" \\
  -H "X-API-Key: your_read_key_here"`}</CodeBlock>

      <div className="callout">
        <strong>Next step:</strong> Learn how the dual API key system works in the{' '}
        <Link href="/docs/authentication">Authentication guide</Link>.
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
