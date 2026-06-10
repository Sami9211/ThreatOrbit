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
        <li>Optional: an OTX AlienVault API key (free at otx.alienvault.com) and a VirusTotal key for enrichment</li>
      </ul>

      <h2>1. Clone the repository</h2>
      <CodeBlock>{`git clone https://github.com/Sami9211/ThreatOrbit-V2.git
cd ThreatOrbit-V2`}</CodeBlock>

      <h2>2. Configure environment variables</h2>
      <p>Copy the example file — the defaults work for a local evaluation:</p>
      <CodeBlock>{`cp .env.example .env`}</CodeBlock>
      <p>For anything beyond a local trial, open <code>.env</code> and set:</p>
      <CodeBlock>{`APP_API_KEY=your_read_key_here
ADMIN_API_KEY=your_admin_key_here
DASHBOARD_JWT_SECRET=a_long_random_value
OTX_API_KEY=your_otx_api_key   # optional, enables the OTX feed`}</CodeBlock>

      <h2>3. Start the platform</h2>
      <CodeBlock>{`docker compose up --build -d    # or: make up`}</CodeBlock>
      <p>This brings up the full stack:</p>
      <ul>
        <li><strong>Frontend</strong> on port <code>3000</code> (marketing site + operator dashboard)</li>
        <li><strong>Dashboard API</strong> on port <code>8002</code> (auth, SIEM, SOAR, CTI, assets, feeds)</li>
        <li><strong>Threat API</strong> on port <code>8000</code> (OSINT ingestion engine)</li>
        <li><strong>Log API</strong> on port <code>8001</code> (log anomaly detection)</li>
      </ul>

      <h2>4. Open the dashboard</h2>
      <p>
        Go to <code>http://localhost:3000/dashboard</code> and sign in with the
        seeded admin (<code>admin@threatorbit.space</code> /{' '}
        <code>ChangeMe123!</code>), or create your own account at{' '}
        <code>/signup</code>. Every page loads live data from the Dashboard API.
      </p>

      <h2>5. Verify the services are healthy</h2>
      <CodeBlock>{`curl http://localhost:8000/health   # {"service":"threat_api","status":"ok"}
curl http://localhost:8001/health   # {"service":"log_api","status":"ok"}
curl http://localhost:8002/health   # {"service":"dashboard_api","status":"ok"}`}</CodeBlock>

      <h2>6. Trigger your first threat intelligence fetch</h2>
      <p>
        In the dashboard: <strong>Feeds → Sources → Trigger Fetch</strong>, then{' '}
        <strong>Sync IOCs to CTI</strong>. Or via the API:
      </p>
      <CodeBlock>{`curl -X POST http://localhost:8000/fetch \\
  -H "X-API-Key: your_admin_key_here"`}</CodeBlock>
      <p>
        The endpoint returns a <code>job_id</code> immediately. The full OSINT pipeline runs
        asynchronously in the background.
      </p>

      <h2>7. Check job status and list indicators</h2>
      <CodeBlock>{`curl http://localhost:8000/jobs/{job_id} \\
  -H "X-API-Key: your_read_key_here"

curl "http://localhost:8000/iocs?limit=20" \\
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
