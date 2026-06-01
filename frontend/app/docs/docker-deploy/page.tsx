import type { Metadata } from 'next'
import Link from 'next/link'
import { ArrowRight } from 'lucide-react'

export const metadata: Metadata = { title: 'Docker Deploy · ThreatOrbit Docs' }

export default function DockerDeployPage() {
  return (
    <article className="prose-docs max-w-2xl">
      <Breadcrumb items={[{ label: 'Docs', href: '/docs' }, { label: 'Docker Deploy' }]} />

      <h1>Docker Deployment</h1>
      <p className="lead">
        The recommended way to run ThreatOrbit is Docker Compose. Both API services start
        with a single command and share a persistent data volume.
      </p>

      <h2>Architecture</h2>
      <p>The Compose stack contains three components:</p>
      <ul>
        <li><strong>threat_api</strong> — FastAPI service on port 8000. Handles OSINT ingestion, indicator storage, STIX export, and OpenCTI push.</li>
        <li><strong>log_api</strong> — FastAPI service on port 8001. Handles log submission, anomaly detection, and report generation.</li>
        <li><strong>data volume</strong> — Shared SQLite databases (WAL mode) for both services.</li>
      </ul>

      <h2>Environment variables</h2>
      <p>Create a <code>.env</code> file in the repo root before starting:</p>
      <CodeBlock>{`# Required
APP_API_KEY=any_random_string_for_read_access
ADMIN_API_KEY=another_random_string_for_write_access

# OSINT sources (at least one recommended)
OTX_API_KEY=your_otx_key

# Enrichment (optional but recommended)
VIRUSTOTAL_API_KEY=your_vt_key

# OpenCTI (optional — only if you run OpenCTI)
OPENCTI_URL=http://your-opencti-host:8080
OPENCTI_TOKEN=your_opencti_api_token

# Log analysis tuning (optional — defaults shown)
ANOMALY_THRESHOLD=0.75
MAX_LOG_SIZE_MB=50`}</CodeBlock>

      <h2>Start</h2>
      <CodeBlock>{`docker compose up -d`}</CodeBlock>

      <h2>Verify</h2>
      <CodeBlock>{`docker compose ps
# Both services should show state: running

curl http://localhost:8000/health
# { "status": "healthy", "version": "2.0.0" }

curl http://localhost:8001/health
# { "status": "healthy", "version": "2.0.0" }`}</CodeBlock>

      <h2>View logs</h2>
      <CodeBlock>{`# All services
docker compose logs -f

# Single service
docker compose logs -f threat_api
docker compose logs -f log_api`}</CodeBlock>

      <h2>Stop and clean up</h2>
      <CodeBlock>{`# Stop without removing data
docker compose down

# Stop and remove all data volumes (destructive)
docker compose down -v`}</CodeBlock>

      <h2>Updating</h2>
      <CodeBlock>{`git pull
docker compose pull
docker compose up -d --build`}</CodeBlock>

      <h2>Frontend deployment</h2>
      <p>
        The Next.js frontend is designed to deploy on Vercel. In the Vercel dashboard, set
        the <strong>Root Directory</strong> to <code>frontend</code>. No other configuration
        is needed.
      </p>
      <p>
        Point the frontend environment variable <code>NEXT_PUBLIC_API_URL</code> to your
        deployed Threat API base URL if you want live data on the site.
      </p>

      <h2>Production hardening</h2>
      <ul>
        <li>Run behind a reverse proxy (nginx / Caddy) with TLS</li>
        <li>Restrict port 8000 and 8001 to internal network only</li>
        <li>Use secrets management (Docker Secrets or Vault) instead of a plain .env file</li>
        <li>Enable rate limiting at the proxy layer</li>
        <li>Set <code>ADMIN_API_KEY</code> to a long random string (min 32 chars)</li>
      </ul>

      <div className="callout">
        For API endpoint details, see the <Link href="/docs/rest-api">REST API reference</Link>.
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
