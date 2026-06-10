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
        The easiest way to run ThreatOrbit is Docker Compose: the full stack —
        three APIs plus the web frontend — starts with a single command.
      </p>

      <h2>Architecture</h2>
      <p>The Compose stack contains four services:</p>
      <ul>
        <li><strong>frontend</strong> — the marketing site and operator dashboard, served by nginx on port 3000.</li>
        <li><strong>dashboard_api</strong> — FastAPI service on port 8002. JWT auth, SIEM/SOAR/CTI/assets/feeds, and the service bridge that proxies the other two engines.</li>
        <li><strong>threat_api</strong> — Flask service on port 8000. OSINT ingestion, indicator storage, STIX export, OpenCTI push.</li>
        <li><strong>log_api</strong> — FastAPI service on port 8001. Log submission, four anomaly detectors, report generation.</li>
      </ul>
      <p>Each API keeps its WAL-mode SQLite database on its own named volume.</p>

      <h2>Environment variables</h2>
      <p>Copy <code>.env.example</code> to <code>.env</code> in the repo root. The defaults work for a local evaluation; for production set at minimum:</p>
      <CodeBlock>{`# Required — keys the two ingestion engines authenticate with
APP_API_KEY=any_random_string_for_read_access
ADMIN_API_KEY=another_random_string_for_admin_access

# Required in production — JWT signing key for the dashboard
DASHBOARD_JWT_SECRET=$(openssl rand -hex 32)

# Optional — OSINT sources and enrichment
OTX_API_KEY=your_otx_key
VIRUSTOTAL_API_KEY=your_vt_key

# Optional — only if you run OpenCTI
OPENCTI_ENABLED=true
OPENCTI_URL=http://your-opencti-host:8080
OPENCTI_API_KEY=your_opencti_api_token`}</CodeBlock>

      <h2>Start</h2>
      <CodeBlock>{`docker compose up --build -d    # or: make up`}</CodeBlock>
      <p>
        Then open <code>http://localhost:3000</code> and sign in at{' '}
        <code>/dashboard</code> with the seeded admin
        (<code>admin@threatorbit.space</code> / <code>ChangeMe123!</code>) — or
        create an account at <code>/signup</code>. The service bridge is
        pre-wired container-to-container, so live OSINT ingestion and log
        analysis work out of the box.
      </p>

      <h2>Verify</h2>
      <CodeBlock>{`docker compose ps
# All four services should show state: running (healthy)

curl http://localhost:8000/health   # {"service":"threat_api","status":"ok"}
curl http://localhost:8001/health   # {"service":"log_api","status":"ok"}
curl http://localhost:8002/health   # {"service":"dashboard_api","status":"ok"}`}</CodeBlock>

      <h2>View logs</h2>
      <CodeBlock>{`# All services
docker compose logs -f              # or: make logs

# Single service
docker compose logs -f dashboard_api
docker compose logs -f threat_api`}</CodeBlock>

      <h2>Stop and clean up</h2>
      <CodeBlock>{`# Stop without removing data
docker compose down                 # or: make down

# Stop and remove all data volumes (destructive)
docker compose down -v`}</CodeBlock>

      <h2>Updating</h2>
      <CodeBlock>{`git pull
docker compose up -d --build`}</CodeBlock>

      <h2>Frontend on Vercel / Netlify instead</h2>
      <p>
        The Next.js frontend also deploys cleanly to Vercel or Netlify: set the
        project <strong>Root Directory</strong> to <code>frontend</code>. Point
        the build-time variable <code>NEXT_PUBLIC_API_URL</code> at your
        deployed <strong>Dashboard API</strong> (port 8002) so the operator
        dashboard loads live data.
      </p>

      <h2>Production hardening</h2>
      <ul>
        <li>Run behind a reverse proxy (nginx / Caddy) with TLS</li>
        <li>Expose only the frontend publicly; keep ports 8000–8002 on the internal network</li>
        <li>Set <code>DASHBOARD_JWT_SECRET</code> to a long random value — the API logs a warning if you keep the dev default</li>
        <li>Set <code>DASHBOARD_CORS_ORIGINS</code> to your real frontend origin(s)</li>
        <li>Disable self-service signup on closed deployments: <code>DASHBOARD_ALLOW_REGISTRATION=false</code></li>
        <li>Use secrets management (Docker Secrets or Vault) instead of a plain .env file</li>
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
