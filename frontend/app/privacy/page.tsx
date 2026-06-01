import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'

export const metadata: Metadata = {
  title: 'Privacy Policy · ThreatOrbit',
  description: 'ThreatOrbit Privacy Policy.',
}

const LAST_UPDATED = 'June 1, 2025'

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-white/5 bg-bg/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-4xl mx-auto px-6 h-14 flex items-center justify-between">
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

      <main className="max-w-3xl mx-auto px-6 py-16">
        <div className="mb-10">
          <h1 className="font-display text-4xl font-bold text-white mb-3">Privacy Policy</h1>
          <p className="text-sm text-ink-500">Last updated: {LAST_UPDATED}</p>
        </div>

        <div className="space-y-8 text-ink-300">
          <Section title="1. Overview">
            <p>
              ThreatOrbit is committed to protecting your privacy. This policy describes what
              information we collect, how we use it, and your rights regarding that information.
            </p>
          </Section>

          <Section title="2. Information We Collect">
            <p>When you use ThreatOrbit, we may collect:</p>
            <ul>
              <li><strong>Account information:</strong> email address and API credentials when you register for a managed account.</li>
              <li><strong>Usage data:</strong> API request logs including endpoint, timestamp, response code, and key tier (not key value).</li>
              <li><strong>Submitted data:</strong> indicators and log content you submit for analysis. This data is processed and stored to provide the service.</li>
              <li><strong>Technical data:</strong> IP address, browser type, and device information when you visit the ThreatOrbit website.</li>
            </ul>
          </Section>

          <Section title="3. How We Use Your Data">
            <p>We use collected information to:</p>
            <ul>
              <li>Provide, operate, and improve the ThreatOrbit platform</li>
              <li>Authenticate API requests and enforce rate limits</li>
              <li>Detect abuse and protect platform security</li>
              <li>Send service-related communications (downtime notices, security alerts)</li>
              <li>Comply with legal obligations</li>
            </ul>
            <p>We do not sell or rent your data to third parties.</p>
          </Section>

          <Section title="4. Data Retention">
            <p>
              Indicator data and analysis results are retained for the duration of your subscription
              or until you delete them via the API. On account closure, data is deleted within 30 days.
              Usage logs are retained for 90 days.
            </p>
          </Section>

          <Section title="5. Third-Party Services">
            <p>
              ThreatOrbit integrates with third-party services to deliver its functionality:
            </p>
            <ul>
              <li><strong>VirusTotal:</strong> indicator enrichment. Indicator values are sent to VirusTotal for reputation scoring.</li>
              <li><strong>AlienVault OTX:</strong> threat feed ingestion.</li>
              <li><strong>abuse.ch:</strong> malware hash feed ingestion.</li>
            </ul>
            <p>
              Each third-party service has its own privacy policy. We only share the minimum data
              necessary to perform the service.
            </p>
          </Section>

          <Section title="6. Security">
            <p>
              We take security seriously. API keys are stored as hashed values. Data in transit is
              encrypted via TLS. See our{' '}
              <Link href="/security" className="text-magenta hover:underline">Security page</Link>{' '}
              for our responsible disclosure policy.
            </p>
          </Section>

          <Section title="7. Self-Hosted Deployments">
            <p>
              If you deploy ThreatOrbit on your own infrastructure, all data stays on your servers.
              ThreatOrbit does not receive any telemetry or usage data from self-hosted instances.
            </p>
          </Section>

          <Section title="8. Your Rights">
            <p>Depending on your jurisdiction, you may have the right to:</p>
            <ul>
              <li>Access the personal data we hold about you</li>
              <li>Request correction of inaccurate data</li>
              <li>Request deletion of your data</li>
              <li>Object to or restrict certain processing</li>
            </ul>
            <p>
              To exercise these rights, contact us at{' '}
              <a href="mailto:hello@threatorbit.io" className="text-magenta hover:underline">
                hello@threatorbit.io
              </a>.
            </p>
          </Section>

          <Section title="9. Changes">
            <p>
              We may update this policy. We will notify registered users of material changes by
              email and update the &ldquo;Last updated&rdquo; date above.
            </p>
          </Section>

          <Section title="10. Contact">
            <p>
              Privacy questions or requests:{' '}
              <a href="mailto:hello@threatorbit.io" className="text-magenta hover:underline">
                hello@threatorbit.io
              </a>
            </p>
          </Section>
        </div>
      </main>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2 className="font-display font-semibold text-white text-lg mb-3">{title}</h2>
      <div className="space-y-3 text-sm leading-relaxed [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1.5 [&_strong]:text-ink-200">
        {children}
      </div>
    </div>
  )
}
