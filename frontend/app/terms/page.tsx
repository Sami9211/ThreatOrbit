import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'

export const metadata: Metadata = {
  title: 'Terms of Service · ThreatOrbit',
  description: 'ThreatOrbit Terms of Service.',
}

const LAST_UPDATED = 'June 1, 2025'

export default function TermsPage() {
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
          <h1 className="font-display text-4xl font-bold text-white mb-3">Terms of Service</h1>
          <p className="text-sm text-ink-500">Last updated: {LAST_UPDATED}</p>
        </div>

        <div className="prose-legal space-y-8 text-ink-300">
          <Section title="1. Acceptance of Terms">
            <p>
              By accessing or using ThreatOrbit (the &ldquo;Platform&rdquo;), you agree to be bound
              by these Terms of Service. If you do not agree to these terms, do not use the Platform.
            </p>
          </Section>

          <Section title="2. Description of Service">
            <p>
              ThreatOrbit provides enterprise-grade threat intelligence ingestion, log anomaly
              detection, and security orchestration services via a REST API. The Platform is offered
              as self-hosted open-core software and as a managed cloud service.
            </p>
          </Section>

          <Section title="3. API Keys and Account Security">
            <p>
              You are responsible for maintaining the confidentiality of your API keys. Any activity
              performed using your API keys is your responsibility. You must notify us immediately if
              you become aware of any unauthorized use.
            </p>
            <p>
              We reserve the right to revoke API keys that are used in violation of these terms or
              that pose a security risk.
            </p>
          </Section>

          <Section title="4. Acceptable Use">
            <p>You agree not to use ThreatOrbit to:</p>
            <ul>
              <li>Conduct offensive security operations against systems you do not own or have permission to test</li>
              <li>Violate any applicable laws or regulations</li>
              <li>Resell or redistribute the service without written permission</li>
              <li>Attempt to circumvent rate limits, authentication, or access controls</li>
              <li>Introduce malicious code or interfere with the platform&apos;s integrity</li>
            </ul>
          </Section>

          <Section title="5. Data and Privacy">
            <p>
              Indicator data and log content you submit to the Platform may be stored and processed
              to provide the service. We do not sell or share your data with third parties. See our{' '}
              <Link href="/privacy" className="text-magenta hover:underline">Privacy Policy</Link> for details.
            </p>
          </Section>

          <Section title="6. Intellectual Property">
            <p>
              The ThreatOrbit software is open-core. The core platform is available under the MIT
              License. Enterprise features and the managed cloud service are proprietary and subject
              to separate commercial licensing.
            </p>
          </Section>

          <Section title="7. Disclaimers">
            <p>
              THE PLATFORM IS PROVIDED &ldquo;AS IS&rdquo; WITHOUT WARRANTIES OF ANY KIND. THREATORBIT
              DOES NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, ERROR-FREE, OR THAT THREAT
              DETECTIONS WILL BE COMPLETE OR ACCURATE. SECURITY OUTCOMES DEPEND ON YOUR ENVIRONMENT,
              CONFIGURATION, AND RESPONSE PROCESSES.
            </p>
          </Section>

          <Section title="8. Limitation of Liability">
            <p>
              TO THE MAXIMUM EXTENT PERMITTED BY LAW, THREATORBIT SHALL NOT BE LIABLE FOR ANY
              INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING OUT OF YOUR
              USE OF THE PLATFORM.
            </p>
          </Section>

          <Section title="9. Changes to Terms">
            <p>
              We may update these terms from time to time. Continued use of the Platform after
              changes are posted constitutes your acceptance of the revised terms.
            </p>
          </Section>

          <Section title="10. Contact">
            <p>
              For questions about these terms, contact us at{' '}
              <a href="mailto:hello@threatorbit.space" className="text-magenta hover:underline">
                hello@threatorbit.space
              </a>.
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
      <div className="space-y-3 text-sm leading-relaxed [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1.5">
        {children}
      </div>
    </div>
  )
}
