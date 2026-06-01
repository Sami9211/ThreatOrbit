import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'
import { Shield, Bug, Lock, AlertTriangle } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Security · ThreatOrbit',
  description: 'ThreatOrbit security practices and responsible disclosure policy.',
}

export default function SecurityPage() {
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
        <div className="mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-safe/20 bg-safe/5 mb-6">
            <Shield className="w-3 h-3 text-safe" />
            <span className="text-xs text-safe tracking-wide">Security</span>
          </div>
          <h1 className="font-display text-4xl font-bold text-white mb-4">Security at ThreatOrbit</h1>
          <p className="text-lg text-ink-400 leading-relaxed">
            We build security software, so we hold ourselves to a high standard. Here is how we
            protect the platform and how to report issues responsibly.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 gap-4 mb-12">
          {[
            { icon: Lock, title: 'Encrypted in transit', desc: 'All API traffic is encrypted with TLS 1.2 or higher.', color: '#34F5C5' },
            { icon: Shield, title: 'Hashed credentials', desc: 'API keys are stored as secure hashes, never in plaintext.', color: '#FF2E97' },
            { icon: Bug, title: 'Regular audits', desc: 'Dependencies are audited for known vulnerabilities before each release.', color: '#7A3CFF' },
            { icon: AlertTriangle, title: 'Principle of least privilege', desc: 'Dual key tiers ensure read and write operations are separated.', color: '#FFB23E' },
          ].map(({ icon: Icon, title, desc, color }) => (
            <div
              key={title}
              className="rounded-2xl border border-white/6 p-5 glass"
            >
              <div
                className="w-9 h-9 rounded-xl flex items-center justify-center mb-3 border"
                style={{ color, backgroundColor: `${color}1a`, borderColor: `${color}33` }}
              >
                <Icon className="w-4 h-4" strokeWidth={1.5} />
              </div>
              <h3 className="font-display font-semibold text-white text-sm mb-1">{title}</h3>
              <p className="text-[13px] text-ink-400 leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>

        <div className="space-y-8 text-ink-300">
          <Section title="Responsible Disclosure">
            <p>
              If you discover a security vulnerability in ThreatOrbit, we ask that you report it
              privately before public disclosure. This allows us to investigate and release a fix
              without putting users at risk.
            </p>
            <p>
              <strong>How to report:</strong> email{' '}
              <a href="mailto:security@threatorbit.io" className="text-magenta hover:underline">
                security@threatorbit.io
              </a>{' '}
              with a description of the vulnerability, steps to reproduce, and the potential impact.
              Include &ldquo;[SECURITY]&rdquo; in the subject line.
            </p>
            <p>
              We will acknowledge your report within 48 hours and aim to release a fix within 14
              days for critical issues.
            </p>
          </Section>

          <Section title="Scope">
            <p>The following are in scope for responsible disclosure:</p>
            <ul>
              <li>The ThreatOrbit Threat API (port 8000)</li>
              <li>The ThreatOrbit Log API (port 8001)</li>
              <li>The ThreatOrbit web application (threatorbit.io)</li>
            </ul>
            <p>The following are out of scope:</p>
            <ul>
              <li>Third-party services we integrate with (OTX, VirusTotal, etc.)</li>
              <li>Denial of service attacks</li>
              <li>Social engineering or phishing</li>
              <li>Findings from automated scanners without proof of exploitability</li>
            </ul>
          </Section>

          <Section title="What We Promise">
            <ul>
              <li>We will not take legal action against researchers who report in good faith</li>
              <li>We will credit researchers who help improve security (unless they prefer anonymity)</li>
              <li>We will keep you updated on the status of your report</li>
            </ul>
          </Section>

          <Section title="Self-Hosted Security">
            <p>
              If you are running a self-hosted instance, you are responsible for your own deployment
              security. Recommendations:
            </p>
            <ul>
              <li>Run behind a TLS-terminating reverse proxy</li>
              <li>Restrict API ports to your internal network</li>
              <li>Rotate API keys regularly</li>
              <li>Keep Docker images updated to pick up dependency patches</li>
              <li>Enable firewall rules to block direct access to the SQLite data volume</li>
            </ul>
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
