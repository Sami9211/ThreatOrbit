import type { Metadata } from 'next'
import { Inter, Space_Grotesk, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
})

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-space-grotesk',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  metadataBase: new URL('https://threatorbit.io'),
  title: {
    default: 'ThreatOrbit · Enterprise Threat Intelligence Platform',
    template: '%s · ThreatOrbit',
  },
  description:
    'Enterprise-grade threat intelligence ingestion, log anomaly detection, and OpenCTI integration. Detect. Analyze. Neutralize.',
  applicationName: 'ThreatOrbit',
  keywords: [
    'threat intelligence',
    'STIX',
    'OpenCTI',
    'log analysis',
    'anomaly detection',
    'cybersecurity platform',
    'IOC',
    'SIEM',
    'SOAR',
    'OSINT',
  ],
  authors: [{ name: 'ThreatOrbit' }],
  robots: { index: true, follow: true },
  openGraph: {
    title: 'ThreatOrbit · Enterprise Threat Intelligence Platform',
    description: 'Detect. Analyze. Neutralize. Enterprise-grade threat intelligence built for the modern security team.',
    type: 'website',
    siteName: 'ThreatOrbit',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ThreatOrbit · Enterprise Threat Intelligence Platform',
    description: 'Detect. Analyze. Neutralize. Enterprise-grade threat intelligence.',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable}`}
    >
      <body className="bg-bg text-ink-100 overflow-x-hidden">
        <a href="#main-content" className="skip-link">Skip to content</a>
        {children}
        <div className="grain-overlay" aria-hidden />
      </body>
    </html>
  )
}
