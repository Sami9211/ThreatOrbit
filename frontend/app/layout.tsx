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
  title: 'ThreatOrbit · Enterprise Threat Intelligence Platform',
  description:
    'Enterprise-grade threat intelligence ingestion, log anomaly detection, and OpenCTI integration. Detect. Analyze. Neutralize.',
  keywords: [
    'threat intelligence',
    'STIX',
    'OpenCTI',
    'log analysis',
    'anomaly detection',
    'cybersecurity platform',
    'IOC',
    'SIEM',
  ],
  openGraph: {
    title: 'ThreatOrbit · Enterprise Threat Intelligence Platform',
    description: 'Detect. Analyze. Neutralize. Enterprise-grade threat intelligence built for the modern security team.',
    type: 'website',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable}`}
    >
      <body className="bg-bg text-ink-100 overflow-x-hidden">
        {children}
      </body>
    </html>
  )
}
