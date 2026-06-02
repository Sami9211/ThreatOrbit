'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'

const INTEGRATIONS = [
  { name: 'OpenCTI',    sub: 'STIX push / pull',       accent: '#FF2E97' },
  { name: 'MISP',       sub: 'Threat sharing',          accent: '#7A3CFF' },
  { name: 'VirusTotal', sub: 'IOC enrichment',          accent: '#FFB23E' },
  { name: 'AlienVault', sub: 'OTX OSINT feed',          accent: '#2DD4BF' },
  { name: 'Shodan',     sub: 'Host intelligence',       accent: '#FF4D6D' },
  { name: 'abuse.ch',   sub: 'Malware hashes',          accent: '#7A3CFF' },
  { name: 'TAXII 2.1',  sub: 'Standards transport',     accent: '#FFB23E' },
  { name: 'Elasticsearch','sub': 'Log storage',         accent: '#34F5C5' },
  { name: 'Grafana',    sub: 'Threat dashboards',       accent: '#FF2E97' },
  { name: 'Splunk',     sub: 'SIEM forwarding',         accent: '#7A3CFF' },
]

const DOUBLED = [...INTEGRATIONS, ...INTEGRATIONS]

function IntegrationChip({ name, sub, accent }: { name: string; sub: string; accent: string }) {
  return (
    <div className="inline-flex items-center gap-3 shrink-0 px-4 py-2.5 rounded-2xl glass border border-white/8 hover:border-white/16 transition-colors mx-2">
      <span
        className="w-7 h-7 rounded-lg flex items-center justify-center text-[11px] font-bold shrink-0"
        style={{ background: `${accent}1a`, color: accent, border: `1px solid ${accent}33` }}
      >
        {name.slice(0, 2).toUpperCase()}
      </span>
      <div>
        <div className="text-sm font-semibold text-white whitespace-nowrap">{name}</div>
        <div className="text-[11px] text-ink-500 whitespace-nowrap">{sub}</div>
      </div>
    </div>
  )
}

export default function IntegrationsBar() {
  const ref    = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })

  return (
    <section ref={ref} className="relative py-14 border-y border-white/5 bg-surface overflow-hidden">
      <motion.div
        initial={{ opacity: 0 }}
        animate={inView ? { opacity: 1 } : {}}
        transition={{ duration: 0.6 }}
        className="text-center mb-6 px-6"
      >
        <p className="text-xs text-ink-500 uppercase tracking-widest">
          Works with your security stack
        </p>
      </motion.div>

      {/* Fading masks on edges */}
      <div className="absolute left-0 top-0 bottom-0 w-24 z-10 pointer-events-none"
           style={{ background: 'linear-gradient(90deg, #100A1C, transparent)' }} />
      <div className="absolute right-0 top-0 bottom-0 w-24 z-10 pointer-events-none"
           style={{ background: 'linear-gradient(-90deg, #100A1C, transparent)' }} />

      <div className="relative overflow-hidden">
        <div className="flex animate-ticker" style={{ width: 'max-content' }}>
          {DOUBLED.map((item, i) => (
            <IntegrationChip key={i} {...item} />
          ))}
        </div>
      </div>
    </section>
  )
}
