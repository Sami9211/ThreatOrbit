'use client'

import { ArrowRight, Terminal, Github } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'
import MagneticButton from '@/components/ui/MagneticButton'
import Logo from '@/components/ui/Logo'

export default function CTA() {
  return (
    <section id="cta" className="py-28 overflow-hidden">
      <div className="max-w-4xl mx-auto px-6">
        <Reveal variant="bloom" className="relative rounded-3xl overflow-hidden">
          <div className="absolute inset-0 bg-surface-2" />
          <div className="absolute inset-0 bg-grid-dim opacity-60" />
          <div className="absolute inset-0 plasma-mesh" />

          <div className="absolute inset-0 rounded-3xl border-animated" />

          <div className="relative px-8 py-16 text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/3 border border-white/10 mb-8">
              <Logo size={36} />
            </div>

            <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
              Ready to secure your
              <br />
              <span className="text-gradient-animate">infrastructure?</span>
            </h2>

            <p className="text-ink-300 text-lg max-w-xl mx-auto mb-10">
              Deploy ThreatOrbit in minutes with Docker. Connect your OSINT sources, point it at your
              logs, and push to OpenCTI, all with a single API key.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4 mb-10">
              <MagneticButton
                href="/docs/docker-deploy"
                className="px-8 py-3.5 rounded-xl bg-plasma text-white font-semibold text-sm transition-shadow duration-300 hover:shadow-magenta-lg"
              >
                Deploy Now
                <ArrowRight className="w-4 h-4" />
              </MagneticButton>
              <MagneticButton
                href="https://github.com/Sami9211/ThreatOrbit-V2"
                className="px-8 py-3.5 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:border-white/25 hover:text-white transition-colors duration-300"
              >
                <Github className="w-4 h-4" />
                View on GitHub
              </MagneticButton>
            </div>

            <div className="inline-flex items-center gap-3 px-5 py-3 rounded-xl glass border border-white/8 font-mono text-xs text-ink-300">
              <Terminal className="w-3.5 h-3.5 text-ink-500 shrink-0" />
              <span>
                docker compose up -d{' '}
                <span className="text-safe">{'>'} Ready on :8000 and :8001</span>
              </span>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  )
}
