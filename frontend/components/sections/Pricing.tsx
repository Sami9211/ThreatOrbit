'use client'

import { motion } from 'framer-motion'
import { Check, Sparkles } from 'lucide-react'
import { cn } from '@/lib/utils'
import Reveal from '@/components/ui/Reveal'
import TiltCard from '@/components/ui/TiltCard'

const TIERS = [
  {
    name: 'CTI Library',
    tagline: 'Threat intelligence on its own',
    price: 'Free',
    note: 'self-hosted, open core',
    accent: '#FF2E97',
    features: [
      'Five OSINT source connectors',
      'VirusTotal enrichment',
      'STIX 2.1 export',
      'OpenCTI read + push',
      'WAL SQLite storage',
      'Community support',
    ],
    cta: 'Deploy free',
    highlighted: false,
  },
  {
    name: 'SIEM + SOAR',
    tagline: 'Detection and automated response',
    price: 'Talk to us',
    note: 'usage-based',
    accent: '#7A3CFF',
    features: [
      'Everything in CTI Library',
      'Four detection engines',
      'Multi-format log parsing',
      'Async analysis pipeline',
      'Automated STIX response',
      'HTML reporting + trends',
    ],
    cta: 'Contact sales',
    highlighted: false,
  },
  {
    name: 'Super SOC',
    tagline: 'CTI + SIEM + SOAR, unified',
    price: 'Custom',
    note: 'enterprise',
    accent: '#FFB23E',
    features: [
      'The full platform, one core',
      'Dual API key + role access',
      'Priority OpenCTI sync',
      'Dedicated onboarding',
      'SLA-backed support',
      'Roadmap influence',
    ],
    cta: 'Book a demo',
    highlighted: true,
  },
]

export default function Pricing() {
  return (
    <section id="pricing" className="py-28 max-w-7xl mx-auto px-6">
      <Reveal variant="rise" className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-5">
          <Sparkles className="w-3 h-3 text-amber" />
          <span className="text-xs text-ink-300 tracking-wide">Products and Pricing</span>
        </div>
        <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
          Buy one orbit,
          <br />
          <span className="text-gradient-plasma">or lock in all three.</span>
        </h2>
        <p className="text-lg text-ink-400 max-w-xl mx-auto">
          Start with just the CTI library, add SIEM and SOAR when you are ready, or run the entire
          Super SOC as one platform.
        </p>
      </Reveal>

      <div className="grid md:grid-cols-3 gap-5">
        {TIERS.map((tier, i) => (
          <Reveal key={tier.name} variant="bloom" delay={i * 0.08} className={cn('relative', tier.highlighted && 'md:-mt-3 md:mb-3')}>
            {/* Spinning conic gradient ring behind the flagship tier */}
            {tier.highlighted && (
              <div className="absolute -inset-px rounded-3xl overflow-hidden pointer-events-none">
                <div
                  className="absolute -inset-[40%] animate-spin-slow"
                  style={{
                    background: 'conic-gradient(from 0deg, transparent 0deg, #FFB23E 60deg, #FF2E97 120deg, transparent 200deg, #7A3CFF 300deg, transparent 360deg)',
                    opacity: 0.5,
                  }}
                />
              </div>
            )}
            <TiltCard
              intensity={6}
              className={cn(
                'relative h-full rounded-3xl p-7 glass border transition-colors duration-300',
                tier.highlighted ? 'border-amber/30 bg-surface/95' : 'border-white/8 hover:border-white/15'
              )}
            >
              {tier.highlighted && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-plasma text-white text-[10px] font-semibold tracking-wide uppercase z-10">
                  Most complete
                </span>
              )}

              <div
                className="w-10 h-1 rounded-full mb-5"
                style={{ background: tier.accent }}
              />
              <h3 className="font-display text-xl font-bold text-white">{tier.name}</h3>
              <p className="text-sm text-ink-400 mb-5">{tier.tagline}</p>

              <div className="flex items-end gap-2 mb-1">
                <span className="font-display text-3xl font-bold" style={{ color: tier.accent }}>
                  {tier.price}
                </span>
              </div>
              <p className="text-[11px] text-ink-500 mb-6">{tier.note}</p>

              <a
                href="#contact"
                className={cn(
                  'block text-center px-4 py-2.5 rounded-xl font-medium text-sm mb-7 transition-all',
                  tier.highlighted
                    ? 'bg-plasma text-white hover:shadow-magenta-md'
                    : 'glass border border-white/10 text-ink-200 hover:text-white hover:border-white/25'
                )}
              >
                {tier.cta}
              </a>

              <ul className="space-y-3">
                {tier.features.map((f, fi) => (
                  <motion.li
                    key={f}
                    initial={{ opacity: 0, x: -8 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true, margin: '-40px' }}
                    transition={{ delay: 0.2 + fi * 0.06 }}
                    className="flex items-start gap-2.5"
                  >
                    <Check className="w-4 h-4 mt-0.5 shrink-0" style={{ color: tier.accent }} />
                    <span className="text-sm text-ink-300">{f}</span>
                  </motion.li>
                ))}
              </ul>
            </TiltCard>
          </Reveal>
        ))}
      </div>
    </section>
  )
}
