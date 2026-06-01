'use client'

import { Radio, Activity, Zap } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'

const PILLARS = [
  {
    icon: Radio,
    name: 'CTI',
    full: 'Cyber Threat Intelligence',
    color: '#FF2E97',
    desc: 'Know the threat before it reaches you. ThreatOrbit pulls live indicators from five OSINT sources and enriches them into a single library.',
  },
  {
    icon: Activity,
    name: 'SIEM',
    full: 'Security Information & Event Management',
    color: '#7A3CFF',
    desc: 'See what is happening inside. Four detection engines analyse your logs and surface the anomalies that signal a real incident.',
  },
  {
    icon: Zap,
    name: 'SOAR',
    full: 'Security Orchestration & Automated Response',
    color: '#FFB23E',
    desc: 'Act without delay. Findings become STIX bundles and flow straight into OpenCTI, so detection turns into response on its own.',
  },
]

export default function About() {
  return (
    <section id="about" className="py-28 bg-surface overflow-hidden">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center mb-20">
          <Reveal variant="left">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-magenta" />
              <span className="text-xs text-ink-300 tracking-wide">About ThreatOrbit</span>
            </div>
            <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight mb-6">
              Three disciplines.
              <br />
              <span className="text-gradient-magenta">One source of truth.</span>
            </h2>
            <p className="text-ink-300 leading-relaxed mb-4">
              Most security teams stitch together a threat-intel feed, a SIEM, and a SOAR tool from
              three different vendors, then spend their time keeping the seams from tearing.
            </p>
            <p className="text-ink-300 leading-relaxed">
              ThreatOrbit collapses that stack into one platform with a single API surface. Run just
              the piece you need today, and let the others click into orbit when you are ready. That
              is what we mean by a Super SOC: not more tools, but fewer, working as one.
            </p>
          </Reveal>

          <Reveal variant="right" className="space-y-4">
            {PILLARS.map((p) => {
              const Icon = p.icon
              return (
                <div
                  key={p.name}
                  className="glass border border-white/8 rounded-2xl p-5 flex gap-4 hover:border-white/15 transition-colors"
                >
                  <div
                    className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border"
                    style={{ color: p.color, backgroundColor: `${p.color}1a`, borderColor: `${p.color}33` }}
                  >
                    <Icon className="w-5 h-5" strokeWidth={1.5} />
                  </div>
                  <div>
                    <div className="flex items-baseline gap-2">
                      <span className="font-display font-bold text-white">{p.name}</span>
                      <span className="text-[11px] text-ink-500">{p.full}</span>
                    </div>
                    <p className="text-sm text-ink-400 leading-relaxed mt-1">{p.desc}</p>
                  </div>
                </div>
              )
            })}
          </Reveal>
        </div>
      </div>
    </section>
  )
}
