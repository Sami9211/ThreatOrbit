'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { Radio, Activity, Zap, ArrowDown } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'
import { usePerfProfile } from '@/lib/usePerf'

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
  const colRef = useRef<HTMLDivElement>(null)
  const colView = useInView(colRef, { margin: '-80px' })
  const { prefersReducedMotion } = usePerfProfile()
  const [active, setActive] = useState(0)

  useEffect(() => {
    if (prefersReducedMotion || !colView) return
    const t = setInterval(() => setActive((a) => (a + 1) % PILLARS.length), 2200)
    return () => clearInterval(t)
  }, [prefersReducedMotion, colView])

  return (
    <section id="about" className="py-28 bg-surface overflow-hidden">
      <div className="site-container">
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

          <Reveal variant="right">
            <div ref={colRef} className="relative">
              {PILLARS.map((p, i) => {
                const Icon = p.icon
                const isActive = active === i
                return (
                  <div key={p.name}>
                    <motion.div
                      onMouseEnter={() => setActive(i)}
                      animate={{
                        borderColor: isActive ? `${p.color}55` : 'rgba(255,255,255,0.08)',
                        backgroundColor: isActive ? `${p.color}0c` : 'rgba(255,255,255,0.02)',
                      }}
                      transition={{ duration: 0.4 }}
                      className="glass border rounded-2xl p-5 flex gap-4 cursor-default"
                    >
                      <motion.div
                        className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border relative"
                        style={{ color: p.color, backgroundColor: `${p.color}1a`, borderColor: `${p.color}33` }}
                        animate={isActive ? { scale: [1, 1.08, 1] } : { scale: 1 }}
                        transition={{ duration: 0.5 }}
                      >
                        <Icon className="w-5 h-5" strokeWidth={1.5} />
                        {isActive && (
                          <motion.span
                            className="absolute inset-0 rounded-xl"
                            style={{ boxShadow: `0 0 20px ${p.color}66` }}
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                          />
                        )}
                      </motion.div>
                      <div>
                        <div className="flex items-baseline gap-2">
                          <span className="font-display font-bold text-white">{p.name}</span>
                          <span className="text-[11px] text-ink-500">{p.full}</span>
                        </div>
                        <p className="text-sm text-ink-400 leading-relaxed mt-1">{p.desc}</p>
                      </div>
                    </motion.div>

                    {/* flowing connector between pillars */}
                    {i < PILLARS.length - 1 && (
                      <div className="flex justify-center py-2">
                        <motion.div
                          animate={active === i ? { y: [0, 4, 0], opacity: 1 } : { opacity: 0.35 }}
                          transition={{ duration: 1, repeat: active === i ? Infinity : 0 }}
                        >
                          <ArrowDown className="w-4 h-4" style={{ color: PILLARS[i].color }} strokeWidth={2} />
                        </motion.div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  )
}
