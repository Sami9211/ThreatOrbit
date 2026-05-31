'use client'

import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { ArrowRight, Terminal, Shield, Zap } from 'lucide-react'
import dynamic from 'next/dynamic'

const ParticleNetwork = dynamic(() => import('@/components/effects/ParticleNetwork'), { ssr: false })

const TERMINAL_LINES = [
  { text: '> Ingesting OSINT feeds...', color: 'text-cyan' },
  { text: '  [OTX] 1,247 IOCs synced', color: 'text-slate-400' },
  { text: '  [abuse.ch] 843 malware hashes', color: 'text-slate-400' },
  { text: '> Running anomaly detectors...', color: 'text-cyan' },
  { text: '  [ML] Baseline established', color: 'text-slate-400' },
  { text: '  [PATTERN] 3 threats flagged', color: 'text-threat' },
  { text: '> Pushing to OpenCTI...', color: 'text-cyan' },
  { text: '  [STIX 2.1] Bundle exported', color: 'text-safe' },
]

function TerminalWidget() {
  const [visibleLines, setVisibleLines] = useState(0)

  useEffect(() => {
    if (visibleLines >= TERMINAL_LINES.length) return
    const t = setTimeout(() => setVisibleLines((v) => v + 1), 420)
    return () => clearTimeout(t)
  }, [visibleLines])

  return (
    <div className="glass border border-white/8 rounded-xl p-4 font-mono text-xs leading-relaxed min-h-[190px]">
      <div className="flex items-center gap-1.5 mb-3">
        <span className="w-2.5 h-2.5 rounded-full bg-threat/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-[#FFB300]/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-safe/80" />
        <span className="ml-2 text-slate-600 text-[10px]">threatorbit — threat_api</span>
      </div>
      {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
        <div key={i} className={`${line.color} transition-opacity duration-300`}>
          {line.text}
        </div>
      ))}
      {visibleLines < TERMINAL_LINES.length && (
        <span className="text-cyan cursor-blink" />
      )}
    </div>
  )
}

export default function Hero() {
  const badgeRef = useRef<HTMLDivElement>(null)

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden">
      {/* Particle network background */}
      <ParticleNetwork className="absolute inset-0 z-0 opacity-70" />

      {/* Radial vignette */}
      <div className="absolute inset-0 bg-radial-cyan z-0 pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_120%,rgba(123,47,190,0.12),transparent)] z-0 pointer-events-none" />

      {/* Scan line */}
      <div className="scan-line z-10" />

      <div className="relative z-10 max-w-7xl mx-auto px-6 py-28 grid lg:grid-cols-2 gap-16 items-center">
        {/* Left */}
        <div>
          {/* Badge */}
          <motion.div
            ref={badgeRef}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-cyan/20 bg-cyan/5 mb-7"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-cyan animate-pulse" />
            <span className="text-xs font-medium text-cyan tracking-wide">Enterprise Threat Intelligence Platform</span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 28 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="font-display text-5xl md:text-6xl xl:text-7xl font-bold leading-[1.08] tracking-tight text-white mb-6"
          >
            Detect.<br />
            <span className="text-gradient-animate">Analyze.</span><br />
            Neutralize.
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.35 }}
            className="text-lg text-slate-400 max-w-lg leading-relaxed mb-10"
          >
            Ingest OSINT intelligence feeds, detect log anomalies with ML, and push enriched STIX bundles to OpenCTI — all through a unified API.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.45 }}
            className="flex flex-wrap gap-4"
          >
            <a
              href="#cta"
              className="group inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan text-bg font-semibold text-sm transition-all duration-300 hover:bg-white hover:shadow-cyan-md"
            >
              Start for Free
              <ArrowRight className="w-4 h-4 transition-transform duration-200 group-hover:translate-x-1" />
            </a>
            <a
              href="#docs"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-xl glass border border-white/10 text-slate-300 font-medium text-sm hover:border-cyan/30 hover:text-white transition-all duration-300"
            >
              <Terminal className="w-4 h-4" />
              View API Docs
            </a>
          </motion.div>

          {/* Trust indicators */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
            className="flex items-center gap-6 mt-10"
          >
            {[
              { icon: Shield, label: 'STIX 2.1 native' },
              { icon: Zap, label: 'Sub-second analysis' },
              { icon: Terminal, label: 'Open API' },
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="flex items-center gap-1.5 text-xs text-slate-500">
                <Icon className="w-3.5 h-3.5 text-cyan/60" strokeWidth={1.5} />
                {label}
              </div>
            ))}
          </motion.div>
        </div>

        {/* Right — terminal widget */}
        <motion.div
          initial={{ opacity: 0, x: 40 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.9, delay: 0.4, ease: [0.22, 1, 0.36, 1] }}
          className="flex flex-col gap-4"
        >
          <TerminalWidget />

          {/* Mini stat cards */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { value: '2.1M+', label: 'IOCs tracked', color: 'text-cyan' },
              { value: '99.4%', label: 'Detection rate', color: 'text-safe' },
              { value: '<50ms', label: 'API latency', color: 'text-violet' },
            ].map((s) => (
              <div key={s.label} className="glass border border-white/6 rounded-xl p-4 text-center">
                <div className={`font-display text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{s.label}</div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2"
      >
        <span className="text-[10px] text-slate-600 tracking-widest uppercase">Scroll</span>
        <div className="w-px h-8 bg-gradient-to-b from-cyan/40 to-transparent animate-pulse" />
      </motion.div>
    </section>
  )
}
