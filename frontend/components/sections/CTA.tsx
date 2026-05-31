'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { ArrowRight, Terminal, Github, Shield } from 'lucide-react'

export default function CTA() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section id="cta" ref={ref} className="py-28 overflow-hidden">
      <div className="max-w-4xl mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 32 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="relative rounded-3xl overflow-hidden"
        >
          {/* Background */}
          <div className="absolute inset-0 bg-surface-2" />
          <div className="absolute inset-0 bg-grid-dim opacity-60" />
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_70%_50%_at_50%_0%,rgba(0,212,255,0.1),transparent)]" />
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_50%_50%_at_50%_100%,rgba(123,47,190,0.08),transparent)]" />

          {/* Animated border */}
          <div className="absolute inset-0 rounded-3xl border-animated" />

          <div className="relative px-8 py-16 text-center">
            {/* Icon */}
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan/10 border border-cyan/20 mb-8">
              <Shield className="w-7 h-7 text-cyan" strokeWidth={1.5} />
            </div>

            <h2 className="font-display text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
              Ready to secure your<br />
              <span className="text-gradient-animate">infrastructure?</span>
            </h2>

            <p className="text-slate-400 text-lg max-w-xl mx-auto mb-10">
              Deploy ThreatOrbit in minutes with Docker. Connect your OSINT sources, point it at your logs, and push to OpenCTI — all with a single API key.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4 mb-10">
              <a
                href="#docs"
                className="group inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-cyan text-bg font-semibold text-sm transition-all duration-300 hover:bg-white hover:shadow-cyan-lg"
              >
                Deploy Now
                <ArrowRight className="w-4 h-4 transition-transform duration-200 group-hover:translate-x-1" />
              </a>
              <a
                href="https://github.com"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl glass border border-white/10 text-slate-300 font-medium text-sm hover:border-white/25 hover:text-white transition-all duration-300"
              >
                <Github className="w-4 h-4" />
                View on GitHub
              </a>
            </div>

            {/* Docker snippet */}
            <div className="inline-flex items-center gap-3 px-5 py-3 rounded-xl glass border border-white/8 font-mono text-xs text-slate-400">
              <Terminal className="w-3.5 h-3.5 text-slate-600 shrink-0" />
              <span>
                docker compose up -d &nbsp;
                <span className="text-safe">→ Ready on :8000 &amp; :8001</span>
              </span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
