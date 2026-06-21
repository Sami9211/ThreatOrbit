'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { FileText, AlertCircle, CheckCircle, Activity } from 'lucide-react'
import { usePerfProfile } from '@/lib/usePerf'

type Flag = 'threat' | 'warn' | null

const LOG_LINES: { text: string; flag: Flag; detector?: number }[] = [
  { text: '192.168.1.45 - - [12/May/2024:14:23:01] "GET /admin/../etc/passwd HTTP/1.1" 404', flag: 'threat', detector: 0 },
  { text: '10.0.0.12 - - [12/May/2024:14:23:02] "POST /api/login HTTP/1.1" 200', flag: null },
  { text: '2024-05-12T14:23:03Z [WARN] sshd: Failed password for root from 45.12.34.67', flag: 'threat', detector: 0 },
  { text: '10.0.0.8 - - [12/May/2024:14:23:04] "GET /assets/main.js HTTP/1.1" 200', flag: null },
  { text: '2024-05-12T14:23:05Z Event=4625 IpAddress=192.168.0.254 TargetUser=Administrator', flag: 'warn', detector: 1 },
  { text: '10.0.0.20 - - [12/May/2024:14:23:06] "GET /index.html HTTP/1.1" 200', flag: null },
  { text: '2024-05-12T14:23:07Z [ERROR] sshd: Invalid user nobody from 185.234.218.99', flag: 'threat', detector: 3 },
]

const DETECTORS = [
  { name: 'Pattern Matching', desc: 'Regex rules for known attack signatures', unit: 'hits', color: 'threat' },
  { name: 'Statistical', desc: 'Z-score deviation from per-source baseline', unit: 'anomalies', color: 'warn' },
  { name: 'ML Model', desc: 'Isolation Forest with rolling features', unit: 'flags', color: 'safe' },
  { name: 'Temporal', desc: 'Rate spikes and time-of-day deviation', unit: 'spikes', color: 'warn' },
]

const DETECTOR_COLOR = {
  threat: 'text-threat bg-threat/10 border-threat/20',
  warn: 'text-amber bg-amber/10 border-amber/20',
  safe: 'text-safe bg-safe/10 border-safe/20',
}

export default function LogAnalysisSection() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  const scanRef = useRef<HTMLDivElement>(null)
  const scanInView = useInView(scanRef, { margin: '-40px' })
  const { prefersReducedMotion } = usePerfProfile()

  // scanLine: index of the line currently being analysed (-1 = idle, length = done)
  const [scanLine, setScanLine] = useState(prefersReducedMotion ? LOG_LINES.length : -1)

  useEffect(() => {
    if (prefersReducedMotion || !scanInView) return
    let i = -1
    const tick = () => {
      i += 1
      setScanLine(i)
      if (i > LOG_LINES.length) i = -1 // brief "done" frame then restart
    }
    const t = setInterval(tick, 650)
    return () => clearInterval(t)
  }, [prefersReducedMotion, scanInView])

  // detector counts derived from how far the scan has progressed
  const counts = DETECTORS.map((_, di) =>
    LOG_LINES.filter((l, li) => l.detector === di && li < scanLine).length,
  )

  return (
    <section id="log-analysis" ref={ref} className="py-28 bg-surface-2 overflow-hidden">
      <div className="site-container">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          <motion.div
            initial={{ opacity: 0, x: -32 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.7 }}
            className="flex flex-col gap-3"
          >
            <div ref={scanRef} className="glass border border-white/8 rounded-2xl overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-white/2">
                <FileText className="w-3.5 h-3.5 text-ink-500" strokeWidth={1.5} />
                <span className="text-xs text-ink-300 font-medium">access.log</span>
                <span className="ml-auto flex items-center gap-1.5 text-[10px] font-mono text-violet">
                  <span className="w-1.5 h-1.5 rounded-full bg-violet animate-pulse" />
                  {scanLine >= LOG_LINES.length ? 'analysis complete' : 'scanning…'}
                </span>
              </div>
              <div className="p-4 font-mono text-[10px] space-y-1.5 max-h-[220px] overflow-hidden">
                {LOG_LINES.map((line, i) => {
                  const scanned = i < scanLine
                  const active = i === scanLine
                  const flag = scanned ? line.flag : null
                  return (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0 }}
                      animate={inView ? { opacity: 1 } : {}}
                      transition={{ delay: 0.1 + i * 0.07 }}
                      className="flex items-start gap-2 rounded px-1 -mx-1 transition-colors duration-200"
                      style={{
                        backgroundColor: active ? 'rgba(122,60,255,0.16)' : 'transparent',
                      }}
                    >
                      {active ? (
                        <Activity className="w-3 h-3 text-violet shrink-0 mt-0.5 animate-pulse" strokeWidth={2} />
                      ) : flag === 'threat' ? (
                        <AlertCircle className="w-3 h-3 text-threat shrink-0 mt-0.5" strokeWidth={2} />
                      ) : flag === 'warn' ? (
                        <Activity className="w-3 h-3 text-amber shrink-0 mt-0.5" strokeWidth={2} />
                      ) : scanned ? (
                        <CheckCircle className="w-3 h-3 text-safe/60 shrink-0 mt-0.5" strokeWidth={1.5} />
                      ) : (
                        <span className="w-3 h-3 shrink-0 mt-0.5 rounded-full border border-ink-600/40" />
                      )}
                      <span
                        className={
                          active
                            ? 'text-violet'
                            : flag === 'threat'
                            ? 'text-threat/80'
                            : flag === 'warn'
                            ? 'text-amber/80'
                            : scanned
                            ? 'text-ink-500'
                            : 'text-ink-600/50'
                        }
                      >
                        {line.text}
                      </span>
                    </motion.div>
                  )
                })}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {DETECTORS.map((d, i) => (
                <motion.div
                  key={d.name}
                  initial={{ opacity: 0, y: 16 }}
                  animate={inView ? { opacity: 1, y: 0 } : {}}
                  transition={{ delay: 0.4 + i * 0.07 }}
                  className="glass border border-white/6 rounded-xl p-4"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-ink-200">{d.name}</span>
                    <motion.span
                      key={counts[i]}
                      initial={{ scale: 1.3 }}
                      animate={{ scale: 1 }}
                      transition={{ type: 'spring', stiffness: 400, damping: 18 }}
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                        counts[i] > 0
                          ? DETECTOR_COLOR[d.color as keyof typeof DETECTOR_COLOR]
                          : 'text-safe bg-safe/10 border-safe/20'
                      }`}
                    >
                      {counts[i] > 0 ? `${counts[i]} ${d.unit}` : 'clean'}
                    </motion.span>
                  </div>
                  <p className="text-[10px] text-ink-500 leading-relaxed">{d.desc}</p>
                </motion.div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 32 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.15 }}
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-violet/20 bg-violet/5 mb-6">
              <Activity className="w-3 h-3 text-violet" />
              <span className="text-xs text-violet tracking-wide">Log Analysis API</span>
            </div>

            <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight mb-6">
              Four detection layers.
              <br />
              <span className="text-gradient-threat">One API call.</span>
            </h2>

            <p className="text-ink-300 leading-relaxed mb-8">
              Upload any log file, whether Apache, syslog, Windows Event XML, or generic text, and
              ThreatOrbit&apos;s async pipeline runs four independent detectors, returning
              consolidated anomaly reports in seconds.
            </p>

            <div className="space-y-4">
              {[
                { title: 'Multi-format parsers', desc: 'Four built-in parsers with an extensible architecture. Upload raw bytes or multipart form.' },
                { title: 'Async job model', desc: 'POST /analyse returns immediately. Poll /jobs/{id} or use ?async=false for synchronous mode.' },
                { title: 'Enriched anomaly reports', desc: 'Each finding includes detector name, severity, matched pattern, and line reference.' },
              ].map((item) => (
                <div key={item.title} className="flex gap-4">
                  <div className="w-1 rounded-full bg-gradient-to-b from-violet to-magenta shrink-0" />
                  <div>
                    <h4 className="text-sm font-semibold text-white mb-1">{item.title}</h4>
                    <p className="text-sm text-ink-400 leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-8 glass border border-white/8 rounded-xl p-4 font-mono text-xs text-ink-300">
              <div className="text-ink-500 mb-1"># Analyse a log file</div>
              <div>
                <span className="text-violet">POST</span> /api/analyse
              </div>
              <div className="text-ink-500">Content-Type: multipart/form-data</div>
              <div className="mt-1">
                <span className="text-safe">{'{ "job_id": "b9c3e1...", "anomalies": 3 }'}</span>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
