'use client'

import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { FileText, AlertCircle, CheckCircle, Activity } from 'lucide-react'

const LOG_LINES = [
  { text: '192.168.1.45 - - [12/May/2024:14:23:01 +0000] "GET /admin/../etc/passwd HTTP/1.1" 404', flag: 'threat' },
  { text: '10.0.0.12 - - [12/May/2024:14:23:02 +0000] "POST /api/login HTTP/1.1" 200', flag: null },
  { text: '2024-05-12T14:23:03Z [WARN] sshd: Failed password for root from 45.12.34.67 port 22', flag: 'threat' },
  { text: '10.0.0.8 - - [12/May/2024:14:23:04 +0000] "GET /assets/main.js HTTP/1.1" 200', flag: null },
  { text: '2024-05-12T14:23:05Z Event=4625 IpAddress=192.168.0.254 TargetUser=Administrator', flag: 'warn' },
  { text: '10.0.0.20 - - [12/May/2024:14:23:06 +0000] "GET /index.html HTTP/1.1" 200', flag: null },
  { text: '2024-05-12T14:23:07Z [ERROR] sshd: Invalid user nobody from 185.234.218.99', flag: 'threat' },
]

const DETECTORS = [
  { name: 'Pattern Matching', desc: 'Regex-based rules for known attack signatures', count: '2 hits', color: 'threat' },
  { name: 'Statistical', desc: 'Z-score deviation from per-source baseline', count: '1 anomaly', color: 'warn' },
  { name: 'ML Model', desc: 'Isolation Forest + rolling features', count: 'Clean', color: 'safe' },
  { name: 'Temporal', desc: 'Rate spikes and time-of-day deviation', count: '1 spike', color: 'warn' },
]

const DETECTOR_COLOR = {
  threat: 'text-threat bg-threat/10 border-threat/20',
  warn: 'text-[#FFB300] bg-[#FFB300]/10 border-[#FFB300]/20',
  safe: 'text-safe bg-safe/10 border-safe/20',
}

export default function LogAnalysisSection() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section id="log-analysis" ref={ref} className="py-28 bg-surface-2 overflow-hidden">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left — log viewer mock */}
          <motion.div
            initial={{ opacity: 0, x: -32 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.7 }}
            className="flex flex-col gap-3"
          >
            {/* Log window */}
            <div className="glass border border-white/8 rounded-2xl overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-white/2">
                <FileText className="w-3.5 h-3.5 text-slate-500" strokeWidth={1.5} />
                <span className="text-xs text-slate-400 font-medium">access.log</span>
                <span className="ml-auto text-[10px] text-slate-600 font-mono">Apache · 7 lines</span>
              </div>
              <div className="p-4 font-mono text-[10px] space-y-1.5 max-h-[220px] overflow-hidden">
                {LOG_LINES.map((line, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0 }}
                    animate={inView ? { opacity: 1 } : {}}
                    transition={{ delay: 0.1 + i * 0.07 }}
                    className="flex items-start gap-2"
                  >
                    {line.flag === 'threat' && <AlertCircle className="w-3 h-3 text-threat shrink-0 mt-0.5" strokeWidth={2} />}
                    {line.flag === 'warn' && <Activity className="w-3 h-3 text-[#FFB300] shrink-0 mt-0.5" strokeWidth={2} />}
                    {!line.flag && <CheckCircle className="w-3 h-3 text-slate-700 shrink-0 mt-0.5" strokeWidth={1.5} />}
                    <span className={
                      line.flag === 'threat' ? 'text-threat/80' :
                      line.flag === 'warn' ? 'text-[#FFB300]/80' :
                      'text-slate-600'
                    }>
                      {line.text}
                    </span>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Detector results */}
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
                    <span className="text-[11px] font-semibold text-slate-300">{d.name}</span>
                    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${DETECTOR_COLOR[d.color as keyof typeof DETECTOR_COLOR]}`}>
                      {d.count}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-600 leading-relaxed">{d.desc}</p>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Right content */}
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
              Four detection layers.<br />
              <span className="text-gradient-threat">One API call.</span>
            </h2>

            <p className="text-slate-400 leading-relaxed mb-8">
              Upload any log file — Apache, syslog, Windows Event XML, or generic text — and ThreatOrbit&apos;s async pipeline runs four independent detectors, returning consolidated anomaly reports in seconds.
            </p>

            <div className="space-y-4">
              {[
                { title: 'Multi-format parsers', desc: '4 built-in parsers with extensible architecture. Upload raw bytes or multipart form.' },
                { title: 'Async job model', desc: 'POST /analyse returns immediately. Poll /jobs/{id} or use ?async=false for synchronous mode.' },
                { title: 'Enriched anomaly reports', desc: 'Each finding includes detector name, severity, matched pattern, and line reference.' },
              ].map((item) => (
                <div key={item.title} className="flex gap-4">
                  <div className="w-1 rounded-full bg-gradient-to-b from-violet to-cyan shrink-0" />
                  <div>
                    <h4 className="text-sm font-semibold text-white mb-1">{item.title}</h4>
                    <p className="text-sm text-slate-500 leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* API snippet */}
            <div className="mt-8 glass border border-white/8 rounded-xl p-4 font-mono text-xs text-slate-400">
              <div className="text-slate-600 mb-1"># Analyse a log file</div>
              <div><span className="text-violet">POST</span> /api/analyse</div>
              <div className="text-slate-600">Content-Type: multipart/form-data</div>
              <div className="mt-1"><span className="text-safe">{'{'} "job_id": "b9c3e1...", "anomalies": 3 {'}'}</span></div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
