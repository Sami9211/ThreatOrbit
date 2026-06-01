import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'
import { Activity, Layers, Brain, Clock, BarChart2, FileText, Zap, ArrowRight } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Log Analysis · ThreatOrbit Platform',
  description: 'Four-layer anomaly detection for Apache, syslog, Windows Event, and generic logs. Pattern, statistical, ML, and temporal engines in one pipeline.',
}

const DETECTORS = [
  {
    name: 'Pattern Matching',
    icon: Layers,
    color: '#FF2E97',
    desc: 'Regex-based ruleset scanning for known-bad signatures: shell injection, SQL injection patterns, privilege escalation commands, suspicious user agents, and exfiltration indicators.',
    detail: 'Rules are loaded from a configurable YAML file so you can add site-specific patterns without code changes. Matches include the rule name, matched text, and line offset.',
  },
  {
    name: 'Statistical Baseline',
    icon: BarChart2,
    color: '#7A3CFF',
    desc: 'Rolling mean and standard deviation over a configurable time window. Lines whose metrics exceed the Z-score threshold are flagged as statistical anomalies.',
    detail: 'Baseline is built from the first N lines of each batch (configurable via BASELINE_WINDOW). Useful for detecting volume spikes: a sudden burst of 4xx errors, runaway process writing logs, or DDoS traffic.',
  },
  {
    name: 'ML Anomaly Score',
    icon: Brain,
    color: '#FFB23E',
    desc: 'scikit-learn IsolationForest trained on feature vectors extracted from each log line. Lines with anomaly scores below the contamination threshold are flagged.',
    detail: 'Features include: token count, numeric token ratio, special-character density, HTTP status code class, response size bucket, and hour-of-day. The model is retrained on each batch so it adapts to your log patterns over time.',
  },
  {
    name: 'Temporal Correlation',
    icon: Clock,
    color: '#2DD4BF',
    desc: 'Detects burst events that look normal in isolation but form anomalous clusters in time. Uses a sliding window to count event frequency per source IP, path, or user.',
    detail: 'A single 404 is noise; 200 in 10 seconds from the same IP is a directory scan. Temporal correlation catches the latter. Window size and threshold are configurable per log format.',
  },
]

const FORMATS = [
  { name: 'Apache / Nginx',   sample: '192.168.1.1 - - [01/Jun/2025:12:00:00] "GET /admin HTTP/1.1" 403 256' },
  { name: 'Syslog',           sample: 'Jun  1 12:00:00 host kernel: [12345.678] iptables DROP IN=eth0' },
  { name: 'Windows Event XML',sample: '<Event xmlns="..."><System><EventID>4625</EventID>...</System></Event>' },
  { name: 'Generic / Custom', sample: '2025-06-01T12:00:00Z WARN  service=auth user=bob msg="failed login"' },
]

export default function LogAnalysisPage() {
  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-white/5 bg-bg/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo size={22} />
            <span className="font-display font-semibold text-sm">
              <span className="text-white">Threat</span>
              <span className="text-gradient-magenta">Orbit</span>
            </span>
          </Link>
          <Link href="/" className="text-xs text-ink-400 hover:text-white transition-colors">Back to site</Link>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-16 space-y-20">
        {/* Hero */}
        <section>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-violet/20 bg-violet/5 mb-6">
            <Activity className="w-3 h-3 text-violet" />
            <span className="text-xs text-violet tracking-wide">SIEM · Log Analysis</span>
          </div>
          <h1 className="font-display text-5xl md:text-6xl font-bold text-white leading-tight mb-6">
            Four detectors.<br />
            <span className="text-gradient-magenta">One anomaly score.</span>
          </h1>
          <p className="text-xl text-ink-300 max-w-2xl leading-relaxed mb-8">
            ThreatOrbit&apos;s log analysis pipeline runs pattern matching, statistical baseline,
            machine learning, and temporal correlation in parallel — consolidating all four verdicts
            into a single severity score per line.
          </p>
          <div className="flex gap-4 flex-wrap">
            <Link href="/docs/rest-api" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-violet/15 border border-violet/25 text-violet text-sm font-medium hover:bg-violet/25 transition-colors">
              API Reference <ArrowRight className="w-4 h-4" />
            </Link>
            <Link href="/docs/quick-start" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl glass border border-white/10 text-ink-200 text-sm hover:border-white/25 transition-colors">
              Quick Start
            </Link>
          </div>
        </section>

        {/* Detectors */}
        <section>
          <h2 className="font-display text-3xl font-bold text-white mb-2">Detection engines</h2>
          <p className="text-ink-400 mb-8">Each engine runs independently and contributes to the final anomaly report.</p>
          <div className="grid md:grid-cols-2 gap-5">
            {DETECTORS.map(({ name, icon: Icon, color, desc, detail }) => (
              <div key={name} className="rounded-2xl glass border border-white/6 p-6 hover:border-white/12 transition-colors">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-xl flex items-center justify-center border"
                    style={{ color, backgroundColor: `${color}1a`, borderColor: `${color}33` }}>
                    <Icon className="w-5 h-5" strokeWidth={1.5} />
                  </div>
                  <h3 className="font-display font-semibold text-white">{name}</h3>
                </div>
                <p className="text-sm text-ink-300 leading-relaxed mb-3">{desc}</p>
                <p className="text-xs text-ink-500 leading-relaxed">{detail}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Log Formats */}
        <section>
          <h2 className="font-display text-3xl font-bold text-white mb-2">Supported log formats</h2>
          <p className="text-ink-400 mb-8">Format is auto-detected from the first 10 lines — no configuration needed.</p>
          <div className="space-y-3">
            {FORMATS.map(({ name, sample }) => (
              <div key={name} className="rounded-xl border border-white/6 bg-white/2 p-4">
                <p className="text-xs font-semibold text-ink-300 mb-2">{name}</p>
                <pre className="text-[11px] font-mono text-ink-500 overflow-x-auto">{sample}</pre>
              </div>
            ))}
          </div>
        </section>

        {/* Pipeline */}
        <section>
          <h2 className="font-display text-3xl font-bold text-white mb-8">How the pipeline works</h2>
          <div className="space-y-4">
            {[
              { step: '01', title: 'Submit logs', icon: FileText,  color: '#FF2E97', desc: 'POST /analyze with raw log content (text/plain or application/json). The endpoint auto-detects format and returns a job_id immediately.' },
              { step: '02', title: 'Parse and tokenise', icon: Layers, color: '#7A3CFF', desc: 'Each line is split into structured fields. Apache logs yield method, path, status, bytes; syslog yields facility, severity, process; and so on.' },
              { step: '03', title: 'Run four detectors', icon: Brain,   color: '#FFB23E', desc: 'Pattern, statistical, ML, and temporal engines run concurrently on the parsed data. Each produces a per-line score and a list of matched evidence.' },
              { step: '04', title: 'Merge scores', icon: Activity, color: '#2DD4BF', desc: 'Scores from all four engines are combined with configurable weights into a final severity (0.0–1.0). Lines above the threshold are included in the anomaly report.' },
              { step: '05', title: 'Generate report', icon: Zap,      color: '#FF2E97', desc: 'An HTML report is generated with a severity timeline, top anomalous lines, detector breakdowns, and trend charts. Download via GET /report/{job_id}.' },
            ].map(({ step, title, icon: Icon, color, desc }) => (
              <div key={step} className="flex gap-5 items-start">
                <div className="shrink-0 w-10 h-10 rounded-full flex items-center justify-center border font-mono text-sm font-bold"
                  style={{ color, borderColor: `${color}33`, backgroundColor: `${color}0f` }}>
                  {step}
                </div>
                <div className="pt-2">
                  <div className="flex items-center gap-2 mb-1">
                    <Icon className="w-4 h-4" style={{ color }} strokeWidth={1.5} />
                    <span className="font-display font-semibold text-white">{title}</span>
                  </div>
                  <p className="text-sm text-ink-400 leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="rounded-3xl border border-violet/15 bg-violet/5 p-10 text-center">
          <h2 className="font-display text-3xl font-bold text-white mb-3">Ready to analyse your logs?</h2>
          <p className="text-ink-400 mb-6 max-w-xl mx-auto">Start with Docker Compose and send your first log batch in minutes.</p>
          <div className="flex gap-4 justify-center flex-wrap">
            <Link href="/docs/quick-start" className="px-6 py-3 rounded-xl bg-violet/20 border border-violet/30 text-violet font-semibold text-sm hover:bg-violet/30 transition-colors">
              Quick Start guide
            </Link>
            <Link href="/#contact" className="px-6 py-3 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:border-white/25 transition-colors">
              Talk to sales
            </Link>
          </div>
        </section>
      </main>
    </div>
  )
}
