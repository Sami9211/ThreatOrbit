import type { Metadata } from 'next'
import Link from 'next/link'
import Logo from '@/components/ui/Logo'

export const metadata: Metadata = {
  title: 'SIEM + SOAR · ThreatOrbit',
  description:
    'Four-engine detection and automated STIX response. Pattern matching, statistical baselines, ML IsolationForest, and temporal correlation - all in one async pipeline.',
}

const engines = [
  {
    tag: 'Pattern',
    title: 'Signature Matching',
    desc: 'Every log line is matched against the live CTI library. IP addresses, domains, URLs, and hashes are extracted and checked against known-bad indicators with configurable trust-score thresholds.',
    color: '#FF2E97',
  },
  {
    tag: 'Statistical',
    title: 'Baseline Deviation',
    desc: 'Rolling mean and standard deviation are computed per source IP and endpoint. Events exceeding N standard deviations from the established baseline trigger a statistical anomaly alert.',
    color: '#7A3CFF',
  },
  {
    tag: 'ML',
    title: 'IsolationForest',
    desc: 'A scikit-learn IsolationForest model is trained on historical feature vectors (bytes, status code, method, hour-of-day). Low anomaly scores flag behavioural outliers without manual rule authoring.',
    color: '#FFB23E',
  },
  {
    tag: 'Temporal',
    title: 'Correlation Engine',
    desc: 'Events are bucketed into configurable time windows. Spike detection triggers when the request rate, error rate, or unique-IP count deviates beyond a rolling Z-score threshold within the window.',
    color: '#2DD4BF',
  },
]

const formats = [
  { name: 'Apache / Nginx', detail: 'Combined Log Format - parsed with named-group regex; extracts IP, method, URI, status, bytes, user-agent.' },
  { name: 'Syslog (RFC 5424)', detail: 'Facility, severity, hostname, process, and structured-data parsed from both IETF and BSD syslog variants.' },
  { name: 'Windows Event Log', detail: 'JSON-exported Event Log records; maps EventID, Channel, Computer, User, and TimeCreated fields.' },
  { name: 'Generic JSON', detail: 'Any newline-delimited JSON log stream. Field mapping is configurable per-source so custom schemas work without code changes.' },
]

const steps = [
  { n: '01', title: 'Submit', body: 'POST log data as raw text, a file upload, or a streaming JSON body to the Log API on port 8001. The API returns a job ID immediately.' },
  { n: '02', title: 'Parse', body: 'The async worker auto-detects the log format using header signatures and field patterns, then parses each line into a normalised event record.' },
  { n: '03', title: 'Detect', body: 'All four detection engines run concurrently over the event set. Each engine emits scored anomaly objects with severity (LOW / MEDIUM / HIGH / CRITICAL).' },
  { n: '04', title: 'Score', body: 'Engine outputs are merged and deduplicated. A composite severity is assigned based on the highest engine score and the number of corroborating signals.' },
  { n: '05', title: 'Report', body: 'An HTML report is generated containing executive summary, per-engine findings, and raw evidence. The report is stored and retrievable via GET /jobs/{id}/report.' },
  { n: '06', title: 'Respond', body: 'CRITICAL and HIGH findings are wrapped in a STIX 2.1 Incident bundle and pushed to OpenCTI automatically, closing the loop without analyst intervention.' },
]

export default function SIEMSOARPage() {
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

      <main className="max-w-5xl mx-auto px-6 py-16">
        {/* Hero */}
        <div className="mb-16 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-violet/20 bg-violet/5 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-violet" />
            <span className="text-xs text-violet tracking-wide font-medium">Product · SIEM + SOAR</span>
          </div>
          <h1 className="font-display text-5xl font-bold text-white mb-5 leading-tight">
            Detect, score, respond -{' '}
            <span className="text-gradient-magenta">automatically</span>
          </h1>
          <p className="text-lg text-ink-400 leading-relaxed">
            ThreatOrbit’s SIEM+SOAR layer runs four complementary detection engines over any log
            format in a single async job. Pattern matching catches known IOCs, statistical analysis
            spots baseline deviations, ML IsolationForest surfaces behavioural outliers, and
            temporal correlation detects coordinated multi-event attacks - all without manual rule
            tuning. Confirmed findings trigger automatic STIX 2.1 response pushed to OpenCTI.
          </p>
        </div>

        {/* Detection Engines */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">Four Detection Engines</h2>
          <p className="text-sm text-ink-500 mb-8">Each engine is independent, scores anomalies separately, and outputs are merged into a unified severity.</p>
          <div className="grid sm:grid-cols-2 gap-4">
            {engines.map(({ tag, title, desc, color }) => (
              <div key={tag} className="rounded-2xl border border-white/6 p-5 glass">
                <div className="flex items-center gap-2.5 mb-3">
                  <span
                    className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-full border"
                    style={{ color, backgroundColor: `${color}18`, borderColor: `${color}33` }}
                  >
                    {tag}
                  </span>
                  <h3 className="font-display font-semibold text-white text-sm">{title}</h3>
                </div>
                <p className="text-[13px] text-ink-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Log Formats */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">Supported Log Formats</h2>
          <p className="text-sm text-ink-500 mb-6">Auto-detected on submit - no format flag required.</p>
          <div className="space-y-2">
            {formats.map(({ name, detail }) => (
              <div key={name} className="flex gap-4 rounded-xl border border-white/5 bg-white/2 px-5 py-4 text-[13px]">
                <span className="font-mono text-magenta w-44 shrink-0 font-medium">{name}</span>
                <span className="text-ink-400 leading-relaxed">{detail}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Async Pipeline */}
        <div className="mb-16">
          <h2 className="font-display text-2xl font-bold text-white mb-2">Async Analysis Pipeline</h2>
          <p className="text-sm text-ink-500 mb-8">Submit once, poll or stream for progress. Large log files never block the API.</p>
          <div className="space-y-0">
            {steps.map(({ n, title, body }, i) => (
              <div key={n} className="flex gap-5">
                <div className="flex flex-col items-center">
                  <div className="w-9 h-9 rounded-xl border border-violet/30 bg-violet/5 flex items-center justify-center shrink-0">
                    <span className="text-[11px] font-mono font-bold text-violet">{n}</span>
                  </div>
                  {i < steps.length - 1 && <div className="w-px flex-1 my-1 bg-white/5" />}
                </div>
                <div className="pb-8">
                  <h3 className="font-display font-semibold text-white text-sm mb-1">{title}</h3>
                  <p className="text-[13px] text-ink-400 leading-relaxed">{body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Technical Specs */}
        <div className="glass rounded-2xl border border-white/6 p-6 mb-16">
          <h2 className="font-display text-lg font-bold text-white mb-4">Technical Specifications</h2>
          <div className="grid sm:grid-cols-2 gap-x-10 gap-y-3">
            {[
              ['Detection engines', '4 - Pattern, Statistical, ML, Temporal'],
              ['ML model', 'scikit-learn IsolationForest (auto-trained)'],
              ['Log API port', ':8001 (independent from Threat API :8000)'],
              ['Job model', 'Async - non-blocking submit, poll /jobs/{id}'],
              ['Streaming', 'Server-sent events on /jobs/{id}/stream'],
              ['Report output', 'HTML report + JSON findings per job'],
              ['SOAR output', 'STIX 2.1 Incident bundle → OpenCTI push'],
              ['Severity levels', 'LOW · MEDIUM · HIGH · CRITICAL'],
            ].map(([k, v]) => (
              <div key={k} className="flex gap-3 text-[13px]">
                <span className="text-ink-500 w-36 shrink-0">{k}</span>
                <span className="text-ink-300">{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="text-center rounded-2xl border border-violet/20 bg-violet/5 p-10">
          <h2 className="font-display text-2xl font-bold text-white mb-3">
            Stop tuning rules. Start detecting.
          </h2>
          <p className="text-sm text-ink-400 mb-6 max-w-md mx-auto">
            Drop in any log file and get anomaly-scored, STIX-wrapped findings in minutes.
          </p>
          <Link
            href="/#contact"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-magenta text-white text-sm font-semibold hover:bg-magenta/90 transition-colors"
          >
            Get early access
          </Link>
        </div>
      </main>
    </div>
  )
}
