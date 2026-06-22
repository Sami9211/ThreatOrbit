'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FileText, X, Printer, Download, Loader2, Calendar } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchReport, fetchIncidentReport, createReportSchedule, downloadReport,
         type ReportData, type ReportFinding, type ReportAudience, type ReportFormat } from '@/lib/api'

const SEV_COLOR: Record<string, string> = {
  critical: '#FF2E97', high: '#FF4D6D', medium: '#FFB23E', low: '#34F5C5', info: '#7A3CFF',
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/* Group findings by severity (critical → info) so the report reads by priority
   instead of one flat list - each group gets a header + count. */
function groupFindings(findings: ReportFinding[]): [string, ReportFinding[]][] {
  const groups = new Map<string, ReportFinding[]>()
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase()
    ;(groups.get(s) ?? groups.set(s, []).get(s)!).push(f)
  }
  const known = SEV_ORDER.filter((s) => groups.has(s)).map((s) => [s, groups.get(s)!] as [string, ReportFinding[]])
  const unknown = [...groups.entries()].filter(([s]) => !SEV_ORDER.includes(s)) as [string, ReportFinding[]][]
  return [...known, ...unknown]
}

const PERIODS = [
  { id: 'daily', label: 'Today' },
  { id: 'weekly', label: 'Last 7 days' },
  { id: 'monthly', label: 'Last 30 days' },
  { id: 'custom', label: 'Custom' },
]

/**
 * Generate-Report control + viewer. Drop `<ReportButton kind="siem" />` into
 * any section header. Produces a structured, paginated, print-to-PDF report
 * (Nessus/Acunetix-style) with a period selector - not a CSV dump.
 */
export default function ReportButton({ kind, label, caseId }: { kind: string; label?: string; caseId?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors">
        <FileText className="w-3.5 h-3.5" />
        Report
      </button>
      <AnimatePresence>
        {open && <ReportViewer kind={kind} label={label} caseId={caseId} onClose={() => setOpen(false)} />}
      </AnimatePresence>
    </>
  )
}

function ReportViewer({ kind, label, caseId, onClose }: { kind: string; label?: string; caseId?: string; onClose: () => void }) {
  const [period, setPeriod] = useState('weekly')
  const [audience, setAudience] = useState<ReportAudience>('technical')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [report, setReport] = useState<ReportData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const generate = useCallback(() => {
    setLoading(true)
    setError(null)
    // Incident reports are case-scoped - no period window.
    ;(caseId
      ? fetchIncidentReport(caseId, audience)
      : fetchReport(kind, period, period === 'custom' ? `${from}T00:00:00` : undefined,
          period === 'custom' ? `${to}T23:59:59` : undefined, audience))
      .then(setReport)
      .catch(() => setError('Could not generate the report. Is the dashboard API running?'))
      .finally(() => setLoading(false))
  }, [kind, caseId, period, from, to, audience])

  // Download the current report in a non-JSON format from the backend renderer.
  const dl = (format: ReportFormat) => {
    downloadReport(kind, {
      format, caseId, period, audience,
      from: period === 'custom' ? `${from}T00:00:00` : undefined,
      to: period === 'custom' ? `${to}T23:59:59` : undefined,
    }).catch(() => setError('Could not download the report.'))
  }

  // Generate once on open (and whenever a non-custom period is picked).
  useEffect(() => {
    if (period !== 'custom') generate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [period, audience])

  function downloadHtml() {
    if (!report) return
    const html = renderReportHtml(report)
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threatorbit-${kind}-report-${report.meta.generatedAt.slice(0, 10)}.html`
    a.click()
    URL.revokeObjectURL(url)
  }

  function scheduleReport() {
    const cadence = window.prompt('Deliver this report automatically - type "daily" or "weekly":', period === 'daily' ? 'daily' : 'weekly')
    if (!cadence || !['daily', 'weekly'].includes(cadence)) return
    const url = window.prompt('Webhook URL to deliver to (optional - leave blank to just record on the platform):', '') || undefined
    createReportSchedule({ kind, period, cadence, webhook_url: url })
      .then(() => setError(null))
      .catch(() => setError('Could not create the schedule.'))
  }

  function printReport() {
    if (!report) return
    const w = window.open('', '_blank')
    if (!w) return
    w.document.write(renderReportHtml(report))
    w.document.close()
    w.focus()
    setTimeout(() => w.print(), 350)
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 sm:p-8" onClick={onClose}>
      <motion.div initial={{ scale: 0.97, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.97, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-3xl h-full max-h-[90vh] rounded-2xl border border-white/10 bg-surface flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="flex items-center gap-2 px-5 py-3 border-b border-white/8 shrink-0 flex-wrap">
          <FileText className="w-4 h-4 text-magenta" />
          <h2 className="text-sm font-semibold text-white">{label ?? kind} Report</h2>
          {/* Audience: reshapes depth/framing (Technical full, Executive compact,
              Compliance adds a control-mapping section). */}
          <div className="flex items-center gap-0.5 rounded-md bg-surface-2 border border-white/8 p-0.5" title="Report audience">
            {(['technical', 'executive', 'compliance'] as ReportAudience[]).map((a) => (
              <button key={a} onClick={() => setAudience(a)}
                className={cn('px-2 py-0.5 rounded text-[10px] font-medium capitalize transition-colors',
                  audience === a ? 'bg-magenta/20 text-magenta' : 'text-ink-500 hover:text-ink-200')}>
                {a}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1 ml-auto flex-wrap">
            {!caseId && PERIODS.map((p) => (
              <button key={p.id} onClick={() => setPeriod(p.id)}
                className={cn('px-2 py-1 rounded-md text-[11px] font-medium transition-colors',
                  period === p.id ? 'bg-magenta/15 text-magenta border border-magenta/30' : 'text-ink-500 hover:text-ink-200 border border-transparent')}>
                {p.label}
              </button>
            ))}
            {period === 'custom' && (
              <>
                <input type="date" value={from} onChange={(e) => setFrom(e.target.value)}
                  className="px-2 py-1 rounded-md bg-surface-2 border border-white/8 text-[11px] text-ink-200" />
                <input type="date" value={to} onChange={(e) => setTo(e.target.value)}
                  className="px-2 py-1 rounded-md bg-surface-2 border border-white/8 text-[11px] text-ink-200" />
              </>
            )}
            <button onClick={generate} disabled={loading || (period === 'custom' && !from)}
              className="px-2.5 py-1 rounded-md text-[11px] font-semibold bg-plasma text-white hover:shadow-magenta-sm transition-all disabled:opacity-50">
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Generate'}
            </button>
          </div>
          <div className="flex items-center gap-1">
            {!caseId && (
            <button onClick={scheduleReport} title="Schedule this report (daily/weekly)"
              className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors"><Calendar className="w-4 h-4" /></button>
            )}
            <button onClick={printReport} disabled={!report} title="Print / Save as PDF"
              className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-40"><Printer className="w-4 h-4" /></button>
            <button onClick={downloadHtml} disabled={!report} title="Download HTML"
              className="p-1.5 rounded-lg text-ink-400 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-40"><Download className="w-4 h-4" /></button>
            {/* Other formats straight from the backend renderer. */}
            {(['csv', 'markdown', 'json'] as ReportFormat[]).map((f) => (
              <button key={f} onClick={() => dl(f)} disabled={!report} title={`Download ${f.toUpperCase()}`}
                className="px-1.5 py-1 rounded-lg text-[10px] font-semibold uppercase text-ink-400 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-40">
                {f === 'markdown' ? 'MD' : f}
              </button>
            ))}
            <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5"><X className="w-4 h-4" /></button>
          </div>
        </div>

        {/* Report body */}
        <div className="flex-1 overflow-y-auto bg-[#0b0713]">
          {loading && <p className="text-xs text-ink-600 py-16 text-center animate-pulse">Generating report…</p>}
          {error && <p className="text-xs text-threat py-16 text-center">{error}</p>}
          {report && !loading && <ReportBody report={report} />}
        </div>
      </motion.div>
    </motion.div>
  )
}

function ReportBody({ report }: { report: ReportData }) {
  const maxBar = Math.max(1, ...report.breakdowns.flatMap((b) => b.data.map((d) => d.count)))
  return (
    <div className="p-6 sm:p-8 max-w-2xl mx-auto space-y-7 text-ink-200">
      {/* Cover */}
      <div className="border-b border-white/10 pb-5">
        <div className="flex items-center gap-2 text-[10px] text-magenta uppercase tracking-widest font-semibold mb-1">
          <Calendar className="w-3 h-3" /> {report.meta.period}
        </div>
        <h1 className="font-display text-2xl font-bold text-white">{report.meta.title}</h1>
        <p className="text-[11px] text-ink-500 mt-1">
          Generated {new Date(report.meta.generatedAt).toLocaleString()} · ThreatOrbit
        </p>
      </div>

      {/* Executive summary */}
      <section>
        <h2 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">Executive Summary</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
          {report.summary.headline.map((h, i) => (
            <div key={i} className="px-3 py-2.5 rounded-lg bg-surface-2/60 border border-white/8">
              <div className="text-lg font-bold font-mono" style={{ color: h.color ?? '#fff' }}>{h.value}</div>
              <div className="text-[10px] text-ink-500">{h.label}</div>
            </div>
          ))}
        </div>
        <p className="text-xs text-ink-300 leading-relaxed">{report.summary.narrative}</p>
      </section>

      {/* Breakdowns */}
      {report.breakdowns.map((b, bi) => (
        <section key={bi}>
          <h2 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">{b.heading}</h2>
          <div className="space-y-1.5">
            {b.data.map((d, di) => {
              const color = d.color ?? SEV_COLOR[d.severity ?? ''] ?? '#7A3CFF'
              return (
                <div key={di} className="flex items-center gap-2">
                  <span className="text-[11px] text-ink-400 w-32 truncate capitalize">{d.severity ?? d.label}</span>
                  <div className="flex-1 h-3 rounded bg-white/5 overflow-hidden">
                    <div className="h-full rounded" style={{ width: `${(d.count / maxBar) * 100}%`, background: color }} />
                  </div>
                  <span className="text-[11px] font-mono text-ink-300 w-8 text-right">{d.count}</span>
                </div>
              )
            })}
          </div>
        </section>
      ))}

      {/* Detailed findings */}
      <section>
        <h2 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">
          Detailed Findings <span className="text-ink-600">({report.findings.length})</span>
        </h2>
        <div className="space-y-4">
          {report.findings.length === 0 && <p className="text-xs text-ink-600">No findings in this window.</p>}
          {groupFindings(report.findings).map(([sev, items]) => (
            <div key={sev} className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: SEV_COLOR[sev] ?? '#7A3CFF' }} />
                <h3 className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: SEV_COLOR[sev] ?? '#7A3CFF' }}>{sev}</h3>
                <span className="text-[10px] text-ink-600">({items.length})</span>
                <div className="flex-1 h-px bg-white/5" />
              </div>
              {items.map((f, i) => (
                <div key={i} className="rounded-lg border border-white/8 bg-surface-2/40 p-3">
                  <div className="flex items-start gap-2">
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0 mt-0.5"
                      style={{ color: SEV_COLOR[f.severity] ?? '#7A3CFF', background: `${SEV_COLOR[f.severity] ?? '#7A3CFF'}18` }}>
                      {f.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-white">{f.title}</p>
                      <p className="text-[10px] text-ink-500 mt-0.5">
                        {[f.entity, f.technique, f.tactic, f.rule, f.status].filter(Boolean).join(' · ')}
                        {f.ts ? ` · ${new Date(f.ts).toLocaleString()}` : ''}
                      </p>
                      {f.detail && <p className="text-[10px] text-ink-400 mt-1 leading-snug">{f.detail}</p>}
                    </div>
                    {typeof f.score === 'number' && f.score > 0 && (
                      <span className="text-[11px] font-mono text-ink-300 shrink-0">{f.score}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </section>

      {/* Control mapping (compliance audience only) */}
      {report.compliance && report.compliance.length > 0 && (
        <section>
          <h2 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">Control Mapping</h2>
          <div className="space-y-1.5">
            {report.compliance.map((c, i) => (
              <div key={i} className="flex items-center justify-between gap-3 rounded-lg border border-white/8 bg-surface-2/40 px-3 py-2">
                <span className="text-xs text-ink-200">{c.control}</span>
                <span className="text-[10px] text-ink-500 font-mono text-right">{c.framework}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Recommendations */}
      <section>
        <h2 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">Recommendations</h2>
        <ul className="space-y-1.5">
          {report.recommendations.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-xs text-ink-300">
              <span className="text-magenta mt-0.5">▸</span>{r}
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}

/* Self-contained printable HTML (light theme for paper / PDF). */
function renderReportHtml(report: ReportData): string {
  const esc = (s: unknown) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!))
  const maxBar = Math.max(1, ...report.breakdowns.flatMap((b) => b.data.map((d) => d.count)))
  const head = (h: { label: string; value: number | string; color?: string }) =>
    `<div class="kpi"><div class="kv" style="color:${h.color ?? '#111'}">${esc(h.value)}</div><div class="kl">${esc(h.label)}</div></div>`
  const bar = (d: { label?: string; severity?: string; count: number; color?: string }) =>
    `<div class="row"><span class="rl">${esc(d.severity ?? d.label)}</span><span class="rb"><i style="width:${(d.count / maxBar) * 100}%;background:${d.color ?? SEV_COLOR[d.severity ?? ''] ?? '#7A3CFF'}"></i></span><span class="rc">${d.count}</span></div>`
  const finding = (f: ReportFinding) =>
    `<div class="finding"><span class="sev" style="color:${SEV_COLOR[f.severity] ?? '#555'};background:${(SEV_COLOR[f.severity] ?? '#555')}1a">${esc(f.severity)}</span>
     <div><div class="ft">${esc(f.title)}</div><div class="fm">${[f.entity, f.technique, f.tactic, f.rule, f.status].filter(Boolean).map(esc).join(' · ')}${f.ts ? ' · ' + esc(new Date(f.ts).toLocaleString()) : ''}</div>${f.detail ? `<div class="fd">${esc(f.detail)}</div>` : ''}</div></div>`
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(report.meta.title)}</title>
<style>
  *{box-sizing:border-box} body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:820px;margin:0 auto;padding:40px;line-height:1.5}
  h1{font-size:26px;margin:4px 0} h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#444;border-bottom:1px solid #ddd;padding-bottom:6px;margin:28px 0 12px}
  .period{color:#c0117a;font-size:11px;text-transform:uppercase;letter-spacing:.1em;font-weight:600}
  .meta{color:#888;font-size:11px;margin-top:4px} .narr{font-size:13px;color:#333}
  .kpis{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0} .kpi{flex:1;min-width:120px;border:1px solid #e3e3e3;border-radius:8px;padding:10px 12px}
  .kv{font-size:22px;font-weight:700;font-family:ui-monospace,monospace} .kl{font-size:11px;color:#777}
  .row{display:flex;align-items:center;gap:8px;margin:4px 0} .rl{width:150px;font-size:12px;color:#555;text-transform:capitalize} .rb{flex:1;height:12px;background:#eee;border-radius:6px;overflow:hidden} .rb i{display:block;height:100%} .rc{width:34px;text-align:right;font-size:12px;font-family:ui-monospace,monospace;color:#444}
  .finding{display:flex;gap:10px;border:1px solid #e8e8e8;border-radius:8px;padding:10px;margin:6px 0} .sev{font-size:9px;font-weight:700;text-transform:uppercase;padding:2px 6px;border-radius:4px;height:fit-content}
  .ft{font-size:13px;font-weight:600} .fm{font-size:11px;color:#888;margin-top:2px} .fd{font-size:11px;color:#555;margin-top:4px}
  .sevh{font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:700;margin:16px 0 6px} .sevh span{color:#aaa;font-weight:500}
  ul{padding-left:18px} li{font-size:13px;margin:4px 0}
  @media print{body{padding:20px}}
</style></head><body>
  <div class="period">${esc(report.meta.period)}</div>
  <h1>${esc(report.meta.title)}</h1>
  <div class="meta">${report.meta.audience ? esc(report.meta.audience[0].toUpperCase() + report.meta.audience.slice(1)) + ' audience · ' : ''}Generated ${esc(new Date(report.meta.generatedAt).toLocaleString())} · ThreatOrbit</div>
  <h2>Executive Summary</h2>
  <div class="kpis">${report.summary.headline.map(head).join('')}</div>
  <p class="narr">${esc(report.summary.narrative)}</p>
  ${report.breakdowns.map((b) => `<h2>${esc(b.heading)}</h2>${b.data.map(bar).join('')}`).join('')}
  ${report.compliance && report.compliance.length ? `<h2>Control Mapping</h2>${report.compliance.map((c) => `<div class="row"><span class="rl" style="width:auto;flex:1">${esc(c.control)}</span><span style="font-size:11px;color:#888">${esc(c.framework)}</span></div>`).join('')}` : ''}
  <h2>Detailed Findings (${report.findings.length})</h2>
  ${report.findings.length === 0
    ? '<p style="font-size:12px;color:#888">No findings in this window.</p>'
    : groupFindings(report.findings).map(([sev, items]) =>
        `<h3 class="sevh" style="color:${SEV_COLOR[sev] ?? '#555'}">${esc(sev)} <span>(${items.length})</span></h3>${items.map(finding).join('')}`
      ).join('')}
  <h2>Recommendations</h2>
  <ul>${report.recommendations.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
</body></html>`
}
