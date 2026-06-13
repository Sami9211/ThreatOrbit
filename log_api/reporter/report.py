from datetime import datetime
from typing import List
from log_api.models import AnalysisResult, AnomalyFinding

SEVERITY_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fca5a5"),
    "HIGH": ("#78350f", "#fcd34d"),
    "MEDIUM": ("#1e3a5f", "#93c5fd"),
    "LOW": ("#14532d", "#86efac"),
    "INFO": ("#374151", "#d1d5db"),
}

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}


def generate_html_report(result: AnalysisResult, output_path: str) -> str:
    html = _build_html(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _build_html(result: AnalysisResult) -> str:
    findings_html = "".join(_finding_card(f, i) for i, f in enumerate(result.findings))
    summary = result.summary
    total_findings = sum(summary.values())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ThreatOrbit Log Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;}}
.card{{background:#1e293b;border:1px solid #475569;border-radius:8px;padding:1rem;margin-bottom:1rem;}}
.badge{{padding:0.2rem 0.5rem;border-radius:4px;font-size:0.8rem;}}
.meta{{color:#94a3b8;font-size:0.9rem;}}
code{{display:block;background:#0a0a0a;padding:0.5rem;border-radius:4px;margin-top:0.5rem;white-space:pre-wrap;}}
</style>
</head>
<body>
<h1>🛡️ Log Anomaly Detection Report</h1>
<p class="meta">Generated: {result.analysed_at.strftime('%Y-%m-%d %H:%M:%S UTC')} | Format: {result.log_format} | Findings: {total_findings}</p>
{findings_html if findings_html else "<div class='card'>✅ No anomalies detected.</div>"}
</body>
</html>"""


def _finding_card(f: AnomalyFinding, idx: int) -> str:
    sev = f.severity.value
    fg, bg = SEVERITY_COLORS.get(sev, ("#374151", "#d1d5db"))
    emoji = SEVERITY_EMOJI.get(sev, "⚪")

    mitre_html = " ".join(
        f"<a href='{t.url}' target='_blank' style='color:#818cf8'>{t.technique_id} {t.technique_name}</a>"
        for t in f.mitre_tags
    )
    evidence = "".join(f"<code>{_esc(e)}</code>" for e in f.evidence[:5])

    # User-controlled fields (source_ip, username come from parsed logs) are
    # escaped so a crafted log line can't inject HTML/script into the report.
    meta = []
    if f.source_ip:
        meta.append(f"IP: {_esc(str(f.source_ip))}")
    if f.username:
        meta.append(f"User: {_esc(str(f.username))}")
    if f.timestamp:
        meta.append(f"Time: {f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    meta.append(f"Detector: {_esc(str(f.detector))}")
    meta.append(f"Count: {f.count}")

    return f"""
<div class="card">
  <div><span class="badge" style="background:{bg};color:{fg}">{emoji} {sev}</span> <strong>{_esc(str(f.finding_type))}</strong> (Score: {f.severity_score}/100)</div>
  <p>{_esc(f.description)}</p>
  <p class="meta">{' | '.join(meta)}</p>
  <p>{mitre_html}</p>
  {evidence}
</div>
"""


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))
