"""Render a structured report dict (see reports.py) into downloadable formats.

Mature vuln-assessment tools export the same assessment in several shapes for
several readers. This module turns one report dict into:

  * JSON      - the raw structured document (machine-readable / integrations)
  * CSV       - the findings table, for spreadsheet pivoting
  * Markdown  - compact, readable, version-controllable
  * HTML      - a self-contained, print-friendly document

Dependency-light on purpose: stdlib ``csv`` + string templating, no PDF engine
or template library. (PDF stays browser-side print-to-PDF of the HTML.) All
user-derived text is HTML-escaped in the HTML renderer - report content
includes alert titles, hostnames, etc. that must never inject markup.
"""
from __future__ import annotations

import csv
import io
import json
from html import escape

# Preferred CSV/finding column order; any extra keys are appended after these.
_FINDING_COLS = ["severity", "score", "cvss", "title", "entity", "asset",
                 "status", "technique", "tactic", "rule", "ts", "detail"]


def _finding_columns(findings: list[dict]) -> list[str]:
    cols = [c for c in _FINDING_COLS if any(c in f for f in findings)]
    for f in findings:
        for k in f:
            if k not in cols:
                cols.append(k)
    return cols


def to_csv(report: dict) -> str:
    """The findings table (what analysts pivot on in a spreadsheet)."""
    findings = report.get("findings", []) or []
    out = io.StringIO()
    if not findings:
        out.write("severity,title\n")
        return out.getvalue()
    cols = _finding_columns(findings)
    writer = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow({k: f.get(k, "") for k in cols})
    return out.getvalue()


def _md_cell(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict) -> str:
    meta = report.get("meta", {})
    summary = report.get("summary", {})
    out: list[str] = []
    out.append(f"# {meta.get('title', 'Report')}")
    aud = f" · {meta['audience'].title()} audience" if meta.get("audience") else ""
    out.append(f"_{meta.get('period', '')}{aud} · generated {meta.get('generatedAt', '')}_\n")

    hl = summary.get("headline", [])
    if hl:
        out.append("| Metric | Value |")
        out.append("|---|---|")
        out += [f"| {_md_cell(h.get('label', ''))} | {_md_cell(h.get('value', ''))} |" for h in hl]
        out.append("")
    if summary.get("narrative"):
        out.append("## Summary")
        out.append(summary["narrative"] + "\n")

    for b in report.get("breakdowns", []) or []:
        out.append(f"### {b.get('heading', '')}")
        out.append("| Item | Count |")
        out.append("|---|---|")
        for d in b.get("data", []):
            out.append(f"| {_md_cell(d.get('label') or d.get('severity') or '')} | {_md_cell(d.get('count', ''))} |")
        out.append("")

    comp = report.get("compliance")
    if comp:
        out.append("## Control mapping")
        out.append("| Control | Framework |")
        out.append("|---|---|")
        out += [f"| {_md_cell(c.get('control', ''))} | {_md_cell(c.get('framework', ''))} |" for c in comp]
        out.append("")

    findings = report.get("findings", []) or []
    if findings:
        out.append(f"## Findings ({len(findings)})")
        out.append("| Severity | Title | Score | Entity | Status |")
        out.append("|---|---|---|---|---|")
        for f in findings:
            out.append(
                f"| {_md_cell(f.get('severity', ''))} | {_md_cell(f.get('title', ''))} "
                f"| {_md_cell(f.get('score', f.get('cvss', '')))} "
                f"| {_md_cell(f.get('entity', f.get('asset', '')))} | {_md_cell(f.get('status', ''))} |")
        out.append("")

    recs = report.get("recommendations", []) or []
    if recs:
        out.append("## Recommendations")
        out += [f"- {r}" for r in recs]
        out.append("")
    return "\n".join(out)


_HTML_CSS = """
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:900px;margin:24px auto;padding:0 20px}
h1{font-size:22px;margin:0 0 2px}
.sub{color:#666;margin:0 0 18px;font-size:12px}
h2{font-size:16px;margin:22px 0 8px;border-bottom:1px solid #eee;padding-bottom:4px}
h3{font-size:13px;margin:14px 0 6px;color:#444}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 4px}
.kpi{border:1px solid #eee;border-radius:8px;padding:10px 14px;min-width:110px}
.kpi .v{font-size:20px;font-weight:700}
.kpi .l{font-size:11px;color:#666}
table{border-collapse:collapse;width:100%;margin:4px 0 10px;font-size:12px}
th,td{border:1px solid #eee;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#fafafa}
.sev{font-weight:700;text-transform:uppercase;font-size:10px}
.sev-critical{color:#c1124e}.sev-high{color:#d33}.sev-medium{color:#b8860b}.sev-low{color:#1a8a6a}.sev-info{color:#5a4ad1}
ol,ul{margin:4px 0;padding-left:20px}
@media print{body{margin:0;max-width:none}}
""".strip()


def to_html(report: dict) -> str:
    meta = report.get("meta", {})
    summary = report.get("summary", {})
    e = lambda v: escape(str(v))  # noqa: E731 - tiny local alias
    parts: list[str] = []
    parts.append(f"<h1>{e(meta.get('title', 'Report'))}</h1>")
    aud = f" · {e(meta['audience'].title())} audience" if meta.get("audience") else ""
    parts.append(f"<p class='sub'>{e(meta.get('period', ''))}{aud} · generated {e(meta.get('generatedAt', ''))}</p>")

    hl = summary.get("headline", [])
    if hl:
        cards = "".join(
            f"<div class='kpi'><div class='v'>{e(h.get('value', ''))}</div>"
            f"<div class='l'>{e(h.get('label', ''))}</div></div>" for h in hl)
        parts.append(f"<div class='kpis'>{cards}</div>")
    if summary.get("narrative"):
        parts.append(f"<h2>Summary</h2><p>{e(summary['narrative'])}</p>")

    for b in report.get("breakdowns", []) or []:
        rows = "".join(
            f"<tr><td>{e(d.get('label') or d.get('severity') or '')}</td><td>{e(d.get('count', ''))}</td></tr>"
            for d in b.get("data", []))
        parts.append(f"<h3>{e(b.get('heading', ''))}</h3>"
                     f"<table><thead><tr><th>Item</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>")

    comp = report.get("compliance")
    if comp:
        rows = "".join(f"<tr><td>{e(c.get('control', ''))}</td><td>{e(c.get('framework', ''))}</td></tr>" for c in comp)
        parts.append("<h2>Control mapping</h2>"
                     f"<table><thead><tr><th>Control</th><th>Framework</th></tr></thead><tbody>{rows}</tbody></table>")

    findings = report.get("findings", []) or []
    if findings:
        rows = ""
        for f in findings:
            sev = e(f.get("severity", ""))
            rows += (f"<tr><td><span class='sev sev-{sev}'>{sev}</span></td>"
                     f"<td>{e(f.get('title', ''))}</td>"
                     f"<td>{e(f.get('score', f.get('cvss', '')))}</td>"
                     f"<td>{e(f.get('entity', f.get('asset', '')))}</td>"
                     f"<td>{e(f.get('status', ''))}</td></tr>")
        parts.append(f"<h2>Findings ({len(findings)})</h2>"
                     "<table><thead><tr><th>Severity</th><th>Title</th><th>Score</th>"
                     f"<th>Entity</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>")

    recs = report.get("recommendations", []) or []
    if recs:
        parts.append("<h2>Recommendations</h2><ol>" + "".join(f"<li>{e(r)}</li>" for r in recs) + "</ol>")

    body = "\n".join(parts)
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{e(meta.get('title', 'Report'))}</title><style>{_HTML_CSS}</style></head>"
            f"<body>{body}</body></html>")


_RENDERERS = {
    "json": lambda r: (json.dumps(r, indent=2, default=str), "application/json"),
    "csv": lambda r: (to_csv(r), "text/csv"),
    "markdown": lambda r: (to_markdown(r), "text/markdown"),
    "md": lambda r: (to_markdown(r), "text/markdown"),
    "html": lambda r: (to_html(r), "text/html"),
}

FORMATS = ["json", "csv", "markdown", "html"]


def render(report: dict, fmt: str) -> tuple[str, str, str]:
    """Return (content, media_type, file_extension) for the requested format."""
    fmt = (fmt or "json").lower()
    if fmt not in _RENDERERS:
        raise ValueError(f"unknown format: {fmt}; choose one of {FORMATS}")
    content, media = _RENDERERS[fmt](report)
    ext = "md" if fmt in ("markdown", "md") else fmt
    return content, media, ext
