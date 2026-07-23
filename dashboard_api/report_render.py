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
.chart{margin:6px 0 10px;max-width:100%}
.viz{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:8px 0 4px}
.donut{display:flex;gap:14px;align-items:center}
.legend{font-size:11px}
.lg{display:flex;align-items:center;gap:6px;margin:2px 0;color:#444}
.sw{display:inline-block;width:10px;height:10px;border-radius:2px}
@media print{body{margin:0;max-width:none}.chart,.donut svg{page-break-inside:avoid}}
""".strip()


_SEV_HEX = {"critical": "#c1124e", "high": "#d33", "medium": "#b8860b",
            "low": "#1a8a6a", "info": "#5a4ad1"}


def _to_int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _svg_hbar(rows: list[tuple[str, int]]) -> str:
    """A self-contained inline-SVG horizontal bar chart (no external libs, prints
    cleanly). Bars are severity-coloured when the label is a severity."""
    rows = [(str(lbl), _to_int(c)) for lbl, c in rows if str(lbl).strip()]
    if not rows:
        return ""
    mx = max((c for _, c in rows), default=0) or 1
    bar_h, gap, label_w, chart_w = 18, 9, 130, 340
    height = len(rows) * (bar_h + gap)
    total_w = label_w + chart_w + 46
    out = []
    for i, (label, count) in enumerate(rows):
        y = i * (bar_h + gap)
        w = int(round((count / mx) * chart_w))
        color = _SEV_HEX.get(label.lower(), "#4f6bed")
        out.append(
            f"<text x='0' y='{y + 13}' font-size='11' fill='#444'>{escape(label)}</text>"
            f"<rect x='{label_w}' y='{y}' width='{max(w, 1)}' height='{bar_h}' rx='3' fill='{color}'/>"
            f"<text x='{label_w + max(w, 1) + 6}' y='{y + 13}' font-size='11' fill='#666'>{count}</text>"
        )
    return (f"<svg class='chart' width='{total_w}' height='{height}' "
            f"viewBox='0 0 {total_w} {height}' role='img' aria-label='bar chart'>{''.join(out)}</svg>")


def _svg_donut(rows: list[tuple[str, int]], size: int = 132) -> str:
    """A self-contained inline-SVG donut for a severity/category split."""
    rows = [(str(lbl), _to_int(c)) for lbl, c in rows if _to_int(c) > 0]
    total = sum(c for _, c in rows)
    if total == 0:
        return ""
    r, cx, cy, sw = size / 2 - 14, size / 2, size / 2, 16
    import math
    circ = 2 * math.pi * r
    off = 0.0
    segs = []
    for label, count in rows:
        frac = count / total
        color = _SEV_HEX.get(label.lower(), "#4f6bed")
        dash = frac * circ
        segs.append(
            f"<circle cx='{cx}' cy='{cy}' r='{r:.1f}' fill='none' stroke='{color}' "
            f"stroke-width='{sw}' stroke-dasharray='{dash:.1f} {circ - dash:.1f}' "
            f"stroke-dashoffset='{-off:.1f}' transform='rotate(-90 {cx} {cy})'/>")
        off += dash
    legend = "".join(
        f"<div class='lg'><span class='sw' style='background:{_SEV_HEX.get(l.lower(), '#4f6bed')}'></span>"
        f"{escape(l)} <b>{c}</b></div>" for l, c in rows)
    return (f"<div class='donut'><svg width='{size}' height='{size}' viewBox='0 0 {size} {size}' role='img'>"
            f"{''.join(segs)}<text x='{cx}' y='{cy - 2}' text-anchor='middle' font-size='20' "
            f"font-weight='700' fill='#1a1a1a'>{total}</text>"
            f"<text x='{cx}' y='{cy + 14}' text-anchor='middle' font-size='9' fill='#888'>TOTAL</text>"
            f"</svg><div class='legend'>{legend}</div></div>")


def _svg_line(points: list[tuple[str, int]], color: str = "#7A3CFF") -> str:
    """A self-contained inline-SVG line+area chart for a time series (no external
    libs, prints cleanly). `points` is (date-label, count), oldest → newest."""
    pts = [(str(lbl), _to_int(c)) for lbl, c in points]
    if len(pts) < 2:
        return ""
    mx = max((c for _, c in pts), default=0) or 1
    w, h, pad_l, pad_b, pad_t = 460, 132, 30, 22, 12
    plot_w, plot_h, n = w - pad_l - 12, h - pad_b - pad_t, len(pts)
    px = lambda i: pad_l + (i / (n - 1)) * plot_w          # noqa: E731
    py = lambda c: pad_t + plot_h - (c / mx) * plot_h      # noqa: E731
    baseline = pad_t + plot_h
    line = " ".join(f"{px(i):.1f},{py(c):.1f}" for i, (_, c) in enumerate(pts))
    area = f"{pad_l:.1f},{baseline:.1f} {line} {pad_l + plot_w:.1f},{baseline:.1f}"
    dots = "".join(f"<circle cx='{px(i):.1f}' cy='{py(c):.1f}' r='2.5' fill='{color}'/>"
                   for i, (_, c) in enumerate(pts))
    idxs = sorted({0, n // 2, n - 1})
    xlabels = "".join(
        f"<text x='{px(i):.1f}' y='{h - 6}' font-size='9' fill='#888' text-anchor='middle'>"
        f"{escape(pts[i][0])}</text>" for i in idxs)
    return (
        f"<svg class='chart' width='{w}' height='{h}' viewBox='0 0 {w} {h}' role='img' aria-label='trend line'>"
        f"<line x1='{pad_l}' y1='{baseline}' x2='{pad_l + plot_w}' y2='{baseline}' stroke='#ddd' stroke-width='1'/>"
        f"<text x='{pad_l - 4}' y='{pad_t + 8}' font-size='9' fill='#888' text-anchor='end'>{mx}</text>"
        f"<polygon points='{area}' fill='{color}' fill-opacity='0.10'/>"
        f"<polyline points='{line}' fill='none' stroke='{color}' stroke-width='2'/>"
        f"{dots}{xlabels}</svg>")


def to_html(report: dict) -> str:
    meta = report.get("meta", {})
    summary = report.get("summary", {})
    e = lambda v: escape(str(v))  # noqa: E731 - tiny local alias
    parts: list[str] = []
    parts.append(f"<h1>{e(meta.get('title', 'Report'))}</h1>")
    aud = f" · {e(meta['audience'].title())} audience" if meta.get("audience") else ""
    parts.append(f"<p class='sub'>{e(meta.get('period', ''))}{aud} · generated {e(meta.get('generatedAt', ''))}</p>")

    findings = report.get("findings", []) or []
    # Findings-by-severity donut (a visual dashboard element from real findings).
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = str(f.get("severity", "")).lower()
        if s:
            sev_counts[s] = sev_counts.get(s, 0) + 1
    donut_rows = [(s, sev_counts[s]) for s in ("critical", "high", "medium", "low", "info") if s in sev_counts]

    hl = summary.get("headline", [])
    if hl or donut_rows:
        cards = "".join(
            f"<div class='kpi'><div class='v'>{e(h.get('value', ''))}</div>"
            f"<div class='l'>{e(h.get('label', ''))}</div></div>" for h in hl)
        donut = _svg_donut(donut_rows)
        parts.append(f"<div class='viz'><div class='kpis'>{cards}</div>{donut}</div>")
    if summary.get("narrative"):
        parts.append(f"<h2>Summary</h2><p>{e(summary['narrative'])}</p>")

    # Time-series trend line (real per-day volume across the reporting window).
    series = report.get("series")
    if series and series.get("points"):
        pts = [(p.get("date", ""), p.get("count", 0)) for p in series["points"]]
        line = _svg_line(pts)
        if line:
            parts.append(f"<h3>{e(series.get('heading', 'Trend'))}</h3>{line}")

    for b in report.get("breakdowns", []) or []:
        data = b.get("data", []) or []
        chart = _svg_hbar([(d.get("label") or d.get("severity") or "", d.get("count", 0)) for d in data])
        rows = "".join(
            f"<tr><td>{e(d.get('label') or d.get('severity') or '')}</td><td>{e(d.get('count', ''))}</td></tr>"
            for d in data)
        parts.append(f"<h3>{e(b.get('heading', ''))}</h3>{chart}"
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
