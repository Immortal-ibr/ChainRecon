"""HTML report plugin."""

from __future__ import annotations

import json
from copy import deepcopy
from html import escape
from typing import Any, Dict, List

from plugins.base import ReportPlugin

try:
    from jinja2 import Template
except ImportError:  # pragma: no cover
    Template = None


_SEV_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


class HtmlReportPlugin(ReportPlugin):
    name = "html"
    description = "Render analysis output as a self-contained HTML report."

    TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ChainRecon Report</title>
  <style>
    :root { --bg: #f8fafc; --fg: #111827; --muted: #4b5563; --accent: #1f4f7a; --card: #ffffff; --border: #d1d5db; }
    * { box-sizing: border-box; }
    body { font-family: "Segoe UI", system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--bg); color: var(--fg); }
    h1 { color: var(--accent); margin: 0 0 .25rem; }
    h2 { color: var(--accent); margin: 0 0 .75rem; }
    .subtitle { color: var(--muted); margin-bottom: 1.5rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; }
    pre { white-space: pre-wrap; word-break: break-word; background: #f9fafb; padding: 1rem; border: 1px solid var(--border); border-radius: 4px; font-size: .85rem; }
    table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
    th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { background: #eef2f7; font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: .75rem; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #b91c1c; }
    .badge-high { background: #c2410c; }
    .badge-medium { background: #a16207; }
    .badge-low { background: #1d4ed8; }
    .badge-info { background: #4b5563; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: .75rem; margin: 1rem 0; }
    .summary-box { text-align: center; padding: .75rem; border-radius: 6px; color: #fff; font-weight: 700; font-size: 1.5rem; }
    .summary-box small { display: block; font-size: .75rem; font-weight: 400; opacity: .9; }
  </style>
</head>
<body>
  <h1>ChainRecon Analysis Report</h1>
  <div class="subtitle">Generated from selected ChainRecon analysis artifacts.</div>

  {% if findings_summary %}
  <div class="card">
    <h2>Findings Summary</h2>
    <div class="summary-grid">
      {% for sev, count in findings_summary.by_severity.items() %}
      <div class="summary-box" style="background:{{ sev_color(sev) }}">
        {{ count }}<small>{{ sev }}</small>
      </div>
      {% endfor %}
    </div>
    <p><strong>Total findings:</strong> {{ findings_summary.total }}</p>
  </div>
  {% endif %}

  {% if risk_indicators %}
  <div class="card">
    <h2>Risk Indicators</h2>
    <table>
      <thead><tr><th>Severity</th><th>Section</th><th>Title</th><th>Details</th><th>Source File</th></tr></thead>
      <tbody>
      {% for item in risk_indicators %}
        <tr>
          <td><span class="badge badge-{{ item.severity }}">{{ item.severity }}</span></td>
          <td>{{ item.section }}</td>
          <td>{{ item.title }}</td>
          <td>{{ item.details }}</td>
          <td>{{ item.source_file }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if findings %}
  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Source</th><th>Description</th></tr></thead>
      <tbody>
      {% for f in findings %}
        <tr>
          <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.category }}</td>
          <td>{{ f.title }}</td>
          <td>{{ f.source }}</td>
          <td>{{ f.description }}{% if f.recommendation %}<br><em>Fix: {{ f.recommendation }}</em>{% endif %}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% for name, payload in sections.items() %}
  <div class="card">
    <h2>{{ name | title }}</h2>
    <pre>{{ payload | tojson(indent=2) }}</pre>
  </div>
  {% endfor %}
</body>
</html>"""

    def _sev_color(self, sev: str) -> str:
        return _SEV_COLORS.get(sev, "#6b7280")

    def generate(self, analysis_data, output_path):
        payload = deepcopy(analysis_data)
        findings_summary = payload.pop("findings_summary", None)
        findings = payload.pop("findings", None)
        sections = payload
        risk_indicators = _collect_risk_indicators(sections)

        if Template is None:
            html = self._generate_fallback(sections, findings_summary, findings, risk_indicators=risk_indicators)
        else:
            tmpl = Template(self.TEMPLATE)
            tmpl.globals["sev_color"] = self._sev_color
            html = tmpl.render(
                findings_summary=findings_summary,
                findings=findings,
                risk_indicators=risk_indicators,
                sections=sections,
            )

        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return output_path

    def _generate_fallback(self, sections, findings_summary, findings, risk_indicators=None):
        """Plain HTML when Jinja2 is not installed."""
        risk_indicators = risk_indicators or []
        parts = [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            "<title>ChainRecon Report</title></head><body>",
            "<h1>ChainRecon Analysis Report</h1>",
        ]
        if findings_summary:
            parts.append("<h2>Findings Summary</h2>")
            parts.append(f"<p>Total: {escape(str(findings_summary.get('total', 0)))}</p>")
        if risk_indicators:
            parts.append("<h2>Risk Indicators</h2><table border='1'><tr><th>Severity</th><th>Section</th><th>Title</th><th>Details</th></tr>")
            for item in risk_indicators:
                parts.append(
                    f"<tr><td>{escape(str(item.get('severity','')))}</td>"
                    f"<td>{escape(str(item.get('section','')))}</td>"
                    f"<td>{escape(str(item.get('title','')))}</td>"
                    f"<td>{escape(str(item.get('details','')))}</td></tr>"
                )
            parts.append("</table>")
        if findings:
            parts.append("<h2>Findings</h2><table border='1'><tr><th>Severity</th><th>Title</th><th>Description</th></tr>")
            for f in findings:
                parts.append(
                    f"<tr><td>{escape(str(f.get('severity','')))}</td>"
                    f"<td>{escape(str(f.get('title','')))}</td>"
                    f"<td>{escape(str(f.get('description','')))}</td></tr>"
                )
            parts.append("</table>")
        for name, section_payload in sections.items():
            parts.append(f"<h2>{escape(str(name).title())}</h2>")
            parts.append(f"<pre>{escape(json.dumps(section_payload, indent=2, sort_keys=True))}</pre>")
        parts.append("</body></html>")
        return "".join(parts)

    def file_extension(self):
        return ".html"


def _collect_risk_indicators(sections: Dict[str, Any]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for section, payload in sections.items():
        if not isinstance(payload, dict):
            continue
        source_file = str((payload.get("metadata") or {}).get("source_file", ""))
        for item in payload.get("risk_indicators", []) or []:
            if not isinstance(item, dict):
                continue
            rows.append({
                "section": str(section),
                "severity": str(item.get("severity", "info")),
                "title": str(item.get("title", "Risk indicator")),
                "details": str(item.get("details", item.get("description", ""))),
                "source_file": source_file,
            })
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(rows, key=lambda row: severity_rank.get(row["severity"].lower(), 99))
