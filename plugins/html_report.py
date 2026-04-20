"""HTML report plugin."""

from __future__ import annotations

import json
from html import escape

from plugins.base import ReportPlugin

try:
    from jinja2 import Template
except ImportError:  # pragma: no cover
    Template = None

# Severity → badge colour mapping
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
    :root { --bg: #f6f1e8; --fg: #1f2933; --accent: #7c2d12; --card: #fffdf8; --border: #e7d8c9; }
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--bg); color: var(--fg); }
    h1 { color: var(--accent); border-bottom: 2px solid var(--accent); padding-bottom: .5rem; }
    h2 { color: var(--accent); margin-top: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; }
    pre { white-space: pre-wrap; word-break: break-word; background: #fff; padding: 1rem; border: 1px solid var(--border); border-radius: 4px; font-size: .85rem; }
    table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
    th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--border); }
    th { background: #f3ede3; font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: .75rem; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #dc2626; }
    .badge-high { background: #ea580c; }
    .badge-medium { background: #ca8a04; }
    .badge-low { background: #2563eb; }
    .badge-info { background: #6b7280; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: .75rem; margin: 1rem 0; }
    .summary-box { text-align: center; padding: .75rem; border-radius: 6px; color: #fff; font-weight: 700; font-size: 1.5rem; }
    .summary-box small { display: block; font-size: .75rem; font-weight: 400; opacity: .9; }
  </style>
</head>
<body>
  <h1>ChainRecon Analysis Report</h1>

  {% if findings_summary %}
  <div class="card">
    <h2 style="margin-top:0">Findings Summary</h2>
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

  {% if findings %}
  <div class="card">
    <h2 style="margin-top:0">Findings</h2>
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
    <h2 style="margin-top:0">{{ name | title }}</h2>
    <pre>{{ payload | tojson(indent=2) }}</pre>
  </div>
  {% endfor %}

</body>
</html>"""

    def _sev_color(self, sev: str) -> str:
        return _SEV_COLORS.get(sev, "#6b7280")

    def generate(self, analysis_data, output_path):
        findings_summary = analysis_data.pop("findings_summary", None)
        findings = analysis_data.pop("findings", None)
        sections = analysis_data  # remaining keys are analyzer sections

        if Template is None:
            html = self._generate_fallback(sections, findings_summary, findings)
        else:
            tmpl = Template(self.TEMPLATE)
            tmpl.globals["sev_color"] = self._sev_color
            html = tmpl.render(
                findings_summary=findings_summary,
                findings=findings,
                sections=sections,
            )

        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return output_path

    def _generate_fallback(self, sections, findings_summary, findings):
        """Plain HTML when Jinja2 is not installed."""
        parts = [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            "<title>ChainRecon Report</title></head><body>",
            "<h1>ChainRecon Analysis Report</h1>",
        ]
        if findings_summary:
            parts.append(f"<h2>Findings Summary</h2>")
            parts.append(f"<p>Total: {findings_summary.get('total', 0)}</p>")
        if findings:
            parts.append("<h2>Findings</h2><table border='1'><tr><th>Severity</th><th>Title</th><th>Description</th></tr>")
            for f in findings:
                parts.append(
                    f"<tr><td>{escape(str(f.get('severity','')))}</td>"
                    f"<td>{escape(str(f.get('title','')))}</td>"
                    f"<td>{escape(str(f.get('description','')))}</td></tr>"
                )
            parts.append("</table>")
        for name, payload in sections.items():
            parts.append(f"<h2>{escape(str(name).title())}</h2>")
            parts.append(f"<pre>{escape(json.dumps(payload, indent=2, sort_keys=True))}</pre>")
        parts.append("</body></html>")
        return "".join(parts)

    def file_extension(self):
        return ".html"
