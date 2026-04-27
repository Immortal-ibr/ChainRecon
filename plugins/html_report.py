"""HTML report plugin."""

from __future__ import annotations

import json
from copy import deepcopy
from html import escape
from typing import Any, Dict, List

from plugins.base import ReportPlugin
from utils.artifacts import local_file_href, write_text_artifact

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
    :root { --bg: #f8fafc; --fg: #111827; --muted: #4b5563; --accent: #1f4f7a; --card: #ffffff; --border: #d1d5db; --surface: #eef2f7; }
    * { box-sizing: border-box; }
    body { font-family: "Segoe UI", system-ui, sans-serif; margin: 0; padding: 2rem; background: var(--bg); color: var(--fg); }
    h1 { color: var(--accent); margin: 0 0 .25rem; }
    h2 { color: var(--accent); margin: 0 0 .75rem; }
    h3 { margin: 0; color: var(--fg); }
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
    .toc { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: 1rem; }
    .toc a { text-decoration: none; padding: .45rem .75rem; border: 1px solid var(--border); border-radius: 999px; background: var(--card); color: var(--accent); font-weight: 600; }
    details.panel { border: 1px solid var(--border); border-radius: 6px; background: var(--card); margin-bottom: 1rem; overflow: hidden; }
    details.panel summary { list-style: none; cursor: pointer; padding: 1rem 1.25rem; background: var(--surface); display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
    details.panel summary::-webkit-details-marker { display: none; }
    details.panel[open] summary { border-bottom: 1px solid var(--border); }
    .panel-body { padding: 1rem 1.25rem 1.25rem; }
    .meta { color: var(--muted); font-size: .9rem; }
    .stack { display: flex; flex-direction: column; gap: .75rem; }
  </style>
</head>
<body>
  <h1>ChainRecon Analysis Report</h1>
  <div class="subtitle">Generated from selected ChainRecon analysis artifacts.</div>
  <div class="toc">
    {% if findings_summary %}<a href="#findings-summary">Findings Summary</a>{% endif %}
    {% if risk_indicators %}<a href="#risk-indicators">Risk Indicators</a>{% endif %}
    {% if findings %}<a href="#findings-table">Findings</a>{% endif %}
    {% for name, payload in sections.items() %}
    <a href="#section-{{ name }}">{{ name | title }}</a>
    {% endfor %}
  </div>

  {% if findings_summary %}
  <div class="card" id="findings-summary">
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
  <div class="card" id="risk-indicators">
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
          <td>
            {% if item.source_file_href %}
            <a href="{{ item.source_file_href }}">{{ item.source_file }}</a>
            {% else %}
            {{ item.source_file }}
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  {% if findings %}
  <div class="card" id="findings-table">
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
  <details class="panel" id="section-{{ name }}" {% if loop.first %}open{% endif %}>
    <summary>
      <span>
        <h3>{{ name | title }}</h3>
        <div class="meta">
          {% if payload.metadata and payload.metadata.source_count %}
          {{ payload.metadata.source_count }} source file(s)
          {% elif payload.metadata and payload.metadata.source_file %}
          {% if payload.metadata.source_file_href %}
          <a href="{{ payload.metadata.source_file_href }}">{{ payload.metadata.source_file }}</a>
          {% else %}
          {{ payload.metadata.source_file }}
          {% endif %}
          {% else %}
          Raw section data
          {% endif %}
        </div>
      </span>
      <span class="meta">Toggle section</span>
    </summary>
    <div class="panel-body stack">
      {% if payload.summary %}
      <details class="panel" open>
        <summary><span><strong>Summary</strong></span><span class="meta">Toggle</span></summary>
        <div class="panel-body"><pre>{{ payload.summary | tojson(indent=2) }}</pre></div>
      </details>
      {% endif %}
      {% if name == 'frida' and payload.sessions %}
      <details class="panel" open>
        <summary><span><strong>Frida Sessions</strong></span><span class="meta">{{ payload.sessions | length }} session(s)</span></summary>
        <div class="panel-body stack">
          <table>
            <thead><tr><th>Target</th><th>Script</th><th>Status</th><th>Hooks</th><th>Errors</th></tr></thead>
            <tbody>
            {% for session in payload.sessions %}
              <tr>
                <td>{{ session.target }}</td>
                <td>{{ session.script }}</td>
                <td>{{ session.status }}</td>
                <td>{{ session.hook_event_count }}</td>
                <td>{{ session.error_count }}</td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
          {% for session in payload.sessions %}
          <details class="panel">
            <summary><span><strong>{{ session.target }} :: {{ session.script }}</strong></span><span class="meta">{{ session.status }}</span></summary>
            <div class="panel-body stack">
              <pre>{{ session.summary | tojson(indent=2) }}</pre>
              {% if session.events_by_tag %}
              <table>
                <thead><tr><th>Event Tag</th><th>Count</th></tr></thead>
                <tbody>
                {% for tag, count in session.events_by_tag.items() %}
                  <tr><td>{{ tag }}</td><td>{{ count }}</td></tr>
                {% endfor %}
                </tbody>
              </table>
              {% endif %}
              {% if session.hook_events %}
              <details class="panel">
                <summary><span><strong>Hook Excerpts</strong></span><span class="meta">{{ session.hook_events | length }} line(s)</span></summary>
                <div class="panel-body"><pre>{{ session.hook_events | tojson(indent=2) }}</pre></div>
              </details>
              {% endif %}
              {% if session.error_events %}
              <details class="panel">
                <summary><span><strong>Error Excerpts</strong></span><span class="meta">{{ session.error_events | length }} line(s)</span></summary>
                <div class="panel-body"><pre>{{ session.error_events | tojson(indent=2) }}</pre></div>
              </details>
              {% endif %}
              {% if session.artifacts %}
              <table>
                <thead><tr><th>Artifact</th><th>Path</th></tr></thead>
                <tbody>
                {% for artifact in session.artifacts %}
                  <tr>
                    <td>{{ artifact.type }}</td>
                    <td>{% if artifact.href %}<a href="{{ artifact.href }}">{{ artifact.path }}</a>{% else %}{{ artifact.path }}{% endif %}</td>
                  </tr>
                {% endfor %}
                </tbody>
              </table>
              {% endif %}
            </div>
          </details>
          {% endfor %}
        </div>
      </details>
      {% endif %}
      {% if payload.risk_indicators %}
      <details class="panel">
        <summary><span><strong>Section Risk Indicators</strong></span><span class="meta">{{ payload.risk_indicators | length }} item(s)</span></summary>
        <div class="panel-body"><pre>{{ payload.risk_indicators | tojson(indent=2) }}</pre></div>
      </details>
      {% endif %}
      {% if payload.findings %}
      <details class="panel">
        <summary><span><strong>Findings</strong></span><span class="meta">Toggle</span></summary>
        <div class="panel-body"><pre>{{ payload.findings | tojson(indent=2) }}</pre></div>
      </details>
      {% endif %}
      {% if payload.metadata %}
      <details class="panel">
        <summary><span><strong>Metadata</strong></span><span class="meta">Toggle</span></summary>
        <div class="panel-body">
          {% if payload.metadata.source_files %}
          <table>
            <thead><tr><th>Source Files</th></tr></thead>
            <tbody>
            {% for source in payload.metadata.source_files %}
              <tr>
                <td>
                  {% if source.href %}
                  <a href="{{ source.href }}">{{ source.path }}</a>
                  {% else %}
                  {{ source.path }}
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
          {% endif %}
          <pre>{{ payload.metadata | tojson(indent=2) }}</pre>
        </div>
      </details>
      {% endif %}
      {% if payload.artifacts %}
      <details class="panel">
        <summary><span><strong>Artifacts</strong></span><span class="meta">{{ payload.artifacts | length }} item(s)</span></summary>
        <div class="panel-body">
          <table>
            <thead><tr><th>Type</th><th>Path</th></tr></thead>
            <tbody>
            {% for artifact in payload.artifacts %}
              <tr>
                <td>{{ artifact.type }}</td>
                <td>
                  {% if artifact.href %}
                  <a href="{{ artifact.href }}">{{ artifact.path }}</a>
                  {% else %}
                  {{ artifact.path }}
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
      {% endif %}
      <details class="panel">
        <summary><span><strong>Raw JSON</strong></span><span class="meta">Toggle</span></summary>
        <div class="panel-body"><pre>{{ payload | tojson(indent=2) }}</pre></div>
      </details>
    </div>
  </details>
  {% endfor %}
</body>
</html>"""

    def _sev_color(self, sev: str) -> str:
        return _SEV_COLORS.get(sev, "#6b7280")

    def generate(self, analysis_data, output_path):
        payload = deepcopy(analysis_data)
        findings_summary = payload.pop("findings_summary", None)
        findings = payload.pop("findings", None)
        sections = _annotate_sections(payload)
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

        write_text_artifact(output_path, html)
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
            parts.append(
                f"<details open><summary><strong>{escape(str(name).title())}</strong></summary>"
                f"<pre>{escape(json.dumps(section_payload, indent=2, sort_keys=True))}</pre></details>"
            )
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
        source_file_href = str((payload.get("metadata") or {}).get("source_file_href", ""))
        for item in payload.get("risk_indicators", []) or []:
            if not isinstance(item, dict):
                continue
            rows.append({
                "section": str(section),
                "severity": str(item.get("severity", "info")),
                "title": str(item.get("title", "Risk indicator")),
                "details": str(item.get("details", item.get("description", ""))),
                "source_file": source_file,
                "source_file_href": source_file_href,
            })
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(rows, key=lambda row: severity_rank.get(row["severity"].lower(), 99))


def _annotate_sections(sections: Dict[str, Any]) -> Dict[str, Any]:
    annotated = deepcopy(sections)
    for payload in annotated.values():
        if not isinstance(payload, dict):
            continue
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            continue
        source_file = metadata.get("source_file")
        if source_file:
            metadata["source_file_href"] = local_file_href(str(source_file))
        source_files = metadata.get("source_files")
        if isinstance(source_files, list):
            metadata["source_files"] = [
                {"path": str(path), "href": local_file_href(str(path))}
                for path in source_files
            ]
        artifacts = payload.get("artifacts")
        if isinstance(artifacts, list):
            payload["artifacts"] = [
                {**artifact, "href": local_file_href(str(artifact.get("path", "")))}
                if isinstance(artifact, dict) else {"type": "artifact", "path": str(artifact), "href": local_file_href(str(artifact))}
                for artifact in artifacts
            ]
        sessions = payload.get("sessions")
        if isinstance(sessions, list):
          payload["sessions"] = [
            {
              **session,
              "artifacts": [
                {**artifact, "href": local_file_href(str(artifact.get("path", "")))}
                if isinstance(artifact, dict) else {"type": "artifact", "path": str(artifact), "href": local_file_href(str(artifact))}
                for artifact in (session.get("artifacts") or [])
              ],
            }
            for session in sessions if isinstance(session, dict)
          ]
    return annotated
