"""HTML report plugin."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List

from chainrecon.plugins.base import ReportPlugin
from chainrecon.utils.artifacts import local_file_href, write_text_artifact

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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ChainRecon Report</title>
  <style>
    :root {
      --bg: #f5f7fb;
      --ink: #111827;
      --muted: #64748b;
      --panel: #ffffff;
      --line: #d9e1ea;
      --line-strong: #b8c4d2;
      --brand: #0f5f72;
      --brand-soft: #e5f5f8;
      --accent: #1d4ed8;
      --good: #15803d;
      --warn: #b45309;
      --shadow: 0 14px 35px rgba(15, 23, 42, .08);
    }
    :root[data-theme="dark"] {
      --bg: #08111a;
      --ink: #e6eef8;
      --muted: #91a4b8;
      --panel: #0f1b28;
      --line: #233447;
      --line-strong: #37506a;
      --brand: #75c3d2;
      --brand-soft: #0d2330;
      --accent: #8dc4ff;
      --good: #4ade80;
      --warn: #fbbf24;
      --shadow: 0 18px 38px rgba(0, 0, 0, .35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      line-height: 1.45;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .shell { max-width: 1220px; margin: 0 auto; padding: 28px 24px 44px; }
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 22px;
      align-items: end;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(135deg, #ffffff 0%, #f0f9fb 100%);
      box-shadow: var(--shadow);
    }
    h1, h2, h3 { margin: 0; letter-spacing: 0; }
    h1 { font-size: 2rem; color: #0b3f4b; }
    h2 { font-size: 1.15rem; color: #0f3440; }
    h3 { font-size: 1rem; }
    .subtitle { margin-top: 8px; color: var(--muted); max-width: 760px; }
    .generated { text-align: right; color: var(--muted); font-size: .9rem; white-space: nowrap; }
    .hero-actions { display: flex; flex-direction: column; align-items: flex-end; gap: 10px; }
    .theme-toggle {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 12px;
      background: var(--panel);
      color: var(--ink);
      font: inherit;
      cursor: pointer;
    }
    .nav { display: flex; flex-wrap: wrap; gap: 8px; margin: 18px 0; }
    .nav a {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 12px;
      background: var(--panel);
      color: #0f4654;
      font-weight: 600;
      font-size: .88rem;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 18px 0;
    }
    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 8px 22px rgba(15, 23, 42, .05);
    }
    .metric strong { display: block; font-size: 1.8rem; line-height: 1; color: #0f4654; }
    .metric span { display: block; margin-top: 7px; color: var(--muted); font-size: .85rem; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 8px 22px rgba(15, 23, 42, .05);
      margin-top: 16px;
      overflow: hidden;
    }
    .panel-header {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
      background: #fbfdff;
    }
    .panel-body { padding: 18px; }
    .section-grid {
      display: grid;
      grid-template-columns: minmax(260px, .75fr) minmax(0, 1.25fr);
      gap: 16px;
    }
    .subtle { color: var(--muted); font-size: .9rem; }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 9px;
      background: #fff;
      color: #334155;
      font-size: .82rem;
      font-weight: 600;
    }
    .badge {
      display: inline-flex;
      min-width: 72px;
      justify-content: center;
      border-radius: 999px;
      padding: 4px 9px;
      color: #fff;
      font-size: .74rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-critical { background: #b91c1c; }
    .badge-high { background: #c2410c; }
    .badge-medium { background: #a16207; }
    .badge-low { background: #1d4ed8; }
    .badge-info { background: #475569; }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
      font-size: .9rem;
    }
    th { color: #475569; font-size: .76rem; text-transform: uppercase; letter-spacing: .04em; background: #f8fafc; }
    tr:last-child td { border-bottom: 0; }
    .kv {
      display: grid;
      grid-template-columns: minmax(120px, 170px) minmax(0, 1fr);
      gap: 8px 12px;
      font-size: .9rem;
    }
    .kv dt { color: var(--muted); }
    .kv dd { margin: 0; word-break: break-word; }
    details {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      margin-top: 12px;
      overflow: hidden;
    }
    details > summary {
      cursor: pointer;
      padding: 12px 14px;
      background: #f8fafc;
      font-weight: 700;
      color: #243447;
    }
    details[open] > summary { border-bottom: 1px solid var(--line); }
    pre {
      margin: 0;
      max-height: 460px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      background: #0f172a;
      color: #e5eef8;
      padding: 14px;
      font-size: .82rem;
      line-height: 1.5;
    }
    .raw-block { padding: 0; }
    .frida-session {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      margin-top: 12px;
      background: #fbfdff;
    }
    .frida-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }
    .empty {
      padding: 22px;
      color: var(--muted);
      text-align: center;
      border: 1px dashed var(--line-strong);
      border-radius: 8px;
      background: #fbfdff;
    }
    @media (max-width: 820px) {
      .shell { padding: 18px 12px 30px; }
      .hero { grid-template-columns: 1fr; padding: 20px; }
      .generated { text-align: left; white-space: normal; }
      .hero-actions { align-items: flex-start; }
      .section-grid { grid-template-columns: 1fr; }
      .panel-header { align-items: flex-start; flex-direction: column; }
      th, td { padding: 8px; }
    }
    @media (prefers-color-scheme: dark) {
      :root:not([data-theme="light"]) {
        --bg: #08111a;
        --ink: #e6eef8;
        --muted: #91a4b8;
        --panel: #0f1b28;
        --line: #233447;
        --line-strong: #37506a;
        --brand: #75c3d2;
        --brand-soft: #0d2330;
        --accent: #8dc4ff;
        --good: #4ade80;
        --warn: #fbbf24;
        --shadow: 0 18px 38px rgba(0, 0, 0, .35);
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header class="hero">
      <div>
        <h1>ChainRecon Analysis Report</h1>
        <div class="subtitle">Prioritized findings, session evidence, and source artifacts from the selected ChainRecon run.</div>
      </div>
      <div class="hero-actions">
        <button type="button" class="theme-toggle" id="theme-toggle">Toggle dark mode</button>
        <div class="generated">
          <strong>Generated</strong><br>
          {{ metrics.generated_at }}
        </div>
      </div>
    </header>

    <nav class="nav">
      {% if risk_indicators %}<a href="#priority-risks">Priority Risks</a>{% endif %}
      {% if findings %}<a href="#findings-table">Findings</a>{% endif %}
      {% for name, payload in sections.items() %}<a href="#section-{{ name }}">{{ name | title }}</a>{% endfor %}
    </nav>

    <section class="metrics" aria-label="Report metrics">
      <div class="metric"><strong>{{ metrics.section_count }}</strong><span>Report sections</span></div>
      <div class="metric"><strong>{{ metrics.finding_total }}</strong><span>Structured findings</span></div>
      <div class="metric"><strong>{{ metrics.risk_count }}</strong><span>Risk indicators</span></div>
      <div class="metric"><strong>{{ metrics.frida_sessions }}</strong><span>Frida sessions</span></div>
      <div class="metric"><strong>{{ metrics.artifact_count }}</strong><span>Linked artifacts</span></div>
    </section>

    {% if findings_summary %}
    <section class="panel" id="findings-summary">
      <div class="panel-header">
        <h2>Findings Summary</h2>
        <div class="chips">
          {% for sev, count in findings_summary.by_severity.items() %}
          <span class="chip"><span class="badge badge-{{ sev }}">{{ sev }}</span>{{ count }}</span>
          {% endfor %}
        </div>
      </div>
    </section>
    {% endif %}

    {% if risk_indicators %}
    <section class="panel" id="priority-risks">
      <div class="panel-header">
        <div>
          <h2>Priority Risks</h2>
          <div class="subtle">High-value signals from scan, analysis, APK, firmware, and Frida output.</div>
        </div>
      </div>
      <div class="panel-body">
        <table>
          <thead><tr><th>Severity</th><th>Section</th><th>Title</th><th>Evidence</th><th>Source</th></tr></thead>
          <tbody>
          {% for item in risk_indicators %}
            <tr>
              <td><span class="badge badge-{{ item.severity_class }}">{{ item.severity }}</span></td>
              <td>{{ item.section }}</td>
              <td>{{ item.title }}</td>
              <td>{{ item.details }}</td>
              <td>{% if item.source_file_href %}<a href="{{ item.source_file_href }}" title="{{ item.source_file }}">{{ item.source_label }}</a>{% else %}{{ item.source_label }}{% endif %}</td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if findings %}
    <section class="panel" id="findings-table">
      <div class="panel-header"><h2>Structured Findings</h2></div>
      <div class="panel-body">
        <table>
          <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Source</th><th>Description</th></tr></thead>
          <tbody>
          {% for f in findings %}
            <tr>
              <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
              <td>{{ f.category }}</td>
              <td>{{ f.title }}</td>
              <td>{{ f.source }}</td>
              <td>{{ f.description }}{% if f.recommendation %}<br><span class="subtle">Recommendation: {{ f.recommendation }}</span>{% endif %}</td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if not sections %}
    <div class="empty">No report sections were provided.</div>
    {% endif %}

    {% for name, payload in sections.items() %}
    <section class="panel" id="section-{{ name }}">
      <div class="panel-header">
        <div>
          <h2>{{ name | title }}</h2>
          <div class="subtle">
            {% if payload.metadata and payload.metadata.source_count %}
            {{ payload.metadata.source_count }} source file(s)
            {% elif payload.metadata and payload.metadata.source_file %}
            {% if payload.metadata.source_file_href %}<a href="{{ payload.metadata.source_file_href }}" title="{{ payload.metadata.source_file }}">{{ payload.metadata.source_file_label }}</a>{% else %}{{ payload.metadata.source_file_label or payload.metadata.source_file }}{% endif %}
            {% else %}
            Normalized report section
            {% endif %}
          </div>
        </div>
        <div class="chips">
          {% if payload.risk_indicators %}<span class="chip">{{ payload.risk_indicators | length }} risks</span>{% endif %}
          {% if payload.artifacts %}<span class="chip">{{ payload.artifacts | length }} artifacts</span>{% endif %}
          {% if name == 'frida' and payload.sessions %}<span class="chip">{{ payload.sessions | length }} sessions</span>{% endif %}
        </div>
      </div>
      <div class="panel-body">
        <div class="section-grid">
          <div>
            {% if payload.summary %}
            <h3>Summary</h3>
            <dl class="kv">
              {% for key, value in payload.summary.items() %}
              <dt>{{ key }}</dt>
              <dd>{{ value }}</dd>
              {% endfor %}
            </dl>
            {% else %}
            <div class="empty">No summary values were provided for this section.</div>
            {% endif %}
          </div>
          <div>
            {% if payload.artifacts %}
            <h3>Artifacts</h3>
            <table>
              <thead><tr><th>Type</th><th>Path</th></tr></thead>
              <tbody>
              {% for artifact in payload.artifacts %}
                <tr><td>{{ artifact.type }}</td><td>{% if artifact.href %}<a href="{{ artifact.href }}" title="{{ artifact.path }}">{{ artifact.label }}</a>{% else %}{{ artifact.label }}{% endif %}</td></tr>
              {% endfor %}
              </tbody>
            </table>
            {% elif payload.metadata and payload.metadata.source_files %}
            <h3>Source Files</h3>
            <table>
              <thead><tr><th>Path</th></tr></thead>
              <tbody>
              {% for source in payload.metadata.source_files %}
                <tr><td>{% if source.href %}<a href="{{ source.href }}" title="{{ source.path }}">{{ source.label }}</a>{% else %}{{ source.label }}{% endif %}</td></tr>
              {% endfor %}
              </tbody>
            </table>
            {% endif %}
          </div>
        </div>

        {% if name == 'frida' and payload.sessions %}
        <details open>
          <summary>Frida Sessions</summary>
          <div class="panel-body">
            <table>
              <thead><tr><th>Target</th><th>Script</th><th>Status</th><th>Hooks</th><th>Errors</th><th>Tags</th></tr></thead>
              <tbody>
              {% for session in payload.sessions %}
                <tr>
                  <td>{{ session.target }}</td>
                  <td>{{ session.script }}</td>
                  <td>{{ session.status }}</td>
                  <td>{{ session.hook_event_count }}</td>
                  <td>{{ session.error_count }}</td>
                  <td>{% for tag, count in session.events_by_tag.items() %}<span class="chip">{{ tag }}: {{ count }}</span>{% endfor %}</td>
                </tr>
              {% endfor %}
              </tbody>
            </table>
            {% for session in payload.sessions %}
            <div class="frida-session">
              <div class="frida-title">
                <h3>{{ session.target }} :: {{ session.script }}</h3>
                <span class="chip">{{ session.status }}</span>
              </div>
              {% if session.artifacts %}
              <table>
                <thead><tr><th>Artifact</th><th>Path</th></tr></thead>
                <tbody>
                {% for artifact in session.artifacts %}
                  <tr><td>{{ artifact.type }}</td><td>{% if artifact.href %}<a href="{{ artifact.href }}" title="{{ artifact.path }}">{{ artifact.label }}</a>{% else %}{{ artifact.label }}{% endif %}</td></tr>
                {% endfor %}
                </tbody>
              </table>
              {% endif %}
              {% if session.hook_events %}
              <details open><summary>Hook Timeline</summary><div class="raw-block"><pre>{{ session.hook_events | tojson(indent=2) }}</pre></div></details>
              {% endif %}
              {% if session.error_events %}
              <details open><summary>Error and stderr Excerpts</summary><div class="raw-block"><pre>{{ session.error_events | tojson(indent=2) }}</pre></div></details>
              {% endif %}
              <details><summary>Session Summary JSON</summary><div class="raw-block"><pre>{{ session.summary | tojson(indent=2) }}</pre></div></details>
            </div>
            {% endfor %}
          </div>
        </details>
        {% endif %}

        {% if payload.risk_indicators %}
        <details open title="Toggle section"><summary>Section Risk Indicators</summary><div class="raw-block"><pre>{{ payload.risk_indicators | tojson(indent=2) }}</pre></div></details>
        {% endif %}

        {% if name == 'workflow' and payload.findings and payload.findings.steps %}
        <details open><summary>Workflow Steps</summary>
          <div class="panel-body">
            <table>
              <thead><tr><th>Step</th><th>Type</th><th>Status</th><th>Error / Details</th></tr></thead>
              <tbody>
              {% for step_id, step in payload.findings.steps.items() %}
                <tr>
                  <td>{{ step_id }}</td>
                  <td>{{ step.get("type", "") }}</td>
                  <td><span class="badge badge-{{ "high" if step.get("status") == "failed" else ("info" if step.get("status") in ("skipped","planned") else "low") }}">{{ step.get("status","?") }}</span></td>
                  <td>{{ step.get("error", step.get("reason", "")) }}</td>
                </tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </details>
        {% endif %}

        {% if name == 'firmware' and payload.findings %}
        {% set fw = payload.findings %}
        {% if fw.credential_hits %}
        <details open><summary>Credential-like Strings ({{ fw.credential_hits | length }})</summary>
          <div class="panel-body">
            <table>
              <thead><tr><th>File</th><th>Keyword</th><th>Description</th></tr></thead>
              <tbody>
              {% for hit in fw.credential_hits %}
                <tr><td>{{ hit.path }}</td><td>{{ hit.keyword }}</td><td>{{ hit.description }}</td></tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </details>
        {% endif %}
        {% if fw.private_keys or fw.shadow_files or fw.certificate_files %}
        <details open><summary>Security-sensitive Files</summary>
          <div class="panel-body">
            {% if fw.private_keys %}<h3>Private Keys</h3><ul>{% for p in fw.private_keys %}<li>{{ p }}</li>{% endfor %}</ul>{% endif %}
            {% if fw.shadow_files %}<h3>Password Databases</h3><ul>{% for p in fw.shadow_files %}<li>{{ p }}</li>{% endfor %}</ul>{% endif %}
            {% if fw.certificate_files %}<h3>Certificates</h3><ul>{% for p in fw.certificate_files %}<li>{{ p }}</li>{% endfor %}</ul>{% endif %}
          </div>
        </details>
        {% endif %}
        {% if fw.network_indicators %}
        {% set ni = fw.network_indicators %}
        <details><summary>Embedded Network Indicators</summary>
          <div class="panel-body">
            {% if ni.urls %}<h3>URLs ({{ ni.urls | length }})</h3><ul>{% for u in ni.urls[:20] %}<li>{{ u.value }}</li>{% endfor %}{% if ni.urls | length > 20 %}<li>...and {{ (ni.urls | length) - 20 }} more</li>{% endif %}</ul>{% endif %}
            {% if ni.ips %}<h3>IP Addresses ({{ ni.ips | length }})</h3><ul>{% for i in ni.ips[:20] %}<li>{{ i.value }}</li>{% endfor %}</ul>{% endif %}
            {% if ni.domains %}<h3>Domains ({{ ni.domains | length }})</h3><ul>{% for d in ni.domains[:20] %}<li>{{ d.value }}</li>{% endfor %}</ul>{% endif %}
            {% if ni.rule_hits %}<h3>Device Profile Rule Hits ({{ ni.rule_hits | length }})</h3><table><thead><tr><th>Rule</th><th>Value</th></tr></thead><tbody>{% for h in ni.rule_hits %}<tr><td>{{ h.rule }}</td><td>{{ h.value }}</td></tr>{% endfor %}</tbody></table>{% endif %}
          </div>
        </details>
        {% endif %}
        {% endif %}

        {% if name == 'community' %}
        {% set items = payload.findings.items if payload.findings and payload.findings.items else [] %}
        {% if items %}
        <details open><summary>Plugin Results ({{ items | length }})</summary>
          <div class="panel-body">
            <table>
              <thead><tr><th>Plugin</th><th>Version</th><th>Type</th><th>Findings</th></tr></thead>
              <tbody>
              {% for item in items %}
                <tr>
                  <td>{{ item.get("metadata", {}).get("analyzer", item.get("name", "?")) }}</td>
                  <td>{{ item.get("metadata", {}).get("version", "?") }}</td>
                  <td>{{ item.get("metadata", {}).get("type", "analyzer") }}</td>
                  <td>{{ item.get("summary", {}) | tojson }}</td>
                </tr>
              {% endfor %}
              </tbody>
            </table>
          </div>
        </details>
        {% endif %}
        {% endif %}

        {% if name == 'device_profile' %}
        <details open><summary>Profile Details</summary>
          <div class="panel-body">
            <dl class="kv">
              {% for key, value in (payload.findings or payload.metadata or payload).items() %}
              {% if not key.startswith("_") and value is not none %}
              <dt>{{ key }}</dt>
              <dd>{% if value is iterable and value is not string %}{{ value | tojson }}{% else %}{{ value }}{% endif %}</dd>
              {% endif %}
              {% endfor %}
            </dl>
          </div>
        </details>
        {% endif %}

        {% if payload.findings %}
        <details title="Toggle section"><summary>Findings JSON</summary><div class="raw-block"><pre>{{ payload.findings | tojson(indent=2) }}</pre></div></details>
        {% endif %}
        {% if payload.metadata %}
        <details title="Toggle section"><summary>Metadata JSON</summary><div class="raw-block"><pre>{{ payload.metadata | tojson(indent=2) }}</pre></div></details>
        {% endif %}
        <details title="Toggle section"><summary>Raw Section JSON</summary><div class="raw-block"><pre>{{ payload | tojson(indent=2) }}</pre></div></details>
      </div>
    </section>
    {% endfor %}
  </main>
  <script>
    (function () {
      const root = document.documentElement;
      const storageKey = "chainrecon-report-theme";
      const saved = window.localStorage.getItem(storageKey);
      if (saved === "dark" || saved === "light") {
        root.setAttribute("data-theme", saved);
      }
      const button = document.getElementById("theme-toggle");
      if (!button) return;
      button.addEventListener("click", function () {
        const current = root.getAttribute("data-theme") === "dark" ? "dark" : "light";
        const next = current === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        window.localStorage.setItem(storageKey, next);
      });
    }());
  </script>
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
        metrics = _dashboard_metrics(sections, findings_summary, findings, risk_indicators)

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
                metrics=metrics,
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
        metadata = payload.get("metadata") or {}
        source_file = str(metadata.get("source_file", ""))
        source_file_href = str(metadata.get("source_file_href", ""))
        for item in payload.get("risk_indicators", []) or []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "info")).lower()
            rows.append({
                "section": str(section),
                "severity": severity,
                "severity_class": severity if severity in _SEV_COLORS else "info",
                "title": str(item.get("title", "Risk indicator")),
                "details": str(item.get("details", item.get("description", ""))),
                "source_file": source_file,
                "source_file_href": source_file_href,
                "source_label": _display_path(source_file, prefix="Source"),
            })
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(rows, key=lambda row: severity_rank.get(row["severity"].lower(), 99))


def _annotate_sections(sections: Dict[str, Any]) -> Dict[str, Any]:
    annotated = deepcopy(sections)
    for payload in annotated.values():
        if not isinstance(payload, dict):
            continue
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            source_file = metadata.get("source_file")
            if source_file:
                metadata["source_file_href"] = local_file_href(str(source_file))
                metadata["source_file_label"] = _display_path(str(source_file), prefix="Source")
            source_files = metadata.get("source_files")
            if isinstance(source_files, list):
                metadata["source_files"] = [
                    {"path": str(path), "href": local_file_href(str(path)), "label": _display_path(str(path), prefix="Source")}
                    for path in source_files
                ]
        artifacts = payload.get("artifacts")
        if isinstance(artifacts, list):
            payload["artifacts"] = [_annotate_artifact(artifact) for artifact in artifacts]
        sessions = payload.get("sessions")
        if isinstance(sessions, list):
            payload["sessions"] = [
                {
                    **session,
                    "artifacts": [_annotate_artifact(artifact) for artifact in (session.get("artifacts") or [])],
                }
                for session in sessions
                if isinstance(session, dict)
            ]
    return annotated


def _annotate_artifact(artifact: Any) -> Dict[str, str]:
    if isinstance(artifact, dict):
        path = str(artifact.get("path", ""))
        artifact_type = str(artifact.get("type", "artifact")).replace("_", " ").strip().title()
        return {
            **artifact,
            "path": path,
            "href": local_file_href(path),
            "label": _display_path(path, prefix=artifact_type),
        }
    path = str(artifact)
    return {"type": "artifact", "path": path, "href": local_file_href(path), "label": _display_path(path, prefix="Artifact")}


def _display_path(path: str, *, prefix: str = "Artifact") -> str:
    if not path:
        return prefix
    return f"{prefix}: {Path(path).name}"


def _dashboard_metrics(sections: Dict[str, Any], findings_summary: Any, findings: Any, risk_indicators: List[Dict[str, str]]) -> Dict[str, Any]:
    artifact_count = 0
    frida_sessions = 0
    for name, payload in sections.items():
        if not isinstance(payload, dict):
            continue
        artifact_count += len(payload.get("artifacts") or [])
        sessions = payload.get("sessions") if name == "frida" else []
        if isinstance(sessions, list):
            frida_sessions += len(sessions)
            for session in sessions:
                if isinstance(session, dict):
                    artifact_count += len(session.get("artifacts") or [])
    if isinstance(findings_summary, dict):
        finding_total = int(findings_summary.get("total", 0) or 0)
    elif isinstance(findings, list):
        finding_total = len(findings)
    else:
        finding_total = 0
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "section_count": len(sections),
        "finding_total": finding_total,
        "risk_count": len(risk_indicators),
        "frida_sessions": frida_sessions,
        "artifact_count": artifact_count,
    }
