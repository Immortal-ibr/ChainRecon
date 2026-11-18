"""Case report assembly with provenance, coverage, and review decisions."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from chainrecon.analysis.report_generator import ReportGenerator
from chainrecon.case_model import Case
from chainrecon.utils.artifacts import write_text_artifact
from chainrecon.utils.redaction import redact_report_data


_CASE_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ChainRecon investigation report</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;background:#f3f6f8;color:#17212b;margin:0}
main{max-width:1100px;margin:auto;padding:30px 20px 70px}h1,h2,h3{line-height:1.2}
header,section,article{background:white;border:1px solid #d4dde5;border-radius:8px;padding:20px;margin:0 0 18px}
.muted{color:#536475}.status{font-weight:700}.candidate{color:#945500}.confirmed{color:#126636}.rejected{color:#6a6f75}
table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid #e1e7ed;overflow-wrap:anywhere}
code,pre{background:#edf1f5;padding:2px 4px;border-radius:3px;overflow-wrap:anywhere}pre{padding:12px;white-space:pre-wrap}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 12px}dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}
.pill{display:inline-block;border:1px solid #c7d5df;border-radius:12px;padding:2px 8px;margin:2px 4px 2px 0}
</style></head><body><main>
<header><h1>{{ case.title }}</h1><p class="muted">Investigation ID {{ case.case_id }} · schema {{ case.schema_version }}</p>
<p>{{ evidence|length }} evidence items · {{ runs|length }} runs · {{ findings|length }} findings</p>
<p class="muted">Candidate findings require researcher review. Coverage limits and skipped checks do not prove absence.</p></header>
<section><h2>Evidence</h2><table><thead><tr><th>ID</th><th>Name and kind</th><th>SHA-256</th><th>Investigation path</th></tr></thead><tbody>
{% for item in evidence %}<tr><td><code>{{ item.id }}</code></td><td>{{ item.name }}<br><span class="muted">{{ item.kind }}</span></td><td><code>{{ item.sha256 }}</code></td><td><code>{{ item.path }}</code></td></tr>{% endfor %}
</tbody></table></section>
<section><h2>Analysis runs</h2>{% for run in runs %}<article><h3>{{ run.analyzer }} <code>{{ run.id }}</code> <span class="status {{ run.status }}">{{ run.status }}</span></h3>
<dl><dt>Input evidence</dt><dd>{{ run.input_ids|join(', ') }}</dd><dt>Completed</dt><dd>{{ run.completed_at }}</dd>
<dt>Tool versions</dt><dd><pre>{{ run.tool_versions|tojson(indent=2) }}</pre></dd><dt>Settings</dt><dd><pre>{{ run.settings|tojson(indent=2) }}</pre></dd>
<dt>Coverage</dt><dd><pre>{{ run.coverage|tojson(indent=2) }}</pre></dd><dt>Derived artifacts</dt><dd>{{ run.artifacts|join(', ') }}</dd></dl>
{% if run.warnings %}<details><summary>{{ run.warnings|length }} coverage notes or warnings</summary><ul>{% for warning in run.warnings %}<li>{{ warning }}</li>{% endfor %}</ul></details>{% endif %}</article>{% endfor %}</section>
<section><h2>Findings for disclosure review</h2>
{% if not findings %}<p>No candidate or reviewed findings were recorded. This is not an assurance that the device is free of vulnerabilities.</p>{% endif %}
{% for finding in findings %}<article><h3>{{ finding.title }}</h3><p><span class="pill">{{ finding.severity }}</span><span class="status {{ finding.status }}">{{ finding.status }}</span></p>
<dl><dt>Finding ID</dt><dd><code>{{ finding.id }}</code></dd><dt>Run</dt><dd><code>{{ finding.run_id }}</code></dd>
<dt>Affected component</dt><dd>{{ finding.affected_component or 'To be determined' }}</dd><dt>Affected versions</dt><dd>{{ finding.affected_versions or 'To be determined' }}</dd>
<dt>Rationale</dt><dd>{{ finding.rationale }}</dd><dt>Reproduction</dt><dd>{{ finding.reproduction or 'To be documented by reviewer' }}</dd>
<dt>Impact</dt><dd>{{ finding.impact or 'To be established by reviewer' }}</dd><dt>Remediation</dt><dd>{{ finding.remediation or 'To be proposed by reviewer' }}</dd>
<dt>References</dt><dd>{{ finding.references|join(', ') }}</dd><dt>Reviewer</dt><dd>{{ finding.reviewer or 'Pending' }}</dd><dt>Review note</dt><dd>{{ finding.review_note }}</dd></dl>
<h4>Linked observations and evidence locations</h4><ul>{% for observation in finding.linked_observations %}<li><strong>{{ observation.summary }}</strong> · <code>{{ observation.evidence_id }}</code> · <code>{{ observation.locator }}</code> · {{ observation.kind }}</li>{% endfor %}</ul>
</article>{% endfor %}</section>
<section><h2>Review history</h2><table><thead><tr><th>Finding</th><th>Decision</th><th>Reviewer</th><th>When</th><th>Note</th></tr></thead><tbody>
{% for decision in review_history %}<tr><td><code>{{ decision.finding_id }}</code></td><td>{{ decision.status }}</td><td>{{ decision.reviewer }}</td><td>{{ decision.reviewed_at }}</td><td>{{ decision.note }}</td></tr>{% endfor %}
</tbody></table></section>
</main></body></html>"""


def export_case_report(case: Case, format_name: str, output: str | Path) -> Path:
    rows = []
    runs = list(case.iter_runs())
    for run in runs:
        for finding in run["findings"]:
            reviewed = case.manifest["reviews"].get(finding["id"], {})
            rows.append({
                **finding,
                "status": reviewed.get("status", finding["status"]),
                "review_note": reviewed.get("note", ""),
                "reviewer": reviewed.get("reviewer", ""),
                "run_id": run["id"],
            })
    report = ReportGenerator()
    report.add_results("case", {
        "metadata": {"case_id": case.manifest["case_id"], "title": case.manifest["title"], "schema_version": 2},
        "summary": {"evidence_count": len(case.manifest["evidence"]), "run_count": len(runs), "finding_count": len(rows)},
        "findings": {
            "evidence": case.manifest["evidence"],
            "runs": [{
                "id": run["id"], "analyzer": run["analyzer"], "status": run["status"],
                "input_ids": run["input_ids"], "started_at": run["started_at"], "completed_at": run["completed_at"],
                "tool_versions": run["tool_versions"], "settings": run["settings"],
                "warnings": run["warnings"], "coverage": run["coverage"], "artifacts": run["artifacts"],
            } for run in runs],
            "observations": [item for run in runs for item in run["observations"]],
            "reviewed_findings": rows,
            "review_history": case.manifest.get("review_history", []),
        },
        "risk_indicators": [],
    })
    path = Path(output).expanduser().resolve()
    if format_name == "html":
        observations = {item["id"]: item for run in runs for item in run["observations"]}
        for row in rows:
            row["linked_observations"] = [observations[oid] for oid in row["observation_ids"] if oid in observations]
        view = redact_report_data({"case": {"case_id": case.manifest["case_id"], "title": case.manifest["title"], "schema_version": 2}, "evidence": case.manifest["evidence"], "runs": runs, "findings": rows, "review_history": case.manifest.get("review_history", [])})
        html = Environment(autoescape=select_autoescape(default=True, default_for_string=True)).from_string(_CASE_TEMPLATE).render(**view)
        write_text_artifact(path, html)
        return path
    report.generate(format_name, str(path))
    return path
