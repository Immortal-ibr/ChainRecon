"""HTML report plugin."""

from __future__ import annotations

import json
from html import escape

from plugins.base import ReportPlugin

try:
    from jinja2 import Template
except ImportError:  # pragma: no cover
    Template = None


class HtmlReportPlugin(ReportPlugin):
    name = "html"
    description = "Render analysis output as a self-contained HTML report."

    TEMPLATE = """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>ChainRecon Report</title>
      <style>
        body { font-family: Georgia, serif; margin: 2rem; background: #f6f1e8; color: #1f2933; }
        h1, h2 { color: #7c2d12; }
        section { background: #fffdf8; border: 1px solid #e7d8c9; padding: 1rem; margin-bottom: 1rem; }
        pre { white-space: pre-wrap; word-break: break-word; background: #fff; padding: 1rem; border: 1px solid #eadfce; }
      </style>
    </head>
    <body>
      <h1>ChainRecon Analysis Report</h1>
      {% for name, payload in analysis_data.items() %}
      <section>
        <h2>{{ name|title }}</h2>
        <pre>{{ payload | tojson(indent=2) }}</pre>
      </section>
      {% endfor %}
    </body>
    </html>
    """

    def generate(self, analysis_data, output_path):
        if Template is None:
            body = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>ChainRecon Report</title></head><body>"]
            body.append("<h1>ChainRecon Analysis Report</h1>")
            for name, payload in analysis_data.items():
                body.append(f"<h2>{escape(str(name).title())}</h2>")
                body.append(f"<pre>{escape(json.dumps(payload, indent=2, sort_keys=True))}</pre>")
            body.append("</body></html>")
            html = "".join(body)
        else:
            html = Template(self.TEMPLATE).render(analysis_data=analysis_data)

        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return output_path

    def file_extension(self):
        return ".html"
