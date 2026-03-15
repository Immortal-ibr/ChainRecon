"""JSON report plugin."""

from __future__ import annotations

import json

from plugins.base import ReportPlugin


class JsonReportPlugin(ReportPlugin):
    name = "json"
    description = "Serialize analysis output as JSON."

    def generate(self, analysis_data, output_path):
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(analysis_data, handle, indent=2, sort_keys=True)
        return output_path

    def file_extension(self):
        return ".json"
