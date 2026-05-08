"""JSON report plugin."""

from __future__ import annotations

from chainrecon.plugins.base import ReportPlugin
from chainrecon.utils.artifacts import write_json_artifact


class JsonReportPlugin(ReportPlugin):
    name = "json"
    description = "Serialize analysis output as JSON."

    def generate(self, analysis_data, output_path):
        write_json_artifact(output_path, analysis_data, sort_keys=True)
        return output_path

    def file_extension(self):
        return ".json"
