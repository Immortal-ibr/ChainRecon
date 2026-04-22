"""CSV export plugin."""

from __future__ import annotations

import csv

from plugins.base import ReportPlugin


class CsvExportPlugin(ReportPlugin):
    name = "csv"
    description = "Flatten analysis output into CSV rows."

    def generate(self, analysis_data, output_path):
        rows = list(self._flatten_data(analysis_data))
        fieldnames = sorted({key for row in rows for key in row.keys()}) if rows else ["section", "key", "value"]
        with open(output_path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            if rows:
                writer.writerows(rows)
        return output_path

    def file_extension(self):
        return ".csv"

    def _flatten_data(self, analysis_data):
        for section, payload in analysis_data.items():
            if not payload:
                continue
            if not isinstance(payload, dict):
                if isinstance(payload, list):
                    for item in payload:
                        row = {"section": section}
                        if isinstance(item, dict):
                            row.update(item)
                        else:
                            row["value"] = item
                        yield row
                else:
                    yield {"section": section, "value": payload}
                continue
            metadata = payload.get("metadata", {}) if isinstance(payload.get("metadata", {}), dict) else {}
            for item in payload.get("risk_indicators", []) or []:
                row = {"section": section, "key": "risk_indicators"}
                if isinstance(item, dict):
                    row.update(item)
                else:
                    row["value"] = item
                if metadata.get("source_file"):
                    row["source_file"] = metadata["source_file"]
                yield row
            findings = payload.get("findings", {})
            for key, value in findings.items():
                if isinstance(value, list):
                    for item in value:
                        row = {"section": section, "key": key}
                        if isinstance(item, dict):
                            row.update(item)
                        else:
                            row["value"] = item
                        yield row
                elif isinstance(value, dict):
                    row = {"section": section, "key": key}
                    row.update(value)
                    yield row
                else:
                    yield {"section": section, "key": key, "value": value}
