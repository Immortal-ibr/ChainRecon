"""CSV export plugin."""

from __future__ import annotations

import csv

from plugins.base import ReportPlugin
from utils.artifacts import write_text_artifact


class CsvExportPlugin(ReportPlugin):
    name = "csv"
    description = "Flatten analysis output into CSV rows."

    def generate(self, analysis_data, output_path):
        rows = list(self._flatten_data(analysis_data))
        fieldnames = sorted({key for row in rows for key in row.keys()}) if rows else ["section", "key", "value"]
        def _write(handle):
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            if rows:
                writer.writerows(rows)

        write_text_artifact(output_path, _write)
        return output_path

    def file_extension(self):
        return ".csv"

    def _flatten_data(self, analysis_data):
        page_index = 1
        for section, payload in analysis_data.items():
            if not payload:
                continue
            page_name = f"{page_index:02d}_{section}"
            page_index += 1
            if not isinstance(payload, dict):
                if isinstance(payload, list):
                    for item in payload:
                        row = {"page": page_name, "section": section, "row_type": "item"}
                        if isinstance(item, dict):
                            row.update(item)
                        else:
                            row["value"] = item
                        yield row
                else:
                    yield {"page": page_name, "section": section, "row_type": "value", "value": payload}
                continue
            metadata = payload.get("metadata", {}) if isinstance(payload.get("metadata", {}), dict) else {}
            if metadata:
                row = {"page": page_name, "section": section, "row_type": "metadata", "key": "__metadata__"}
                row.update({k: v for k, v in metadata.items() if not isinstance(v, (dict, list))})
                yield row
            if section == "frida":
                sessions = payload.get("sessions") or payload.get("findings", {}).get("sessions", [])
                for index, session in enumerate(sessions or [], start=1):
                    if not isinstance(session, dict):
                        continue
                    yield {
                        "page": page_name,
                        "section": section,
                        "row_type": "session",
                        "key": "session",
                        "session_index": index,
                        "target": session.get("target"),
                        "script": session.get("script"),
                        "status": session.get("status"),
                        "hook_event_count": session.get("hook_event_count"),
                        "error_count": session.get("error_count"),
                        "source_file": session.get("source_file"),
                    }
                    for tag, count in (session.get("events_by_tag") or {}).items():
                        yield {
                            "page": page_name,
                            "section": section,
                            "row_type": "session_event_summary",
                            "key": "events_by_tag",
                            "session_index": index,
                            "event_tag": tag,
                            "count": count,
                        }
                    for line in session.get("hook_events") or []:
                        yield {
                            "page": page_name,
                            "section": section,
                            "row_type": "session_hook_event",
                            "key": "hook_events",
                            "session_index": index,
                            "value": line,
                        }
                    for line in session.get("error_events") or []:
                        yield {
                            "page": page_name,
                            "section": section,
                            "row_type": "session_error_event",
                            "key": "error_events",
                            "session_index": index,
                            "value": line,
                        }
                    for artifact in session.get("artifacts") or []:
                        row = {
                            "page": page_name,
                            "section": section,
                            "row_type": "session_artifact",
                            "key": "artifacts",
                            "session_index": index,
                        }
                        if isinstance(artifact, dict):
                            row.update(artifact)
                        else:
                            row["path"] = artifact
                        yield row
                continue
            for item in payload.get("risk_indicators", []) or []:
                row = {"page": page_name, "section": section, "row_type": "risk_indicator", "key": "risk_indicators"}
                if isinstance(item, dict):
                    row.update(item)
                else:
                    row["value"] = item
                if metadata.get("source_file"):
                    row["source_file"] = metadata["source_file"]
                yield row
            for item in payload.get("artifacts", []) or []:
                row = {"page": page_name, "section": section, "row_type": "artifact", "key": "artifacts"}
                if isinstance(item, dict):
                    row.update(item)
                else:
                    row["path"] = item
                yield row
            findings = payload.get("findings", {})
            for key, value in findings.items():
                if isinstance(value, list):
                    for item in value:
                        row = {"page": page_name, "section": section, "row_type": "finding", "key": key}
                        if isinstance(item, dict):
                            row.update(item)
                        else:
                            row["value"] = item
                        yield row
                elif isinstance(value, dict):
                    row = {"page": page_name, "section": section, "row_type": "finding", "key": key}
                    row.update(value)
                    yield row
                else:
                    yield {"page": page_name, "section": section, "row_type": "finding", "key": key, "value": value}
