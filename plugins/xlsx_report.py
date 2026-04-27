"""XLSX export plugin with one worksheet per report section."""

from __future__ import annotations

import os
import tempfile
from collections import defaultdict
from pathlib import Path

from plugins.base import ReportPlugin
from plugins.csv_export import CsvExportPlugin

try:  # pragma: no cover - import guard exercised via plugin tests
    from openpyxl import Workbook
except ImportError:  # pragma: no cover
    Workbook = None


class XlsxReportPlugin(ReportPlugin):
    name = "xlsx"
    description = "Spreadsheet export with a summary sheet and one worksheet per section."

    def generate(self, analysis_data, output_path):
        if Workbook is None:
            raise RuntimeError("XLSX export requires openpyxl. Install it with: python -m pip install openpyxl")

        flattener = CsvExportPlugin()
        rows = list(flattener._flatten_data(analysis_data))
        grouped = defaultdict(list)
        for row in rows:
            grouped[str(row.get("section", "report"))].append(row)

        workbook = Workbook()
        summary = workbook.active
        summary.title = "summary"
        summary.append(["section", "row_count", "risk_indicator_count"])
        for section, section_rows in grouped.items():
            risk_count = sum(1 for row in section_rows if row.get("key") == "risk_indicators")
            summary.append([section, len(section_rows), risk_count])

        for section, section_rows in grouped.items():
            sheet = workbook.create_sheet(title=_sheet_name(section))
            fieldnames = _fieldnames(section_rows)
            sheet.append(fieldnames)
            for row in section_rows:
                sheet.append([_scalarize(row.get(name, "")) for name in fieldnames])

        target = Path(output_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            workbook.save(tmp_path)
            try:
                os.replace(tmp_path, target)
            except PermissionError:
                workbook.save(target)
                tmp_path.unlink(missing_ok=True)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise
        return output_path

    def file_extension(self):
        return ".xlsx"


def _sheet_name(section: str) -> str:
    cleaned = "".join(ch for ch in section if ch not in r'[]:*?/\\')
    return (cleaned or "section")[:31]


def _fieldnames(rows):
    seen = []
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.append(key)
    return seen


def _scalarize(value):
    if isinstance(value, (list, dict)):
        return str(value)
    return value
