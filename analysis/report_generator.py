"""Aggregate analysis results and render reports."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional

from models.finding import FindingCollection
from plugins import get_plugin


class ReportGenerator:
    """Collect analyzer outputs and hand them to a report plugin."""

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {"traffic": None, "ssl": None, "scan": None}
        self._findings = FindingCollection()

    # -- Legacy convenience setters (still work) ----------------------

    def add_traffic_results(self, results: Dict[str, Any]) -> None:
        self._data["traffic"] = results

    def add_ssl_results(self, results: Dict[str, Any]) -> None:
        self._data["ssl"] = results

    def add_scan_results(self, results: Dict[str, Any]) -> None:
        self._data["scan"] = results

    # -- Generic setters for any analyzer -----------------------------

    def add_results(self, section: str, results: Dict[str, Any]) -> None:
        """Add results from any analyzer under *section* key."""
        self._data[section] = results

    def add_finding(self, finding) -> None:
        """Append a single Finding to the collection."""
        self._findings.add(finding)

    def add_findings(self, findings) -> None:
        """Append an iterable of Findings."""
        for f in findings:
            self._findings.add(f)

    # -- Accessors ----------------------------------------------------

    @property
    def findings(self) -> FindingCollection:
        return self._findings

    def get_data(self) -> Dict[str, Any]:
        data = deepcopy(self._data)
        if self._findings:
            data["findings_summary"] = {
                "total": len(self._findings),
                "by_severity": self._findings.severity_counts,
            }
            data["findings"] = self._findings.to_list()
        return data

    # -- Report generation --------------------------------------------

    def generate(self, format_name: str, output_path: str) -> str:
        return get_plugin(format_name).generate(self.get_data(), output_path)
