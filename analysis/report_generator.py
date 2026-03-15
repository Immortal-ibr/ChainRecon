"""Aggregate analysis results and render reports."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from plugins import get_plugin


class ReportGenerator:
    """Collect analyzer outputs and hand them to a report plugin."""

    def __init__(self):
        self._data = {"traffic": None, "ssl": None, "scan": None}

    def add_traffic_results(self, results: Dict[str, Any]) -> None:
        self._data["traffic"] = results

    def add_ssl_results(self, results: Dict[str, Any]) -> None:
        self._data["ssl"] = results

    def add_scan_results(self, results: Dict[str, Any]) -> None:
        self._data["scan"] = results

    def get_data(self) -> Dict[str, Any]:
        return deepcopy(self._data)

    def generate(self, format_name: str, output_path: str) -> str:
        return get_plugin(format_name).generate(self.get_data(), output_path)
