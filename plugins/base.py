"""Plugin contract for ChainRecon report outputs."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ReportPlugin(ABC):
    name = ""
    description = ""

    @abstractmethod
    def generate(self, analysis_data, output_path):
        """Generate a report and return the written path."""

    @abstractmethod
    def file_extension(self):
        """Return the preferred file extension for this plugin."""
