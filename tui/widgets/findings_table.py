"""Findings data-table widget used across multiple screens."""

from __future__ import annotations

from typing import TYPE_CHECKING, List

from textual.widgets import DataTable

if TYPE_CHECKING:
    from models.finding import Finding

_SEV_STYLE = {
    "critical": "[bold red]",
    "high": "[dark_orange]",
    "medium": "[yellow]",
    "low": "[blue]",
    "info": "[dim]",
}


class FindingsTable(DataTable):
    """Read-only table that displays a list of Finding objects."""

    DEFAULT_CSS = """
    FindingsTable {
        height: 1fr;
    }
    """

    def on_mount(self) -> None:
        self.add_columns("Sev", "Category", "Title", "Source", "Description")
        self.cursor_type = "row"

    def load(self, findings: List["Finding"]) -> None:
        self.clear()
        for f in findings:
            style = _SEV_STYLE.get(f.severity.value, "")
            end = "[/]" if style else ""
            self.add_row(
                f"{style}{f.severity.value.upper()}{end}",
                f.category.value,
                f.title,
                f.source,
                f.description[:80],
            )
