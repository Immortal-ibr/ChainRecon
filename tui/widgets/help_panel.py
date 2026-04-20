"""Collapsible help panel — press '?' on any screen to toggle."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static


class HelpPanel(VerticalScroll):
    """A scrollable documentation panel hidden by default.

    Embed in any screen and call .toggle() to show/hide.
    """

    DEFAULT_CSS = """
    HelpPanel {
        display: none;
        background: $boost;
        border: tall $accent;
        padding: 1 2;
        margin: 0 0 1 0;
        max-height: 50vh;
    }
    HelpPanel.visible {
        display: block;
    }
    """

    def __init__(self, help_text: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._help_text = help_text

    def compose(self) -> ComposeResult:
        yield Static(self._help_text)

    def toggle(self) -> None:
        """Show or hide the panel."""
        self.toggle_class("visible")
