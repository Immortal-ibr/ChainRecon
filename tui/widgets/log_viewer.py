"""Reusable log viewer widget — streams text output in a scrollable panel."""

from __future__ import annotations

import platform
import re
import subprocess

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, RichLog, TextArea


class _LogModal(ModalScreen):
    """Modal screen that displays log content in a selectable TextArea."""

    DEFAULT_CSS = """
    _LogModal {
        align: center middle;
    }
    #modal-box {
        width: 90%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #modal-log-area {
        height: 1fr;
        margin-bottom: 1;
    }
    #btn-close-modal {
        width: 12;
    }
    """

    def __init__(self, content: str) -> None:
        super().__init__()
        self._content = content

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield TextArea(self._content, id="modal-log-area", read_only=True)
            yield Button("Close  [dim](Esc)[/]", id="btn-close-modal")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss()


class LogViewer(RichLog):
    """A scrollable rich-text log panel with clipboard copy and text-selection support."""

    BINDINGS = [
        Binding("y", "copy_log", "Copy log", show=True),
        Binding("e", "view_raw", "Select/copy", show=True),
    ]

    can_focus = True

    DEFAULT_CSS = """
    LogViewer {
        border: solid $accent;
        height: 1fr;
        scrollbar-size: 1 1;
    }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._log_lines: list[str] = []

    def append(self, text: str) -> None:
        """Write a line with Rich markup rendered (bold, green, red, dim, etc.)."""
        self._log_lines.append(text)
        self.write(Text.from_markup(text))

    def _plain_text(self) -> str:
        """Return log content with Rich markup stripped."""
        return re.sub(r"\[/?[^\]]*\]", "", "\n".join(self._log_lines))

    def action_copy_log(self) -> None:
        """Copy the plain-text log content to the system clipboard."""
        plain = self._plain_text()
        try:
            if platform.system() == "Windows":
                subprocess.run(
                    ["clip"],
                    input=plain.encode("utf-8", errors="replace"),
                    capture_output=True,
                    check=False,
                )
            elif platform.system() == "Darwin":
                subprocess.run(
                    ["pbcopy"],
                    input=plain.encode("utf-8", errors="replace"),
                    capture_output=True,
                    check=False,
                )
            else:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=plain.encode("utf-8", errors="replace"),
                    capture_output=True,
                    check=False,
                )
            self.write(Text.from_markup("[dim]Log copied to clipboard.[/]"))
        except Exception as exc:
            self.write(Text.from_markup(f"[red]Clipboard error: {exc}[/]"))

    def action_view_raw(self) -> None:
        """Open log content in a selectable TextArea modal (use Ctrl+A / Ctrl+C to copy)."""
        plain = self._plain_text()
        self.app.push_screen(_LogModal(plain))
