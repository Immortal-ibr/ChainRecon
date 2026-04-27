"""Reusable bounded log viewer with copy, clear, save, and open actions."""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, RichLog, TextArea

from utils.artifacts import artifact_path


LOG_CLEAR_ID = "log-clear"
LOG_COPY_ID = "log-copy"
LOG_SAVE_ID = "log-save"
LOG_OPEN_LAST_ID = "log-open-last"
LOG_OPEN_DIR_ID = "log-open-dir"


def strip_rich_markup(text: str) -> str:
    """Remove simple Rich markup tags from log text."""
    return re.sub(r"\[/?[^\]]*\]", "", text)


class LogActionBar(Horizontal):
    """Small control row for the output box on each screen."""

    DEFAULT_CSS = """
    LogActionBar {
        height: auto;
        margin-top: 1;
        width: 1fr;
    }
    LogActionBar Button {
        min-width: 8;
        width: auto;
    }
    """

    def compose(self) -> ComposeResult:
        yield Button("Clear", id=LOG_CLEAR_ID)
        yield Button("Copy", id=LOG_COPY_ID)
        yield Button("Save Log", id=LOG_SAVE_ID)
        yield Button("Open File", id=LOG_OPEN_LAST_ID)
        yield Button("Open Folder", id=LOG_OPEN_DIR_ID)


class _LogModal(ModalScreen):
    """Modal screen that displays retained log content in a selectable TextArea."""

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
    """Scrollable output panel with bounded retained lines."""

    BINDINGS = [
        Binding("y", "copy_log", "Copy log", show=True),
        Binding("ctrl+c", "copy_log", "Copy log", show=False, priority=True),
        Binding("ctrl+shift+c", "copy_log", "Copy log", show=False, priority=True),
        Binding("e", "view_raw", "Select/copy", show=True),
        Binding("ctrl+l", "clear_log", "Clear", show=False),
    ]

    can_focus = True

    DEFAULT_CSS = """
    LogViewer {
        border: solid $accent;
        height: 1fr;
        scrollbar-size: 1 1;
    }
    """

    def __init__(self, *args, max_retained_lines: int = 1000, **kwargs) -> None:
        kwargs.setdefault("max_lines", max_retained_lines + 5)
        kwargs.setdefault("markup", True)
        super().__init__(*args, **kwargs)
        self.max_retained_lines = max_retained_lines
        self._log_lines: list[str] = []
        self._dropped_count = 0
        self._notified_drop = False
        self._last_output_path: Optional[Path] = None

    def append(self, text: str) -> None:
        """Append text to the log, retaining only the newest configured lines."""
        self._record_path_from_text(text)
        lines = text.splitlines() or [text]
        for line in lines:
            self._append_one(line)

    def set_last_output_path(self, path: str | Path) -> None:
        self._last_output_path = Path(path).expanduser()

    def _append_one(self, text: str) -> None:
        self._log_lines.append(text)
        if len(self._log_lines) > self.max_retained_lines:
            overflow = len(self._log_lines) - self.max_retained_lines
            self._dropped_count += overflow
            del self._log_lines[:overflow]
            if not self._notified_drop:
                self._notified_drop = True
                notice = (
                    f"[yellow]Output is bounded to the last {self.max_retained_lines} "
                    "lines. Full tool artifacts are saved in the output directory.[/]"
                )
                self.write(Text.from_markup(_wrap_display_text(notice)))
        self.write(Text.from_markup(_wrap_display_text(text)))

    def _plain_text(self) -> str:
        retained = "\n".join(strip_rich_markup(line) for line in self._log_lines)
        if self._dropped_count:
            return (
                f"[{self._dropped_count} older line(s) dropped from the visible log]\n"
                f"{retained}"
            )
        return retained

    def action_copy_log(self) -> None:
        if self.copy_log_to_clipboard():
            self.write(Text.from_markup("[dim]Log copied to clipboard.[/]"))

    def copy_log_to_clipboard(self) -> bool:
        """Copy retained plain-text log content to the system clipboard."""
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
            return True
        except Exception as exc:
            self.write(Text.from_markup(f"[red]Clipboard error: {exc}[/]"))
            return False

    def action_view_raw(self) -> None:
        self.app.push_screen(_LogModal(self._plain_text()))

    def action_clear_log(self) -> None:
        self.clear_log()

    def clear_log(self) -> None:
        self._log_lines.clear()
        self._dropped_count = 0
        self._notified_drop = False
        super().clear()

    def save_log(self) -> Optional[Path]:
        """Save retained log content to the configured output directory."""
        try:
            from utils.config import get_output_dir

            outdir = get_output_dir()
            path = artifact_path(outdir, "tui_log", ".txt")
            path.write_text(self._plain_text(), encoding="utf-8")
            self.set_last_output_path(path)
            self.append(f"[green]Log saved: {path.resolve()}[/]")
            return path
        except Exception as exc:
            self.append(f"[red]Could not save log: {exc}[/]")
            return None

    def open_last_output(self) -> None:
        if self._last_output_path is None:
            self.append("[yellow]No saved output file has been recorded yet.[/]")
            return
        self._open_path(self._last_output_path)

    def open_output_folder(self) -> None:
        try:
            from utils.config import get_output_dir

            self._open_path(get_output_dir())
        except Exception as exc:
            self.append(f"[red]Could not open output folder: {exc}[/]")

    def _open_path(self, path: Path) -> None:
        target = path.expanduser()
        if not target.is_absolute():
            target = target.resolve()
        if not target.exists():
            self.append(f"[yellow]Path does not exist: {target}[/]")
            return
        try:
            if platform.system() == "Windows":
                os.startfile(str(target))  # type: ignore[attr-defined]
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target)])
            self.append(f"[dim]Opened: {target}[/]")
        except Exception as exc:
            self.append(f"[red]Could not open {target}: {exc}[/]")

    def _record_path_from_text(self, text: str) -> None:
        plain = strip_rich_markup(text)
        markers = (
            "Saved:",
            "Result saved:",
            "Report saved:",
            "Analysis:",
            "Decompiled:",
            "Log saved:",
        )
        for line in plain.splitlines():
            for marker in markers:
                if marker in line:
                    candidate = line.split(marker, 1)[1].strip().strip('"\'')
                    candidate = candidate.rstrip(".")
                    if candidate:
                        self._last_output_path = Path(candidate).expanduser()


def _wrap_display_text(text: str, width: int = 110) -> str:
    """Wrap very long path- or URL-like lines so scrollbars do not hide them."""
    wrapped: list[str] = []
    for line in text.splitlines() or [text]:
        plain = strip_rich_markup(line)
        if len(plain) <= width:
            wrapped.append(line)
            continue
        if not any(token in plain for token in ("\\", "/", "://")):
            wrapped.append(line)
            continue
        chunks: list[str] = []
        current = ""
        for piece in re.split(r"([\\/])", line):
            if not piece:
                continue
            if len(strip_rich_markup(current + piece)) > width and current:
                chunks.append(current)
                current = piece
            else:
                current += piece
        if current:
            chunks.append(current)
        normalized_chunks: list[str] = []
        for chunk in chunks:
            if len(strip_rich_markup(chunk)) <= width:
                normalized_chunks.append(chunk)
                continue
            start = 0
            while start < len(chunk):
                normalized_chunks.append(chunk[start:start + width])
                start += width
        wrapped.append("\n".join(normalized_chunks))
    return "\n".join(wrapped)
