"""Keyboard-accessible case chooser with a small local recent-case list."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Collapsible, DirectoryTree, Input, Label, Select, Static

from chainrecon.case_model import Case
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.path_input import PathInput
from chainrecon.utils.config import get_case_directory, user_data_dir


HELP_TEXT = """An investigation is one folder for imported files, analysis runs,
reviewer decisions, and reports. Choose an existing folder or create one.

Ctrl+O opens the investigation in the path field. Ctrl+N creates one there.
In the folder browser, use arrow keys to move and Enter to select a folder.
The current and recent investigations can be selected without typing a path.
"""


def _recent_file() -> Path:
    return user_data_dir() / "recent_cases.json"


def recent_cases() -> list[Path]:
    """Read local case shortcuts; a corrupt or stale list never blocks the UI."""
    try:
        values = json.loads(_recent_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(values, list):
        return []
    result: list[Path] = []
    for value in values[:20]:
        if not isinstance(value, str):
            continue
        try:
            path = Path(value).expanduser()
        except (OSError, ValueError):
            continue
        if path.is_absolute() and (path / "case.json").is_file() and path not in result:
            result.append(path)
    return result[:8]


def remember_case(path: Path) -> None:
    """Keep a bounded per-user history outside portable case folders."""
    path = path.expanduser().resolve()
    entries = [path, *(item for item in recent_cases() if item != path)][:8]
    destination = _recent_file()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".recent_cases.", dir=destination.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump([str(item) for item in entries], handle, indent=2)
                handle.write("\n")
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except OSError:
        # A read-only profile should not prevent opening a case.
        return


class CasePickerScreen(ModalScreen[str | None]):
    """Choose an existing case or create one in a folder."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+o", "open_case", "Open"),
        Binding("ctrl+n", "create_case", "Create"),
        Binding("question_mark", "toggle_help", "Help"),
    ]
    DEFAULT_CSS = """
    CasePickerScreen { align: center middle; }
    CasePickerScreen #picker-dialog {
        width: 88; max-width: 96%; height: 22; max-height: 96%;
        border: round $accent; background: $surface; padding: 0 2;
    }
    CasePickerScreen #picker-title { text-style: bold; color: $accent; height: 1; margin: 1 0; }
    CasePickerScreen #picker-body { height: 1fr; padding-right: 1; }
    CasePickerScreen #picker-status { color: $warning; height: 1; }
    CasePickerScreen #folder-tree { height: 8; }
    CasePickerScreen #picker-actions { height: 3; }
    CasePickerScreen #picker-actions Button { margin: 0 1 0 0; }
    CasePickerScreen #picker-keys { height: 2; color: $text-muted; }
    CasePickerScreen #picker-body Collapsible { margin: 0; }
    """

    def __init__(self, current: Path | None = None) -> None:
        super().__init__()
        self._current = current

    def compose(self) -> ComposeResult:
        configured = get_case_directory()
        initial = self._current or configured
        root = initial.parent if initial else Path.home()
        while not root.is_dir() and root != root.parent:
            root = root.parent
        if not root.is_dir():
            root = Path.home()
        choices: list[tuple[str, str]] = []
        seen: set[Path] = set()
        for label, path in (
            ("Current", self._current), ("Configured default", configured),
            *(("Recent", item) for item in recent_cases()),
        ):
            if path is None or path in seen or not (path / "case.json").is_file():
                continue
            choices.append((f"{label}: {path.name}  —  {path.parent}", str(path)))
            seen.add(path)
        with Vertical(id="picker-dialog"):
            yield Static("Choose investigation folder", id="picker-title")
            with VerticalScroll(id="picker-body"):
                if choices:
                    yield Label("Current and recent investigations")
                    yield Select(choices, prompt="Choose a recent investigation", id="recent-cases")
                yield Label("Folder path")
                yield PathInput(
                    value=str(initial) if initial else "",
                    placeholder="Type a folder path; Tab completes it",
                    directories_only=True,
                    id="folder-path",
                )
                with Collapsible(title="Browse folders with arrow keys", collapsed=True, id="browse-section"):
                    yield DirectoryTree(root, id="folder-tree")
                yield Label("New investigation name (optional)")
                yield Input(placeholder="Uses the folder name when blank", id="new-case-title")
            yield Static("", id="picker-status")
            with Horizontal(id="picker-actions"):
                yield Button("Open investigation", id="picker-open", variant="primary")
                yield Button("Create investigation", id="picker-create")
                yield Button("Cancel", id="picker-cancel")
            yield Static("Tab: complete path · Ctrl+Tab: next field · ↑↓: browse · F1: keyboard help", id="picker-keys")

    def on_mount(self) -> None:
        self.query_one("#folder-path", PathInput).focus()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Investigation folder"))

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "recent-cases" and isinstance(event.value, str):
            self.query_one("#folder-path", PathInput).value = event.value
            self._set_status("Ready to open the selected investigation.")

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.query_one("#folder-path", PathInput).value = str(event.path)
        self._set_status("Folder selected. Press Ctrl+O to open or Ctrl+N to create.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "picker-open":
                self.action_open_case()
            case "picker-create":
                self.action_create_case()
            case "picker-cancel":
                self.action_cancel()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "folder-path":
            self.action_open_case()
        elif event.input.id == "new-case-title":
            self.action_create_case()

    def _path(self) -> Path | None:
        raw = self.query_one("#folder-path", PathInput).value.strip()
        if not raw:
            self._set_status("Choose a folder first.")
            self.query_one("#folder-path", PathInput).focus()
            return None
        return Path(os.path.expandvars(raw)).expanduser()

    def _set_status(self, message: str) -> None:
        status = self.query_one("#picker-status", Static)
        status.update(escape(message))
        status.tooltip = message

    def action_open_case(self) -> None:
        path = self._path()
        if path is None:
            return
        try:
            case = Case.open(path)
        except FileNotFoundError:
            self._set_status("No investigation in that folder. Use Create investigation to start one.")
            return
        except (OSError, ValueError, KeyError) as exc:
            self._set_status(f"Cannot open investigation: {exc}")
            return
        remember_case(case.root)
        self.dismiss(str(case.root))

    def action_create_case(self) -> None:
        path = self._path()
        if path is None:
            return
        title = self.query_one("#new-case-title", Input).value.strip() or path.name or "Untitled investigation"
        try:
            case = Case.create(path, title)
        except FileExistsError:
            self._set_status("An investigation exists in that folder. Use Open investigation.")
            return
        except (OSError, ValueError) as exc:
            self._set_status(f"Cannot create investigation: {exc}")
            return
        remember_case(case.root)
        self.dismiss(str(case.root))

    def action_cancel(self) -> None:
        self.dismiss(None)
