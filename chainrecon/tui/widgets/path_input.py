"""Filesystem path input with shell-style Tab completion."""

from __future__ import annotations

import os
from pathlib import Path

from textual.binding import Binding

from chainrecon.tui.widgets.pasteable_input import PasteableInput


def path_matches(value: str, *, directories_only: bool = False) -> list[Path]:
    """Return bounded, sorted completions without traversing subdirectories."""
    expanded = Path(os.path.expandvars(value)).expanduser()
    parent = expanded if value.endswith(("/", "\\")) else expanded.parent
    prefix = "" if value.endswith(("/", "\\")) else expanded.name
    if not parent.is_dir():
        return []
    try:
        matches = (
            child for child in parent.iterdir()
            if (not directories_only or child.is_dir())
            and (child.name.casefold().startswith(prefix.casefold()) if os.name == "nt"
                 else child.name.startswith(prefix))
        )
        return sorted(matches, key=lambda child: (not child.is_dir(), child.name.casefold()))[:200]
    except OSError:
        return []


class PathInput(PasteableInput):
    """Complete paths with Tab; repeated Tab cycles ambiguous matches."""

    BINDINGS = [
        *PasteableInput.BINDINGS,
        Binding("tab", "complete_path", "Complete path", priority=True),
        Binding("ctrl+tab", "next_field", "Next field", priority=True),
    ]

    def __init__(self, *args, directories_only: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.directories_only = directories_only
        self._cycle: list[str] = []
        self._cycle_index = -1
        self._cycle_value = ""

    def action_complete_path(self) -> None:
        raw = self.value
        if not raw:
            return
        if self._cycle and raw == self._cycle_value:
            self._cycle_index = (self._cycle_index + 1) % len(self._cycle)
            self._set_completed(self._cycle[self._cycle_index])
            return
        if not self.directories_only and Path(os.path.expandvars(raw)).expanduser().is_file():
            return
        if not raw.endswith(("/", "\\")) and Path(os.path.expandvars(raw)).expanduser().is_dir():
            self._set_completed(raw + os.sep)
            return
        matches = path_matches(raw, directories_only=self.directories_only)
        if not matches:
            return
        options = [str(path) + (os.sep if path.is_dir() else "") for path in matches]
        self._cycle = options
        self._cycle_index = -1
        if len(options) == 1:
            self._set_completed(options[0])
            return
        parent = str(matches[0].parent)
        common = os.path.commonprefix([path.name for path in matches])
        if len(common) > len(Path(raw).name):
            self._set_completed(str(Path(parent) / common))
            return
        self._cycle_index = 0
        self._set_completed(options[0])

    def _set_completed(self, value: str) -> None:
        self.value = value
        self.cursor_position = len(value)
        self._cycle_value = value

    def action_next_field(self) -> None:
        self.screen.focus_next()
