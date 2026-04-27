"""Input widget with reliable clipboard paste and stable long-value behavior."""

from __future__ import annotations

import sys
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from textual.binding import Binding
from textual.events import Focus
from textual.geometry import Region
from textual.widgets import Input
from textual.widgets._input import Selection


class PasteableInput(Input):
    """Single-line input that normalizes pasted clipboard text.

    Windows conhost can swallow normal terminal paste events, especially in
    elevated PowerShell. These explicit bindings read the Win32 clipboard
    directly and normalize common path formats before insertion.
    """

    BINDINGS = [
        *Input.BINDINGS,
        Binding("ctrl+c", "copy", "Copy", show=False, priority=True),
        Binding("ctrl+v", "paste_clipboard", "Paste", show=False, priority=True),
        Binding("ctrl+shift+v", "paste_clipboard", "Paste", show=False, priority=True),
        Binding("shift+insert", "paste_clipboard", "Paste", show=False, priority=True),
    ]

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("select_on_focus", False)
        super().__init__(*args, **kwargs)

    def on_mount(self) -> None:
        self.show_horizontal_scrollbar = False
        self.show_vertical_scrollbar = False
        try:
            self.styles.scrollbar_size_horizontal = 0
            self.styles.scrollbar_size_vertical = 0
        except Exception:
            pass
        self._update_path_ui(self.value)

    def watch_value(self, value: str) -> None:
        normalized = self.normalize_paste_text(value) if value else ""
        self._update_path_ui(normalized)
        if self._looks_like_path(normalized) and len(normalized) > 48:
            self._snap_cursor_to_end(len(value))

    def action_paste_clipboard(self) -> None:
        text = self._get_clipboard()
        if text:
            self.insert_text_at_cursor(self.normalize_paste_text(text))
            self._snap_cursor_to_end(len(self.value))

    def on_focus(self, event: Focus) -> None:
        if self.value:
            self._snap_cursor_to_end(len(self.value))

    def _update_path_ui(self, value: str) -> None:
        if self._looks_like_path(value):
            self.tooltip = value
            self.add_class("path-value")
        else:
            self.tooltip = None
            self.remove_class("path-value")

    @staticmethod
    def normalize_paste_text(text: str) -> str:
        """Normalize clipboard text so pasted paths work in input fields."""
        cleaned = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.strip() for line in cleaned.split("\n") if line.strip()]
        cleaned = " ".join(lines) if lines else cleaned.strip()
        cleaned = cleaned.strip().strip('"\'')

        if cleaned.lower().startswith("file:"):
            parsed = urlparse(cleaned)
            raw_path = unquote(parsed.path or "")
            if sys.platform == "win32":
                if parsed.netloc:
                    cleaned = f"//{parsed.netloc}{raw_path}"
                else:
                    cleaned = url2pathname(raw_path)
            else:
                cleaned = raw_path

        return cleaned.strip().strip('"\'')

    @staticmethod
    def _looks_like_path(text: str) -> bool:
        return bool(text) and any(token in text for token in ("\\", "/", "://"))

    def _snap_cursor_to_end(self, position: int) -> None:
        try:
            self.selection = Selection.cursor(position)
            self.scroll_to_region(Region(self._cursor_offset, 0, width=1, height=1), force=True, animate=False)
        except Exception:
            return

    @staticmethod
    def _get_clipboard() -> str:
        """Read plain text from the system clipboard on Windows."""
        if sys.platform != "win32":
            return ""
        try:
            import ctypes

            CF_UNICODETEXT = 13
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            if not user32.OpenClipboard(0):
                return ""
            try:
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if not handle:
                    return ""
                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    return ""
                try:
                    return ctypes.c_wchar_p(ptr).value or ""
                finally:
                    kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()
        except Exception:
            return ""
