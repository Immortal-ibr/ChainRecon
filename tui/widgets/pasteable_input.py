"""Input widget with reliable clipboard paste on Windows console hosts."""

from __future__ import annotations

import sys
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from textual.binding import Binding
from textual.widgets import Input


class PasteableInput(Input):
    """Single-line input that normalizes pasted clipboard text.

    Windows conhost can swallow normal terminal paste events, especially in
    elevated PowerShell. These explicit bindings read the Win32 clipboard
    directly and normalize common path formats before insertion.
    """

    BINDINGS = [
        *Input.BINDINGS,
        Binding("ctrl+v", "paste_clipboard", "Paste", show=False, priority=True),
        Binding("ctrl+shift+v", "paste_clipboard", "Paste", show=False, priority=True),
        Binding("shift+insert", "paste_clipboard", "Paste", show=False, priority=True),
    ]

    def action_paste_clipboard(self) -> None:
        text = self._get_clipboard()
        if text:
            self.insert_text_at_cursor(self.normalize_paste_text(text))

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
