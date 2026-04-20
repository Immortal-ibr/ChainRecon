"""PasteableInput — Input widget with reliable Ctrl+V paste on Windows conhost."""

from __future__ import annotations

import sys

from textual.binding import Binding
from textual.widgets import Input


class PasteableInput(Input):
    """An Input widget that reads from the clipboard on Ctrl+V.

    On Windows conhost.exe (e.g. admin PowerShell without Windows Terminal),
    the standard Ctrl+V paste may be swallowed by the terminal host or not
    forwarded to the Textual app.  This subclass intercepts Ctrl+V and reads
    from the clipboard directly via the Win32 API so pasting always works.
    """

    BINDINGS = [
        *Input.BINDINGS,
        Binding("ctrl+v", "paste_clipboard", "Paste", show=False),
    ]

    def action_paste_clipboard(self) -> None:
        text = self._get_clipboard()
        if text:
            # Strip surrounding quotes that Windows Explorer adds to paths
            cleaned = text.strip().strip('"\'')
            self.insert_text_at_cursor(cleaned)

    @staticmethod
    def _get_clipboard() -> str:
        """Read plain text from the system clipboard."""
        if sys.platform != "win32":
            # On non-Windows, fall back to doing nothing (terminal handles paste)
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
