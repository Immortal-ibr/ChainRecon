"""ChainRecon TUI — main Textual application."""

from __future__ import annotations

import platform

from textual.app import App

from analysis.report_generator import ReportGenerator
from tui.screens.analyze import AnalyzeScreen
from tui.screens.apk import APKScreen
from tui.screens.capture import CaptureScreen
from tui.screens.dashboard import DashboardScreen
from tui.screens.frida import FridaScreen
from tui.screens.network_setup import NetworkSetupScreen
from tui.screens.reports import ReportsScreen
from tui.screens.scan import ScanScreen
from tui.screens.settings import SettingsScreen
from tui.screens.welcome import WelcomeScreen
from tui.screens.custom_script import CustomScriptScreen

CSS = """
Screen {
    background: $surface;
}
#dashboard, #scan-form, #capture-form, #analyze-form, #frida-form,
#apk-form, #reports-form, #settings, #network-setup-form {
    padding: 1 2;
}
#title {
    text-style: bold;
    color: $accent;
    margin-bottom: 1;
}
Input {
    margin-bottom: 1;
}
Select {
    margin-bottom: 1;
}
Button {
    margin: 1 1 0 0;
    min-width: 12;
}
Button.primary {
    color: $text;
}
Label {
    margin-bottom: 0;
}
LogViewer {
    margin-top: 1;
    min-height: 10;
}
RichLog {
    margin-top: 1;
    min-height: 10;
}

/* ---- Admin PowerShell / conhost.exe ASCII fallback ----
   conhost.exe cannot render Unicode box-drawing characters even with VT
   mode.  When WT_SESSION is missing we add .ascii-mode on the App root
   and force every bordered widget to plain ASCII (+, -, |).

   Textual specificity: App.CSS > Widget.DEFAULT_CSS so these win over
   the widget-level border: solid rules.  */
.ascii-mode * {
    scrollbar-size: 1 1;
}
.ascii-mode SelectCurrent {
    border: ascii $accent;
}
.ascii-mode SelectOverlay {
    border: ascii $accent;
}
.ascii-mode Input {
    border: ascii $accent;
}
.ascii-mode Button {
    border: ascii $accent;
}
.ascii-mode LogViewer {
    border: ascii $accent;
}
.ascii-mode RichLog {
    border: ascii $accent;
}
.ascii-mode TextArea {
    border: ascii $accent;
}
.ascii-mode Static {
    border: none;
}
.ascii-mode #welcome-box {
    border: ascii $accent;
}
.ascii-mode #modal-box {
    border: ascii $accent;
}
.ascii-mode #help-box {
    border: ascii $accent;
}
.ascii-mode Vertical {
    border: none;
}
.ascii-mode Horizontal {
    border: none;
}
"""


class ChainReconApp(App):
    """The ChainRecon TUI."""

    TITLE = "ChainRecon"
    SUB_TITLE = "IoT Security Assessment Framework"
    CSS = CSS

    SCREENS = {
        "dashboard": DashboardScreen,
        "scan": ScanScreen,
        "capture": CaptureScreen,
        "analyze": AnalyzeScreen,
        "frida": FridaScreen,
        "apk": APKScreen,
        "reports": ReportsScreen,
        "settings": SettingsScreen,
        "network_setup": NetworkSetupScreen,
        "custom_script": CustomScriptScreen,
    }

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # Shared report generator that screens can populate
        self._report_gen = ReportGenerator()
        # OS mode — set by WelcomeScreen, defaults to current platform
        self.os_mode: str = platform.system() if platform.system() in ("Windows", "Linux") else "Linux"

    def on_mount(self) -> None:
        import os
        import sys
        # In admin PowerShell (conhost.exe), WT_SESSION is not set.
        # Unicode box-drawing characters don't render even with VT mode,
        # so fall back to ASCII-only borders.
        if sys.platform == "win32" and not os.environ.get("WT_SESSION"):
            self.add_class("ascii-mode")
        # Show OS selection first, then fall through to dashboard
        self.push_screen("dashboard")
        self.push_screen(WelcomeScreen())


def run_tui() -> None:
    """Entry-point called from the CLI."""
    import sys
    import os
    # Ensure UTF-8 output — required for Unicode box-drawing in older
    # Windows console hosts (conhost.exe / admin PowerShell).
    if sys.platform == "win32":
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, IOError):
            pass
        # Enable Virtual Terminal Processing + set UTF-8 codepage so that
        # Unicode box-drawing characters render correctly in conhost.exe.
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)  # UTF-8
            kernel32.SetConsoleCP(65001)
            # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            STDOUT_HANDLE = kernel32.GetStdHandle(-11)
            kernel32.SetConsoleMode(STDOUT_HANDLE, 0x0007)
        except Exception:
            pass
    ChainReconApp().run()
