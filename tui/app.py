"""ChainRecon TUI main application."""

from __future__ import annotations

import platform

from textual.app import App
from textual.binding import Binding
from textual.widgets import Button, TextArea

from analysis.report_generator import ReportGenerator
from tui.screens.analyze import AnalyzeScreen
from tui.screens.apk import APKScreen
from tui.screens.capture import CaptureScreen
from tui.screens.community_plugins import CommunityPluginsScreen
from tui.screens.custom_script import CustomScriptScreen
from tui.screens.dashboard import DashboardScreen
from tui.screens.device_profiles import DeviceProfilesScreen
from tui.screens.firmware import FirmwareScreen
from tui.screens.frida import FridaScreen
from tui.screens.network_setup import NetworkSetupScreen
from tui.screens.reports import ReportsScreen
from tui.screens.scan import ScanScreen
from tui.screens.settings import SettingsScreen
from tui.screens.welcome import WelcomeScreen
from tui.screens.workflow import WorkflowScreen
from tui.widgets.log_viewer import (
    LOG_CLEAR_ID,
    LOG_COPY_ID,
    LOG_OPEN_DIR_ID,
    LOG_OPEN_LAST_ID,
    LOG_SAVE_ID,
    LogViewer,
)

CSS = """
Screen {
    background: $surface;
    overflow-x: hidden;
}
#dashboard, #scan-form, #capture-form, #analyze-form, #frida-form,
#apk-form, #reports-form, #settings, #network-setup-form,
#custom-script-form {
    padding: 1 6 1 2;
}
#title {
    text-style: bold;
    color: $accent;
    margin-bottom: 1;
}
Input {
    margin-bottom: 1;
    width: 1fr;
    padding-right: 1;
    min-width: 0;
    overflow-x: hidden;
    scrollbar-size: 0 0;
    scrollbar-background: transparent;
    scrollbar-background-hover: transparent;
    scrollbar-background-active: transparent;
    scrollbar-color: transparent;
    scrollbar-color-hover: transparent;
    scrollbar-color-active: transparent;
    scrollbar-corner-color: transparent;
}
.path-value {
    margin-right: 0;
    scrollbar-size: 0 0;
}
Select {
    margin-bottom: 1;
    width: 1fr;
    min-width: 0;
}
SelectCurrent, SelectOverlay {
    scrollbar-background: transparent;
    scrollbar-background-hover: transparent;
    scrollbar-background-active: transparent;
    scrollbar-color: transparent;
    scrollbar-color-hover: transparent;
    scrollbar-color-active: transparent;
    scrollbar-corner-color: transparent;
}
Button {
    margin: 1 1 0 0;
    min-width: 8;
    width: auto;
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
Horizontal {
    height: auto;
    width: 1fr;
    dock: none;
    overflow-x: hidden;
}
VerticalScroll {
    height: 1fr;
    width: 1fr;
    padding-right: 7;
    scrollbar-gutter: stable;
    overflow-x: hidden;
}
Vertical {
    width: 1fr;
    min-width: 0;
    overflow-x: hidden;
}
Static {
    width: 1fr;
    min-width: 0;
    overflow-x: hidden;
}
Label {
    width: 1fr;
    overflow-x: hidden;
}
#dashboard Label,
#dashboard Static {
    overflow-x: hidden;
}
Footer {
    overflow-x: hidden;
}

/* Admin PowerShell / conhost.exe ASCII fallback.
   conhost.exe can render borders poorly. When WT_SESSION is missing we
   add .ascii-mode on the App root and force bordered widgets to ASCII. */
.ascii-mode * {
    scrollbar-size: 1 1;
}
.ascii-mode VerticalScroll {
    scrollbar-background: transparent;
    scrollbar-background-hover: transparent;
    scrollbar-background-active: transparent;
    scrollbar-color: transparent;
    scrollbar-color-hover: transparent;
    scrollbar-color-active: transparent;
    scrollbar-corner-color: transparent;
}
.ascii-mode SelectCurrent {
    border: ascii $accent;
}
.ascii-mode SelectOverlay {
    border: ascii $accent;
}
.ascii-mode Input {
    border: ascii $accent;
    scrollbar-size: 0 0;
    scrollbar-background: transparent;
    scrollbar-background-hover: transparent;
    scrollbar-background-active: transparent;
    scrollbar-color: transparent;
    scrollbar-color-hover: transparent;
    scrollbar-color-active: transparent;
    scrollbar-corner-color: transparent;
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
.ascii-mode #help-dialog {
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
    BINDINGS = [
        Binding("ctrl+c", "copy_focused", "Copy", show=False, priority=True),
        Binding("ctrl+shift+c", "copy_focused", "Copy", show=False, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=False, priority=True),
    ]

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
        "workflow": WorkflowScreen,
        "firmware": FirmwareScreen,
        "plugins": CommunityPluginsScreen,
        "profiles": DeviceProfilesScreen,
    }

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._report_gen = ReportGenerator()
        self.os_mode: str = platform.system() if platform.system() in ("Windows", "Linux") else "Linux"

    def on_mount(self) -> None:
        import os
        import sys

        if sys.platform == "win32" and not os.environ.get("WT_SESSION"):
            self.add_class("ascii-mode")
        self.push_screen("dashboard")
        self.push_screen(WelcomeScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle shared log action buttons that bubble up from screens."""
        if event.button.id not in {
            LOG_CLEAR_ID,
            LOG_COPY_ID,
            LOG_SAVE_ID,
            LOG_OPEN_LAST_ID,
            LOG_OPEN_DIR_ID,
        }:
            return

        log = self._active_log_viewer()
        if log is None:
            return
        event.stop()
        if event.button.id == LOG_CLEAR_ID:
            log.clear_log()
        elif event.button.id == LOG_COPY_ID:
            log.action_copy_log()
        elif event.button.id == LOG_SAVE_ID:
            log.save_log()
        elif event.button.id == LOG_OPEN_LAST_ID:
            log.open_last_output()
        elif event.button.id == LOG_OPEN_DIR_ID:
            log.open_output_folder()

    def action_copy_focused(self) -> None:
        """Copy from the focused widget without letting Ctrl+C terminate."""
        focused = self.focused
        if isinstance(focused, LogViewer):
            focused.action_copy_log()
            return
        if isinstance(focused, TextArea):
            focused.action_copy()
            return
        if hasattr(focused, "action_copy"):
            try:
                focused.action_copy()  # type: ignore[attr-defined]
                return
            except Exception:
                pass
        log = self._active_log_viewer()
        if log is not None:
            log.action_copy_log()

    def _active_log_viewer(self) -> LogViewer | None:
        try:
            focused = self.focused
            if isinstance(focused, LogViewer):
                return focused
            logs = list(self.screen.query(LogViewer))
            return logs[-1] if logs else None
        except Exception:
            return None


def run_tui() -> None:
    """Entry point called from the CLI."""
    import os
    import signal
    import sys

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if sys.platform == "win32":
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, IOError):
            pass
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            stdin_handle = kernel32.GetStdHandle(-10)
            stdout_handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(stdin_handle, ctypes.byref(mode)):
                # Disable processed input so Ctrl+C reaches the TUI as a key event.
                kernel32.SetConsoleMode(stdin_handle, mode.value & ~0x0001)
            kernel32.SetConsoleMode(stdout_handle, 0x0007)
        except Exception:
            pass
    ChainReconApp().run()
