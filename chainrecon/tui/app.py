"""ChainRecon TUI main application."""

from __future__ import annotations

import platform

# catch for missing textual

try:
   from textual.app import App
except ImportError:
   print("Can't launch TUI, is textual available on this system?")
   raise SystemExit

from textual.binding import Binding
from textual.widgets import Button, TextArea

from chainrecon.analysis.report_generator import ReportGenerator
from chainrecon.tui.screens.analyze import AnalyzeScreen
from chainrecon.tui.screens.apk import APKScreen
from chainrecon.tui.screens.capture import CaptureScreen
from chainrecon.tui.screens.case import CaseScreen
from chainrecon.tui.screens.case_analysis import CaseAnalysisScreen
from chainrecon.tui.screens.community_plugins import CommunityPluginsScreen
from chainrecon.tui.screens.custom_script import CustomScriptScreen
from chainrecon.tui.screens.dashboard import DashboardScreen
from chainrecon.tui.screens.device_profiles import DeviceProfilesScreen
from chainrecon.tui.screens.frida import FridaScreen
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.screens.network_setup import NetworkSetupScreen
from chainrecon.tui.screens.reports import ReportsScreen
from chainrecon.tui.screens.scan import ScanScreen
from chainrecon.tui.screens.settings import SettingsScreen
from chainrecon.tui.screens.workflow import WorkflowScreen
from chainrecon.tui.widgets.log_viewer import (
    LOG_CLEAR_ID,
    LOG_COPY_ID,
    LOG_OPEN_DIR_ID,
    LOG_OPEN_LAST_ID,
    LOG_SAVE_ID,
    LogViewer,
)

_DISABLE_MOUSE_REPORTING = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l"


def disable_terminal_mouse_reporting() -> None:
    """Clear leaked mouse tracking modes before raw events can echo as text."""
    try:
        import sys

        if not getattr(sys.stdout, "isatty", lambda: False)():
            return
        sys.stdout.write(_DISABLE_MOUSE_REPORTING)
        sys.stdout.flush()
    except Exception:
        pass


CSS = """
Screen {
    background: $surface;
    overflow-x: hidden;
}
#dashboard, #scan-form, #capture-form, #analyze-form, #frida-form,
#apk-form, #reports-form, #settings, #network-setup-form,
#custom-script-form, #workflow-form, #plugins-form,
#profiles-form {
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
#reports-form { padding: 0 2 1 2; }
#reports-form Input, #reports-form Select { margin-bottom: 0; }
#reports-form Button { margin: 0 1 0 0; }
#report-source-detail { height: 1; color: $text-muted; overflow: hidden; }
DashboardScreen .home-row Button {
    width: 1fr;
    min-width: 0;
    margin: 0 1 0 0;
}
FridaScreen #frida-form { padding: 0 2; }
FridaScreen #title, FridaScreen #frida-form Input,
FridaScreen #frida-form Select { margin-bottom: 0; }
FridaScreen #frida-form Button { margin: 0 1 0 0; }
CaptureScreen #capture-form { padding: 0 2; }
CaptureScreen #capture-form Input, CaptureScreen #capture-form Select { margin-bottom: 0; }
CaptureScreen #capture-form Button { margin: 0 1 0 0; }
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
    padding-right: 1;
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
HelpFooter HelpShortcut {
    dock: right;
    width: 9;
    min-width: 9;
    height: 1;
    padding: 0 1;
    color: $footer-foreground;
    background: $footer-description-background;
}

/* Optional ASCII fallback for terminals that cannot render box characters. */
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
    SUB_TITLE = "Investigation workspace"
    CSS = CSS
    BINDINGS = [
        Binding("tab", "focus_next", "Next field"),
        Binding("f1", "keyboard_help", "Help", show=False, priority=True),
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
        "plugins": CommunityPluginsScreen,
        "profiles": DeviceProfilesScreen,
        "case": CaseScreen,
        "case_analysis": CaseAnalysisScreen,
    }

    def __init__(self, case_path: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._open_case_on_start = bool(case_path)
        if case_path is None:
            from chainrecon.utils.config import get_case_directory

            configured = get_case_directory()
            case_path = str(configured) if configured is not None else None
        self._case_path = case_path
        self._report_gen = ReportGenerator()
        self._active_device_profile: str | None = None
        self.os_mode: str = platform.system() if platform.system() in ("Windows", "Linux") else "Linux"

    def on_mount(self) -> None:
        import os
        import sys

        if sys.platform == "win32":
            from textual.drivers.windows_driver import WindowsDriver

            if isinstance(self._driver, WindowsDriver):
                # Keep clicks and drags, but stop the flood of SGR mouse-move
                # reports that some Windows terminals reissue as typed text.
                self._driver.write("\x1b[?1003l\x1b[?1002h")
                self._driver.flush()
        if sys.platform == "win32" and os.environ.get("CHAINRECON_ASCII_UI") == "1":
            self.add_class("ascii-mode")
        self.push_screen("dashboard")
        if self._open_case_on_start:
            self.push_screen("case")

    def action_keyboard_help(self) -> None:
        """Show navigation keys and the active screen's contextual help."""
        if isinstance(self.screen, HelpScreen):
            return
        show_help = getattr(self.screen, "action_toggle_help", None)
        if callable(show_help):
            show_help()
        else:
            self.push_screen(HelpScreen("", title="Keyboard guide"))

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
        if focused is not None and hasattr(focused, "action_copy"):
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


def run_tui(case_path: str | None = None) -> None:
    """Entry point called from the CLI."""
    import os
    import signal
    import sys

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if sys.platform == "win32":
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")
        for stream in (sys.stdout, sys.stderr):
            try:
                reconfigure = getattr(stream, "reconfigure", None)
                if reconfigure is not None:
                    reconfigure(encoding="utf-8", errors="replace")
            except IOError:
                pass
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            stdin_handle = kernel32.GetStdHandle(-10)
            stdout_handle = kernel32.GetStdHandle(-11)
            stderr_handle = kernel32.GetStdHandle(-12)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(stdin_handle, ctypes.byref(mode)):
                # Disable processed input so Ctrl+C reaches the TUI as a key event.
                kernel32.SetConsoleMode(stdin_handle, mode.value & ~0x0001)
            if kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(stdout_handle, mode.value | 0x0004)
            if kernel32.GetConsoleMode(stderr_handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(stderr_handle, mode.value | 0x0004)
        except Exception:
            pass
        os.system("cls")
    disable_terminal_mouse_reporting()
    try:
        ChainReconApp(case_path=case_path).run()
    finally:
        disable_terminal_mouse_reporting()
