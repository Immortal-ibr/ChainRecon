"""A focused home for the current investigation and daily tools."""

from __future__ import annotations

from pathlib import Path

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Collapsible, Header, Static

from chainrecon.case_model import Case
from chainrecon.tui.screens.case_analysis import ANALYSIS_VIEWS, CaseAnalysisScreen
from chainrecon.tui.screens.case_picker import CasePickerScreen
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter

HELP_TEXT = """[bold]ChainRecon[/]

[bold]Investigation[/] is one folder for copied source files, analysis runs,
finding reviews, and reports. Use Files & findings to import files or review
results. Switch investigation to work in a different folder.

[bold]Analysis[/] starts with the file type: firmware, packet capture, Android
APK, Nmap XML, or Frida log. Import that file first. Packet and APK screens
also link to optional standalone specialist tools.

[bold]Reports[/] exports the active investigation by default. You can choose
session or saved standalone results there instead.

[bold]Live work[/] starts a device scan, traffic capture, or Frida session.
Use More tools for settings and extensions.

[bold]Keys[/]  i investigation   f firmware   p packets   k APK
        r reports         s scan       c capture   F1 help   q quit

Each tool has its own help page. Press Esc to return here.
"""


_BUTTON_ROUTES = {
    "home-case": "case",
    "home-scan": "scan",
    "home-capture": "capture",
    "home-frida": "frida",
    "home-workflow": "workflow",
    "home-reports": "reports",
    "home-network": "network_setup",
    "home-scripts": "custom_script",
    "home-plugins": "plugins",
    "home-profiles": "profiles",
    "home-settings": "settings",
}
_ANALYSIS_BUTTONS = {
    "home-firmware": "firmware",
    "home-packets": "packets",
    "home-android": "apk",
    "home-nmap": "scan",
    "home-frida-log": "frida",
}


class DashboardScreen(Screen):
    """Show the active case first, with specialist tools one step away."""

    BINDINGS = [
        Binding("i", "app.push_screen('case')", "Investigation"),
        Binding("f", "open_view('firmware')", "Firmware", show=False),
        Binding("p", "open_view('packets')", "Packets", show=False),
        Binding("k", "open_view('apk')", "APK", show=False),
        Binding("s", "app.push_screen('scan')", "Scan", show=False),
        Binding("c", "app.push_screen('capture')", "Capture", show=False),
        Binding("question_mark", "toggle_help", "Help", show=False),
        Binding("q", "app.quit", "Quit"),
        Binding("w", "app.push_screen('workflow')", "Workflow", show=False),
        Binding("r", "app.push_screen('reports')", "Reports", show=False),
        Binding("n", "app.push_screen('network_setup')", "Network", show=False),
        Binding("x", "app.push_screen('custom_script')", "Scripts", show=False),
        Binding("d", "app.push_screen('profiles')", "Profiles", show=False),
        Binding("t", "app.push_screen('settings')", "Settings", show=False),
    ]

    DEFAULT_CSS = """
    DashboardScreen #dashboard { padding: 0 2; }
    DashboardScreen #active-case {
        height: auto; background: $panel; border-left: solid $accent;
        padding: 0 2; margin: 0;
    }
    DashboardScreen #case-eyebrow, DashboardScreen .section-label {
        color: $text-muted; text-style: bold; height: 1;
    }
    DashboardScreen #case-name { text-style: bold; height: 1; }
    DashboardScreen #case-meta, DashboardScreen #case-location {
        color: $text-muted; height: 1; overflow: hidden;
    }
    DashboardScreen #case-location { display: none; }
    DashboardScreen #home-case, DashboardScreen #home-switch { margin: 0 1 0 0; }
    DashboardScreen .home-row { height: auto; }
    DashboardScreen #more-tools { margin-top: 0; }
    DashboardScreen #more-tools .section-label { margin: 1 0 1 0; }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="dashboard"):
            with Vertical(id="active-case"):
                yield Static("INVESTIGATION FOLDER", id="case-eyebrow")
                yield Static("", id="case-name")
                yield Static("", id="case-meta")
                yield Static("", id="case-location")
                with Horizontal(classes="home-row"):
                    yield Button("Files & findings", id="home-case", variant="primary")
                    yield Button("Switch investigation", id="home-switch")
            yield Static("ANALYSIS", classes="section-label")
            with Horizontal(classes="home-row"):
                yield Button("Firmware / flash", id="home-firmware")
                yield Button("Packet captures", id="home-packets")
                yield Button("Android APK", id="home-android")
            with Horizontal(classes="home-row"):
                yield Button("Nmap XML", id="home-nmap")
                yield Button("Frida logs", id="home-frida-log")
            yield Static("REPORTS", classes="section-label")
            with Horizontal(classes="home-row"):
                yield Button("Reports", id="home-reports")
            yield Static("DEVICE WORK & WORKFLOWS", classes="section-label")
            with Horizontal(classes="home-row"):
                yield Button("Scan device", id="home-scan")
                yield Button("Capture traffic", id="home-capture")
                yield Button("Frida session", id="home-frida")
                yield Button("Run workflow", id="home-workflow")
            with Collapsible(title="More tools", collapsed=True, id="more-tools"):
                yield Static("SETUP AND EXTENSIONS", classes="section-label")
                with Horizontal(classes="home-row"):
                    yield Button("Network setup", id="home-network")
                    yield Button("Custom scripts", id="home-scripts")
                    yield Button("Plugins", id="home-plugins")
                with Horizontal(classes="home-row"):
                    yield Button("Device profiles", id="home-profiles")
                    yield Button("Settings and tools", id="home-settings")
        yield HelpFooter()

    def on_mount(self) -> None:
        self._refresh_case()

    def on_screen_resume(self) -> None:
        self._refresh_case()

    def _refresh_case(self) -> None:
        name = self.query_one("#case-name", Static)
        meta = self.query_one("#case-meta", Static)
        location = self.query_one("#case-location", Static)
        button = self.query_one("#home-case", Button)
        raw_path = getattr(self.app, "_case_path", None)
        if not raw_path:
            name.update("No investigation selected")
            meta.update("Choose a folder to keep imported files, runs, and reports together.")
            location.update("")
            button.label = "Files & findings"
            return
        path = Path(raw_path).expanduser()
        location.update(escape(_short_path(path)))
        location.tooltip = str(path)
        name.tooltip = str(path)
        try:
            case = Case.open(path)
        except (OSError, ValueError, KeyError):
            name.update("Investigation folder needs setup")
            meta.update("Switch investigation to open or create a folder.")
            button.label = "Files & findings"
            return
        manifest = case.manifest
        name.update(escape(str(manifest["title"])))
        evidence_count = len(manifest["evidence"])
        run_count = len(manifest["runs"])
        meta.update(f"{evidence_count} files  ·  {run_count} runs")
        button.label = "Files & findings"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id in _ANALYSIS_BUTTONS:
            self.action_open_view(_ANALYSIS_BUTTONS[button_id])
            return
        if button_id == "home-switch":
            self.action_switch_investigation()
            return
        route = _BUTTON_ROUTES.get(button_id)
        if route:
            self.app.push_screen(route)

    def action_open_view(self, view: str) -> None:
        if view not in ANALYSIS_VIEWS:
            raise ValueError(f"Unknown analysis view: {view}")
        self.app.push_screen(CaseAnalysisScreen(view=view))

    def action_switch_investigation(self) -> None:
        raw = getattr(self.app, "_case_path", None)
        current = Path(raw) if raw and (Path(raw) / "case.json").is_file() else None
        self.app.push_screen(CasePickerScreen(current=current), self._investigation_chosen)

    def _investigation_chosen(self, path: str | None) -> None:
        if path:
            setattr(self.app, "_case_path", path)
            self._refresh_case()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="ChainRecon"))


def _short_path(path: Path, *, limit: int = 64) -> str:
    value = str(path)
    return value if len(value) <= limit else "…" + value[-(limit - 1):]
