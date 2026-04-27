"""Device Profiles screen -- browse and select shared device profiles."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, Static

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogActionBar, LogViewer

HELP_TEXT = """[bold underline]Device Profiles[/]

Device profiles are YAML files in profiles/devices/ that describe a specific
IoT device: its expected ports, protocols, default scan settings, Frida
target, firmware analysis rules, and report metadata.

[bold]Profile schema[/]
  name              -- display name (e.g. "Nooie Lab Device")
  vendor            -- manufacturer name
  model             -- device model
  target            -- default IP or hostname
  ports             -- list of expected open ports
  expected_protocols -- list of expected protocols (http, mqtt, rtsp ...)
  scan_defaults     -- {profile: iot, interface: Ethernet}
  frida_defaults    -- {target: com.nooie.home}
  firmware_rules    -- {keywords: [...], domains: [...], urls: [...]}

[bold]How profiles are used[/]
  - Workflow engine: pass --device-profile nooie to inject defaults
  - Firmware screen: profile firmware_rules match against extracted content
  - Workflow screen: device-profile selector pulls from this list
  - Reports: device_profile section records which profile was active

[bold]Creating a profile[/]
  Copy profiles/devices/generic_camera.yaml, fill in your device details,
  and save it in the same folder.  It will appear here on next load.

[bold]Selecting an active profile[/]
  Pressing "Set as Active" stores the selected profile name in the session.
  The Workflow and Firmware screens will pre-select it on next open.

[bold]Sharing profiles[/]
  Profiles should NOT contain secrets (passwords, API keys, private IPs
  that could identify your internal network).  The sample profiles use
  192.168.123.99 as a placeholder -- change it to your actual device before
  running live tests, and do not commit real IPs to a public repository.

[dim]To edit this screen: tui/screens/device_profiles.py[/]
"""


class DeviceProfilesScreen(Screen):
    HELP_TEXT = HELP_TEXT
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "toggle_help", "Help"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            with Vertical(id="profiles-form"):
                yield Label("[bold]Device Profiles[/]", id="title")
                yield Label("Available Profiles")
                yield Select([], id="profile-select", allow_blank=True)
                yield Static("", id="profile-detail")
                with Horizontal():
                    yield Button("Set as Active", id="set-active", variant="primary")
                    yield Button("Refresh", id="refresh-profiles")
                    yield Button("Back", id="back-btn")
                yield LogActionBar()
                yield LogViewer(id="profiles-log")
        yield Footer()

    def on_mount(self) -> None:
        self._profiles: list = []
        self._active_profile: str | None = None
        self._load_profiles()

    def _load_profiles(self) -> None:
        log = self.query_one(LogViewer)
        try:
            from utils.config import list_device_profiles
            self._profiles = list_device_profiles()
        except Exception as exc:
            log.append(f"[yellow]Could not load profiles:[/] {exc}")
            self._profiles = []

        if self._profiles:
            options = [(f"{p['name']} ({p.get('vendor', '?')} / {p.get('model', '?')})", p.get("stem") or p["name"]) for p in self._profiles]
            self.query_one("#profile-select", Select).set_options(options)
            log.append(f"Loaded {len(self._profiles)} device profile(s).")
        else:
            log.append("[dim]No device profiles found in profiles/devices/.[/]")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "profile-select":
            return
        detail = self.query_one("#profile-detail", Static)
        if event.value in (Select.BLANK, None):
            detail.update("")
            return
        profile = next((p for p in self._profiles if (p.get("stem") or p["name"]) == event.value), None)
        if profile:
            lines = [
                f"[bold]{profile.get('name')}[/]",
                f"Vendor: {profile.get('vendor', '?')}  Model: {profile.get('model', '?')}",
                f"Target: {profile.get('target', '?')}",
                f"Ports: {', '.join(str(p) for p in profile.get('ports', []))}",
                f"Protocols: {', '.join(profile.get('expected_protocols', []))}",
                f"Scan profile: {profile.get('scan_defaults', {}).get('profile', '?')}",
                f"Frida target: {profile.get('frida_defaults', {}).get('target', '?')}",
            ]
            rules = profile.get("firmware_rules", {})
            if rules:
                rule_parts = []
                for k, v in rules.items():
                    if isinstance(v, list):
                        rule_parts.append(f"{k}: {', '.join(str(i) for i in v[:3])}")
                    else:
                        rule_parts.append(f"{k}: {v}")
                lines.append(f"Firmware rules: {'; '.join(rule_parts[:3])}")
            detail.update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "refresh-profiles":
            self._load_profiles()
        elif event.button.id == "set-active":
            self._set_active()

    def _set_active(self) -> None:
        val = self.query_one("#profile-select", Select).value
        if val in (Select.BLANK, None):
            self.query_one(LogViewer).append("[red]Select a profile first.[/]")
            return
        self._active_profile = str(val)
        # Store on app for other screens to read
        if hasattr(self, "app"):
            self.app._active_device_profile = self._active_profile  # type: ignore[attr-defined]
        self.query_one(LogViewer).append(f"[green]Active profile set:[/] {self._active_profile}")

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Device Profiles"))
