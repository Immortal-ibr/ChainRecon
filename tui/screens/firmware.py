"""Firmware screen -- extract and inspect firmware images."""

from __future__ import annotations

import threading

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogActionBar, LogViewer
from tui.widgets.pasteable_input import PasteableInput as Input
from utils.config import get_output_dir, list_device_profiles

HELP_TEXT = """[bold underline]Firmware Analysis[/]

Extracts and inspects a firmware image using binwalk, then scans the
extracted filesystem for credentials, private keys, certificates, password
databases, and embedded network endpoints.

[bold]What to provide[/]
  Firmware Image -- path to the firmware binary (.bin, .img, .tar.gz, etc.)
  Extract Dir    -- where to write extracted files.  Leave empty to use a
                   temp directory under your output/ folder.
  Device Profile -- optional; firmware rules from the profile (expected
                   domains/URLs/keywords) are matched against extracted files.
  Output Format  -- json / html / csv / xlsx for the firmware report.

[bold]Requires binwalk[/]
  binwalk must be installed and on PATH.  Install it with:
    pip install binwalk       (Python wrapper)
    sudo apt install binwalk  (Debian/Ubuntu)
    brew install binwalk      (macOS)
  Without binwalk the analyzer will fail with a clear error message.

[bold]What the analyzer finds[/]
  - Files with credential keywords: admin, password, token, secret, mqtt, webrtc
  - PEM private keys (.key files, -----BEGIN PRIVATE KEY-----)
  - Certificates (.crt, .pem, -----BEGIN CERTIFICATE-----)
  - UNIX password/shadow databases
  - Embedded URLs, IP addresses, and domain names
  - Hits against device-profile firmware rules

[bold]Risk levels[/]
  HIGH   -- private keys or shadow/passwd files found
  MEDIUM -- credential strings or hardcoded network endpoints

[bold]Where outputs go[/]
Each run creates a timestamped folder under output/.  A firmware_report.json
is written there alongside the full extracted filesystem.

[dim]To edit this screen: tui/screens/firmware.py[/]
"""


class FirmwareScreen(Screen):
    HELP_TEXT = HELP_TEXT
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "toggle_help", "Help"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            with Vertical(id="firmware-form"):
                yield Label("[bold]Firmware Analysis[/]", id="title")
                yield Label("Firmware Image Path")
                yield Input(placeholder="/path/to/firmware.bin", id="firmware-path")
                yield Label("Extract Directory (optional)")
                yield Input(placeholder="leave empty for auto temp dir", id="extract-dir")
                yield Label("Device Profile (optional)")
                yield Select([], id="firmware-device-profile", allow_blank=True)
                yield Label("Output Format")
                yield Select(
                    [("JSON", "json"), ("HTML", "html"), ("CSV", "csv"), ("XLSX", "xlsx")],
                    id="firmware-format",
                    value="json",
                )
                with Horizontal():
                    yield Button("Analyze Firmware", id="run-firmware", variant="primary")
                    yield Button("Back", id="back-btn")
                yield LogActionBar()
                yield LogViewer(id="firmware-log")
        yield Footer()

    def on_mount(self) -> None:
        self._running = False
        self._populate_device_profiles()

    def _populate_device_profiles(self) -> None:
        try:
            profiles = list_device_profiles()
            options = [("(none)", "__none__")] + [(p["name"], p.get("stem") or p["name"]) for p in profiles]
            self.query_one("#firmware-device-profile", Select).set_options(options)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "run-firmware":
            self._start_analysis()

    def _start_analysis(self) -> None:
        if self._running:
            return
        firmware_path = self.query_one("#firmware-path", Input).value.strip()
        if not firmware_path:
            self.query_one(LogViewer).append("[red]Firmware image path is required.[/]")
            return
        extract_dir = self.query_one("#extract-dir", Input).value.strip() or None
        device_profile_val = self.query_one("#firmware-device-profile", Select).value
        device_profile_name = None if (device_profile_val in (Select.BLANK, "__none__", None)) else str(device_profile_val)
        fmt = self.query_one("#firmware-format", Select).value or "json"

        log = self.query_one(LogViewer)
        log.clear_log()
        log.append(f"[cyan]Analyzing firmware:[/] {firmware_path}")

        self._running = True
        threading.Thread(
            target=self._run_firmware,
            args=(firmware_path, extract_dir, device_profile_name, str(fmt)),
            daemon=True,
        ).start()

    def _run_firmware(self, firmware_path: str, extract_dir, device_profile_name, fmt: str) -> None:
        log = self.query_one(LogViewer)
        try:
            from analysis.firmware_analyzer import FirmwareAnalyzer
            from utils.config import load_device_profile
            from utils.platform_info import find_tool

            if not find_tool("binwalk"):
                log.append(
                    "[red]binwalk not found.[/]\n"
                    "Install it with:  pip install binwalk  (Python wrapper)\n"
                    "                  sudo apt install binwalk  (Debian/Ubuntu)\n"
                    "                  brew install binwalk  (macOS)"
                )
                return

            rules = {}
            if device_profile_name:
                try:
                    profile = load_device_profile(device_profile_name)
                    rules = profile.get("firmware_rules") or {}
                    log.append(f"Using device profile: {profile.get('name', device_profile_name)}")
                except Exception as exc:
                    log.append(f"[yellow]Device profile not loaded:[/] {exc}")

            output_dir = extract_dir or str(get_output_dir() / "firmware")
            analyzer = FirmwareAnalyzer()
            result = analyzer.analyze(firmware_path, output_dir=output_dir, rules=rules)

            summary = result.get("summary", {})
            risk = result.get("risk_indicators", [])
            log.append(f"[green]Analysis complete.[/]")
            log.append(
                f"Files extracted: {summary.get('file_count', 0)}  "
                f"Credential hits: {summary.get('credential_hit_count', 0)}  "
                f"Private keys: {summary.get('private_key_count', 0)}  "
                f"Shadow files: {summary.get('shadow_file_count', 0)}"
            )
            log.append(
                f"URLs: {summary.get('url_count', 0)}  "
                f"IPs: {summary.get('ip_count', 0)}  "
                f"Domains: {summary.get('domain_count', 0)}  "
                f"Rule hits: {summary.get('firmware_rule_hit_count', 0)}"
            )
            for ri in risk:
                sev = ri.get("severity", "info").upper()
                sev_color = "red" if sev == "HIGH" else ("yellow" if sev == "MEDIUM" else "cyan")
                log.append(f"  [{sev_color}][{sev}][/] {ri.get('title', '')}")

            # Save report in requested format
            try:
                from analysis.report_generator import ReportGenerator
                from utils.artifacts import artifact_path
                from pathlib import Path
                rg = ReportGenerator()
                rg.add_results("firmware", result)
                out_path = artifact_path(Path(output_dir), "firmware_report", f".{fmt}")
                rg.generate(fmt, str(out_path))
                log.append(f"Report saved: {out_path}")
                if hasattr(self, "app") and hasattr(self.app, "_report_gen"):
                    self.app._report_gen.add_results("firmware", result, mode="append")
            except Exception as exc:
                log.append(f"[yellow]Report not saved:[/] {exc}")

        except FileNotFoundError as exc:
            log.append(f"[red]File not found:[/] {exc}")
        except Exception as exc:
            log.append(f"[red]Firmware analysis error:[/] {exc}")
        finally:
            self._running = False

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Firmware Analysis"))
