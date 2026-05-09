"""Firmware screen -- extract and inspect firmware images."""

from __future__ import annotations

import threading

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select

from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.utils.config import get_output_dir, list_device_profiles

HELP_TEXT = """[bold underline]Firmware Analysis[/]

Extracts and inspects a firmware image using binwalk, then scans the
extracted filesystem for credentials, private keys, certificates, password
databases, and embedded network endpoints.

This module is in its beginnings and will be expanded later with deeper
filesystem, architecture, and vendor-specific firmware analysis.

[bold]What to provide[/]
  Firmware Image -- path to the firmware binary (.bin, .img, .tar.gz, etc.)
  Extract Dir    -- where to write extracted files.  Leave empty to use a
                   temp directory under your output/ folder.
  Device Profile -- optional; firmware rules from the profile (expected
                   domains/URLs/keywords) are matched against extracted files.
  Output Format  -- json / html / csv / xlsx for the firmware report.

[bold]Optional binwalk extraction[/]
  binwalk should be installed and on PATH for full filesystem extraction:
    pip install binwalk       (Python wrapper)
    sudo apt install binwalk  (Debian/Ubuntu)
    brew install binwalk      (macOS)
  If binwalk cannot run, ChainRecon still scans the firmware image directly
  and records the extraction warning in the report metadata.

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
        with VerticalScroll(id="firmware-form"):
            yield Label("[bold]Firmware Analysis[/]", id="title")
            yield Label(
                "[dim]Firmware analysis is in its beginnings and will be expanded later with deeper firmware coverage.[/]"
            )
            yield Label("Firmware Image Path")
            yield Input(placeholder="/path/to/firmware.bin", id="firmware-path")
            yield Label("Extract Directory (optional)")
            yield Input(placeholder="leave empty for auto temp dir", id="extract-dir")
            yield Label("Device Profile (optional)")
            yield Select([("(none)", "__none__")], id="firmware-device-profile", value="__none__")
            yield Label("Output Format")
            yield Select(
                [("XLSX", "xlsx"), ("HTML", "html"), ("JSON", "json"), ("CSV", "csv")],
                id="firmware-format",
                value="xlsx",
            )
            with Horizontal():
                yield Button("Analyze Firmware", id="run-firmware", variant="primary")
                yield Button("Back", id="back-btn")
            yield LogActionBar()
            yield LogViewer(id="firmware-log")
        yield Footer()

    def on_mount(self) -> None:
        self._firmware_running = False
        self.call_after_refresh(self._populate_device_profiles)

    def _populate_device_profiles(self) -> None:
        try:
            profiles = list_device_profiles()
            options = [("(none)", "__none__")] + [(p["name"], p["stem"]) for p in profiles]
            select = self.query_one("#firmware-device-profile", Select)
            select.set_options(options)
            active_profile = getattr(self.app, "_active_device_profile", None)
            select.value = active_profile if active_profile in {value for _, value in options} else "__none__"
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "run-firmware":
            self._start_analysis()

    def _start_analysis(self) -> None:
        if self._firmware_running:
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

        self._firmware_running = True
        threading.Thread(
            target=self._run_firmware,
            args=(firmware_path, extract_dir, device_profile_name, str(fmt)),
            daemon=True,
        ).start()

    def _run_firmware(self, firmware_path: str, extract_dir, device_profile_name, fmt: str) -> None:
        log = self.query_one(LogViewer)
        emit = self.app.call_from_thread
        try:
            from chainrecon.analysis.firmware_analyzer import FirmwareAnalyzer
            from chainrecon.utils.config import load_device_profile

            rules = {}
            if device_profile_name:
                try:
                    profile = load_device_profile(device_profile_name)
                    rules = profile.get("firmware_rules") or {}
                    emit(log.append, f"Using device profile: {profile.get('name', device_profile_name)}")
                except Exception as exc:
                    emit(log.append, f"[yellow]Device profile not loaded:[/] {exc}")

            if extract_dir:
                output_dir = extract_dir
            else:
                from chainrecon.utils.artifacts import timestamped_dir
                output_dir = str(timestamped_dir(get_output_dir(), "firmware_extract"))
            analyzer = FirmwareAnalyzer()
            result = analyzer.analyze(firmware_path, output_dir=output_dir, rules=rules)

            summary = result.get("summary", {})
            risk = result.get("risk_indicators", [])
            emit(log.append, f"[green]Analysis complete.[/]")
            emit(
                log.append,
                f"Files extracted: {summary.get('file_count', 0)}  "
                f"Credential hits: {summary.get('credential_hit_count', 0)}  "
                f"Private keys: {summary.get('private_key_count', 0)}  "
                f"Shadow files: {summary.get('shadow_file_count', 0)}",
            )
            emit(
                log.append,
                f"URLs: {summary.get('url_count', 0)}  "
                f"IPs: {summary.get('ip_count', 0)}  "
                f"Domains: {summary.get('domain_count', 0)}  "
                f"Rule hits: {summary.get('firmware_rule_hit_count', 0)}",
            )
            for ri in risk:
                sev = ri.get("severity", "info").upper()
                sev_color = "red" if sev == "HIGH" else ("yellow" if sev == "MEDIUM" else "cyan")
                emit(log.append, f"  [{sev_color}][{sev}][/] {ri.get('title', '')}")

            # Save report in requested format
            try:
                from chainrecon.analysis.report_generator import ReportGenerator
                from chainrecon.utils.artifacts import artifact_path
                from pathlib import Path
                rg = ReportGenerator()
                rg.add_results("firmware", result)
                out_path = artifact_path(Path(output_dir), "firmware_report", f".{fmt}")
                rg.generate(fmt, str(out_path))
                emit(log.append, f"Report saved: {out_path}")
                if hasattr(self, "app") and hasattr(self.app, "_report_gen"):
                    self.app._report_gen.add_results("firmware", result, mode="append")
                    if device_profile_name:
                        profile = load_device_profile(device_profile_name)
                        self.app._report_gen.add_results(
                            "device_profile",
                            {
                                "metadata": {"section": "device_profile"},
                                "summary": {"field_count": len(profile)},
                                "findings": profile,
                                "risk_indicators": [],
                                "artifacts": [],
                            },
                            mode="replace",
                        )
            except Exception as exc:
                emit(log.append, f"[yellow]Report not saved:[/] {exc}")

        except FileNotFoundError as exc:
            emit(log.append, f"[red]File not found:[/] {exc}")
        except Exception as exc:
            emit(log.append, f"[red]Firmware analysis error:[/] {exc}")
        finally:
            self._firmware_running = False

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Firmware Analysis"))
