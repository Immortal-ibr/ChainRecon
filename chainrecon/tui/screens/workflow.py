"""Workflow screen -- run YAML-defined scan pipelines."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Label, Select

from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.utils.config import list_device_profiles

HELP_TEXT = """[bold underline]Workflow -- YAML Pipeline Runner[/]

Runs a declarative YAML pipeline where each step can scan, analyze, run
Frida, analyze firmware, or generate a report.  Steps can be conditional:
only run if a prior step completed or produced specific findings.

[bold]What to provide[/]
  Pipeline YAML -- path to your pipeline file.  A sample pipeline is at
                   workflows/nooie_mqtt_tls.yaml.
  Target        -- IP or hostname to pass into {{ target }} variables inside
                   the YAML.  Leave empty to use values hard-coded in the file.
  Scan Profile  -- overrides the scan profile for all scan steps (arp/quick/
                   iot/full/ssl etc.).  Leave empty to use per-step defaults.
  Device Profile -- pre-defined device profile (Nooie Lab Device etc.) that
                    injects default target/ports/firmware rules into the run.
  Dry Run       -- validates the YAML, renders variables, and evaluates when
                   conditions WITHOUT calling any real tools.  Use this first.

[bold]Where outputs go[/]
Each run creates a timestamped folder under your configured output directory
(default: output/).  A workflow_summary.json is written there with per-step
status, errors, and artifact links.

[bold]Condition syntax[/]
  when: "steps.scan_main.status == 'completed'"
  when: "steps.port_scan.status == 'completed' and 8883 in steps.port_scan.summary.open_ports"

Conditions only see prior completed steps; forward references fail validation.
Dry-run validates and renders all steps, but does not evaluate tool-dependent conditions.

[bold]Step types[/]
  scan         -- nmap scan, stores findings as scan section
  tls_scan     -- SSL/TLS probe on detected TLS ports
  pcap_analysis -- run PCAP analyzers on a capture file
  frida        -- run a Frida script against a target process
  firmware     -- run FirmwareAnalyzer on a firmware image
  report       -- generate HTML/JSON/CSV/XLSX from all prior results
  community    -- run a community plugin by name
  assert       -- fail the workflow when a post-condition is false

[dim]To edit this screen: tui/screens/workflow.py[/]
"""


class WorkflowScreen(Screen):
    HELP_TEXT = HELP_TEXT
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "toggle_help", "Help"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="workflow-form"):
            yield Label("[bold]Workflow -- YAML Pipeline Runner[/]", id="title")
            yield Label("Pipeline YAML")
            yield Input(placeholder="workflows/nooie_mqtt_tls.yaml", id="pipeline-path")
            yield Label("Target (optional override)")
            yield Input(placeholder="192.168.1.1", id="workflow-target")
            yield Label("Scan Profile (optional override)")
            yield Input(placeholder="iot", id="workflow-profile")
            yield Label("Device Profile")
            yield Select([("(none)", "__none__")], id="device-profile-select", value="__none__")
            yield Checkbox("Dry Run (validate without running tools)", True, id="dry-run")
            with Horizontal():
                yield Button("Run Workflow", id="run-workflow", variant="primary")
                yield Button("Back", id="back-btn")
            yield LogActionBar()
            yield LogViewer(id="workflow-log")
        yield Footer()

    def on_mount(self) -> None:
        self._workflow_running = False
        self.call_after_refresh(self._populate_device_profiles)

    def _populate_device_profiles(self) -> None:
        try:
            profiles = list_device_profiles()
            options = [("(none)", "__none__")] + [(p["name"], p["stem"]) for p in profiles]
            select = self.query_one("#device-profile-select", Select)
            select.set_options(options)
            active_profile = getattr(self.app, "_active_device_profile", None)
            select.value = active_profile if active_profile in {value for _, value in options} else "__none__"
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "run-workflow":
            self._start_run()

    def _start_run(self) -> None:
        if self._workflow_running:
            return
        pipeline = self.query_one("#pipeline-path", Input).value.strip()
        if not pipeline:
            self.query_one(LogViewer).append("[red]Pipeline path is required.[/]")
            return
        target = self.query_one("#workflow-target", Input).value.strip() or None
        profile = self.query_one("#workflow-profile", Input).value.strip() or None
        device_profile_val = self.query_one("#device-profile-select", Select).value
        device_profile = None if (device_profile_val in (Select.BLANK, "__none__", None)) else str(device_profile_val)
        dry_run = self.query_one("#dry-run", Checkbox).value

        log = self.query_one(LogViewer)
        log.clear_log()
        log.append(f"[cyan]Starting workflow:[/] {pipeline}")
        if dry_run:
            log.append("[dim]Dry-run mode: no tools will be invoked.[/]")

        self._workflow_running = True
        threading.Thread(target=self._run_workflow, args=(pipeline, target, profile, device_profile, dry_run), daemon=True).start()

    def _run_workflow(self, pipeline: str, target, profile, device_profile, dry_run: bool) -> None:
        log = self.query_one(LogViewer)
        emit = self.app.call_from_thread
        try:
            from chainrecon.runners.workflow_runner import WorkflowRunner
            runner = WorkflowRunner()
            result = runner.run(pipeline, target=target, profile=profile, device_profile=device_profile, dry_run=dry_run)
            summary = result.get("summary", {})
            status = summary.get("status", "unknown")
            color = "green" if status == "completed" else ("yellow" if "error" in status else "red")
            emit(
                log.append,
                f"[{color}]Workflow {status}[/]",
            )
            emit(
                log.append,
                f"Steps: {summary.get('step_count', 0)}  Completed: {summary.get('completed_step_count', 0)}  "
                f"Failed: {summary.get('failed_step_count', 0)}  Skipped: {summary.get('skipped_step_count', 0)}  "
                f"Planned: {summary.get('planned_step_count', 0)}",
            )
            steps = result.get("findings", {}).get("steps", {})
            for step_id, step in steps.items():
                step_status = step.get("status", "?")
                step_color = "green" if step_status == "completed" else ("dim" if step_status in ("skipped", "planned") else "red")
                emit(log.append, f"  [{step_color}]{step_status:12}[/] {step_id}")
                if step.get("error"):
                    emit(log.append, f"    [red]Error:[/] {step['error']}")
            out_dir = result.get("metadata", {}).get("output_dir", "")
            if out_dir:
                emit(log.append, f"Output: {out_dir}")
            if hasattr(self.app, "_report_gen"):
                self.app._report_gen.add_results("workflow", result, mode="append")
            if device_profile:
                profile = next((item for item in list_device_profiles() if item["stem"] == device_profile), None)
                if profile and hasattr(self.app, "_report_gen"):
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
            emit(log.append, f"[red]Workflow error:[/] {exc}")
        finally:
            self._workflow_running = False

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Workflow -- YAML Pipeline Runner"))
