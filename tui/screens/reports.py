"""Reports screen — generate reports from collected results."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select

from tui.widgets.pasteable_input import PasteableInput as Input

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogViewer

HELP_TEXT = """[bold underline]Report Generation[/]

Combines results from scans, captures, and analysis into a single report.
All JSON files saved in the output/ directory are automatically loaded —
you don't need to run scans in the same session.

[bold]Formats[/]
  • HTML — Human-readable report: severity badges, findings table, section
    cards for each analysis type. Opens in any web browser.
  • JSON — Full machine-readable output. Good for scripting or other tools.
  • CSV  — Flat tabular export. Import into Excel / Google Sheets.

[bold]Source files[/]
Every scan, capture, and analysis saves a JSON file to output/.
The report screen loads all of them automatically. If you want to include
only specific files, delete the ones you don't want from output/ first.

[bold]Reading the report[/]
  risk_indicators — each has severity (critical/high/medium/low/info),
    a title, and details. Start here.
  findings — raw per-analyzer output (ports, DNS queries, certs, etc.)
  summary — high-level counts per section

[dim]Report plugin code: plugins/
Finding model: models/finding.py
To edit this screen: tui/screens/reports.py[/]
"""


def _load_output_files(log_func=None) -> dict:
    """Scan output/ for saved JSON analysis files and merge them into one dict."""
    from utils.config import get_output_dir
    outdir = get_output_dir()
    sections: dict = {}
    if not outdir.exists():
        return sections
    for jfile in sorted(outdir.glob("*.json")):
        try:
            data = json.loads(jfile.read_text(encoding="utf-8"))
            # Use the stem as the section key, deduplicate with a counter
            key = jfile.stem
            sections[key] = data
            if log_func:
                log_func(f"[dim]Loaded: {jfile.name}[/]")
        except Exception as exc:
            if log_func:
                log_func(f"[yellow]Skipped {jfile.name}: {exc}[/]")
    return sections


class ReportsScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("question_mark", "toggle_help", "Help")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="reports-form"):
            yield Label("[bold]Report Generation[/]")
            yield Label("[dim]All JSON files in output/ are included automatically.[/]")
            yield Label("Output file path (without extension):")
            yield Input(placeholder="output/report", value="output/report", id="output-path")
            yield Label("Format:")
            yield Select(
                [("HTML (browser-readable)", "html"), ("JSON (machine-readable)", "json"), ("CSV (spreadsheet)", "csv")],
                value="html",
                id="format",
            )
            with Horizontal():
                yield Button("Generate Report", variant="primary", id="btn-gen")
                yield Button("Back", id="btn-back")
            yield LogViewer(id="reports-log")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return
        if event.button.id == "btn-gen":
            self._generate()

    def _generate(self) -> None:
        out_path = self.query_one("#output-path", Input).value.strip().strip('"\'')
        fmt = self.query_one("#format", Select).value
        log = self.query_one("#reports-log", LogViewer)

        if not out_path:
            log.append("[red]Please provide an output path.[/]")
            return

        log.append(f"[bold]Generating {fmt.upper()} report…[/]")

        def _worker() -> None:
            try:
                from analysis.report_generator import ReportGenerator
                from plugins import get_plugin

                plugin = get_plugin(fmt)
                full_path = f"{out_path}{plugin.file_extension()}"

                # Start with any results already accumulated in the app session
                gen = getattr(self.app, "_report_gen", None) or ReportGenerator()

                # Load all saved JSON files from output/ into the report
                loaded_count = 0
                for key, data in _load_output_files(
                    log_func=lambda msg: self.app.call_from_thread(log.append, msg)
                ).items():
                    gen.add_results(key, data)
                    loaded_count += 1

                if loaded_count == 0 and not gen.get_data().get("traffic"):
                    self.app.call_from_thread(
                        log.append,
                        "[yellow]No results found. Run a scan or analysis first to populate output/.[/]"
                    )

                # Ensure output directory exists
                Path(full_path).parent.mkdir(parents=True, exist_ok=True)
                gen.generate(fmt, full_path)
                self.app.call_from_thread(log.append, f"[green]Report saved: {full_path}[/]")
                self.app.call_from_thread(log.append, f"[dim]{loaded_count} result file(s) included.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Report Generation"))

