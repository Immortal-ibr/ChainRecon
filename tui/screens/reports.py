"""Reports screen for generating JSON, HTML, and CSV artifacts."""

from __future__ import annotations

import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogActionBar, LogViewer
from tui.widgets.pasteable_input import PasteableInput as Input

HELP_TEXT = """[bold underline]Report Generation[/]

Combines results from scans, captures, and analysis into a single report.
By default it uses the current TUI session only. You can also include every
JSON file from the configured output directory.

[bold]Formats[/]
  - HTML: Human-readable report with risk summary and raw sections.
  - JSON: Full machine-readable output. Good for scripting.
  - CSV: Flat tabular export for Excel or Google Sheets.

[bold]Source files[/]
Current session mode avoids stale result files. All output files mode loads
every *.json file from the configured output directory and records each
source filename in report metadata.

[bold]Reading the report[/]
  risk_indicators: severity, title, and details. Start here.
  findings: raw per-analyzer output such as ports, DNS queries, and certs.
  summary: high-level counts per section.

[dim]Report plugin code: plugins/
Finding model: models/finding.py
To edit this screen: tui/screens/reports.py[/]
"""


def _load_output_files(log_func=None, output_dir: Path | None = None) -> dict:
    """Scan configured output directory for saved JSON analysis files."""
    from utils.config import get_output_dir
    from chainrecon import load_report_inputs

    outdir = output_dir or get_output_dir()
    if not outdir.exists():
        return {}
    sections = load_report_inputs([str(outdir)])
    if log_func:
        for section, payload in sections.items():
            metadata = payload.get("metadata") if isinstance(payload, dict) else {}
            count = metadata.get("source_count", 1) if isinstance(metadata, dict) else 1
            log_func(f"[dim]Loaded {count} file(s) into {section}.[/]")
    return sections


class ReportsScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("question_mark", "toggle_help", "Help")]

    def compose(self) -> ComposeResult:
        from utils.config import get_output_dir

        default_output = str((get_output_dir() / "report").resolve())
        yield Header()
        with VerticalScroll(id="reports-form"):
            yield Label("[bold]Report Generation[/]")
            yield Label("[dim]Choose current session results or all saved JSON files from the configured output directory.[/]")
            yield Label("Output file path (without extension):")
            yield Input(placeholder=default_output, value=default_output, id="output-path")
            yield Label("Format:")
            yield Select(
                [("HTML (browser-readable)", "html"), ("JSON (machine-readable)", "json"), ("CSV (spreadsheet)", "csv")],
                value="html",
                id="format",
            )
            yield Label("Source:")
            yield Select(
                [
                    ("Current session only", "session"),
                    ("All JSON files in configured output directory", "all_output"),
                ],
                value="session",
                id="source-mode",
            )
            with Horizontal():
                yield Button("Generate Report", variant="primary", id="btn-gen")
                yield Button("Back", id="btn-back")
            yield LogActionBar()
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
        source_mode = self.query_one("#source-mode", Select).value
        log = self.query_one("#reports-log", LogViewer)

        if not out_path:
            log.append("[red]Please provide an output path.[/]")
            return

        log.append(f"[bold]Generating {fmt.upper()} report from {source_mode}...[/]")

        def _worker() -> None:
            try:
                from analysis.report_generator import ReportGenerator
                from plugins import get_plugin

                plugin = get_plugin(fmt)
                full_path = _report_output_path(out_path, plugin.file_extension())
                gen = getattr(self.app, "_report_gen", None) or ReportGenerator()

                loaded_count = 0
                if source_mode == "all_output":
                    for key, data in _load_output_files(
                        log_func=lambda msg: self.app.call_from_thread(log.append, msg)
                    ).items():
                        gen.add_results(key, data)
                        loaded_count += 1

                if not _has_report_data(gen.get_data()):
                    self.app.call_from_thread(
                        log.append,
                        "[yellow]No results found for the selected source. Run a scan or choose all output files.[/]",
                    )

                Path(full_path).parent.mkdir(parents=True, exist_ok=True)
                gen.generate(fmt, full_path)
                self.app.call_from_thread(log.set_last_output_path, full_path)
                self.app.call_from_thread(log.append, f"[green]Report saved: {Path(full_path).resolve()}[/]")
                if source_mode == "all_output":
                    self.app.call_from_thread(log.append, f"[dim]{loaded_count} result file(s) included.[/]")
                else:
                    self.app.call_from_thread(log.append, "[dim]Current session results included.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Report Generation"))


def _report_output_path(raw_path: str, extension: str) -> str:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = path.resolve()
    if path.suffix.lower() == extension.lower():
        return str(path)
    return str(path.with_suffix(extension))


def _has_report_data(data: dict) -> bool:
    for key, value in data.items():
        if key == "findings_summary":
            continue
        if value not in (None, {}, []):
            return True
    return False
