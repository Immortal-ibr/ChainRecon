"""Reports screen for generating JSON, HTML, CSV, and XLSX artifacts."""

from __future__ import annotations

import threading
from pathlib import Path

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Header, Label, Select, Static

from chainrecon.case_model import Case
from chainrecon.case_reporting import export_case_report
from chainrecon.tui.screens.case_picker import CasePickerScreen
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.tui.widgets.path_input import PathInput
from chainrecon.utils.artifacts import artifact_path
from chainrecon.utils.config import get_case_directory, get_output_dir

HELP_TEXT = """[bold]Reports[/]

When an investigation is selected, Reports exports its imported-file inventory,
analysis runs, coverage, findings, and reviewer decisions by default. Choose
another investigation with the button at the top. You can also export only
results from this TUI session or saved standalone JSON results.

[bold]Formats[/] HTML, JSON, CSV, and XLSX. Leave Output path empty to save
inside the investigation's reports folder or the configured output directory.
The investigation report includes reviewer decisions; session and standalone
reports use only their selected result source.

Review candidate findings in Files & findings before exporting a disclosure
report. An unreviewed indicator is not a confirmed vulnerability.
"""


def _load_output_files(log_func=None, output_dir: Path | None = None) -> dict:
    """Scan configured output directory for saved JSON analysis files."""
    from chainrecon import load_report_inputs
    from chainrecon.utils.config import get_output_dir

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

    def _current_investigation(self) -> Case | None:
        raw = getattr(self.app, "_case_path", None) or get_case_directory()
        if not raw:
            return None
        try:
            return Case.open(raw)
        except (OSError, ValueError, KeyError):
            return None

    def compose(self) -> ComposeResult:
        case = self._current_investigation()
        yield Header()
        with VerticalScroll(id="reports-form"):
            yield Label("[bold]Reports[/]")
            yield Static("", id="report-source-detail")
            yield Button("Choose investigation", id="report-choose-case")
            yield Label("Report source")
            yield Select(
                [("Current investigation", "investigation"),
                 ("This TUI session", "session"),
                 ("Saved standalone results", "all_output")],
                value="investigation" if case else "session",
                id="source-mode",
            )
            yield Label("Output path (optional)")
            yield PathInput(placeholder="Leave blank for the default reports folder", id="output-path")
            yield Label("Format:")
            yield Select(
                [
                    ("XLSX (multi-sheet workbook)", "xlsx"),
                    ("HTML (browser-readable)", "html"),
                    ("JSON (machine-readable)", "json"),
                    ("CSV (spreadsheet)", "csv"),
                ],
                value="xlsx",
                id="format",
            )
            with Horizontal():
                yield Button("Export report", variant="primary", id="btn-gen")
                yield Button("Back", id="btn-back")
            yield LogActionBar()
            yield LogViewer(id="reports-log")
        yield HelpFooter()

    def on_mount(self) -> None:
        self._refresh_source_detail()

    def on_screen_resume(self) -> None:
        self._refresh_source_detail()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "source-mode" and self.query("#report-source-detail"):
            self._refresh_source_detail()

    def _refresh_source_detail(self) -> None:
        case = self._current_investigation()
        mode = self.query_one("#source-mode", Select).value
        detail = self.query_one("#report-source-detail", Static)
        if mode == "investigation":
            if case:
                detail.update(escape(f"Investigation: {case.manifest['title']}  ·  {case.root}"))
                detail.tooltip = str(case.root)
            else:
                detail.update("No investigation selected. Choose one above before exporting.")
        elif mode == "all_output":
            detail.update(escape(f"Saved standalone JSON files in {get_output_dir()}"))
        else:
            detail.update("Only results produced during this TUI session.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "report-choose-case":
            self.action_choose_investigation()
            return
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return
        if event.button.id == "btn-gen":
            self._generate()

    def action_choose_investigation(self) -> None:
        current = self._current_investigation()
        self.app.push_screen(CasePickerScreen(current=current.root if current else None), self._investigation_chosen)

    def _investigation_chosen(self, path: str | None) -> None:
        if path:
            setattr(self.app, "_case_path", path)
            self.query_one("#source-mode", Select).value = "investigation"
            self._refresh_source_detail()

    def _generate(self) -> None:
        out_path = self.query_one("#output-path", Input).value.strip().strip('"\'')
        fmt = self.query_one("#format", Select).value
        source_mode = self.query_one("#source-mode", Select).value
        log = self.query_one("#reports-log", LogViewer)

        if not isinstance(fmt, str) or not isinstance(source_mode, str):
            log.append("[red]Choose a report format and source.[/]")
            return
        case = self._current_investigation() if source_mode == "investigation" else None
        if source_mode == "investigation" and case is None:
            log.append("[yellow]Choose an investigation before exporting its report.[/]")
            return

        log.append(f"[bold]Exporting {escape(fmt.upper())} report from {escape(source_mode)}...[/]")

        def _worker() -> None:
            try:
                from chainrecon.analysis.report_generator import ReportGenerator
                from chainrecon.plugins import get_plugin

                plugin = get_plugin(fmt)
                if source_mode == "investigation" and case is not None:
                    destination = (_report_output_path(out_path, plugin.file_extension(), stem="investigation")
                                   if out_path else str(case.root / "reports" / f"investigation{plugin.file_extension()}"))
                    saved = export_case_report(Case.open(case.root), fmt, destination)
                    self._post(log.set_last_output_path, saved)
                    self._post(log.append, f"[green]Investigation report saved: {escape(str(saved))}[/]")
                    return
                stem = "report_all" if source_mode == "all_output" else "report_current"
                full_path = _report_output_path(out_path or str(get_output_dir()), plugin.file_extension(), stem=stem)
                if source_mode == "session":
                    gen = getattr(self.app, "_report_gen", None) or ReportGenerator()
                else:
                    gen = ReportGenerator()

                loaded_count = 0
                if source_mode == "all_output":
                    for key, data in _load_output_files(
                        log_func=lambda msg: self._post(log.append, msg)
                    ).items():
                        gen.add_results(key, data)
                        loaded_count += 1

                if not _has_report_data(gen.get_data()):
                    self._post(
                        log.append,
                        "[yellow]No results found for the selected source. Run a scan or choose all output files.[/]",
                    )

                Path(full_path).parent.mkdir(parents=True, exist_ok=True)
                gen.generate(fmt, full_path)
                self._post(log.set_last_output_path, full_path)
                self._post(log.append, f"[green]Report saved: {escape(str(Path(full_path).resolve()))}[/]")
                if source_mode == "all_output":
                    self._post(log.append, f"[dim]{loaded_count} result file(s) included.[/]")
                else:
                    self._post(log.append, "[dim]Current session results included.[/]")
            except Exception as exc:
                self._post(log.append, f"[red]Error: {escape(str(exc))}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _post(self, callback, *args) -> None:
        try:
            self.app.call_from_thread(callback, *args)
        except RuntimeError:
            # A report can finish after the TUI has been closed.
            pass

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Report Generation"))


def _report_output_path(raw_path: str, extension: str, stem: str = "report") -> str:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = path.resolve()
    if path.exists() and path.is_dir():
        return str(artifact_path(path, stem, extension))
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
