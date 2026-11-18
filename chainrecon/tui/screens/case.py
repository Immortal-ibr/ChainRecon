"""Investigation workspace for evidence, review, and export."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import cast

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Collapsible, Header, Label, Select, Static

from chainrecon.analysis_catalog import BY_KIND, IMPORT_OPTIONS, analyzer_for_kind
from chainrecon.case_model import Case, FindingStatus
from chainrecon.tui.screens.case_picker import CasePickerScreen
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.tui.widgets.path_input import PathInput
from chainrecon.utils.config import get_case_directory

HELP_TEXT = """[bold]Investigation files and findings[/]

An investigation is one folder for imported files, analysis runs, reviewer
decisions, and reports. Import source files here. Analyze file opens the
matching analyzer for the selected file. Review candidate findings here;
Reports exports the current investigation.

[bold]Keyboard[/]  a import file   Ctrl+O switch folder   r analyze file
            v review        e reports         l activity
            ? help           Esc back

Tab moves between controls. In a path field, Tab completes the path and
Ctrl+Tab moves to the next field. Shift+Tab moves backward. Use arrow keys
and Enter in menus and the folder browser.
"""


class CaseScreen(Screen):
    """A compact client for the same case APIs exposed by the CLI."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("a", "add_evidence", "Import"),
        Binding("ctrl+o", "choose_case", "Folder", priority=True),
        Binding("o", "choose_case", "Folder", show=False),
        Binding("r", "open_analysis", "Analysis"),
        Binding("question_mark", "toggle_help", "Help", show=False),
        Binding("v", "review_findings", "Review", show=False),
        Binding("e", "export_report", "Reports", show=False),
        Binding("l", "show_activity", "Activity", show=False),
    ]
    DEFAULT_CSS = """
    CaseScreen #case-form { padding: 0 2; padding-right: 2; scrollbar-gutter: stable; }
    CaseScreen #case-form Collapsible { margin: 0; }
    CaseScreen #case-form Button { margin: 0 1 0 0; }
    CaseScreen #title { margin-bottom: 0; }
    CaseScreen #case-summary, CaseScreen #case-location,
    CaseScreen #evidence-details { color: $text-muted; margin-bottom: 0; }
    CaseScreen #case-status { display: none; color: $warning; }
    CaseScreen #import-status { display: none; color: $warning; }
    CaseScreen #case-actions { height: 3; margin: 1 0; }
    CaseScreen #case-log { min-height: 7; height: 9; }
    """

    def compose(self) -> ComposeResult:
        initial = getattr(self.app, "_case_path", None) or get_case_directory()
        has_case = bool(initial and (Path(initial) / "case.json").exists())
        yield Header()
        with VerticalScroll(id="case-form"):
            yield Label("Investigation files and findings", id="title")
            yield Static("Choose or create an investigation folder.", id="case-summary")
            yield Static("", id="case-location")
            with Horizontal(id="case-actions"):
                yield Button("Import file", id="case-add-open", disabled=not has_case)
                yield Button("Switch folder", id="case-choose", variant="primary" if not has_case else "default")
                yield Button("Analyze file", id="case-open-analysis", disabled=not has_case)
                yield Button("Reports", id="case-open-reports")
            yield Static("", id="case-status")
            with Collapsible(title="Imported files", collapsed=not has_case, id="evidence-section"):
                yield Select([], prompt="No files imported", id="evidence-select")
                yield Static("Select a file to see its type and SHA-256 hash.", id="evidence-details")
            with Collapsible(title="Import file", collapsed=False if has_case and not self._case_has_evidence(initial) else True, id="import-section"):
                yield Label("Source file")
                yield PathInput(placeholder="Source file path — Tab completes", id="evidence-source")
                yield Label("File type")
                yield Select(IMPORT_OPTIONS, prompt="Choose a type", id="evidence-kind")
                yield Static("", id="import-status")
                yield Button("Import file", id="case-add")
            with Collapsible(title="Review findings", collapsed=True, id="review-section"):
                yield Select([], prompt="No candidate findings", id="finding-select")
                yield Select([("Confirmed", "confirmed"), ("Rejected", "rejected"), ("Candidate", "candidate")], id="finding-status", value="confirmed")
                yield Input(placeholder="Reviewer name (optional)", id="reviewer")
                yield Input(placeholder="Review note", id="review-note")
                yield Button("Save review", id="case-review")
            with Collapsible(title="Recent activity", collapsed=True, id="activity-section"):
                yield LogViewer(id="case-log")
            yield Button("Back", id="case-back")
        yield HelpFooter()

    @staticmethod
    def _case_has_evidence(path: str | Path | None) -> bool:
        if not path:
            return False
        try:
            return bool(Case.open(path).manifest["evidence"])
        except (OSError, ValueError, KeyError):
            return False

    def on_mount(self) -> None:
        self._busy = False
        self._pending_evidence_id: str | None = None
        initial = getattr(self.app, "_case_path", None) or get_case_directory()
        if initial:
            if (Path(initial) / "case.json").exists():
                self._refresh()
                target = "#case-open-analysis" if self._case_has_evidence(initial) else "#evidence-source"
                self.call_after_refresh(self.query_one(target).focus)
                return
        self.query_one("#case-choose", Button).focus()

    def _case_path(self) -> Path:
        raw = getattr(self.app, "_case_path", None) or get_case_directory()
        if raw is None:
            raise ValueError("Choose or create an investigation first")
        return Path(raw).expanduser()

    def _case(self) -> Case:
        return Case.open(self._case_path())

    def _job_case_path(self) -> Path | None:
        try:
            return self._case_path()
        except ValueError as exc:
            self._show_status(str(exc))
            return None

    def _show_status(self, message: str) -> None:
        status = self.query_one("#case-status", Static)
        status.update(escape(message))
        status.display = True

    def _show_import_status(self, message: str) -> None:
        status = self.query_one("#import-status", Static)
        status.update(escape(message))
        status.display = True

    def _selected_evidence_id(self) -> str:
        selected = self.query_one("#evidence-select", Select).value
        return selected if isinstance(selected, str) else ""

    def _selected_finding_id(self) -> str:
        selected = self.query_one("#finding-select", Select).value
        return selected if isinstance(selected, str) else ""

    def _refresh(self) -> None:
        try:
            case = self._case()
            self.query_one("#case-status", Static).display = False
            self.query_one("#import-status", Static).display = False
            setattr(self.app, "_case_path", str(case.root))
            self.query_one("#case-add-open", Button).disabled = False
            self.query_one("#case-open-analysis", Button).disabled = False
            choose_button = self.query_one("#case-choose", Button)
            choose_button.label = "Switch folder"
            choose_button.tooltip = str(case.root)
            evidence = case.manifest["evidence"]
            runs = case.manifest["runs"]
            findings = case.query("findings")
            summary = (f"{case.manifest['title']}  •  {len(evidence)} files  •  {len(runs)} runs"
                       f"  •  {len(findings)} findings across runs")
            self.query_one("#case-summary", Static).update(escape(summary))
            location = self.query_one("#case-location", Static)
            location.update(escape(f"Folder: {case.root}"))
            location.tooltip = str(case.root)
            evidence_select = self.query_one("#evidence-select", Select)
            old_evidence = self._pending_evidence_id or evidence_select.value
            evidence_select.set_options([
                (f"{item['name']}  [{BY_KIND[item['kind']].label if item['kind'] in BY_KIND else item['kind']}]", item["id"])
                for item in evidence
            ])
            if evidence:
                ids = {item["id"] for item in evidence}
                evidence_select.value = old_evidence if old_evidence in ids else evidence[-1]["id"]
                self._update_evidence_details(evidence)
                if self._pending_evidence_id:
                    self.query_one("#evidence-section", Collapsible).collapsed = False
                    self.query_one("#import-section", Collapsible).collapsed = True
                    self.call_after_refresh(self.query_one("#case-open-analysis", Button).focus)
                self._pending_evidence_id = None
            else:
                self.query_one("#evidence-details", Static).update("Import a source file to start the investigation.")
                self.query_one("#evidence-section", Collapsible).collapsed = True
                self.query_one("#import-section", Collapsible).collapsed = False
                self.call_after_refresh(self.query_one("#evidence-source", PathInput).focus)
            finding_select = self.query_one("#finding-select", Select)
            old_finding = finding_select.value
            finding_select.set_options([
                (f"{item['severity']}: {item['title']}  [run {item['run_id'][4:12]}]", item["id"])
                for item in findings
            ])
            if findings:
                ids = {item["id"] for item in findings}
                finding_select.value = old_finding if old_finding in ids else findings[-1]["id"]
            log = self.query_one("#case-log", LogViewer)
            log.clear_log()
            for item in evidence[-10:]:
                log.append(f"[cyan]File[/] {escape(item['name'])} [{escape(item['kind'])}] {item['sha256'][:12]}…")
            for item in runs[-10:]:
                log.append(f"[green]Run[/] {item['id'][:18]}… {escape(item['analyzer'])} — {escape(item['status'])}")
            for item in findings[-10:]:
                log.append(f"[yellow]Finding[/] {escape(item['status'])}: {escape(item['title'])}")
        except Exception as exc:
            self.query_one("#case-summary", Static).update("Investigation could not be opened. Choose another folder.")
            self.query_one("#case-location", Static).update("")
            self.query_one("#case-add-open", Button).disabled = True
            self.query_one("#case-open-analysis", Button).disabled = True
            self._show_status(f"{type(exc).__name__}: {exc}")
            self.query_one("#case-log", LogViewer).append(f"[red]{type(exc).__name__}: {escape(str(exc))}[/]")

    def _update_evidence_details(self, evidence: list[dict]) -> None:
        selected = self.query_one("#evidence-select", Select).value
        item = next((row for row in evidence if row["id"] == selected), None)
        if item is None:
            return
        analyzer = analyzer_for_kind(item["kind"])
        kind_label = BY_KIND[item["kind"]].label if item["kind"] in BY_KIND else item["kind"]
        details = f"{kind_label}  •  {item['size'] / (1024 * 1024):.1f} MiB  •  SHA-256 {item['sha256'][:16]}…"
        details += f"  •  Built-in analysis: {analyzer}" if analyzer else "  •  Manual review only"
        self.query_one("#evidence-details", Static).update(escape(details))

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "evidence-select":
            return
        try:
            self._update_evidence_details(self._case().manifest["evidence"])
        except (OSError, ValueError, KeyError):
            pass

    def action_add_evidence(self) -> None:
        if self.query_one("#case-add-open", Button).disabled:
            self.action_choose_case()
            return
        self.query_one("#import-section", Collapsible).collapsed = False
        self.call_after_refresh(self.query_one("#evidence-source", PathInput).focus)

    def action_choose_case(self) -> None:
        raw = getattr(self.app, "_case_path", None)
        current = Path(raw) if raw and (Path(raw) / "case.json").is_file() else None
        self.app.push_screen(CasePickerScreen(current=current), self._case_chosen)

    def _case_chosen(self, path: str | None) -> None:
        if path is None:
            return
        setattr(self.app, "_case_path", path)
        self._refresh()
        has_evidence = self._case_has_evidence(path)
        self.query_one("#evidence-section", Collapsible).collapsed = not has_evidence
        self.query_one("#import-section", Collapsible).collapsed = has_evidence
        target = "#case-open-analysis" if has_evidence else "#evidence-source"
        self.call_after_refresh(self.query_one(target).focus)

    def action_open_analysis(self) -> None:
        if self.query_one("#case-open-analysis", Button).disabled:
            self.action_choose_case()
            return
        from chainrecon.tui.screens.case_analysis import (
            VIEW_FOR_KIND,
            CaseAnalysisScreen,
        )

        evidence_id = self._selected_evidence_id()
        kind = self._case().evidence(evidence_id).kind if evidence_id else None
        view = VIEW_FOR_KIND.get(kind) if kind is not None else None
        self.app.push_screen(CaseAnalysisScreen(evidence_id=evidence_id, view=view))

    def on_screen_resume(self) -> None:
        if self.query("#case-summary"):
            self._refresh()

    def action_review_findings(self) -> None:
        self.query_one("#review-section", Collapsible).collapsed = False
        self.call_after_refresh(self.query_one("#finding-select", Select).focus)

    def action_export_report(self) -> None:
        self.app.push_screen("reports")

    def action_show_activity(self) -> None:
        self.query_one("#activity-section", Collapsible).collapsed = False
        self.call_after_refresh(self.query_one("#case-log", LogViewer).focus)

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Investigation"))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "evidence-source":
            self.query_one("#evidence-kind", Select).focus()
        elif event.input.id == "review-note":
            self.query_one("#case-review", Button).press()

    def _launch(self, job) -> None:
        if self._busy:
            return
        self._busy = True
        app = self.app
        log = self.query_one("#case-log", LogViewer)
        self.query_one("#activity-section", Collapsible).collapsed = False
        log.append("[yellow]Working…[/]")
        self.call_after_refresh(self.query_one("#case-form", VerticalScroll).scroll_to_widget, log, animate=False)
        def post(callback, *args) -> None:
            try:
                app.call_from_thread(callback, *args)
            except RuntimeError:
                # A job may finish after its TUI has closed.
                pass
        def worker() -> None:
            try:
                message = job()
                post(self._refresh)
                post(log.append, f"[green]{escape(str(message))}[/]")
            except Exception as exc:
                post(log.append, f"[red]{type(exc).__name__}: {escape(str(exc))}[/]")
            finally:
                post(self._set_idle)
        threading.Thread(target=worker, daemon=True).start()

    def _set_idle(self) -> None:
        self._busy = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = event.button.id
        if action == "case-back":
            self.app.pop_screen()
        elif action == "case-add-open":
            self.action_add_evidence()
        elif action == "case-choose":
            self.action_choose_case()
        elif action == "case-open-analysis":
            self.action_open_analysis()
        elif action == "case-open-reports":
            self.action_export_report()
        elif action == "case-add":
            path = self._job_case_path()
            if path is None:
                return
            case_path = cast(Path, path)
            source = self.query_one("#evidence-source", PathInput).value.strip()
            kind = self.query_one("#evidence-kind", Select).value
            if not source:
                self._show_import_status("Choose a source file before importing.")
                self.query_one("#evidence-source", PathInput).focus()
                return
            if not isinstance(kind, str):
                self._show_import_status("Choose the evidence type before importing.")
                self.query_one("#evidence-kind", Select).focus()
                return
            app = self.app
            def add() -> str:
                ref = Case.open(case_path).add_evidence(source, kind=kind)
                app.call_from_thread(setattr, self, "_pending_evidence_id", ref.id)
                return f"Imported {ref.name}"
            self._launch(add)
        elif action == "case-review":
            path = self._job_case_path()
            if path is None:
                return
            case_path = cast(Path, path)
            finding_id = self._selected_finding_id()
            status = cast(FindingStatus, self.query_one("#finding-status", Select).value)
            reviewer = self.query_one("#reviewer", Input).value.strip()
            note = self.query_one("#review-note", Input).value.strip()
            def review() -> str:
                if not finding_id:
                    raise ValueError("Select a finding to review")
                Case.open(case_path).review_finding(finding_id, status, note=note, reviewer=reviewer)
                return f"Reviewed {finding_id}: {status}"
            self._launch(review)
