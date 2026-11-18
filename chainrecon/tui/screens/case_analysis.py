"""Case-backed analysis workspace for every supported evidence type."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Collapsible, Header, Label, Select, Static

from chainrecon.analysis_catalog import BY_KIND, analyzer_for_kind
from chainrecon.case_analysis import analyze_evidence
from chainrecon.case_model import Case
from chainrecon.tui.screens.case_picker import CasePickerScreen
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.utils.config import get_case_directory, get_firmware_mode

HELP_TEXT = """[bold]Analyze imported files[/]

An investigation is a folder that stores copied source files, analysis runs,
review decisions, and reports. Choose an imported file. Its type determines
the built-in analyzer. Firmware, packet captures, Android APKs, Nmap XML,
and Frida logs can be analyzed. UART logs and other files can be kept for
manual review. Add files through the Investigation screen.

Firmware extraction uses an isolated container by default. Trusted WSL and
host modes require an explicit choice. Each run records its status, warnings,
coverage, observations, and candidate findings in the investigation.
Packet capture and Android APK screens also link to optional standalone tools;
their outputs are separate from investigation runs.

[bold]Keyboard[/]  r run analysis   Ctrl+O switch investigation
            e manage files
            ? help          Esc back
"""


@dataclass(frozen=True)
class AnalysisView:
    title: str
    kinds: tuple[str, ...]
    description: str
    run_label: str


ANALYSIS_VIEWS = {
    "firmware": AnalysisView("Firmware analysis", ("firmware", "flash_dump"), "Firmware images and flash dumps", "Analyze firmware"),
    "packets": AnalysisView("Packet capture analysis", ("pcap",), "PCAP and PCAPNG captures", "Analyze capture"),
    "apk": AnalysisView("Android APK analysis", ("apk",), "Android application packages", "Analyze APK"),
    "scan": AnalysisView("Nmap XML analysis", ("scan_xml",), "Imported Nmap XML results", "Analyze scan"),
    "frida": AnalysisView("Frida log analysis", ("frida_log",), "Recorded Frida event logs", "Analyze log"),
}
VIEW_FOR_KIND = {kind: view for view, spec in ANALYSIS_VIEWS.items() for kind in spec.kinds}


class CaseAnalysisScreen(Screen):
    """Run compatible analyzers and inspect past runs without mixing import UI."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "run_analysis", "Run"),
        Binding("ctrl+o", "choose_case", "Folder", priority=True),
        Binding("e", "manage_evidence", "Evidence", show=False),
        Binding("question_mark", "toggle_help", "Help", show=False),
    ]
    DEFAULT_CSS = """
    CaseAnalysisScreen #analysis-workspace { padding: 0 2; padding-right: 2; scrollbar-gutter: stable; }
    CaseAnalysisScreen #analysis-workspace Collapsible { margin: 0; }
    CaseAnalysisScreen #analysis-workspace Button { margin: 0 1 0 0; }
    CaseAnalysisScreen #analysis-title { text-style: bold; color: $accent; }
    CaseAnalysisScreen #analysis-case, CaseAnalysisScreen #analysis-evidence-detail,
    CaseAnalysisScreen #analysis-run-detail, CaseAnalysisScreen #analysis-scope { color: $text-muted; }
    CaseAnalysisScreen #analysis-actions { height: 3; margin: 1 0; }
    CaseAnalysisScreen #analysis-status { display: none; color: $warning; }
    CaseAnalysisScreen #analysis-progress { min-height: 7; height: 9; }
    """

    def __init__(self, evidence_id: str | None = None, *, view: str | None = None) -> None:
        super().__init__()
        if view is not None and view not in ANALYSIS_VIEWS:
            raise ValueError(f"Unknown analysis view: {view}")
        self._view = view
        self._requested_evidence_id = evidence_id
        self._requested_run_id: str | None = None
        self._busy = False

    def compose(self) -> ComposeResult:
        spec = ANALYSIS_VIEWS.get(self._view) if self._view else None
        yield Header()
        with VerticalScroll(id="analysis-workspace"):
            yield Static(spec.title if spec else "Analyze imported file", id="analysis-title")
            yield Static(spec.description if spec else "Firmware · packets · Android APK · Nmap XML · Frida logs", id="analysis-scope")
            yield Static("Choose an investigation to analyze an imported file.", id="analysis-case")
            with Horizontal(id="analysis-actions"):
                yield Button("Choose investigation", id="analysis-choose-case")
                yield Button("Add or manage files", id="analysis-manage-evidence", disabled=True)
            yield Label("Imported file")
            yield Select([], prompt="No matching files imported", id="analysis-evidence")
            yield Static("Choose an imported file to see its analyzer.", id="analysis-evidence-detail")
            with Horizontal():
                yield Button(spec.run_label if spec else "Run analysis", id="analysis-run", variant="primary", disabled=True)
                if self._view == "packets":
                    yield Button("Advanced packet checks", id="analysis-packet-tools")
                elif self._view == "apk":
                    yield Button("Standalone APK tools", id="analysis-apk-tools")
            yield Static("", id="analysis-status")
            with Collapsible(title="Firmware extraction settings", collapsed=True, id="analysis-firmware-options"):
                yield Label("Extraction environment")
                yield Select(
                    [("Isolated container", "container"), ("Trusted WSL", "trusted-wsl"),
                     ("Trusted host", "trusted-host")],
                    value="container", id="analysis-firmware-mode",
                )
                yield Static("Use the isolated container for unknown images.")
            with Collapsible(title="Runs for this file", collapsed=False, id="analysis-history"):
                yield Select([], prompt="No runs for this file", id="analysis-run-select")
                yield Static("Run status, coverage, and warnings appear here.", id="analysis-run-detail")
            with Collapsible(title="Progress", collapsed=True, id="analysis-progress-section"):
                yield LogViewer(id="analysis-progress")
            yield Button("Back", id="analysis-back")
        yield HelpFooter()

    def on_mount(self) -> None:
        self.query_one("#analysis-firmware-mode", Select).value = get_firmware_mode()
        self.query_one("#analysis-firmware-options", Collapsible).display = False
        raw = getattr(self.app, "_case_path", None) or get_case_directory()
        if raw and (Path(raw) / "case.json").is_file():
            self._refresh()
            target = "#analysis-run" if not self.query_one("#analysis-run", Button).disabled else "#analysis-choose-case"
            self.call_after_refresh(self.query_one(target).focus)
        else:
            self.call_after_refresh(self.query_one("#analysis-choose-case", Button).focus)

    def on_screen_resume(self) -> None:
        if self.query("#analysis-case"):
            self._refresh()

    def _case(self) -> Case:
        path = getattr(self.app, "_case_path", None) or get_case_directory()
        if not path:
            raise ValueError("Choose or create an investigation first")
        return Case.open(path)

    def _selected_evidence_id(self) -> str | None:
        value = self.query_one("#analysis-evidence", Select).value
        return value if isinstance(value, str) else None

    def _set_status(self, message: str) -> None:
        status = self.query_one("#analysis-status", Static)
        status.update(escape(message))
        status.display = True

    def _refresh(self) -> None:
        try:
            case = self._case()
            self.query_one("#analysis-case", Static).update(
                escape(f"{case.manifest['title']}  •  {len(case.manifest['evidence'])} files  •  {len(case.manifest['runs'])} runs")
            )
            choose = self.query_one("#analysis-choose-case", Button)
            choose.label = "Switch investigation"
            choose.tooltip = str(case.root)
            self.query_one("#analysis-manage-evidence", Button).disabled = False
            select = self.query_one("#analysis-evidence", Select)
            previous = self._requested_evidence_id or select.value
            evidence = [item for item in case.manifest["evidence"]
                        if self._view is None or item["kind"] in ANALYSIS_VIEWS[self._view].kinds]
            select.set_options([
                (f"{item['name']}  [{BY_KIND[item['kind']].label if item['kind'] in BY_KIND else item['kind']}]", item["id"])
                for item in evidence
            ])
            self._requested_evidence_id = None
            if evidence:
                ids = {item["id"] for item in evidence}
                select.value = previous if previous in ids else evidence[-1]["id"]
            else:
                select.value = Select.NULL
            self._update_evidence(case)
        except (OSError, ValueError, KeyError) as exc:
            self.query_one("#analysis-case", Static).update("No investigation is selected.")
            self.query_one("#analysis-evidence", Select).set_options([])
            self.query_one("#analysis-run", Button).disabled = True
            self.query_one("#analysis-manage-evidence", Button).disabled = True
            self._set_status(f"{type(exc).__name__}: {exc}")

    def _update_evidence(self, case: Case) -> None:
        evidence_id = self._selected_evidence_id()
        if evidence_id is None:
            expected = ANALYSIS_VIEWS[self._view].description if self._view else "a supported source file"
            self.query_one("#analysis-evidence-detail", Static).update(
                f"No {expected.lower()} in this investigation. Use Add or manage files to import one."
            )
            self.query_one("#analysis-run", Button).disabled = True
            self.query_one("#analysis-firmware-options", Collapsible).display = False
            self.query_one("#analysis-run-select", Select).set_options([])
            self.query_one("#analysis-run-detail", Static).update("No runs for this file.")
            return
        ref = case.evidence(evidence_id)
        spec = BY_KIND.get(ref.kind)
        analyzer = analyzer_for_kind(ref.kind)
        description = spec.description if spec else "Unrecognized evidence type."
        detail = f"{ref.size / (1024 * 1024):.1f} MiB  •  SHA-256 {ref.sha256[:16]}…  •  {description}"
        detail += f"  Analyzer: {analyzer}." if analyzer else "  No built-in analyzer; manual review only."
        self.query_one("#analysis-evidence-detail", Static).update(escape(detail))
        self.query_one("#analysis-run", Button).disabled = self._busy or analyzer is None
        self.query_one("#analysis-firmware-options", Collapsible).display = analyzer == "firmware"
        runs = [case.get_run(item["id"]) for item in case.manifest["runs"]]
        runs = [run for run in runs if evidence_id in run["input_ids"]]
        run_select = self.query_one("#analysis-run-select", Select)
        previous = self._requested_run_id or run_select.value
        run_select.set_options([
            (f"{run['analyzer']}  •  {run['started_at']}  •  {run['status']}  •  {run['id'][4:12]}", run["id"])
            for run in reversed(runs)
        ])
        if runs:
            run_ids = {run["id"] for run in runs}
            run_select.value = previous if previous in run_ids else runs[-1]["id"]
        self._requested_run_id = None
        self._update_run_detail(case)

    def _update_run_detail(self, case: Case) -> None:
        run_id = self.query_one("#analysis-run-select", Select).value
        if not isinstance(run_id, str):
            self.query_one("#analysis-run-detail", Static).update("No runs for this file.")
            return
        run = case.get_run(run_id)
        observations = run.get("observations", [])
        findings = run.get("findings", [])
        warnings = run.get("warnings", [])
        lines = [f"Status: {run['status']}  •  {len(observations)} observations  •  {len(findings)} findings"]
        if warnings:
            lines.append("Warnings: " + "; ".join(str(item) for item in warnings[:3]))
        coverage = run.get("coverage", {})
        if coverage:
            lines.append("Coverage: " + ", ".join(f"{key}={value}" for key, value in coverage.items()))
        if findings:
            by_id = {item["id"]: item for item in observations}
            for finding in findings[:5]:
                review = case.manifest["reviews"].get(finding["id"], {})
                state = review.get("status", finding.get("status", "candidate"))
                linked = next((by_id[oid] for oid in finding["observation_ids"] if oid in by_id), None)
                location = f" @ {linked['locator']}" if linked else ""
                lines.append(f"{finding['title']} [{state}]{location}"[:180])
        artifacts = run.get("artifacts", [])
        if artifacts:
            lines.append("Derived output: " + str(artifacts[0]))
        self.query_one("#analysis-run-detail", Static).update(escape("\n".join(lines)))

    def on_select_changed(self, event: Select.Changed) -> None:
        try:
            case = self._case()
            if event.select.id == "analysis-evidence":
                self._update_evidence(case)
            elif event.select.id == "analysis-run-select":
                self._update_run_detail(case)
        except (OSError, ValueError, KeyError):
            pass

    def action_choose_case(self) -> None:
        if self._busy:
            self._set_status("Wait for the current analysis to finish before switching investigations.")
            return
        raw = getattr(self.app, "_case_path", None)
        current = Path(raw) if raw and (Path(raw) / "case.json").is_file() else None
        self.app.push_screen(CasePickerScreen(current=current), self._case_chosen)

    def _case_chosen(self, path: str | None) -> None:
        if path is None:
            return
        setattr(self.app, "_case_path", path)
        self._requested_evidence_id = None
        self._refresh()
        self.call_after_refresh(self.query_one("#analysis-evidence", Select).focus)

    def action_manage_evidence(self) -> None:
        if self._busy:
            self._set_status("Wait for the current analysis to finish before leaving this screen.")
            return
        self.app.push_screen("case")

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Analysis"))

    def action_run_analysis(self) -> None:
        if self._busy:
            return
        evidence_id = self._selected_evidence_id()
        if not evidence_id:
            self._set_status("Import and select a file before running analysis.")
            return
        try:
            case = self._case()
            kind = case.evidence(evidence_id).kind
        except (OSError, ValueError, KeyError) as exc:
            self._set_status(f"Cannot open evidence: {exc}")
            return
        if analyzer_for_kind(kind) is None:
            self._set_status(f"No built-in analyzer accepts {kind} evidence. Review it manually.")
            return
        mode = str(self.query_one("#analysis-firmware-mode", Select).value)
        self._busy = True
        self.query_one("#analysis-run", Button).disabled = True
        self._set_status("Analysis is running. Its result will be saved in this investigation.")
        self.query_one("#analysis-progress-section", Collapsible).collapsed = False
        log = self.query_one("#analysis-progress", LogViewer)
        log.append(f"[cyan]Analyzing {escape(case.evidence(evidence_id).name)}[/]")
        app = self.app

        def post(callback, *args) -> None:
            try:
                app.call_from_thread(callback, *args)
            except RuntimeError:
                pass

        def progress(message: str) -> None:
            post(log.append, f"[cyan]{escape(message)}[/]")

        def worker() -> None:
            try:
                run = analyze_evidence(Case.open(case.root), evidence_id, firmware_mode=mode, progress=progress)
                post(self._finish_run, run.id, run.status, len(run.observations), len(run.findings))
            except Exception as exc:
                post(self._finish_error, f"{type(exc).__name__}: {exc}")

        threading.Thread(target=worker, daemon=True).start()

    def _finish_run(self, run_id: str, status: str, observations: int, findings: int) -> None:
        self._busy = False
        self._requested_run_id = run_id
        self._refresh()
        message = f"{status.title()} run {run_id[4:12]}: {observations} observations, {findings} candidate findings."
        self._set_status(message)
        color = "red" if status == "failed" else "yellow" if status != "complete" else "green"
        self.query_one("#analysis-progress", LogViewer).append(f"[{color}]{escape(message)}[/]")

    def _finish_error(self, message: str) -> None:
        self._busy = False
        self._refresh()
        self._set_status(message)
        self.query_one("#analysis-progress", LogViewer).append(f"[red]{escape(message)}[/]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "analysis-back":
                self.app.pop_screen()
            case "analysis-choose-case":
                self.action_choose_case()
            case "analysis-manage-evidence":
                self.action_manage_evidence()
            case "analysis-run":
                self.action_run_analysis()
            case "analysis-packet-tools":
                self.app.push_screen("analyze")
            case "analysis-apk-tools":
                self.app.push_screen("apk")
