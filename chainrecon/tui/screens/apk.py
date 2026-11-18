"""APK analysis screen."""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from pathlib import Path

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Header, Label, Select

from chainrecon.analysis.apk_analyzer import APKAnalyzer
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.tui.widgets.path_input import PathInput
from chainrecon.utils.artifacts import (
    artifact_path,
    safe_token,
    update_artifact_index,
    write_json_artifact,
)
from chainrecon.utils.redaction import redact_report_data, redact_text

HELP_TEXT = """[bold]APK toolkit[/]

Inspect a local APK with JADX. The toolkit records decoded permissions,
components, app flags, network security settings, library hints, and
credential-like strings. These are leads to review, not verified flaws.

This standalone tool saves a result and decompiled files separately. For
evidence-linked runs, coverage, and reviewer decisions, import the APK into
an investigation and choose Android APK on the home screen.

Select Built-in analyzer only to run JADX and the built-in checks. Select
Custom Script to run your chosen script afterward. The script runs only when
that option is selected. Configure JADX under Settings and tools.
"""


class APKScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("question_mark", "toggle_help", "Help")]

    DEFAULT_CSS = """
    #custom-section {
        display: none;
        height: auto;
    }
    #custom-section.visible {
        display: block;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="apk-form"):
            yield Label("[bold]APK toolkit[/]")
            yield Label("APK file — standalone result")
            yield PathInput(placeholder="APK file path — Tab completes", id="apk-path")
            yield Label("Post-analysis:")
            yield Select(
                [
                    ("Built-in analyzer only", "builtin"),
                    ("Custom Script...", "custom"),
                ],
                value="builtin",
                id="mode",
            )
            with Vertical(id="custom-section"):
                yield Label("[dim]-- Custom Script --[/]")
                yield Label("Script path:")
                yield PathInput(placeholder="Script path — Tab completes", id="custom-path")
                yield Label("Interpreter:")
                yield Select(
                    [("Python", "python"), ("PowerShell", "powershell"), ("Bash / sh", "bash"), ("Executable", "exe")],
                    value="python",
                    id="custom-interp",
                )
                yield Checkbox("Save to library (remember for future sessions)", id="custom-save")
            with Horizontal():
                yield Button("Analyze", variant="primary", id="btn-analyze")
                yield Button("Back", id="btn-back")
            yield LogActionBar()
            yield LogViewer(id="apk-log")
        yield HelpFooter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "mode":
            section = self.query_one("#custom-section")
            if event.value == "custom":
                section.add_class("visible")
            else:
                section.remove_class("visible")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return
        if event.button.id == "btn-analyze":
            self._analyze()

    def _analyze(self) -> None:
        # Strip surrounding quotes -- common when pasting Windows paths
        path = self.query_one("#apk-path", Input).value.strip().strip('"\'')
        log = self.query_one("#apk-log", LogViewer)
        mode = self.query_one("#mode", Select).value
        if not isinstance(mode, str):
            log.append("[red]Choose a post-analysis option first.[/]")
            return
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        custom_interp = self.query_one("#custom-interp", Select).value
        if not isinstance(custom_interp, str):
            custom_interp = "python"

        if not path:
            log.append("[red]Please provide an APK path.[/]")
            return

        if mode == "custom" and not custom_path:
            log.append("[red]Set a script path in the Custom Script field.[/]")
            return

        log.append(f"[bold]Analyzing {escape(path)}...[/]")
        from chainrecon.utils.config import get_output_dir

        outdir = get_output_dir()
        apk_name = safe_token(Path(path).stem, "apk")
        decompiled_dir = artifact_path(outdir, f"apk_decompiled_{apk_name}", "")
        outfile = artifact_path(outdir, f"apk_analysis_{apk_name}", ".json")
        log.append(f"[dim]Analysis will be saved to: {escape(str(outfile.resolve()))}[/]")
        log.append(f"[dim]Decompiled output: {escape(str(decompiled_dir.resolve()))}[/]")
        log.append("[dim]Decompiling with jadx -- large APKs can take 3-5 minutes, please wait...[/]")

        def _worker() -> None:
            def _on_progress(line: str) -> None:
                # Show jadx progress lines in the log (e.g. "progress: 120 of 500 (24%)")
                self.app.call_from_thread(log.append, f"[dim]{escape(redact_text(line))}[/]")

            try:
                result = APKAnalyzer().analyze(path, output_dir=str(decompiled_dir), progress_cb=_on_progress)

                jadx_error_count = int(result.get("summary", {}).get("jadx_error_count", 0) or 0)
                if jadx_error_count > 0:
                    self.app.call_from_thread(
                        log.append,
                        f"[yellow]jadx completed with {jadx_error_count} decompile warnings. "
                        "Analysis still completed; some classes may be partially decoded.[/]"
                    )

                result.setdefault("metadata", {}).setdefault("section", "apk")
                result.setdefault("metadata", {})["artifacts"] = [
                    {"type": "apk_analysis", "path": str(outfile.resolve())},
                    {"type": "apk_decompiled_dir", "path": str(decompiled_dir.resolve())},
                ]
                write_json_artifact(outfile, result)
                verified_outfile = self._verify_artifact_exists(outfile)
                verified_decompiled_dir = self._verify_artifact_exists(decompiled_dir)
                update_artifact_index(outdir, {
                    "section": "apk",
                    "type": "apk_analysis",
                    "path": str(verified_outfile.resolve()),
                    "decompiled_dir": str(verified_decompiled_dir.resolve()),
                    "apk": str(Path(path).resolve()),
                })

                report_gen = getattr(self.app, "_report_gen", None)
                if report_gen is None:
                    from chainrecon.analysis.report_generator import ReportGenerator

                    report_gen = ReportGenerator()
                    setattr(self.app, "_report_gen", report_gen)
                result["metadata"]["source_file"] = str(verified_outfile.resolve())
                result["metadata"]["source_filename"] = verified_outfile.name
                report_gen.add_results("apk", result)

                text = escape(json.dumps(redact_report_data(result), indent=2, default=str)[:4000])
                self.app.call_from_thread(log.set_last_output_path, verified_outfile)
                self.app.call_from_thread(
                    log.append,
                    f"[green]Done.[/]\n[dim]Analysis: {escape(str(verified_outfile))}[/]\n[dim]Decompiled: {escape(str(verified_decompiled_dir))}[/]\n{text}"
                )
                if mode == "custom":
                    self.app.call_from_thread(self._run_custom_inline, path, custom_path, custom_interp, log)
            except Exception as exc:
                import traceback
                tb = traceback.format_exc()
                self.app.call_from_thread(log.append, f"[red]Error: {escape(redact_text(str(exc)))}\n{escape(redact_text(tb[:1500]))}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, apk_path: str, script_path: str, interp: str, log: LogViewer) -> None:
        log.append(f"[bold]Running custom script: {escape(script_path)}[/]")

        try:
            save_to_lib = self.query_one("#custom-save", Checkbox).value
        except Exception:
            save_to_lib = False

        def _worker() -> None:
            try:
                if interp == "python":
                    cmd = ["python", script_path, apk_path]
                elif interp == "powershell":
                    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path, apk_path]
                elif interp == "bash":
                    cmd = ["bash", script_path, apk_path]
                else:
                    cmd = [script_path, apk_path]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                out = result.stdout.strip()
                if out:
                    self.app.call_from_thread(log.append, escape(redact_text(out[:3000])))
                if result.returncode != 0:
                    self.app.call_from_thread(log.append, f"[yellow]Script exited with code {result.returncode}[/]")
                    if result.stderr:
                        self.app.call_from_thread(log.append, f"[red]{escape(redact_text(result.stderr[:500]))}[/]")
                else:
                    self.app.call_from_thread(log.append, "[green]Custom script complete.[/]")

                from chainrecon.utils.config import get_output_dir
                outdir = get_output_dir()
                safe = re.sub(r"[^a-z0-9_]", "_", Path(script_path).stem.lower())
                outfile = artifact_path(outdir, f"custom_apk_{safe}", ".json")
                write_json_artifact(outfile, {
                    "metadata": {
                        "section": "apk_custom",
                        "source_file": str(outfile.resolve()),
                        "artifacts": [{"type": "custom_apk_result", "path": str(outfile.resolve())}],
                    },
                    "tool": "custom_script", "script": script_path, "apk": apk_path,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                })
                update_artifact_index(outdir, {
                    "section": "apk_custom",
                    "type": "custom_apk_result",
                    "path": str(outfile.resolve()),
                    "apk": apk_path,
                })
                self.app.call_from_thread(log.append, f"[dim]Result saved: {escape(str(outfile))}[/]")

                if save_to_lib:
                    from chainrecon.utils.custom_scripts import save_to_library
                    save_to_library("apk", script_path, interp)
                    self.app.call_from_thread(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Custom script error: {escape(redact_text(str(exc)))}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="APK Analysis"))

    @staticmethod
    def _verify_artifact_exists(path: Path, retries: int = 10, delay: float = 0.2) -> Path:
        target = path.expanduser().resolve()
        for _ in range(retries):
            if target.exists():
                return target
            time.sleep(delay)
        raise FileNotFoundError(f"Expected APK artifact was not created: {target}")
