"""APK analysis screen."""

from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Label, Select

from tui.widgets.pasteable_input import PasteableInput as Input

from analysis.apk_analyzer import APKAnalyzer
from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogViewer

HELP_TEXT = """[bold underline]APK Static Analysis[/]

Decompiles an Android APK file using JADX and inspects the resulting
Java source code, manifests, and resources for security issues.

[bold]What It Does (Step by Step)[/]
  1. Decompiles the APK: JADX converts DEX bytecode back into readable
     Java source and extracts all resources (XML, images, configs).
  2. Parses AndroidManifest.xml: Reads declared permissions, exported
     components (activities, services, receivers, content providers),
     and app flags (debuggable, allowBackup, usesCleartextTraffic).
  3. Checks network_security_config.xml: Looks for cleartext traffic
     permissions, certificate pins, and custom trusted CAs.
  4. Scans for hardcoded credentials: Regex patterns search Java and
     XML files for passwords, API keys, AWS credentials, Firebase URLs,
     and private keys embedded in the source.
  5. Detects IoT SDKs: Identifies Tuya, AWS IoT, Firebase, MQTT
     (Paho/HiveMQ), OkHttp, Retrofit, Agora, and WebRTC libraries.
  6. Checks certificate pinning implementation and method used.

[bold]Tool[/]: JADX (download from github.com/skylot/jadx/releases)
  Configure path in Settings or config/default.yaml → tools.jadx
  Or set environment variable: CHAINRECON_JADX_PATH=C:\\path\\to\\jadx.bat

[dim]Credential patterns: config/apk_patterns.yaml
Analyzer code: analysis/apk_analyzer.py
To edit this screen: tui/screens/apk.py[/]
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
        with Vertical(id="apk-form"):
            yield Label("[bold]APK Static Analysis[/]")
            yield Label("APK file path:")
            yield Input(placeholder="path/to/app.apk", id="apk-path")
            yield Label("Post-analysis:")
            yield Select(
                [
                    ("Built-in analyzer only", "builtin"),
                    ("Custom Script…", "custom"),
                ],
                value="builtin",
                id="mode",
            )
            with Vertical(id="custom-section"):
                yield Label("[dim]── Custom Script ──[/]")
                yield Label("Script path:")
                yield Input(placeholder="e.g. C:\\scripts\\apk_check.py", id="custom-path")
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
            yield LogViewer(id="apk-log")
        yield Footer()

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
        # Strip surrounding quotes — common when pasting Windows paths
        path = self.query_one("#apk-path", Input).value.strip().strip('"\'')
        log = self.query_one("#apk-log", LogViewer)
        mode = self.query_one("#mode", Select).value
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        custom_interp = self.query_one("#custom-interp", Select).value

        if not path:
            log.append("[red]Please provide an APK path.[/]")
            return

        if mode == "custom" and not custom_path:
            log.append("[red]Set a script path in the Custom Script field.[/]")
            return

        log.append(f"[bold]Analyzing {path}…[/]")
        log.append("[dim]Decompiling with jadx — large APKs can take 3-5 minutes, please wait…[/]")

        def _worker() -> None:
            def _on_progress(line: str) -> None:
                # Show jadx progress lines in the log (e.g. "progress: 120 of 500 (24%)")
                self.app.call_from_thread(log.append, f"[dim]{line}[/]")

            try:
                result = APKAnalyzer().analyze(path, progress_cb=_on_progress)

                # Save to output/
                from datetime import datetime
                outdir = Path("output")
                outdir.mkdir(exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                outfile = outdir / f"apk_analysis_{ts}.json"
                outfile.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

                text = json.dumps(result, indent=2, default=str)[:4000]
                self.app.call_from_thread(log.append, f"[green]Done. Saved: {outfile}[/]\n{text}")
                if custom_path:
                    self.app.call_from_thread(self._run_custom_inline, path, custom_path, custom_interp, log)
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, apk_path: str, script_path: str, interp: str, log: LogViewer) -> None:
        log.append(f"[bold]Running custom script: {script_path}[/]")

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
                    self.app.call_from_thread(log.append, out[:3000])
                if result.returncode != 0:
                    self.app.call_from_thread(log.append, f"[yellow]Script exited with code {result.returncode}[/]")
                    if result.stderr:
                        self.app.call_from_thread(log.append, f"[red]{result.stderr[:500]}[/]")
                else:
                    self.app.call_from_thread(log.append, "[green]Custom script complete.[/]")

                outdir = Path("output")
                outdir.mkdir(exist_ok=True)
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe = re.sub(r"[^a-z0-9_]", "_", Path(script_path).stem.lower())
                outfile = outdir / f"custom_apk_{safe}_{ts}.json"
                outfile.write_text(json.dumps({
                    "tool": "custom_script", "script": script_path, "apk": apk_path,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                }, indent=2))
                self.app.call_from_thread(log.append, f"[dim]Result saved: {outfile}[/]")

                if save_to_lib:
                    from utils.custom_scripts import save_to_library
                    save_to_library("apk", script_path, interp)
                    self.app.call_from_thread(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Custom script error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="APK Analysis"))
