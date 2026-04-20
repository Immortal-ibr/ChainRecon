"""Custom Script Runner screen.

Lets the user point to any script they wrote, pick the language/interpreter,
add arguments, give it a description for the report, and run it.  The
stdout/stderr output is captured and saved as a JSON findings file that can
be aggregated by ``chainrecon.py report`` or the Reports screen.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, TextArea

from tui.widgets.pasteable_input import PasteableInput as Input

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogViewer
from utils.config import get_config

HELP_TEXT = """[bold underline]Custom Script Runner[/]

Run any script you wrote and include its results in the ChainRecon report.

[bold]Fields[/]
  • Script Path — Full path to your script file.
      Examples:
        C:\\Users\\you\\my_check.py
        /home/you/scripts/check_ports.sh
  • Language / Interpreter — How to run the script:
        Python       → python <script>
        PowerShell   → powershell -File <script>
        Bash         → bash <script>
        Executable   → run the file directly (chmod +x required on Linux)
        Custom cmd   → you type the full command in "Arguments / Command"
                       and the script path is appended at the end
  • Arguments / Command — Extra flags passed after the script path.
    If you chose "Custom cmd", type the FULL command here (the script
    path will be appended automatically at the end).
  • Description — A short name for this check.  Appears in the report as
    the finding title so you know what the script was for.

[bold]Report Integration[/]
After a successful run the output is saved as a JSON file in the output
directory (same folder used by all other ChainRecon analyzers).  Open
the Reports screen and click Generate to include it.

[bold]Exit Codes[/]
  0 → success (finding severity: Info)
  Non-zero → something flagged (finding severity: High)

[bold]Security Note[/]
Only run scripts you trust.  ChainRecon will execute the file with the
permissions of the current user.

[dim]Output folder: configured via output.directory in config/default.yaml
To edit this screen: tui/screens/custom_script.py[/]
"""

_INTERPRETERS = [
    ("Python  (python <script>)", "python"),
    ("PowerShell  (powershell -File <script>)", "powershell"),
    ("Bash  (bash <script>)", "bash"),
    ("Executable  (run directly)", "exec"),
    ("Custom command  (full cmd + script path appended)", "custom"),
]


class CustomScriptScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "toggle_help", "Help"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="custom-script-form"):
            yield Label("[bold]Custom Script Runner[/]")
            yield Label(
                "[dim]Run your own script and add its results to the report. "
                "Press [b]?[/b] for full documentation.[/]"
            )
            yield Label("")

            yield Label("Script path:")
            yield Input(
                placeholder="e.g. C:\\scripts\\my_check.py  or  /home/you/check.sh",
                id="script-path",
            )

            yield Label("Language / interpreter:")
            yield Select(_INTERPRETERS, value="python", id="interpreter")

            yield Label("Arguments  [dim](optional — passed after the script path)[/]:")
            yield Input(
                placeholder="e.g. --target 192.168.1.1 --port 8883",
                id="script-args",
            )

            yield Label("Description  [dim](used as the finding title in the report)[/]:")
            yield Input(
                placeholder="e.g. Check MQTT topic enumeration",
                id="description",
            )

            yield Label("Additional notes / instructions for this run  [dim](optional)[/]:")
            yield TextArea(id="notes", language=None)

            with Horizontal():
                yield Button("▶  Run Script", variant="primary", id="btn-run")
                yield Button("Back", id="btn-back")

            yield LogViewer(id="script-log")
        yield Footer()

    # ------------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-run":
            self._run_script()

    # ------------------------------------------------------------------
    def _run_script(self) -> None:
        log = self.query_one("#script-log", LogViewer)

        script_path = self.query_one("#script-path", Input).value.strip()
        interpreter = self.query_one("#interpreter", Select).value
        args_raw = self.query_one("#script-args", Input).value.strip()
        description = self.query_one("#description", Input).value.strip() or "Custom Script"
        notes = self.query_one("#notes", TextArea).text.strip()

        if not script_path:
            log.append("[red]Please enter a script path.[/]")
            return

        if not Path(script_path).exists():
            log.append(f"[red]File not found: {script_path}[/]")
            return

        # Build the command list
        extra_args = args_raw.split() if args_raw else []

        if interpreter == "python":
            cmd = ["python", script_path] + extra_args
        elif interpreter == "powershell":
            cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path] + extra_args
        elif interpreter == "bash":
            cmd = ["bash", script_path] + extra_args
        elif interpreter == "exec":
            cmd = [script_path] + extra_args
        else:  # custom — args_raw is treated as the prefix command, script appended
            cmd = extra_args + [script_path]

        log.append(f"[bold]Running:[/] {' '.join(cmd)}")
        if notes:
            log.append(f"[dim]Notes: {notes}[/]")

        def _worker() -> None:
            start = datetime.datetime.now(datetime.timezone.utc)
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5-minute cap
                )
                duration = (datetime.datetime.now(datetime.timezone.utc) - start).total_seconds()
                stdout = result.stdout.strip()
                stderr = result.stderr.strip()

                # Emit output to log viewer
                if stdout:
                    for line in stdout.splitlines()[-200:]:
                        self.app.call_from_thread(log.append, line)
                if stderr:
                    for line in stderr.splitlines()[-50:]:
                        self.app.call_from_thread(log.append, f"[yellow]{line}[/]")

                exit_code = result.returncode
                severity = "info" if exit_code == 0 else "high"
                color = "green" if exit_code == 0 else "red"
                self.app.call_from_thread(
                    log.append,
                    f"[{color}]Script exited with code {exit_code} in {duration:.1f}s[/]",
                )

                # Save findings JSON for report aggregation
                self.app.call_from_thread(
                    self._save_result,
                    description=description,
                    script_path=script_path,
                    cmd=" ".join(cmd),
                    notes=notes,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    severity=severity,
                    duration=duration,
                    log=log,
                )
            except subprocess.TimeoutExpired:
                self.app.call_from_thread(log.append, "[red]Script timed out (5 minutes).[/]")
            except FileNotFoundError as exc:
                self.app.call_from_thread(log.append, f"[red]Interpreter not found: {exc}[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    # ------------------------------------------------------------------
    @staticmethod
    def _save_result(
        *,
        description: str,
        script_path: str,
        cmd: str,
        notes: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        severity: str,
        duration: float,
        log: LogViewer,
    ) -> None:
        cfg = get_config()
        out_dir = Path(cfg.get("output", {}).get("directory", "output"))
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in description)[:40]
        out_file = out_dir / f"custom_{safe_name}_{timestamp}.json"

        payload = {
            "metadata": {
                "analyzer": "CustomScriptRunner",
                "description": description,
                "script": script_path,
                "command": cmd,
                "notes": notes,
                "exit_code": exit_code,
                "duration_seconds": duration,
            },
            "findings": {
                "stdout": stdout,
                "stderr": stderr,
            },
            "summary": {
                "exit_code": exit_code,
                "duration_seconds": duration,
            },
            "risk_indicators": [
                {
                    "severity": severity,
                    "title": description,
                    "details": (
                        f"Script exited {exit_code}. "
                        f"Output ({len(stdout)} chars): {stdout[:500]}"
                        if stdout else f"Script exited {exit_code} (no output)."
                    ),
                }
            ],
        }

        try:
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            log.append(f"[green]Results saved → {out_file}[/]")
            log.append("[dim]Open the Reports screen to include this in your report.[/]")
        except Exception as exc:
            log.append(f"[yellow]Could not save results: {exc}[/]")

    # ------------------------------------------------------------------
    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Custom Script Runner"))
