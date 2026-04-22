"""Frida screen -- attach/spawn and run instrumentation scripts."""

from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Label, Select

from tui.widgets.pasteable_input import PasteableInput as Input

from runners.frida_runner import FRIDA_SCRIPTS, FridaRunner
from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogActionBar, LogViewer

HELP_TEXT = r"""[bold underline]Frida Dynamic Instrumentation[/]

Frida injects JavaScript into a running Android app to intercept function
calls, read memory, and modify behavior at runtime. It requires a rooted
device or emulator with frida-server running on it.

[bold]Attach vs Spawn[/]
  - Attach -- Connects to an already-running app. Use this when the app is
    open and you want to start monitoring its behavior.
  - Spawn -- Kills and restarts the app with your script injected from the
    very first instruction. Use this to catch initialization code, startup
    network calls, and early crypto operations that happen before you
    could attach.

[bold]Built-in Scripts[/]
  - List Classes -- Dumps all loaded Java classes. Filter by package name.
  - Hook All Methods -- Hooks every method in specified classes, logs calls.
  - Hook Single Method -- Targets one specific class.method for monitoring.
  - SSL Pinning Bypass -- Disables certificate pinning so you can intercept
    HTTPS traffic with a proxy like Burp Suite or mitmproxy.
  - Network Traffic Monitor -- Hooks Java networking APIs (URL, Socket,
    OkHttp) to log all network calls with URLs and payloads.
  - Crypto Monitor -- Hooks javax.crypto (Cipher, MessageDigest, SecretKey)
    to capture encryption keys, IVs, and plaintext before encryption.
  - Shared Preferences Dump -- Reads all key-value pairs stored in Android
    SharedPreferences (tokens, device IDs, settings, credentials).
  - Database Dump -- Hooks SQLite operations to log queries, inserts, and
    database file opens.
  - HTTP Intercept -- Hooks OkHttp3, HttpURLConnection, WebView, Retrofit.
  - Cert Pinning Detect -- Identifies which pinning libraries the app uses
    (OkHttp, NetworkSecurityConfig, TrustKit) without bypassing them.

  - WebRTC Frame Buffer Dump -- Hooks decoder buffers and prints encoded
  - WebRTC Frame Buffer Dump -- Hooks decoder buffers and prints encoded
    frame bytes for video-stream inspection.

[bold]Setup Requirements[/]
  Recommended emulator:
    Android 15 / API 35, Google APIs, x86_64, AVD name ChainRecon_API35.
    Avoid Play Store images; they usually do not allow adb root.

  Windows setup commands:
    winget install --id EclipseAdoptium.Temurin.17.JDK --source winget
    sdkmanager --sdk_root=%LOCALAPPDATA%\Android\Sdk "platform-tools" "emulator" "platforms;android-35" "system-images;android-35;google_apis;x86_64"
    avdmanager create avd --force --name ChainRecon_API35 --package "system-images;android-35;google_apis;x86_64" --device "Nexus 5X"
    emulator -avd ChainRecon_API35 -no-window -no-audio -no-snapshot -gpu swiftshader_indirect

  Frida setup commands:
    python -m pip install frida-tools
    adb devices
    adb shell getprop sys.boot_completed
    adb root
    adb shell getprop ro.product.cpu.abi
    frida --version
    Download matching frida-server-<version>-android-x86_64.xz from Frida releases.
    adb push frida-server /data/local/tmp/frida-server
    adb shell chmod +x /data/local/tmp/frida-server
    adb shell "/data/local/tmp/frida-server &"
    adb forward tcp:27042 tcp:27042
    frida-ps -U

  Smoke test:
    adb shell monkey -p com.android.settings 1
    frida -U -N com.android.settings -l runners/frida_scripts/network_traffic_monitor.js -q -t 10 --exit-on-error

[dim]Scripts: runners/frida_scripts/ directory
To add a script: add entry to FRIDA_SCRIPTS in runners/frida_runner.py
To edit this screen: tui/screens/frida.py[/]
"""

HELP_TEXT = r"""[bold underline]Frida Dynamic Instrumentation[/]

Frida injects JavaScript into a running Android app to intercept function
calls, read memory, and modify behavior at runtime. It requires a rooted
device or emulator with frida-server running on it.

[bold]Attach vs Spawn[/]
  - Attach: connect to an already-running app.
  - Spawn: start the app with your script injected from launch.

[bold]Built-in Scripts[/]
  - List Classes: enumerate loaded Java classes.
  - Hook All Methods: hook all methods in specified classes.
  - Hook Single Method: hook one specific class.method.
  - SSL Pinning Bypass: bypass common certificate pinning.
  - Network Traffic Monitor: hook URL, Socket, and OkHttp calls.
  - Crypto Monitor: log Cipher, MessageDigest, and Mac operations.
  - Shared Preferences Dump: log SharedPreferences reads/writes.
  - Database Dump: log SQLite queries and updates.
  - HTTP Intercept: hook OkHttp, HttpURLConnection, WebView, Retrofit.
  - Cert Pinning Detect: identify pinning libraries without bypassing them.
  - WebRTC Frame Buffer Dump: inspect encoded WebRTC frame buffers.

[bold]Recommended Android Device[/]
  Use Android 15 / API 35, Google APIs, x86_64, AVD name ChainRecon_API35.
  Avoid Play Store emulator images because they usually do not allow adb root.

[bold]Windows Emulator Setup[/]
  winget install --id EclipseAdoptium.Temurin.17.JDK --source winget
  sdkmanager --sdk_root=%LOCALAPPDATA%\\Android\\Sdk "platform-tools" "emulator" "platforms;android-35" "system-images;android-35;google_apis;x86_64"
  avdmanager create avd --force --name ChainRecon_API35 --package "system-images;android-35;google_apis;x86_64" --device "Nexus 5X"
  emulator -avd ChainRecon_API35 -no-window -no-audio -no-snapshot -gpu swiftshader_indirect

[bold]Frida Setup[/]
  python -m pip install frida-tools
  adb devices
  adb shell getprop sys.boot_completed
  adb root
  adb shell getprop ro.product.cpu.abi
  frida --version
  Download matching frida-server-<version>-android-x86_64.xz from Frida releases.
  adb push frida-server /data/local/tmp/frida-server
  adb shell chmod +x /data/local/tmp/frida-server
  adb shell "/data/local/tmp/frida-server &"
  adb forward tcp:27042 tcp:27042
  frida-ps -U

[bold]Smoke Test[/]
  adb shell monkey -p com.android.settings 1
  frida -U -N com.android.settings -l runners/frida_scripts/network_traffic_monitor.js -q -t 10 --exit-on-error

[dim]Scripts: runners/frida_scripts/ directory
To add a script: add entry to FRIDA_SCRIPTS in runners/frida_runner.py
To edit this screen: tui/screens/frida.py[/]
"""


class FridaScreen(Screen):
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
        with VerticalScroll(id="frida-form"):
            yield Label("[bold]Frida Instrumentation[/]")
            yield Label("Target process / package:")
            yield Input(placeholder="com.example.app", id="target")
            yield Label("Script:")
            frida_opts = [(v["label"], k) for k, v in FRIDA_SCRIPTS.items()] + [("Custom Script...", "custom")]
            yield Select(frida_opts, id="script")
            yield Label("Mode:")
            yield Select(
                [("Attach (running)", "attach"), ("Spawn (cold start)", "spawn")],
                value="attach",
                id="mode",
            )
            with Vertical(id="custom-section"):
                yield Label("[dim]-- Custom Script --[/]")
                yield Label("Script path:")
                yield Input(placeholder="e.g. C:\\scripts\\frida_hook.js  or  my_hook.py", id="custom-path")
                yield Label("Interpreter / language:")
                yield Select(
                    [("Python", "python"), ("PowerShell", "powershell"), ("Bash / sh", "bash"), ("Executable", "exe")],
                    value="python",
                    id="custom-interp",
                )
                yield Checkbox("Save to library (remember for future sessions)", id="custom-save")
            with Horizontal():
                yield Button("Run", variant="primary", id="btn-run")
                yield Button("List Devices", id="btn-devices")
                yield Button("List Processes", id="btn-procs")
                yield Button("Back", id="btn-back")
            yield LogActionBar()
            yield LogViewer(id="frida-log")
        yield Footer()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "script":
            section = self.query_one("#custom-section")
            if event.value == "custom":
                section.add_class("visible")
            else:
                section.remove_class("visible")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return

        log = self.query_one("#frida-log", LogViewer)
        runner = FridaRunner()

        if event.button.id == "btn-devices":
            threading.Thread(target=self._list_devices, args=(runner, log), daemon=True).start()
        elif event.button.id == "btn-procs":
            threading.Thread(target=self._list_procs, args=(runner, log), daemon=True).start()
        elif event.button.id == "btn-run":
            self._run_script(runner, log)

    def _list_devices(self, runner: FridaRunner, log: LogViewer) -> None:
        try:
            out = runner.list_devices()
            self.app.call_from_thread(log.append, out or "[dim]No output.[/]")
        except Exception as exc:
            self.app.call_from_thread(log.append, f"[red]{exc}[/]")

    def _list_procs(self, runner: FridaRunner, log: LogViewer) -> None:
        try:
            out = runner.list_processes()
            self.app.call_from_thread(log.append, out or "[dim]No output.[/]")
        except Exception as exc:
            self.app.call_from_thread(log.append, f"[red]{exc}[/]")

    def _run_script(self, runner: FridaRunner, log: LogViewer) -> None:
        target = self.query_one("#target", Input).value.strip().strip('"\'')
        script_key = self.query_one("#script", Select).value
        mode = self.query_one("#mode", Select).value
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        custom_interp = self.query_one("#custom-interp", Select).value

        if not target:
            log.append("[red]Enter a target process/package name.[/]")
            return

        if script_key == "custom":
            if not custom_path:
                log.append("[red]Set a script path in the Custom Script field.[/]")
                return
            self._run_custom_inline(target, custom_path, custom_interp, log)
            return

        log.append(f"[bold]{mode.title()}ing {target} with {script_key}...[/]")

        def _worker() -> None:
            try:
                if mode == "spawn":
                    result = runner.spawn_and_run(target, script_key)
                else:
                    result = runner.run_script(target, script_key)
                out = result.get("stdout", "") or result.get("stderr", "")
                self.app.call_from_thread(log.append, out[:3000] or "[dim]No output.[/]")
                if custom_path:
                    self.app.call_from_thread(self._run_custom_inline, target, custom_path, custom_interp, log)
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, target: str, script_path: str, interp: str, log: LogViewer) -> None:
        log.append(f"[bold]Running custom script: {script_path}[/]")

        try:
            save_to_lib = self.query_one("#custom-save", Checkbox).value
        except Exception:
            save_to_lib = False

        def _worker() -> None:
            try:
                if interp == "python":
                    cmd = ["python", script_path, target]
                elif interp == "powershell":
                    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path, target]
                elif interp == "bash":
                    cmd = ["bash", script_path, target]
                else:
                    cmd = [script_path, target]

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

                import re as _re
                from datetime import datetime
                from pathlib import Path as _Path
                import json as _json
                from utils.config import get_output_dir
                outdir = get_output_dir()
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe = _re.sub(r"[^a-z0-9_]", "_", _Path(script_path).stem.lower())
                outfile = outdir / f"custom_frida_{safe}_{ts}.json"
                outfile.write_text(_json.dumps({
                    "tool": "custom_script", "script": script_path, "target": target,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                }, indent=2))
                self.app.call_from_thread(log.append, f"[dim]Result saved: {outfile}[/]")

                if save_to_lib:
                    from utils.custom_scripts import save_to_library
                    save_to_library("frida", script_path, interp)
                    self.app.call_from_thread(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Custom script error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Frida Instrumentation"))
