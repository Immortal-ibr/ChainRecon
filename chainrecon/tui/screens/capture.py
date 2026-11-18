"""Capture screen -- configure and run traffic captures."""

from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Header, Label, Select

from chainrecon.runners.capture_runner import CaptureRunner
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.utils.config import get_config, get_network_config
from chainrecon.utils.network import list_interfaces

HELP_TEXT = """[bold underline]Traffic Capture[/]

This runs tshark (Windows) or tcpdump (Linux/Mac) and saves a .pcap file
you can drag into Wireshark or feed into the Analyze screen.

[bold]The exact command that runs[/]

  Windows: C:\\Program Files\\Wireshark\\tshark.exe -i <interface> -a duration:<secs> -w output/traffic_<mode>_<ts>.pcap [-f "<BPF>"]
  Linux:   tshark -i <iface> -a duration:<secs> -w <file> [-f "<BPF>"]

  If tshark isn't found: install Wireshark from https://www.wireshark.org/
  -- tshark comes bundled with it. Make sure to install with Npcap driver
  (the default installer option) so it can open network adapters.

[bold]Capture modes and their BPF filters[/]

  Full          -> no filter -- captures everything on the interface
  DNS Only      -> -f "port 53"
  HTTP Only     -> -f "port 80 or port 8080"
  TLS / HTTPS   -> -f "port 443 or port 8443"
  IoT Ports     -> -f "port 1883 or port 8883 or port 5353 or port 1900 or port 5683"

  If you have a target IP saved from Network Setup, it gets ANDed in:
    -f "host 10.50.0.254 and (port 1883 or port 8883)"
  This cuts pcap size dramatically and speeds up analysis.

[bold]Interface[/]

  Pick the adapter on the same network as your IoT device. In a typical
  interception setup, that's the Ethernet adapter going to the dedicated
  router. The dropdown shows friendly names and sends the NPF device path
  (\\Device\\NPF_{...}) to tshark automatically.

  If your adapter isn't listed: make sure Npcap is installed and try
  restarting the app.

[bold]Duration[/]

  Seconds to capture. While it's running, use the IoT app normally
  -- open a live stream, trigger a motion alert, reboot the device --
  to generate the traffic you want to see. 60-120 s is usually enough
  for a first look. For a full session, use 300+.

[bold]After capture[/]

  Open the Analyze screen and point it at the saved pcap:
    Traffic (DNS/HTTP/TLS) -> extracts every hostname, URL, SNI field
    WebRTC                 -> finds STUN/TURN servers and ICE candidates
    MQTT                   -> decodes publish/subscribe messages and topics
    PCAP Statistics        -> protocol breakdown + cloud provider attribution

  Or open in Wireshark with these display filters:
    dns                           -- all DNS queries
    http                          -- HTTP traffic
    tls.handshake.type == 1       -- TLS ClientHellos (shows SNI fields)
    mqtt                          -- MQTT traffic

[bold]Custom Script[/]

  Provide a script path to run after the capture finishes. The script
  receives: <target_ip> <pcap_file_path> as arguments. Useful for
  automated Wireshark dissection, custom protocol decoders, etc.

[dim]tshark resolved from C:\\Program Files\\Wireshark\\tshark.exe on Windows
pcap files saved to: output/traffic_<mode>_<timestamp>.pcap[/]
"""


class CaptureScreen(Screen):
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
        with VerticalScroll(id="capture-form"):
            yield Label("[bold]Traffic Capture[/]")
            yield Label("Interface:")
            ifaces_raw = list_interfaces() or []
            iface_opts = [
                (i["name"], i.get("device", i["name"]))
                for i in ifaces_raw
            ] if ifaces_raw else [("any", "any")]
            yield Select(
                iface_opts,
                value=iface_opts[0][1],
                id="iface",
            )
            yield Label("Capture Mode:")
            yield Select(
                [
                    ("Full  --  all traffic", "full"),
                    ("DNS Only  --  port 53", "dns"),
                    ("HTTP Only  --  port 80/8080", "http"),
                    ("TLS / HTTPS  --  port 443/8443", "tls"),
                    ("IoT Ports  --  MQTT + mDNS + UPnP", "iot"),
                    ("Custom Script...", "custom"),
                ],
                value="full",
                id="mode",
            )
            yield Label("Duration (seconds):")
            yield Input(placeholder="30", value="30", id="duration")
            with Vertical(id="custom-section"):
                yield Label("[dim]-- Custom Script --[/]")
                yield Label("Script path:")
                yield Input(placeholder="e.g. C:\\scripts\\analyze.py", id="custom-path")
                yield Label("Interpreter:")
                yield Select(
                    [("Python", "python"), ("PowerShell", "powershell"), ("Bash / sh", "bash"), ("Executable", "exe")],
                    value="python",
                    id="custom-interp",
                )
                yield Checkbox("Save to library (remember for future sessions)", id="custom-save")
            with Horizontal():
                yield Button("Start Capture", variant="primary", id="btn-capture")
                yield Button("Back", id="btn-back")
            yield LogActionBar()
            yield LogViewer(id="capture-log")
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
        if event.button.id == "btn-capture":
            self._run_capture()

    def _run_capture(self) -> None:
        iface = self.query_one("#iface", Select).value
        mode = self.query_one("#mode", Select).value
        dur = self.query_one("#duration", Input).value.strip()
        log = self.query_one("#capture-log", LogViewer)
        custom_path = self.query_one("#custom-path", Input).value.strip()
        custom_interp = self.query_one("#custom-interp", Select).value

        try:
            duration = int(dur)
        except ValueError:
            log.append("[red]Duration must be an integer.[/]")
            return

        cfg = get_config()
        output_dir = cfg.get("output", {}).get("directory", "output")
        net_cfg = get_network_config()
        target_ip = net_cfg.get("target_ip")

        if mode == "custom":
            if not custom_path:
                log.append("[red]Set a script path in the Custom Script field before using the Custom Script mode.[/]")
                return
            self._run_custom_inline(target_ip or "", custom_path, custom_interp, log)
            return

        log.append(f"[bold]Capturing on {iface} ({mode}) for {duration}s...[/]")

        def _worker() -> None:
            try:
                runner = CaptureRunner()
                result = runner.run_capture(
                    interface=iface, mode=mode, duration=duration,
                    target_ip=target_ip, output_dir=output_dir,
                )
                pcap_files = result.get("pcap_files", [])
                case_path = getattr(self.app, "_case_path", None)
                if case_path:
                    run_ids = _record_case_capture(pcap_files, case_path)
                    self._post(log.append, f"[dim]Case traffic runs: {', '.join(run_ids)}[/]")
                self._post(log.append, "[green]Capture complete.[/]")
                for f in pcap_files:
                    self._post(log.append, f"[dim]Saved: {f}[/]")
                if custom_path and pcap_files:
                    args = [target_ip or "", pcap_files[0]]
                    self._post(
                        self._run_custom_inline, args, custom_path, custom_interp, log
                    )
            except Exception as exc:
                self._post(log.append, f"[red]Error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, args: str | list[str], script_path: str, interp: str, log: LogViewer) -> None:
        """Run a user-provided script and append its output to the log."""
        log.append(f"[bold]Running custom script: {script_path}[/]")

        try:
            save_to_lib = self.query_one("#custom-save", Checkbox).value
        except Exception:
            save_to_lib = False

        def _worker() -> None:
            try:
                arg_list = args if isinstance(args, list) else ([args] if args.strip() else [])
                if interp == "python":
                    cmd = ["python", script_path] + arg_list
                elif interp == "powershell":
                    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path] + arg_list
                elif interp == "bash":
                    cmd = ["bash", script_path] + arg_list
                else:
                    cmd = [script_path] + arg_list

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                out = result.stdout.strip()
                if out:
                    self._post(log.append, out[:3000])
                if result.returncode != 0:
                    self._post(log.append, f"[yellow]Script exited with code {result.returncode}[/]")
                    if result.stderr:
                        self._post(log.append, f"[red]{result.stderr[:500]}[/]")
                else:
                    self._post(log.append, "[green]Custom script complete.[/]")

                from chainrecon.utils.config import get_output_dir
                outdir = get_output_dir()
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe = re.sub(r"[^a-z0-9_]", "_", Path(script_path).stem.lower())
                outfile = outdir / f"custom_capture_{safe}_{ts}.json"
                outfile.write_text(json.dumps({
                    "tool": "custom_script", "script": script_path, "args": arg_list,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                }, indent=2))
                self._post(log.append, f"[dim]Result saved: {outfile}[/]")

                if save_to_lib:
                    from chainrecon.utils.custom_scripts import save_to_library
                    save_to_library("capture", script_path, interp)
                    self._post(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self._post(log.append, f"[red]Custom script error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Traffic Capture"))

    def _post(self, callback, *args) -> None:
        try:
            self.app.call_from_thread(callback, *args)
        except RuntimeError:
            # A capture may finish after the user closes the TUI.
            pass


def _record_case_capture(paths: list[str], case_path: str) -> list[str]:
    """Preserve captured bytes and run bounded traffic analysis in the case."""
    from chainrecon.case_analysis import CaseAnalysisService
    from chainrecon.case_model import Case

    case = Case.open(case_path)
    run_ids = []
    for name in paths:
        path = Path(name)
        if not path.is_file():
            raise FileNotFoundError(f"Capture output missing: {path}")
        evidence = case.add_evidence(path, kind="pcap")
        run = CaseAnalysisService(case).run(evidence.id, "traffic")
        if run.status == "failed":
            raise RuntimeError(f"Case traffic analysis {run.id} failed: {'; '.join(run.warnings)}")
        run_ids.append(run.id)
    if not run_ids:
        raise ValueError("Capture produced no PCAP files")
    return run_ids
