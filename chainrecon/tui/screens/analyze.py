"""Standalone packet-analysis toolkit for existing capture files."""

from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Header, Label, Select

from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.tui.widgets.path_input import PathInput
from chainrecon.utils.artifacts import artifact_path
from chainrecon.utils.redaction import redact_report_data, redact_text

HELP_TEXT = """[bold]Packet toolkit[/]

Run a specialist analyzer on a local capture without importing it into a case.
For a run linked to an investigation and its review history, choose Packet
captures on the home screen. This toolkit saves a separate result file.

Traffic reads observable DNS, HTTP, TLS, endpoints, and conversations. Other
tools inspect statistics, WebRTC/STUN, MQTT, entropy, RTP/media indicators,
certificates, or credential patterns. Several specialist tools cap the packets
they inspect and report partial coverage when that bound is reached.

Port conventions, entropy, IP ownership guesses, absent handshakes, and
protocol-like byte patterns do not establish transport security or a
vulnerability. Review raw packets and endpoint roles before making a claim.
TShark/PyShark or another supported packet backend must be available.
"""


class AnalyzeScreen(Screen):
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
        with VerticalScroll(id="analyze-form"):
            yield Label("[bold]Packet toolkit[/]")
            yield Label("PCAP/PCAPNG file — standalone result")
            yield PathInput(placeholder="Capture file path — Tab completes", id="filepath")
            yield Label("Analyzer:")
            yield Select(
                [
                    ("Traffic (DNS / HTTP / TLS)", "traffic"),
                    ("PCAP Statistics", "pcap_stats"),
                    ("WebRTC", "webrtc"),
                    ("MQTT", "mqtt"),
                    ("Endpoint map (addresses)", "endpoint"),
                    ("Credential indicators", "credentials"),
                    ("Entropy (data distribution)", "entropy"),
                    ("RTP / protocol indicators", "rtp"),
                    ("Certificate Extraction (from pcap)", "certs"),
                    ("Custom Script...", "custom"),
                ],
                value="traffic",
                id="analyzer",
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
            yield LogViewer(id="analyze-log")
        yield HelpFooter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "analyzer":
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
            self._run_analysis()

    def _run_analysis(self) -> None:
        # Strip surrounding quotes -- common when pasting Windows paths
        filepath = self.query_one("#filepath", Input).value.strip().strip('"\'')
        log = self.query_one("#analyze-log", LogViewer)
        analyzer = self.query_one("#analyzer", Select).value
        if not isinstance(analyzer, str):
            log.append("[red]Choose a packet analyzer first.[/]")
            return
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        custom_interp = self.query_one("#custom-interp", Select).value
        if not isinstance(custom_interp, str):
            custom_interp = "python"

        if analyzer == "custom":
            if not custom_path:
                log.append("[red]Set a script path in the Custom Script field before using Custom Script analyzer.[/]")
                return
            self._run_custom_inline(filepath, custom_path, custom_interp, log)
            return

        if not filepath:
            log.append("[red]Please provide a PCAP file path.[/]")
            return

        log.append(f"[bold]Running {escape(str(analyzer))} analysis on {escape(filepath)}...[/]")

        def _worker() -> None:
            try:
                result = self._dispatch(analyzer, filepath)

                # Save to output directory (from config)
                from chainrecon.utils.config import get_output_dir
                outdir = get_output_dir()
                result.setdefault("metadata", {}).setdefault("section", analyzer)
                outfile = artifact_path(outdir, f"analysis_{analyzer}", ".json")
                outfile.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

                # Store in app-level report generator for report screen
                report_gen = getattr(self.app, "_report_gen", None)
                if report_gen is None:
                    from chainrecon.analysis.report_generator import ReportGenerator
                    report_gen = ReportGenerator()
                    setattr(self.app, "_report_gen", report_gen)
                report_gen.add_results(analyzer, result)

                if result.get("summary", {}).get("result_truncated"):
                    self.app.call_from_thread(log.append, "[yellow]Packet analysis reached its 10,000-packet batch limit; results are partial.[/]")
                text = escape(json.dumps(redact_report_data(result), indent=2, default=str)[:4000])
                self.app.call_from_thread(log.append, f"[green]Done. Saved: {escape(str(outfile))}[/]\n{text}")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Error: {escape(redact_text(str(exc)))}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, filepath: str, script_path: str, interp: str, log: LogViewer) -> None:
        """Run a user-provided analysis script and append its output to the log."""
        log.append(f"[bold]Running custom script: {escape(script_path)}[/]")

        try:
            save_to_lib = self.query_one("#custom-save", Checkbox).value
        except Exception:
            save_to_lib = False

        def _worker() -> None:
            try:
                arg_list = [filepath] if filepath else []
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
                outfile = artifact_path(outdir, f"custom_analyze_{safe}", ".json")
                outfile.write_text(json.dumps({
                    "tool": "custom_script", "script": script_path, "input_file": filepath,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                }, indent=2))
                self.app.call_from_thread(log.append, f"[dim]Result saved: {escape(str(outfile))}[/]")

                if save_to_lib:
                    from chainrecon.utils.custom_scripts import save_to_library
                    save_to_library("analyze", script_path, interp)
                    self.app.call_from_thread(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Custom script error: {escape(redact_text(str(exc)))}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    @staticmethod
    def _dispatch(analyzer: str, filepath: str) -> dict:
        # Strip surrounding quotes -- common when pasting Windows paths
        filepath = filepath.strip().strip('"\'')

        if analyzer == "traffic":
            from chainrecon.analysis.traffic import TrafficAnalyzer
            return TrafficAnalyzer().analyze_pcap(filepath)

        elif analyzer == "ssl":
            # filepath is treated as a target IP/hostname for live cert probing
            from chainrecon.analysis.ssl_analyzer import SSLAnalyzer
            return SSLAnalyzer().probe_certificates(filepath, [443, 8443, 8883, 8080])

        elif analyzer == "scan":
            from chainrecon.analysis.scanner import ScannerAnalyzer
            return ScannerAnalyzer().parse_nmap_output(filepath)

        elif analyzer in ("pcap_stats", "webrtc", "mqtt", "endpoint", "credentials", "entropy", "rtp", "certs"):
            # These analyzers consume a packet list -- load via TrafficAnalyzer's helper
            from chainrecon.analysis.traffic import TrafficAnalyzer
            ta = TrafficAnalyzer()
            packets, capture = ta._load_packets(filepath)
            try:
                if analyzer == "pcap_stats":
                    from chainrecon.analysis.pcap_stats import PcapStatsAnalyzer
                    result = PcapStatsAnalyzer().analyze(packets)
                elif analyzer == "webrtc":
                    from chainrecon.analysis.webrtc_analyzer import WebRTCAnalyzer
                    result = WebRTCAnalyzer().analyze(packets)
                elif analyzer == "endpoint":
                    from chainrecon.analysis.endpoint_analyzer import EndpointAnalyzer
                    result = EndpointAnalyzer().analyze(packets)
                elif analyzer == "entropy":
                    from chainrecon.analysis.entropy_analyzer import EntropyAnalyzer
                    result = EntropyAnalyzer().analyze(packets)
                elif analyzer == "rtp":
                    from chainrecon.analysis.rtp_analyzer import RTPAnalyzer
                    result = RTPAnalyzer().analyze(packets)
                elif analyzer == "certs":
                    from chainrecon.analysis.cert_analyzer import CertAnalyzer
                    result = CertAnalyzer().analyze(packets)
                elif analyzer == "credentials":
                    findings = ta.detect_plaintext_credentials(packets)
                    result = {
                        "metadata": {"source": filepath, "packet_count": len(packets)},
                        "findings": {"credentials": findings},
                        "summary": {"credential_hits": len(findings)},
                        "risk_indicators": [
                            {"severity": "medium", "title": "Credential-like plaintext pattern observed",
                             "details": f"{len(findings)} packet payload(s) matched a credential-like pattern. Review the captured bytes and context."}
                        ] if findings else [],
                    }
                else:
                    from chainrecon.analysis.mqtt_analyzer import MQTTAnalyzer
                    result = MQTTAnalyzer().analyze(packets)
                result.setdefault("metadata", {})["capture_truncated"] = packets.truncated
                result.setdefault("summary", {})["result_truncated"] = packets.truncated
                return result
            finally:
                if hasattr(capture, "close"):
                    capture.close()

        raise ValueError(f"Unknown analyzer: {analyzer}")

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Analysis"))
