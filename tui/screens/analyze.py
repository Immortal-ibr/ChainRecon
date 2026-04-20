"""Analyze screen — run analyzers on existing files."""

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

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogViewer

HELP_TEXT = """[bold underline]Traffic & Scan Analysis[/]

This parses files you've already captured and pulls out the security-relevant
stuff. Point it at a .pcap from the Capture screen, or an nmap .txt output.

[bold]Traffic (DNS/HTTP/TLS)[/]

  Uses pyshark — a Python wrapper around tshark — to iterate every packet.
  Equivalent to these tshark commands run manually:
    tshark -r file.pcap -Y dns -T fields -e dns.qry.name        (DNS queries)
    tshark -r file.pcap -Y http.request -T fields -e http.host  (HTTP hosts)
    tshark -r file.pcap -Y tls -T fields -e tls.handshake.extensions_server_name

  What it finds: every domain the device queried (including at startup before
  you touched anything), every HTTP URL with headers, and every TLS SNI field
  that shows what cloud backends the device phones home to.

  On the Nooie baby monitor we found CRITICAL: the device POSTs its MAC address
  and device ID to a Chinese CDN endpoint over plain HTTP before TLS starts.

[bold]SSL / TLS Certificates[/]

  Connects to each open port and downloads certs using Python's ssl module.
  Equivalent to:
    openssl s_client -connect <host>:443 </dev/null | openssl x509 -noout -text

  Checks: expiry date, self-signed flag, RSA key size (< 2048 = weak),
  issuer common name, and subject alternative names.

  On the Nooie we found a cert issued by "Apeman CA" valid for 100 years.
  Private CA cert = the vendor controls the CA key, it can't be publicly
  revoked. Combine that with 100-year validity and it's a permanent backdoor
  if that key is ever leaked.

[bold]Nmap Scan Results[/]

  Parses the .txt output from an nmap run. Extracts port/service/version
  mappings, checks versions against a CVE database (if configured), and
  maps ports to the IoT protocol database (MQTT, Modbus, UPnP, etc.).

[bold]PCAP Statistics[/]

  High-level breakdown without reading every packet:
    - Protocol distribution (%DNS, %HTTP, %TLS, %MQTT, etc.)
    - Top talkers by IP and how many bytes they sent
    - Cloud provider attribution: matches IPs against AWS/Azure/GCP/
      Cloudflare/Akamai/Fastly IP ranges to show what infrastructure is used
    - Session count and average session duration

[bold]WebRTC[/]

  Looks for STUN (port 3478) and TURN exchanges in the pcap. Extracts
  ICE candidates that tell you what relay infrastructure the device uses.
  The Nooie live stream goes through Amazon TURN servers — even when both
  client and camera are on the same LAN, traffic still routes via AWS.

[bold]MQTT[/]

  Decodes MQTT packets from the pcap:
    CONNECT   → broker address, client ID, username/password fields
    PUBLISH   → topic names and message payloads
    SUBSCRIBE → what topics the device subscribes to
  1883 = unencrypted, 8883 = MQTT over TLS. If there's no password in the
  CONNECT packet, the broker has auth disabled.

[bold]Custom Script[/]

  Run your own analyzer instead of or after the built-in one. The script
  receives the file path as its first argument. Good for: RsaCTFtool (to
  check for weak RSA keys in extracted certs), custom protocol decoders,
  or piping output into other tools.

[bold]Entropy Analysis[/]

  Computes Shannon entropy (bits per byte, 0–8) for every payload in the
  pcap.  Classifies each packet and stream as plaintext (< 4.5), structured
  (4.5–6.0), compressed (6.0–7.2), or encrypted (> 7.2).  Flags anomalies
  like low entropy on ports that should be encrypted (443, 8443, 8883).
  Also detects near-perfect entropy which may indicate XOR obfuscation.

[bold]RTP / Protocol Classification[/]

  Identifies UDP protocols by first-byte heuristics: STUN (magic cookie),
  DTLS (content types 20–25), RTP/SRTP (version 2), TURN channel data.
  Groups RTP packets by SSRC to identify media streams, extracts payload
  types (H.264, Opus, PCMU, etc.), and estimates packet loss from sequence
  number gaps.  Detects H.264 NAL units (SPS, PPS, IDR, FU-A) in RTP
  payloads.

[bold]Certificate Extraction (from pcap)[/]

  Scans TLS and DTLS handshakes for DER-encoded X.509 certificates.
  Parses each certificate and checks: RSA key size, signature algorithm
  (SHA-1 / MD5 = weak), expiry date, self-signed status, and Fermat
  factorisation vulnerability (p ≈ q).  Requires the 'cryptography'
  package for full analysis.

[dim]pyshark requires tshark installed (it shells out to tshark internally)
Analyzer code: analysis/ directory
openssl must be on PATH for SSL cert checks[/]
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
        with Vertical(id="analyze-form"):
            yield Label("[bold]Analysis[/]")
            yield Label("PCAP file / nmap output / target IP  [dim](SSL analyzer = enter IP, others = file path)[/]")
            yield Input(placeholder="path/to/file.pcap  or  192.168.1.99", id="filepath")
            yield Label("Analyzer:")
            yield Select(
                [
                    ("Traffic (DNS / HTTP / TLS)", "traffic"),
                    ("SSL / TLS Certificates", "ssl"),
                    ("Nmap Scan Results", "scan"),
                    ("PCAP Statistics", "pcap_stats"),
                    ("WebRTC", "webrtc"),
                    ("MQTT", "mqtt"),
                    ("Endpoint Map (IPs + Cloud)", "endpoint"),
                    ("Credential Scan (plaintext passwords)", "credentials"),
                    ("Entropy Analysis (encryption detection)", "entropy"),
                    ("RTP / Protocol Classification", "rtp"),
                    ("Certificate Extraction (from pcap)", "certs"),
                    ("Custom Script...", "custom"),
                ],
                value="traffic",
                id="analyzer",
            )
            with Vertical(id="custom-section"):
                yield Label("[dim]── Custom Script ──[/]")
                yield Label("Script path:")
                yield Input(placeholder="e.g. rsactftool.py  or  my_analysis.py", id="custom-path")
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
            yield LogViewer(id="analyze-log")
        yield Footer()

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
        # Strip surrounding quotes — common when pasting Windows paths
        filepath = self.query_one("#filepath", Input).value.strip().strip('"\'')
        analyzer = self.query_one("#analyzer", Select).value
        log = self.query_one("#analyze-log", LogViewer)
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        custom_interp = self.query_one("#custom-interp", Select).value

        if analyzer == "custom":
            if not custom_path:
                log.append("[red]Set a script path in the Custom Script field before using Custom Script analyzer.[/]")
                return
            self._run_custom_inline(filepath, custom_path, custom_interp, log)
            return

        if analyzer == "ssl":
            label = "target"
        else:
            label = "file path"

        if not filepath:
            log.append(f"[red]Please provide a {label}.[/]")
            return

        log.append(f"[bold]Running {analyzer} analysis on {filepath}…[/]")

        def _worker() -> None:
            try:
                result = self._dispatch(analyzer, filepath)

                # Save to output directory (from config)
                from datetime import datetime
                from utils.config import get_output_dir
                outdir = get_output_dir()
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                outfile = outdir / f"analysis_{analyzer}_{ts}.json"
                outfile.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

                # Store in app-level report generator for report screen
                if not hasattr(self.app, "_report_gen"):
                    from analysis.report_generator import ReportGenerator
                    self.app._report_gen = ReportGenerator()
                self.app._report_gen.add_results(analyzer, result)

                text = json.dumps(result, indent=2, default=str)[:4000]
                self.app.call_from_thread(log.append, f"[green]Done. Saved: {outfile}[/]\n{text}")
                if custom_path:
                    self.app.call_from_thread(self._run_custom_inline, filepath, custom_path, custom_interp, log)
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, filepath: str, script_path: str, interp: str, log: LogViewer) -> None:
        """Run a user-provided analysis script and append its output to the log."""
        log.append(f"[bold]Running custom script: {script_path}[/]")

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
                    self.app.call_from_thread(log.append, out[:3000])
                if result.returncode != 0:
                    self.app.call_from_thread(log.append, f"[yellow]Script exited with code {result.returncode}[/]")
                    if result.stderr:
                        self.app.call_from_thread(log.append, f"[red]{result.stderr[:500]}[/]")
                else:
                    self.app.call_from_thread(log.append, "[green]Custom script complete.[/]")

                from utils.config import get_output_dir
                outdir = get_output_dir()
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe = re.sub(r"[^a-z0-9_]", "_", Path(script_path).stem.lower())
                outfile = outdir / f"custom_analyze_{safe}_{ts}.json"
                outfile.write_text(json.dumps({
                    "tool": "custom_script", "script": script_path, "input_file": filepath,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                }, indent=2))
                self.app.call_from_thread(log.append, f"[dim]Result saved: {outfile}[/]")

                if save_to_lib:
                    from utils.custom_scripts import save_to_library
                    save_to_library("analyze", script_path, interp)
                    self.app.call_from_thread(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]Custom script error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    @staticmethod
    def _dispatch(analyzer: str, filepath: str) -> dict:
        # Strip surrounding quotes — common when pasting Windows paths
        filepath = filepath.strip().strip('"\'')

        if analyzer == "traffic":
            from analysis.traffic import TrafficAnalyzer
            return TrafficAnalyzer().analyze_pcap(filepath)

        elif analyzer == "ssl":
            # filepath is treated as a target IP/hostname for live cert probing
            from analysis.ssl_analyzer import SSLAnalyzer
            return SSLAnalyzer().probe_certificates(filepath, [443, 8443, 8883, 8080])

        elif analyzer == "scan":
            from analysis.scanner import ScannerAnalyzer
            return ScannerAnalyzer().parse_nmap_output(filepath)

        elif analyzer in ("pcap_stats", "webrtc", "mqtt", "endpoint", "credentials", "entropy", "rtp", "certs"):
            # These analyzers consume a packet list — load via TrafficAnalyzer's helper
            from analysis.traffic import TrafficAnalyzer
            ta = TrafficAnalyzer()
            packets, capture = ta._load_packets(filepath)
            try:
                if analyzer == "pcap_stats":
                    from analysis.pcap_stats import PcapStatsAnalyzer
                    return PcapStatsAnalyzer().analyze(packets)
                elif analyzer == "webrtc":
                    from analysis.webrtc_analyzer import WebRTCAnalyzer
                    return WebRTCAnalyzer().analyze(packets)
                elif analyzer == "endpoint":
                    from analysis.endpoint_analyzer import EndpointAnalyzer
                    return EndpointAnalyzer().analyze(packets)
                elif analyzer == "entropy":
                    from analysis.entropy_analyzer import EntropyAnalyzer
                    return EntropyAnalyzer().analyze(packets)
                elif analyzer == "rtp":
                    from analysis.rtp_analyzer import RTPAnalyzer
                    return RTPAnalyzer().analyze(packets)
                elif analyzer == "certs":
                    from analysis.cert_analyzer import CertAnalyzer
                    return CertAnalyzer().analyze(packets)
                elif analyzer == "credentials":
                    findings = ta.detect_plaintext_credentials(packets)
                    return {
                        "metadata": {"source": filepath, "packet_count": len(packets)},
                        "findings": {"credentials": findings},
                        "summary": {"credential_hits": len(findings)},
                        "risk_indicators": [
                            {"severity": "high", "title": "Plaintext credentials found",
                             "details": f"{len(findings)} credential pattern(s) detected in traffic."}
                        ] if findings else [],
                    }
                else:
                    from analysis.mqtt_analyzer import MQTTAnalyzer
                    return MQTTAnalyzer().analyze(packets)
            finally:
                if hasattr(capture, "close"):
                    capture.close()

        raise ValueError(f"Unknown analyzer: {analyzer}")

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Analysis"))
