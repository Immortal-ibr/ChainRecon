"""Scan screen -- configure and run Nmap scans."""

from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Collapsible, Header, Label, Select

from chainrecon.runners.nmap_runner import NmapInterfaceMismatchError, NmapRunner
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.tui.widgets.log_viewer import LogActionBar, LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.utils.artifacts import artifact_path, safe_token
from chainrecon.utils.config import (
    get_network_config,
    get_output_dir,
    get_scan_config,
    save_scan_config,
)
from chainrecon.utils.network import list_scan_interfaces, resolve_scan_interface

HELP_TEXT = """[bold underline]Network Scan[/]

What actually runs here: nmap commands via subprocess. nmap is the standard
tool for port scanning -- every pentester has used it, it's been around since
1997, and the IoT research community relies on it for device fingerprinting.

[bold]Profiles and the commands behind them[/]

    ARP Discovery  ->  nmap -sn -PR <target>
        Host discovery only. Uses ARP on the local subnet instead of guessing from
        the host ARP cache. This is the supported local-device discovery path.

  Quick  ->  nmap -Pn -sV -T4 --top-ports 1000 <target>
    -Pn skips host discovery (assumes target is up). -sV grabs service banners.
    Scans the 1000 most common ports -- catches HTTP, RTSP streams, SSH, Telnet.
    Finishes in under 2 minutes on a local network. Good first pass.

    Gentle  ->  nmap -Pn -sT -sV -T2 --max-retries 1 <target>
    Full TCP three-way handshake on every port, slow timing. Use this if the
    device crashes or stops responding under normal scanning. Cheap IP cameras
    and baby monitors often have terrible TCP stacks that die under SYN floods.

  Full  ->  nmap -Pn -A -p- -T4 --version-intensity 9 <target>
    -A means OS detection + service versions + default scripts + traceroute.
    -p- scans all 65535 ports. Takes 20-40 minutes but gives the complete
    picture. Services sometimes hide on non-standard ports to avoid quick scans.

  IoT  ->  two passes:
    TCP: nmap -Pn -sV -T4 -p 80,443,8080,8443,8008,1883,8883,502,102,47808
    UDP: nmap -Pn -sU -T4 -p 53,67,123,1900,5353,5683
    These cover the IoT attack surface:
      1883/8883 = MQTT (most IoT sensors publish data here)
      1900 = UPnP (had multiple pre-auth RCE bugs, e.g. CallStranger 2020)
      5353 = mDNS (device announces its name here, great for fingerprinting)
      502 = Modbus (industrial control, not expected on consumer devices)

  Vulnerability  ->  nmap -Pn -sV --script vuln -T4 <target>
    Runs ~60 NSE scripts checking for EternalBlue (MS17-010), Heartbleed,
    weak SSH keys, Shellshock, default creds on HTTP admin pages, and more.
    Output is long -- look for "VULNERABLE" lines.

  SSL / Cert  ->  nmap -Pn --script ssl-cert,ssl-enum-ciphers -p 443,8443,8883,8080 <target>
    Downloads the TLS certificate from each port and lists what cipher suites
    the server will accept. Specifically look for:
      - RC4 or DES in the cipher list (both broken)
      - RSA key size < 2048 bits (weak, increasingly breakable)
      - Self-signed or private CA cert, reviewed against the device trust model
      - Certificate validity > 1 year on a private CA cert (red flag)
    A long-lived certificate is a review lead; verify its deployment and
    rotation mechanism before making a security claim.

[bold]Target field[/]

  Anything nmap accepts works:
    Single IP    ->  192.0.2.10
    Subnet       ->  192.0.2.0/24
    IP range     ->  192.0.2.1-20

  For a device behind a dedicated router: your PC talks to the router's
  Ethernet-side IP (e.g. .99), not to the IoT device directly. The device
  is behind the router's own NAT. Run  arp -a  to see what's on your network.
  The target you saved in Network Setup is pre-loaded automatically.

[bold]Custom Script[/]

  The bottom section lets you run any script (Python, PowerShell, bash, or
  a bare executable) instead of or in addition to nmap. The script receives
  the target IP as its first argument. Results are saved to output/ as JSON.
  Use this for Shodan lookups, custom fingerprinters, or RsaCTFtool runs.

[dim]nmap path: auto-detected (checks C:\\Program Files (x86)\\Nmap on Windows)
Output saved to: output/nmap_<profile>.txt
To edit profiles: runners/nmap_runner.py -> SCAN_PROFILES dict[/]
"""


SCAN_PROFILE_OPTIONS = [
    ("ARP discovery", "arp"),
    ("Quick: common ports", "quick"),
    ("Gentle: slower TCP", "gentle"),
    ("Full: all TCP ports", "full"),
    ("IoT: common device ports", "iot"),
    ("Vulnerability scripts", "vuln"),
    ("TLS certificates and ciphers", "ssl"),
    ("Custom script", "custom"),
]


class ScanScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("question_mark", "toggle_help", "Help")]

    DEFAULT_CSS = """
    ScanScreen #scan-form { padding: 0 2; }
    ScanScreen #scan-form Button { margin: 0 1 0 0; }
    ScanScreen #scan-form Collapsible { margin: 1 0; }
    #custom-section {
        display: none;
        height: auto;
    }
    #custom-section.visible {
        display: block;
    }
    """

    def compose(self) -> ComposeResult:
        net_cfg = get_network_config()
        scan_cfg = get_scan_config()
        saved_target = net_cfg.get("target_ip") or net_cfg.get("router_ip") or ""
        default_interface = scan_cfg.get("interface_name") or scan_cfg.get("interface") or net_cfg.get("internet_interface") or ""
        interface_options, selected_interface = _interface_options(default_interface)

        yield Header()
        with VerticalScroll(id="scan-form"):
            yield Label("Network scan", id="title")
            yield Label("Target IP or subnet")
            yield Input(placeholder="e.g. 192.168.1.0/24", id="target", value=saved_target)
            yield Label("Scan profile")
            yield Select(SCAN_PROFILE_OPTIONS, value="iot", id="profile")
            with Vertical(id="custom-section"):
                yield Label("Script path")
                yield Input(placeholder="e.g. C:\\scripts\\my_scan.py", id="custom-path")
                yield Label("Interpreter")
                yield Select(
                    [("Python", "python"), ("PowerShell", "powershell"), ("Bash / sh", "bash"), ("Executable", "exe")],
                    value="python",
                    id="custom-interp",
                )
                yield Checkbox("Save to library (remember for future sessions)", id="custom-save")
            with Horizontal():
                yield Button("Run Scan", variant="primary", id="btn-scan")
                yield Button("Back", id="btn-back")
            with Collapsible(title="Interface and options", collapsed=True):
                yield Label("Use automatic routing unless this scan needs a specific adapter.")
                with Horizontal():
                    yield Select(interface_options, value=selected_interface, id="scan-interface")
                    yield Button("Refresh interfaces", id="btn-refresh-ifaces")
            yield LogActionBar()
            yield LogViewer(id="scan-log")
        yield HelpFooter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "profile":
            section = self.query_one("#custom-section")
            if event.value == "custom":
                section.add_class("visible")
            else:
                section.remove_class("visible")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return
        if event.button.id == "btn-refresh-ifaces":
            self._refresh_interfaces()
            return
        if event.button.id == "btn-scan":
            self._run_scan()

    def _run_scan(self) -> None:
        # Strip surrounding quotes -- common when pasting Windows paths
        target = self.query_one("#target", Input).value.strip().strip('"\'')
        interface_value = self.query_one("#scan-interface", Select).value
        profile_value = self.query_one("#profile", Select).value
        log = self.query_one("#scan-log", LogViewer)
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        custom_interp_value = self.query_one("#custom-interp", Select).value
        if not isinstance(profile_value, str):
            log.append("[red]Choose a scan profile.[/]")
            return
        profile = profile_value
        custom_interp = custom_interp_value if isinstance(custom_interp_value, str) else "python"

        scan_cfg = get_scan_config()
        interface_config_value = scan_cfg.get("interface_name") or scan_cfg.get("interface")
        interface = None
        interface_label = "Auto / nmap default"
        interface_runtime = ""
        if interface_value not in (None, Select.BLANK, "__auto__"):
            resolved = resolve_scan_interface(str(interface_value))
            if resolved is None:
                log.append(f"[red]Selected interface '{interface_value}' is no longer available. Refresh interfaces and choose again.[/]")
                return
            interface = resolved.get("runtime_id") or None
            interface_label = resolved.get("label") or str(interface_value)
            interface_runtime = resolved.get("runtime_id", "")
            save_scan_config({
                "interface": resolved.get("runtime_id"),
                "interface_name": resolved.get("name"),
                "interface_device": resolved.get("device"),
            })
        elif interface_config_value:
            resolved = resolve_scan_interface(str(interface_config_value))
            if resolved is not None:
                interface = resolved.get("runtime_id") or None
                interface_label = resolved.get("label") or str(interface_config_value)
                interface_runtime = resolved.get("runtime_id", "")

        if not target:
            log.append("[red]Please enter a target IP or subnet.[/]")
            return

        if profile == "custom":
            if not custom_path:
                log.append("[red]Set a script path in the Custom Script field before using the Custom Script profile.[/]")
                return
            self._run_custom_inline(target, custom_path, custom_interp, log)
            return

        if profile == "full":
            log.append("[yellow]Full scan scans all 65535 ports -- this can take 20-40 minutes on a home network. "
                       "If it times out, run nmap directly from the command line.[/]")

        if interface:
            log.append(f"[bold]Starting {profile} scan on {target} via {interface_label} ({interface_runtime})...[/]")
        else:
            log.append(f"[bold]Starting {profile} scan on {target} with automatic interface selection...[/]")
        output_dir = str(get_output_dir())

        def _worker() -> None:
            try:
                runner = NmapRunner()
                result = runner.run_scan(target, profile, output_dir=output_dir, interface=interface or None)
                self._post(log.append, _describe_nmap_run(result, interface_label=interface_label))

                # Store in app-level report generator
                _ensure_report_generator(self.app)
                structured = _build_scan_report_payload(result)
                getattr(self.app, "_report_gen").add_results("scan", structured)

                structured_path = artifact_path(output_dir, f"scan_{safe_token(str(profile), 'scan')}", ".json")
                structured_path.write_text(json.dumps(structured, indent=2, default=str), encoding="utf-8")
                case_path = getattr(self.app, "_case_path", None)
                if case_path:
                    run_ids = _record_case_scan(result, case_path)
                    self._post(log.append, f"[dim]Case scan runs: {', '.join(run_ids)}[/]")

                self._post(log.append, "[green]Scan complete.[/]")
                self._post(log.append, f"[dim]Result saved: {structured_path.resolve()}[/]")
                for fpath in result.get("output_files", []):
                    self._post(log.append, f"[dim]Saved: {fpath}[/]")
                for fpath in _displayable_output_files(result.get("output_files", [])):
                    try:
                        lines = Path(fpath).read_text(encoding="utf-8", errors="replace").strip().splitlines()
                        self._post(log.append, "\n".join(lines[-60:]))
                    except Exception:
                        pass
                if custom_path:
                    self._post(self._run_custom_inline, target, custom_path, custom_interp, log)
            except subprocess.TimeoutExpired:
                self._post(
                    log.append,
                    f"[red]Scan timed out. Full scans on all 65535 ports can take over an hour. "
                    f"Run nmap directly:\n  nmap -Pn -A -p- -T4 {target}[/]"
                )
            except NmapInterfaceMismatchError as exc:
                preflight = exc.preflight
                recommended = preflight.get("recommended_interface") or {}
                suggestion = recommended.get("label") or recommended.get("name") or recommended.get("runtime_id")
                message = f"[red]{exc}[/]"
                if suggestion:
                    message += f"\n[yellow]Recommended interface: {suggestion}[/]"
                message += "\n[dim]Refresh interfaces and select the route-matching interface, or use the CLI --allow-interface-mismatch for intentional advanced use.[/]"
                self._post(log.append, message)
            except Exception as exc:
                self._post(log.append, f"[red]Error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _run_custom_inline(self, target: str, script_path: str, interp: str, log: LogViewer) -> None:
        """Run a user-provided script and append its output to the log."""
        log.append(f"[bold]Running custom script: {script_path}[/]")

        # Read save-to-library preference on the main thread before spawning worker
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
                    self._post(log.append, out[:3000])
                if result.returncode != 0:
                    self._post(log.append, f"[yellow]Script exited with code {result.returncode}[/]")
                    if result.stderr:
                        self._post(log.append, f"[red]{result.stderr[:500]}[/]")
                else:
                    self._post(log.append, "[green]Custom script complete.[/]")

                from chainrecon.utils.config import get_output_dir
                outdir = get_output_dir()
                safe = re.sub(r"[^a-z0-9_]", "_", Path(script_path).stem.lower())
                outfile = artifact_path(outdir, f"custom_scan_{safe}", ".json")
                outfile.write_text(json.dumps({
                    "tool": "custom_script", "script": script_path, "target": target,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000], "stderr": result.stderr[:2000],
                }, indent=2))
                self._post(log.append, f"[dim]Result saved: {outfile}[/]")

                if save_to_lib:
                    from chainrecon.utils.custom_scripts import save_to_library
                    save_to_library("scan", script_path, interp)
                    self._post(log.append, "[dim]Script saved to library.[/]")
            except Exception as exc:
                self._post(log.append, f"[red]Custom script error: {exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Network Scan"))

    def _post(self, callback, *args) -> None:
        try:
            self.app.call_from_thread(callback, *args)
        except RuntimeError:
            # The user may close the TUI while an external scan is finishing.
            pass

    def _refresh_interfaces(self) -> None:
        scan_cfg = get_scan_config()
        net_cfg = get_network_config()
        default_interface = scan_cfg.get("interface_name") or scan_cfg.get("interface") or net_cfg.get("internet_interface") or ""
        options, selected = _interface_options(default_interface)
        select = self.query_one("#scan-interface", Select)
        select.set_options(options)
        select.value = selected
        self.query_one("#scan-log", LogViewer).append("[dim]Host interface list refreshed.[/]")


def _build_scan_report_payload(run_result: dict) -> dict:
    """Combine nmap runner metadata with parsed nmap outputs."""
    from chainrecon import combine_scan_results
    from chainrecon.analysis.scanner import ScannerAnalyzer

    analyzer = ScannerAnalyzer()
    parsed_results = []
    for fpath in run_result.get("output_files", []):
        path = Path(fpath)
        if path.suffix.lower() == ".xml" and path.exists() and path.stat().st_size > 0:
            parsed_results.append(analyzer.parse_nmap_output(str(path)))
    if not parsed_results:
        raise RuntimeError("Nmap scan produced no XML evidence; coverage is unknown")
    payload = combine_scan_results(run_result, parsed_results)
    payload.setdefault("metadata", {})["backend"] = run_result.get("backend", "nmap")
    return payload


def _record_case_scan(run_result: dict, case_path: str) -> list[str]:
    """Copy each Nmap XML artifact into a case before analyzing it."""
    from chainrecon.case_analysis import CaseAnalysisService
    from chainrecon.case_model import Case

    case = Case.open(case_path)
    run_ids = []
    for name in run_result.get("output_files", []):
        path = Path(name)
        if path.suffix.lower() != ".xml" or not path.is_file():
            continue
        evidence = case.add_evidence(path, kind="scan_xml")
        run = CaseAnalysisService(case).run(evidence.id, "scan")
        if run.status != "complete":
            raise RuntimeError(f"Case scan analysis {run.id} is {run.status}: {'; '.join(run.warnings)}")
        run_ids.append(run.id)
    if not run_ids:
        raise ValueError("Nmap result did not provide XML evidence for the case")
    return run_ids


def _interface_options(default_interface: str) -> tuple[list[tuple[str, str]], str]:
    configured = str(default_interface or "").strip()
    auto_label = "Auto / nmap default"
    if configured:
        auto_label = f"Auto / config default ({configured})"
    options: list[tuple[str, str]] = [(auto_label, "__auto__")]
    seen: set[str] = set()
    for iface in list_scan_interfaces():
        name = str(iface.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        description = str(iface.get("description") or "").strip()
        runtime = str(iface.get("runtime_id") or "").strip()
        label = name if not description else f"{name}  [{description}]"
        if runtime and runtime not in {name, iface.get("device", "")}:
            label = f"{label} -> {runtime}"
        options.append((label, name))
    return options, configured if configured in seen else "__auto__"


def _ensure_report_generator(app) -> None:
    if not hasattr(app, "_report_gen"):
        from chainrecon.analysis.report_generator import ReportGenerator

        app._report_gen = ReportGenerator()


def _describe_nmap_run(run_result: dict, *, interface_label: str) -> str:
    lines = []
    preflight = run_result.get("preflight", {}) or {}
    if preflight.get("dns_error"):
        lines.append(f"[yellow]Preflight DNS resolution failed: {preflight['dns_error']}[/]")
    elif preflight.get("dns_resolved"):
        resolved = ", ".join(preflight.get("resolved_addresses", [])) or "resolved"
        lines.append(f"[dim]Preflight resolved target to: {resolved}[/]")

    icmp = preflight.get("icmp_echo")
    if icmp is False:
        lines.append("[yellow]Preflight ping did not get a reply.[/]")

    tcp_reachable = [probe["port"] for probe in preflight.get("tcp_probe", []) if probe.get("reachable")]
    if tcp_reachable:
        lines.append(f"[dim]Preflight TCP reachable ports: {', '.join(str(port) for port in tcp_reachable)}[/]")
    elif preflight.get("tcp_probe"):
        lines.append("[yellow]Preflight TCP probes did not reach 80/443/8080/8443.[/]")

    if run_result.get("host_discovery", {}).get("pn_assumes_host_up"):
        lines.append("[yellow]-Pn is enabled, so nmap will still scan even if host discovery is inconclusive.[/]")

    interface = run_result.get("interface")
    if interface:
        lines.append(f"[dim]Nmap interface: {interface_label} -> {interface}[/]")
    else:
        lines.append("[dim]Nmap interface: automatic selection[/]")

    for command in run_result.get("commands", []):
        cmd = command.get("powershell_command") or " ".join(command.get("command", []))
        lines.append(f"[dim]Command: {cmd}[/]")
    return "\n".join(lines)


def _displayable_output_files(paths: list[str]) -> list[str]:
    return [path for path in paths if Path(path).suffix.lower() == ".txt"]
