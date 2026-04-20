"""Python-first CLI entrypoint for ChainRecon."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List

from analysis import ReportGenerator, ScannerAnalyzer, SSLAnalyzer, TrafficAnalyzer
from utils.logging_config import get_logger, setup_logging

logger = get_logger("cli")

DEFAULT_SSL_PORTS = [443, 8443, 8008, 8080, 8883, 1883]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ChainRecon Python analysis CLI")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level logging")
    parser.add_argument("--log-file", help="Write log output to a file")
    subparsers = parser.add_subparsers(dest="command")

    traffic_parser = subparsers.add_parser("analyze-traffic", help="Analyze a packet capture")
    traffic_parser.add_argument("pcap")
    traffic_parser.add_argument("--format", choices=["json", "html", "csv"])
    traffic_parser.add_argument("--output")
    traffic_parser.set_defaults(handler=handle_analyze_traffic)

    ssl_parser = subparsers.add_parser("analyze-ssl", help="Analyze SSL/TLS posture for a target")
    ssl_parser.add_argument("target")
    ssl_parser.add_argument("--ports", nargs="*", type=int, default=DEFAULT_SSL_PORTS)
    ssl_parser.add_argument("--pcap", help="Optional pcap file for JA3 computation")
    ssl_parser.add_argument("--format", choices=["json", "html", "csv"])
    ssl_parser.add_argument("--output")
    ssl_parser.set_defaults(handler=handle_analyze_ssl)

    scan_parser = subparsers.add_parser("analyze-scan", help="Analyze saved nmap output")
    scan_parser.add_argument("nmap_output")
    scan_parser.add_argument("--shodan-api-key")
    scan_parser.add_argument("--format", choices=["json", "html", "csv"])
    scan_parser.add_argument("--output")
    scan_parser.set_defaults(handler=handle_analyze_scan)

    report_parser = subparsers.add_parser("report", help="Aggregate saved JSON analysis files")
    report_parser.add_argument("inputs", nargs="+")
    report_parser.add_argument("--format", required=True, choices=["json", "html", "csv"])
    report_parser.add_argument("--output", required=True)
    report_parser.set_defaults(handler=handle_report)

    # ── Live collection subcommands ──────────────────────────────────
    scan_live = subparsers.add_parser("scan", help="Run nmap scan, analyze, and report")
    scan_live.add_argument("target")
    scan_live.add_argument("--profile", default="quick",
                           choices=["quick", "gentle", "full", "iot", "vuln"])
    scan_live.add_argument("--format", choices=["json", "html", "csv"])
    scan_live.add_argument("--output")
    scan_live.set_defaults(handler=handle_scan)

    capture_parser = subparsers.add_parser("capture", help="Capture traffic, analyze, and report")
    capture_parser.add_argument("interface")
    capture_parser.add_argument("--mode", default="full",
                                choices=["basic", "live", "dns", "http", "protocol_stats", "full"])
    capture_parser.add_argument("--duration", type=int, default=60)
    capture_parser.add_argument("--target-ip")
    capture_parser.add_argument("--format", choices=["json", "html", "csv"])
    capture_parser.add_argument("--output")
    capture_parser.set_defaults(handler=handle_capture)

    # ── APK analysis ─────────────────────────────────────────────────
    apk_parser = subparsers.add_parser("apk", help="Run static analysis on an Android APK")
    apk_parser.add_argument("apk_path", help="Path to the APK file")
    apk_parser.add_argument("--format", choices=["json", "html", "csv"])
    apk_parser.add_argument("--output")
    apk_parser.set_defaults(handler=handle_apk)

    # ── TUI ──────────────────────────────────────────────────────────
    subparsers.add_parser("tui", help="Launch the interactive TUI")
    subparsers.add_parser("interactive", help="Launch the legacy interactive menu")
    # ── Network config ───────────────────────────────────────────────
    net_parser = subparsers.add_parser(
        "network-config",
        help="Show, save, or apply the network setup (NAT/routing) config",
    )
    net_parser.add_argument("--eth", metavar="ADAPTER", help="Ethernet adapter name (IoT side)")
    net_parser.add_argument("--internet", metavar="ADAPTER", help="Internet adapter name (Wi-Fi)")
    net_parser.add_argument("--static-ip", default="192.168.123.100/24",
                            help="Static IP/prefix for Ethernet adapter (default 192.168.123.100/24)")
    net_parser.add_argument("--target-ip", help="IoT device IP (used for capture BPF filters)")
    net_parser.add_argument("--router-ip", help="Dedicated router IP")
    net_parser.add_argument("--apply", action="store_true",
                            help="Run the network setup script after saving (Windows: requires Admin)")
    net_parser.add_argument("--remove", action="store_true",
                            help="Tear down NAT / remove static IP")
    net_parser.add_argument("--list-interfaces", action="store_true",
                            help="Print detected network interfaces and exit")
    net_parser.set_defaults(handler=handle_network_config)
    return parser


def handle_network_config(args) -> int:
    """Save / apply the network setup configuration."""
    import platform
    import subprocess as _sp
    from pathlib import Path as _Path
    from utils.config import get_network_config, save_network_config, reset_config
    from utils.network import list_interfaces

    if args.list_interfaces:
        ifaces = list_interfaces()
        print(f"{'NAME':<30} {'DEVICE':<60} DESCRIPTION")
        print("-" * 110)
        for i in ifaces:
            print(f"{i['name']:<30} {i.get('device', i['name']):<60} {i.get('description', '')}")
        return 0

    # Show current config if no save args given
    if not any([args.eth, args.internet, args.target_ip, args.router_ip]):
        reset_config()
        cfg = get_network_config()
        print(json.dumps({"network_config": cfg}, indent=2))
        return 0

    # Save
    data = {
        "eth_interface": args.eth,
        "internet_interface": args.internet,
        "static_ip": args.static_ip,
        "target_ip": args.target_ip,
        "router_ip": args.router_ip,
    }
    save_network_config(data)
    reset_config()
    print(json.dumps({"saved": True, "network_config": get_network_config()}, indent=2))

    if not args.apply and not args.remove:
        return 0

    # Apply or remove
    scripts_dir = _Path(__file__).resolve().parent / "scripts"
    is_win = platform.system() == "Windows"

    if "/" in args.static_ip:
        ip_part, prefix = args.static_ip.split("/", 1)
    else:
        ip_part, prefix = args.static_ip, "24"

    eth = args.eth
    inet = args.internet
    if not eth or not inet:
        print("[!] --eth and --internet are required for --apply / --remove")
        return 1

    if is_win:
        script = str(scripts_dir / "network_setup.ps1")
        ps_args = [
            "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", script,
            "-EthInterface", eth,
            "-InternetInterface", inet,
            "-StaticIP", ip_part,
            "-SubnetPrefix", prefix,
        ]
        if args.remove:
            ps_args.append("-Remove")

        # Check elevation — New-NetNat/New-NetIPAddress require admin
        try:
            import ctypes
            _is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            _is_admin = False

        if _is_admin:
            cmd = ["powershell"] + ps_args
            print(f"[*] Running (elevated)")
            result = _sp.run(cmd, timeout=120)
            return result.returncode
        else:
            import tempfile
            log_path = _Path(tempfile.gettempdir()) / "chainrecon_net_setup.log"
            wrapper_path = _Path(tempfile.gettempdir()) / "chainrecon_setup_run.ps1"

            # Build script-level args only (no powershell.exe flags in the wrapper)
            script_args = [
                "-EthInterface", eth,
                "-InternetInterface", inet,
                "-StaticIP", ip_part,
                "-SubnetPrefix", prefix,
            ]
            if args.remove:
                script_args.append("-Remove")

            # Wrapper: call the PS1 directly and redirect all output to log
            script_escaped = script.replace("'", "''")
            log_escaped = str(log_path).replace("'", "''")
            script_call = f"& '{script_escaped}'"
            for a in script_args:
                script_call += f" {a}" if not " " in str(a) else f" '{a}'"
            wrapper_content = f"{script_call} *> '{log_escaped}'\n"
            wrapper_path.write_text(wrapper_content, encoding="utf-8")

            wrapper_escaped = str(wrapper_path).replace('"', '`"')
            ps_inner = f'-NoProfile -ExecutionPolicy Bypass -File "{wrapper_escaped}"'

            print("[*] Requesting elevation via UAC (approve the dialog)...")
            print(f"[*] Output will be logged to: {log_path}")
            result = _sp.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    f'Start-Process powershell -Verb RunAs -Wait -ArgumentList \'{ps_inner}\''
                ],
                timeout=180,
            )
            if log_path.exists():
                log_text = log_path.read_text(encoding="utf-8", errors="replace").strip()
                if log_text:
                    print(log_text)
            if result.returncode != 0:
                print()
                print("[!] Elevation failed or was cancelled.")
                print("[!] To apply manually, open an ADMIN PowerShell and run:")
                print(f'    powershell -NoProfile -ExecutionPolicy Bypass -File "{script}" \\')
                for a in script_args:
                    print(f"        {a} \\", end="")
                print()
            return result.returncode
    else:
        print("[!] Linux --apply: run scripts/network_setup.sh manually (requires sudo)")
        return 1


def handle_analyze_traffic(args) -> int:
    result = TrafficAnalyzer().analyze_pcap(args.pcap)
    return emit_result(result, "traffic", args.format, args.output)


def handle_analyze_ssl(args) -> int:
    analyzer = SSLAnalyzer()
    certificates = analyzer.probe_certificates(args.target, args.ports)
    ciphers = analyzer.analyze_ciphers(args.target, args.ports)
    security = analyzer.assess_tls_security(certificates, ciphers)
    result = {
        "metadata": {"target": args.target, "ports": args.ports},
        "findings": {
            "certificates": certificates["findings"]["certificates"],
            "cipher_analysis": ciphers["findings"]["cipher_analysis"],
            "security_findings": security["findings"]["security_findings"],
        },
        "summary": {
            "certificate_count": certificates["summary"]["certificate_count"],
            "weak_cipher_count": ciphers["summary"]["weak_cipher_count"],
            "risk_rating": security["summary"]["risk_rating"],
        },
        "risk_indicators": security["risk_indicators"],
    }
    if args.pcap:
        result["findings"]["ja3"] = analyzer.compute_ja3(args.pcap)["findings"]["ja3"]
    return emit_result(result, "ssl", args.format, args.output)


def handle_analyze_scan(args) -> int:
    analyzer = ScannerAnalyzer()
    result = analyzer.parse_nmap_output(args.nmap_output)
    if args.shodan_api_key:
        shodan_results = []
        for host in result["findings"].get("hosts", []):
            if host.get("ip"):
                shodan_results.append(analyzer.lookup_shodan(host["ip"], api_key=args.shodan_api_key))
        result["findings"]["shodan"] = shodan_results
    return emit_result(result, "scan", args.format, args.output)


def handle_report(args) -> int:
    generator = ReportGenerator()
    merged = load_report_inputs(args.inputs)
    if merged.get("traffic"):
        generator.add_traffic_results(merged["traffic"])
    if merged.get("ssl"):
        generator.add_ssl_results(merged["ssl"])
    if merged.get("scan"):
        generator.add_scan_results(merged["scan"])
    output_path = generator.generate(args.format, args.output)
    print(json.dumps({"output": output_path, "format": args.format}, indent=2))
    return 0


def handle_scan(args) -> int:
    from runners import NmapRunner
    from runners.base import ToolNotFoundError

    runner = NmapRunner()
    try:
        scan_result = runner.run_scan(args.target, args.profile)
    except ToolNotFoundError as exc:
        print(f"[!] {exc}")
        return 1

    analyzer = ScannerAnalyzer()
    for output_file in scan_result["output_files"]:
        if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
            result = analyzer.parse_nmap_output(output_file)
            return emit_result(result, "scan", args.format, args.output)

    print("[!] No scan output produced.")
    return 1


def handle_capture(args) -> int:
    from runners import CaptureRunner
    from runners.base import ToolNotFoundError

    runner = CaptureRunner()
    try:
        capture_result = runner.run_capture(
            interface=args.interface,
            mode=args.mode,
            duration=args.duration,
            target_ip=args.target_ip,
        )
    except ToolNotFoundError as exc:
        print(f"[!] {exc}")
        return 1

    analyzer = TrafficAnalyzer()
    for pcap_path in capture_result["pcap_files"]:
        if Path(pcap_path).exists() and Path(pcap_path).stat().st_size > 0:
            result = analyzer.analyze_pcap(pcap_path)
            return emit_result(result, "traffic", args.format, args.output)

    print("[!] No capture output produced.")
    return 1


def handle_apk(args) -> int:
    from analysis.apk_analyzer import APKAnalyzer

    result = APKAnalyzer().analyze(args.apk_path)
    return emit_result(result, "apk", args.format, args.output)


def load_report_inputs(inputs: Iterable[str]):
    merged = {"traffic": None, "ssl": None, "scan": None}
    files = []
    for raw_input in inputs:
        path = Path(raw_input)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        else:
            files.append(path)

    for file_path in files:
        payload = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
        merged[infer_section(payload, file_path.name)] = payload
    return merged


def infer_section(payload, filename: str) -> str:
    metadata = payload.get("metadata", {})
    findings = payload.get("findings", {})
    source = metadata.get("source", "")
    if "packet_count" in metadata or "pcap" in source or "traffic" in filename:
        return "traffic"
    if metadata.get("target") or "security_findings" in findings or "ssl" in filename:
        return "ssl"
    return "scan"


def emit_result(result, section, format_name=None, output_path=None) -> int:
    print(json.dumps(result, indent=2))
    if format_name and output_path:
        generator = ReportGenerator()
        if section == "traffic":
            generator.add_traffic_results(result)
        elif section == "ssl":
            generator.add_ssl_results(result)
        else:
            generator.add_scan_results(result)
        generator.generate(format_name, output_path)
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose, log_file=getattr(args, "log_file", None))

    if args.command is None or args.command == "tui":
        from tui.app import run_tui
        run_tui()
        return 0

    if args.command == "interactive":
        from interactive import run_interactive
        run_interactive()
        return 0

    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
