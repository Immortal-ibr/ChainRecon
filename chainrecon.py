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

    # -- Live collection subcommands ----------------------------------
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

    # -- APK analysis -------------------------------------------------
    apk_parser = subparsers.add_parser("apk", help="Run static analysis on an Android APK")
    apk_parser.add_argument("apk_path", help="Path to the APK file")
    apk_parser.add_argument("--format", choices=["json", "html", "csv"])
    apk_parser.add_argument("--output")
    apk_parser.set_defaults(handler=handle_apk)

    # -- TUI ----------------------------------------------------------
    subparsers.add_parser("tui", help="Launch the interactive TUI")
    subparsers.add_parser("interactive", help="Launch the legacy interactive menu")
    # -- Network config -----------------------------------------------
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

        # Check elevation -- New-NetNat/New-NetIPAddress require admin
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
    for section, payload in merged.items():
        if payload:
            generator.add_results(section, payload)
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
    parsed_results = []
    for output_file in scan_result["output_files"]:
        if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
            parsed_results.append(analyzer.parse_nmap_output(output_file))

    if parsed_results:
        result = combine_scan_results(scan_result, parsed_results)
        return emit_result(result, "scan", args.format, args.output)

    print("[!] No scan output produced.")
    return 1


def combine_scan_results(scan_result: dict, parsed_results: list[dict]) -> dict:
    hosts_by_key = {}
    iot_services = []
    cve_hints = []
    risk_indicators = []
    for parsed in parsed_results:
        for host in parsed.get("findings", {}).get("hosts", []):
            key = host.get("ip") or f"unknown-{len(hosts_by_key)}"
            hosts_by_key[key] = _merge_scan_host(hosts_by_key.get(key), host)
        iot_services.extend(_dedupe_dicts(parsed.get("findings", {}).get("iot_services", [])))
        cve_hints.extend(_dedupe_dicts(parsed.get("findings", {}).get("cve_hints", [])))
        risk_indicators.extend(_dedupe_dicts(parsed.get("risk_indicators", [])))
    hosts = list(hosts_by_key.values())
    iot_services = _dedupe_dicts(iot_services)
    cve_hints = _dedupe_dicts(cve_hints)
    risk_indicators = _dedupe_dicts(risk_indicators)
    services = [service for host in hosts for service in host.get("services", [])]
    ports = [port for host in hosts for port in host.get("ports", [])]
    state_summary = {}
    for host in hosts:
        for state, count in host.get("state_summary", {}).items():
            state_summary[state] = state_summary.get(state, 0) + int(count)
    return {
        "metadata": {
            "target": scan_result.get("target"),
            "profile": scan_result.get("profile"),
            "nmap_path": scan_result.get("nmap_path"),
            "output_dir": scan_result.get("output_dir"),
            "output_files": scan_result.get("output_files", []),
            "preflight": scan_result.get("preflight", {}),
            "host_discovery": scan_result.get("host_discovery", {}),
            "commands": scan_result.get("commands", []),
        },
        "findings": {"hosts": hosts, "iot_services": iot_services, "cve_hints": cve_hints},
        "summary": {
            "host_count": len(hosts),
            "open_port_count": len(services),
            "closed_port_count": _combined_state_count(ports, state_summary, "closed"),
            "filtered_port_count": _combined_state_count(ports, state_summary, "filtered"),
            "scanned_port_count": len(ports) + sum(state_summary.values()),
            "iot_service_count": len(iot_services),
            "cve_hint_count": len(cve_hints),
        },
        "risk_indicators": risk_indicators,
    }


def _merge_scan_host(existing: dict | None, incoming: dict) -> dict:
    if existing is None:
        merged = dict(incoming)
        merged["ports"] = _dedupe_ports(incoming.get("ports", []))
        merged["services"] = _dedupe_services(incoming.get("services", []))
        merged["notes"] = _dedupe_scalars(incoming.get("notes", []))
        merged["state_summary"] = dict(incoming.get("state_summary", {}))
        return merged

    merged = dict(existing)
    if not merged.get("host_state") or incoming.get("host_state") == "up":
        merged["host_state"] = incoming.get("host_state") or merged.get("host_state")
    merged["ports"] = _dedupe_ports([*merged.get("ports", []), *incoming.get("ports", [])])
    merged["services"] = _dedupe_services([*merged.get("services", []), *incoming.get("services", [])])
    merged["notes"] = _dedupe_scalars([*merged.get("notes", []), *incoming.get("notes", [])])
    state_summary = dict(merged.get("state_summary", {}))
    for state, count in incoming.get("state_summary", {}).items():
        state_summary[state] = max(int(state_summary.get(state, 0)), int(count))
    merged["state_summary"] = state_summary
    return merged


def _dedupe_ports(ports: list[dict]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for port in ports:
        key = (port.get("protocol"), port.get("port"), port.get("state"))
        existing = merged.get(key, {})
        merged[key] = {**port, **{k: v for k, v in existing.items() if v not in (None, "")}}
    return list(merged.values())


def _dedupe_services(services: list[dict]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for service in services:
        key = (service.get("protocol"), service.get("port"), service.get("service"))
        existing = merged.get(key, {})
        merged[key] = {**service, **{k: v for k, v in existing.items() if v not in (None, "")}}
    return list(merged.values())


def _dedupe_dicts(items: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _dedupe_scalars(items: list) -> list:
    deduped = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _combined_state_count(ports: list[dict], state_summary: dict, state: str) -> int:
    explicit = sum(1 for port in ports if port.get("state") == state)
    summarized = sum(int(count) for key, count in state_summary.items() if state in str(key).split("|"))
    return explicit + summarized


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
    grouped: dict[str, list[dict]] = {}
    files = []
    for raw_input in inputs:
        path = Path(raw_input)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        else:
            files.append(path)

    for file_path in files:
        try:
            raw_payload = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        payload = _analysis_payload_from_json(raw_payload)
        if payload is None:
            continue
        metadata = dict(payload.get("metadata") or {})
        metadata.setdefault("source_file", str(file_path.resolve()))
        metadata.setdefault("source_filename", file_path.name)
        payload["metadata"] = metadata
        section = infer_section(payload, file_path.name)
        grouped.setdefault(section, []).append(payload)

    return {section: _aggregate_report_section(section, payloads) for section, payloads in grouped.items()}


def _analysis_payload_from_json(payload):
    if not isinstance(payload, dict):
        return None
    if any(key in payload for key in ("metadata", "summary", "risk_indicators")) or isinstance(payload.get("findings"), dict):
        return payload

    known_sections = ("traffic", "ssl", "scan", "apk")
    section_values = [
        value
        for key, value in payload.items()
        if key in known_sections and value not in (None, {}, [])
    ]
    if len(section_values) == 1 and isinstance(section_values[0], dict):
        return section_values[0]
    if any(key in payload for key in known_sections):
        return None
    return payload


def infer_section(payload, filename: str) -> str:
    metadata = payload.get("metadata", {})
    findings = payload.get("findings", {})
    source = metadata.get("source", "")
    analyzer = metadata.get("analyzer", "")
    filename_l = filename.lower()
    if analyzer == "APKAnalyzer" or metadata.get("apk") or "apk" in filename_l:
        return "apk"
    if "app_flags" in findings or "permissions" in findings or "credentials" in findings:
        return "apk"
    if "packet_count" in metadata or "pcap" in source or "traffic" in filename_l or "capture" in filename_l:
        return "traffic"
    if "certificates" in findings or "cipher_analysis" in findings or "security_findings" in findings or "ssl" in filename_l:
        return "ssl"
    if "hosts" in findings or "iot_services" in findings or "cve_hints" in findings or "scan" in filename_l or "nmap" in filename_l:
        return "scan"
    if metadata.get("target"):
        return "ssl"
    return "scan"


def _aggregate_report_section(section: str, payloads: list[dict]):
    if len(payloads) == 1:
        return payloads[0]
    risk_indicators = []
    source_files = []
    for payload in payloads:
        metadata = payload.get("metadata") or {}
        if metadata.get("source_file"):
            source_files.append(metadata["source_file"])
        for item in payload.get("risk_indicators", []) or []:
            if isinstance(item, dict):
                annotated = dict(item)
                annotated.setdefault("source_file", metadata.get("source_file", ""))
                annotated.setdefault("source_filename", metadata.get("source_filename", ""))
                risk_indicators.append(annotated)
    return {
        "metadata": {
            "section": section,
            "source_mode": "multiple_files",
            "source_count": len(payloads),
            "source_files": source_files,
        },
        "summary": {
            "source_count": len(payloads),
            "risk_indicator_count": len(risk_indicators),
        },
        "findings": {
            "items": payloads,
        },
        "risk_indicators": risk_indicators,
    }


def emit_result(result, section, format_name=None, output_path=None) -> int:
    print(json.dumps(result, indent=2))
    if format_name and output_path:
        generator = ReportGenerator()
        generator.add_results(section, result)
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
