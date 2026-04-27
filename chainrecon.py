"""Python-first CLI entrypoint for ChainRecon."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List

from analysis import FirmwareAnalyzer, ReportGenerator, ScannerAnalyzer, SSLAnalyzer, TrafficAnalyzer
from utils.artifacts import safe_token
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
    traffic_parser.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    traffic_parser.add_argument("--output")
    traffic_parser.set_defaults(handler=handle_analyze_traffic)

    ssl_parser = subparsers.add_parser("analyze-ssl", help="Analyze SSL/TLS posture for a target")
    ssl_parser.add_argument("target")
    ssl_parser.add_argument("--ports", nargs="*", type=int, default=DEFAULT_SSL_PORTS)
    ssl_parser.add_argument("--pcap", help="Optional pcap file for JA3 computation")
    ssl_parser.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    ssl_parser.add_argument("--output")
    ssl_parser.set_defaults(handler=handle_analyze_ssl)

    scan_parser = subparsers.add_parser("analyze-scan", help="Analyze saved nmap output")
    scan_parser.add_argument("nmap_output")
    scan_parser.add_argument("--shodan-api-key")
    scan_parser.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    scan_parser.add_argument("--output")
    scan_parser.set_defaults(handler=handle_analyze_scan)

    report_parser = subparsers.add_parser("report", help="Aggregate saved JSON analysis files")
    report_parser.add_argument("inputs", nargs="+")
    report_parser.add_argument("--format", required=True, choices=["json", "html", "csv", "xlsx"])
    report_parser.add_argument("--output", required=True)
    report_parser.set_defaults(handler=handle_report)

    # -- Live collection subcommands ----------------------------------
    scan_live = subparsers.add_parser("scan", help="Run nmap scan, analyze, and report")
    scan_live.add_argument("target")
    scan_live.add_argument("--profile", default="quick",
                           choices=["arp", "quick", "gentle", "full", "iot", "vuln", "ssl"])
    scan_live.add_argument("--interface", help="Network interface for nmap -e (defaults to config scan.interface)")
    scan_live.add_argument(
        "--allow-interface-mismatch",
        action="store_true",
        help="Allow nmap -e even when the selected interface does not match the OS route to the target",
    )
    scan_live.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    scan_live.add_argument("--output")
    scan_live.set_defaults(handler=handle_scan)

    capture_parser = subparsers.add_parser("capture", help="Capture traffic, analyze, and report")
    capture_parser.add_argument("interface")
    capture_parser.add_argument("--mode", default="full",
                                choices=["basic", "live", "dns", "http", "protocol_stats", "full"])
    capture_parser.add_argument("--duration", type=int, default=60)
    capture_parser.add_argument("--target-ip")
    capture_parser.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    capture_parser.add_argument("--output")
    capture_parser.set_defaults(handler=handle_capture)

    # -- APK analysis -------------------------------------------------
    apk_parser = subparsers.add_parser("apk", help="Run static analysis on an Android APK")
    apk_parser.add_argument("apk_path", help="Path to the APK file")
    apk_parser.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    apk_parser.add_argument("--output")
    apk_parser.set_defaults(handler=handle_apk)

    firmware_parser = subparsers.add_parser("firmware", help="Extract and analyze a firmware image")
    firmware_parser.add_argument("firmware_path", help="Path to the firmware image")
    firmware_parser.add_argument("--extract-dir", help="Directory for extracted firmware contents")
    firmware_parser.add_argument("--format", choices=["json", "html", "csv", "xlsx"])
    firmware_parser.add_argument("--output")
    firmware_parser.set_defaults(handler=handle_firmware)

    workflow_parser = subparsers.add_parser("workflow", help="Run a YAML pipeline")
    workflow_subparsers = workflow_parser.add_subparsers(dest="workflow_command")
    workflow_run = workflow_subparsers.add_parser("run", help="Run a workflow pipeline")
    workflow_run.add_argument("pipeline", help="Path to the workflow YAML file")
    workflow_run.add_argument("--target", help="Override the workflow target")
    workflow_run.add_argument("--profile", help="Override the workflow/device profile name")
    workflow_run.add_argument("--device-profile", help="Load a shared device profile from profiles/devices or a YAML path")
    workflow_run.add_argument("--dry-run", action="store_true", help="Render and validate steps without executing them")
    workflow_run.set_defaults(handler=handle_workflow)

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
    certificate_rows = certificates["findings"]["certificates"]
    cipher_rows = ciphers["findings"]["cipher_analysis"]
    result = {
        "metadata": {"target": args.target, "ports": args.ports},
        "findings": {
            "certificates": certificate_rows,
            "cipher_analysis": cipher_rows,
            "security_findings": security["findings"]["security_findings"],
        },
        "summary": {
            "certificate_count": certificates["summary"]["certificate_count"],
            "weak_cipher_count": ciphers["summary"]["weak_cipher_count"],
            "risk_rating": security["summary"]["risk_rating"],
            "target_resolved_count": sum(1 for row in certificate_rows if row.get("target_resolved")),
            "tcp_reachable_count": sum(1 for row in certificate_rows if row.get("tcp_reachable")),
            "tls_reachable_count": sum(1 for row in certificate_rows if row.get("tls_reachable", row.get("reachable"))),
            "certificate_observed_count": sum(1 for row in certificate_rows if row.get("certificate_observed")),
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
    from runners.nmap_runner import NmapInterfaceMismatchError

    runner = NmapRunner()
    try:
        scan_result = runner.run_scan(
            args.target,
            args.profile,
            interface=getattr(args, "interface", None),
            allow_interface_mismatch=getattr(args, "allow_interface_mismatch", False),
        )
    except NmapInterfaceMismatchError as exc:
        print(f"[!] {exc}")
        return 2
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
    ambiguous_udp_count = sum(
        1 for port in ports
        if port.get("protocol") == "udp" and str(port.get("state", "")).lower() == "open|filtered"
    )
    ambiguous_udp_count += sum(int(count) for key, count in state_summary.items() if str(key).lower() == "open|filtered")
    preflight = scan_result.get("preflight", {}) or {}
    if preflight.get("interface_mismatch"):
        risk_indicators.append({
            "severity": "medium",
            "title": "Selected scan interface mismatched target route",
            "details": (
                "The selected nmap interface did not match the OS route to the target. "
                "Results may show filtered/open|filtered states caused by the route mismatch."
            ),
        })
    if ambiguous_udp_count:
        risk_indicators.append({
            "severity": "info",
            "title": "Ambiguous UDP scan results",
            "details": (
                f"{ambiguous_udp_count} UDP result(s) were open|filtered. "
                "This is inconclusive and should not be treated as proof of an open UDP service."
            ),
        })
    tls_probe = _scan_tls_findings(scan_result, hosts)
    if tls_probe:
        risk_indicators.extend(_dedupe_dicts(tls_probe.get("risk_indicators", [])))
    return {
        "metadata": {
            "target": scan_result.get("target"),
            "profile": scan_result.get("profile"),
            "nmap_path": scan_result.get("nmap_path"),
            "output_dir": scan_result.get("output_dir"),
            "output_files": scan_result.get("output_files", []),
            "preflight": preflight,
            "host_discovery": scan_result.get("host_discovery", {}),
            "commands": scan_result.get("commands", []),
            "artifacts": [{"type": "nmap_output", "path": path} for path in scan_result.get("output_files", [])],
        },
        "findings": {
            "hosts": hosts,
            "iot_services": iot_services,
            "cve_hints": cve_hints,
            **({"tls_probe": tls_probe.get("findings", {})} if tls_probe else {}),
        },
        "summary": {
            "host_count": len(hosts),
            "open_port_count": len(services),
            "closed_port_count": _combined_state_count(ports, state_summary, "closed"),
            "filtered_port_count": _combined_state_count(ports, state_summary, "filtered"),
            "ambiguous_udp_count": ambiguous_udp_count,
            "scanned_port_count": len(ports) + sum(state_summary.values()),
            "iot_service_count": len(iot_services),
            "cve_hint_count": len(cve_hints),
            **(_tls_summary_fields(tls_probe) if tls_probe else {}),
        },
        "risk_indicators": risk_indicators,
    }


def _scan_tls_findings(scan_result: dict, hosts: list[dict]) -> dict | None:
    target = str(scan_result.get("target") or "").strip()
    if not target or "/" in target or "-" in target.rsplit(".", 1)[-1] or len(hosts) != 1:
        return None
    try:
        candidate_ports = _tls_candidate_ports(scan_result, hosts[0])
        if not candidate_ports:
            return None
        analyzer = SSLAnalyzer()
        certificates = analyzer.probe_certificates(target, candidate_ports)
        cipher_analysis = analyzer.analyze_ciphers(target, candidate_ports)
        security = analyzer.assess_tls_security(certificates, cipher_analysis)
    except Exception:
        return None
    return {
        "findings": {
            "certificates": certificates.get("findings", {}).get("certificates", []),
            "cipher_analysis": cipher_analysis.get("findings", {}).get("cipher_analysis", []),
            "security_findings": security.get("findings", {}).get("security_findings", []),
        },
        "summary": {
            "candidate_port_count": len(candidate_ports),
            "reachable_port_count": certificates.get("summary", {}).get("reachable_ports", 0),
            "certificate_count": certificates.get("summary", {}).get("certificate_count", 0),
            "weak_cipher_count": cipher_analysis.get("summary", {}).get("weak_cipher_count", 0),
            "risk_rating": security.get("summary", {}).get("risk_rating", "low"),
        },
        "risk_indicators": security.get("risk_indicators", []),
    }


def _tls_candidate_ports(scan_result: dict, host: dict) -> list[int]:
    detected = set()
    for service in host.get("services", []):
        state = str(service.get("state") or "open").lower()
        if state != "open":
            continue
        port = service.get("port")
        service_name = str(service.get("service") or "").lower()
        if _safe_int(port) in {443, 8443, 8883} or "ssl" in service_name or "tls" in service_name or service_name in {"https", "mqtts"}:
            detected.add(int(port))
    profile_ports = set(_profile_declared_ports(str(scan_result.get("profile") or "")))
    for port in (443, 8443, 8883):
        if port in profile_ports or port in detected:
            detected.add(port)
    return sorted(detected)


def _profile_declared_ports(profile: str) -> list[int]:
    if profile == "ssl":
        return [443, 8443, 8883, 8080]
    if profile == "iot":
        return [443, 8443, 8883]
    return []


def _tls_summary_fields(tls_probe: dict) -> dict:
    summary = tls_probe.get("summary", {})
    return {
        "tls_candidate_port_count": summary.get("candidate_port_count", 0),
        "tls_reachable_port_count": summary.get("reachable_port_count", 0),
        "tls_certificate_count": summary.get("certificate_count", 0),
        "tls_weak_cipher_count": summary.get("weak_cipher_count", 0),
    }


def _safe_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
    explicit = sum(1 for port in ports if state in str(port.get("state", "")).split("|"))
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


def handle_firmware(args) -> int:
    result = FirmwareAnalyzer().analyze(args.firmware_path, output_dir=getattr(args, "extract_dir", None))
    return emit_result(result, "firmware", args.format, args.output)


def handle_workflow(args) -> int:
    from runners.workflow_runner import WorkflowRunner

    result = WorkflowRunner().run(
        args.pipeline,
        target=getattr(args, "target", None),
        profile=getattr(args, "profile", None),
        device_profile=getattr(args, "device_profile", None),
        dry_run=bool(getattr(args, "dry_run", False)),
    )
    print(json.dumps(result, indent=2))
    return 0


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
        if file_path.name == "artifact_index.json":
            continue
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

    section_values = [(key, value) for key, value in payload.items() if isinstance(value, dict) and value]
    if len(section_values) > 1:
        return None
    if len(section_values) == 1:
        return section_values[0][1]
    return payload


def infer_section(payload, filename: str) -> str:
    metadata = payload.get("metadata", {})
    findings = payload.get("findings", {})
    source = metadata.get("source", "")
    analyzer = metadata.get("analyzer", "")
    declared_section = metadata.get("section")
    filename_l = filename.lower()
    if declared_section:
        return safe_token(str(declared_section), default="analysis")
    if analyzer:
        normalized = str(analyzer).strip().lower().replace("analyzer", "").strip("_- ")
        aliases = {
            "apk": "apk",
            "traffic": "traffic",
            "ssl": "ssl",
            "scanner": "scan",
            "scan": "scan",
        }
        if normalized in aliases:
            return aliases[normalized]
        if normalized:
            return safe_token(normalized, default="analysis")
    if filename_l[:8].isdigit() and len(filename_l) > 15:
        middle = filename_l[9:-7]
        if middle.startswith("analysis_"):
            return safe_token(middle[len("analysis_"):], default="analysis")
        if middle.startswith("scan_"):
            return "scan"
        if middle.startswith("frida_"):
            return "frida"
        if middle.startswith("capture_") or middle.startswith("traffic_"):
            return "traffic"
        if middle.startswith("apk_"):
            return "apk"
    if "session" in findings or "events_by_tag" in findings or metadata.get("serial") or "frida" in filename_l:
        return "frida"
    if analyzer == "FirmwareAnalyzer" or metadata.get("firmware") or "firmware" in filename_l:
        return "firmware"
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
    return "analysis"


def _aggregate_report_section(section: str, payloads: list[dict]):
    if section == "frida":
        generator = ReportGenerator()
        for payload in payloads:
            generator.add_results("frida", payload, mode="append")
        return generator.get_data()["frida"]
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
