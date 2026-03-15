"""Python-first CLI entrypoint for ChainRecon."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List

from analysis import ReportGenerator, ScannerAnalyzer, SSLAnalyzer, TrafficAnalyzer

DEFAULT_SSL_PORTS = [443, 8443, 8008, 8080, 8883, 1883]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ChainRecon Python analysis CLI")
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

    return parser


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
        payload = json.loads(file_path.read_text(encoding="utf-8"))
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
    if args.command is None:
        from interactive import run_interactive
        run_interactive()
        return 0
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
