"""Interactive menu-driven interface for ChainRecon."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from analysis import ReportGenerator, ScannerAnalyzer, SSLAnalyzer, TrafficAnalyzer
from runners import CaptureRunner, FridaRunner, NmapRunner
from runners.base import ToolNotFoundError, is_linux, make_output_dir


class SessionConfig:
    """Hold session state (replaces bash global variables)."""

    def __init__(self):
        self.router_ip: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.interface: Optional[str] = None
        self.output_dir: str = ""
        self.collected: dict = {"traffic": None, "ssl": None, "scan": None}


def run_interactive() -> None:
    """Entry point for the interactive menu."""
    config = SessionConfig()
    _print_banner()
    _configuration_phase(config)

    while True:
        choice = _show_main_menu()
        if choice == "1":
            _handle_network_setup(config)
        elif choice == "2":
            _handle_scan(config)
        elif choice == "3":
            _handle_capture(config)
        elif choice == "4":
            _handle_ssl(config)
        elif choice == "5":
            _handle_frida(config)
        elif choice == "6":
            _handle_report(config)
        elif choice == "7":
            _handle_reconfigure(config)
        elif choice == "8":
            print("\nExiting ChainRecon. Stay safe!")
            break
        else:
            print("[!] Invalid option.")
        input("\nPress Enter to return to menu...")


def _print_banner() -> None:
    print("=" * 50)
    print("     ChainRecon - IoT Security Recon Tool")
    print("=" * 50)


def _configuration_phase(config: SessionConfig) -> None:
    print("\n--- CONFIGURATION PHASE ---\n")
    config.router_ip = input("  Router IP (e.g., 192.168.123.1): ").strip() or None
    config.target_ip = input("  IoT Device IP (leave blank to scan later): ").strip() or None
    config.interface = input("  Interface for traffic capture (or Enter to skip): ").strip() or None
    config.output_dir = str(make_output_dir())

    print(f"\n  Router IP:     {config.router_ip or 'Not set'}")
    print(f"  IoT Device IP: {config.target_ip or 'Not set'}")
    print(f"  Interface:     {config.interface or 'Not set'}")
    print(f"  Output Dir:    {config.output_dir}\n")


def _show_main_menu() -> str:
    print("\n" + "=" * 50)
    print("  MAIN MENU")
    print("=" * 50)
    print("  1) Network Setup (Enable Routing/NAT)")
    print("  2) Device Scan (Nmap)")
    print("  3) Traffic Capture & Analysis")
    print("  4) SSL/TLS Analysis")
    print("  5) Frida - Android App Analysis")
    print("  6) Generate Report")
    print("  7) Reconfigure Session")
    print("  8) Exit")
    print("=" * 50)
    return input("  Choice [1-8]: ").strip()


# ── Mode 1: Network Setup ──────────────────────────────────────────


def _handle_network_setup(config: SessionConfig) -> None:
    if is_linux():
        script = Path(__file__).parent / "scripts" / "network_setup.sh"
        if script.exists():
            print("[*] Launching network setup script...")
            subprocess.run(["sudo", "bash", str(script)], check=False)
        else:
            print(f"[!] Network setup script not found at {script}")
    else:
        _print_network_instructions()


def _print_network_instructions() -> None:
    print("\n--- Network Setup Instructions (Manual) ---")
    print("This feature requires Linux with root access.")
    print("On your Linux machine, run:")
    print("  sudo bash scripts/network_setup.sh")
    print("")
    print("What it does:")
    print("  1. Brings up the Ethernet interface")
    print("  2. Assigns a static IP to it")
    print("  3. Enables IP forwarding (sysctl)")
    print("  4. Configures NAT via iptables masquerade")
    print("  5. Adds Docker iptables rules (if Docker is present)")
    print("")
    print("After setup, your machine acts as a gateway for the IoT device,")
    print("allowing you to capture all its traffic.")


# ── Mode 2: Device Scan ────────────────────────────────────────────


def _handle_scan(config: SessionConfig) -> None:
    if not config.target_ip:
        config.target_ip = input("  Enter target IP: ").strip()
        if not config.target_ip:
            print("[!] No target IP provided.")
            return

    runner = NmapRunner()
    profiles = runner.list_profiles()

    print("\n  Select scan profile:")
    for i, p in enumerate(profiles, 1):
        print(f"    {i}) {p['label']} - {p['description']}")
    print(f"    {len(profiles) + 1}) Back to main menu")

    choice = input(f"  Choice [1-{len(profiles) + 1}]: ").strip()
    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Invalid option.")
        return
    if idx < 0 or idx >= len(profiles):
        return

    profile_key = profiles[idx]["key"]
    print(f"\n[*] Running {profiles[idx]['label']} against {config.target_ip}...")

    try:
        scan_result = runner.run_scan(config.target_ip, profile_key, config.output_dir)
    except ToolNotFoundError as exc:
        print(f"[!] {exc}")
        return

    analyzer = ScannerAnalyzer()
    for output_file in scan_result["output_files"]:
        if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
            analysis = analyzer.parse_nmap_output(output_file)
            config.collected["scan"] = analysis
            _print_summary("Scan", analysis)
            _auto_report(analysis, "scan", config.output_dir)


# ── Mode 3: Traffic Capture ────────────────────────────────────────


def _handle_capture(config: SessionConfig) -> None:
    if not config.interface:
        config.interface = input("  Enter interface name: ").strip()
        if not config.interface:
            print("[!] No interface provided.")
            return

    runner = CaptureRunner()
    modes = runner.list_modes()

    print("\n  Select capture mode:")
    for i, m in enumerate(modes, 1):
        print(f"    {i}) {m['label']} - {m['description']}")
    print(f"    {len(modes) + 1}) Back to main menu")

    choice = input(f"  Choice [1-{len(modes) + 1}]: ").strip()
    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Invalid option.")
        return
    if idx < 0 or idx >= len(modes):
        return

    mode_key = modes[idx]["key"]
    duration_str = input("  Capture duration in seconds (default 60): ").strip()
    duration = int(duration_str) if duration_str.isdigit() else 60

    print(f"\n[*] Capturing for {duration}s on {config.interface} ({modes[idx]['label']})...")
    print("    Perform actions on the IoT device now!")
    print("    (e.g., reboot it, talk to it, open the companion app)\n")

    try:
        capture_result = runner.run_capture(
            interface=config.interface,
            mode=mode_key,
            duration=duration,
            target_ip=config.target_ip,
            output_dir=config.output_dir,
        )
    except ToolNotFoundError as exc:
        print(f"[!] {exc}")
        return

    analyzer = TrafficAnalyzer()
    for pcap_path in capture_result["pcap_files"]:
        if Path(pcap_path).exists() and Path(pcap_path).stat().st_size > 0:
            print(f"[*] Analyzing {pcap_path}...")
            analysis = analyzer.analyze_pcap(pcap_path)
            config.collected["traffic"] = analysis
            _print_summary("Traffic", analysis)
            _auto_report(analysis, "traffic", config.output_dir)
        else:
            print(f"[!] Capture file empty or not found: {pcap_path}")


# ── Mode 4: SSL/TLS Analysis ──────────────────────────────────────


SSL_PORTS = [443, 8443, 8008, 8080, 8883, 1883]


def _handle_ssl(config: SessionConfig) -> None:
    if not config.target_ip:
        config.target_ip = input("  Enter target IP: ").strip()
        if not config.target_ip:
            print("[!] No target IP provided.")
            return

    print("\n  Select SSL analysis mode:")
    print("    1) Certificate Probe")
    print("    2) Cipher Analysis")
    print("    3) Full Analysis (Certs + Ciphers + Security Assessment)")
    print("    4) Back to main menu")

    choice = input("  Choice [1-4]: ").strip()
    if choice not in ("1", "2", "3"):
        return

    analyzer = SSLAnalyzer()
    certs = ciphers = security = None

    if choice in ("1", "3"):
        print(f"[*] Probing certificates on {config.target_ip}...")
        certs = analyzer.probe_certificates(config.target_ip, SSL_PORTS)
        _print_summary("SSL Certificates", certs)

    if choice in ("2", "3"):
        print(f"[*] Analyzing ciphers on {config.target_ip}...")
        ciphers = analyzer.analyze_ciphers(config.target_ip, SSL_PORTS)
        _print_summary("SSL Ciphers", ciphers)

    if choice == "3" and certs and ciphers:
        security = analyzer.assess_tls_security(certs, ciphers)
        _print_summary("TLS Security Assessment", security)

        combined = {
            "metadata": {"target": config.target_ip, "ports": SSL_PORTS},
            "findings": {
                "certificates": certs["findings"]["certificates"],
                "cipher_analysis": ciphers["findings"]["cipher_analysis"],
                "security_findings": security["findings"]["security_findings"],
            },
            "summary": {
                "certificate_count": certs["summary"]["certificate_count"],
                "weak_cipher_count": ciphers["summary"]["weak_cipher_count"],
                "risk_rating": security["summary"]["risk_rating"],
            },
            "risk_indicators": security["risk_indicators"],
        }
        config.collected["ssl"] = combined
        _auto_report(combined, "ssl", config.output_dir)
    elif certs and choice == "1":
        config.collected["ssl"] = certs
        _auto_report(certs, "ssl", config.output_dir)
    elif ciphers and choice == "2":
        config.collected["ssl"] = ciphers
        _auto_report(ciphers, "ssl", config.output_dir)


# ── Mode 5: Frida - Android App Analysis ─────────────────────────


def _handle_frida(config: SessionConfig) -> None:
    runner = FridaRunner()

    # Check prerequisites
    status = runner.check_prerequisites()
    missing = [t for t, s in status.items() if not s["found"]]
    if missing:
        print("\n[!] Missing tools:", ", ".join(missing))
        _print_frida_setup_guide()
        return

    while True:
        print("\n  --- Frida Android Analysis ---")
        print("    1) Setup Guide (show steps)")
        print("    2) Check Device & Push Frida Server")
        print("    3) Start Frida Server on Device")
        print("    4) List Running Processes")
        print("    5) Run a Built-in Script")
        print("    6) Run a Custom Script")
        print("    7) Spawn App with Script (cold start)")
        print("    8) Back to main menu")

        choice = input("  Choice [1-8]: ").strip()

        if choice == "1":
            _print_frida_setup_guide()
        elif choice == "2":
            _frida_device_setup(runner)
        elif choice == "3":
            _frida_start_server(runner)
        elif choice == "4":
            _frida_list_processes(runner)
        elif choice == "5":
            _frida_run_builtin(runner)
        elif choice == "6":
            _frida_run_custom(runner)
        elif choice == "7":
            _frida_spawn_app(runner)
        elif choice == "8":
            return
        else:
            print("[!] Invalid option.")

        input("\n  Press Enter to continue...")


def _print_frida_setup_guide() -> None:
    print("""
  ============================================================
   Frida Setup Guide (Android Emulator / Rooted Device)
  ============================================================

   STEP 1: Install Frida on your host machine
     pip install frida-tools

   STEP 2: Launch your Android emulator
     - Android Studio AVD  (recommended: x86_64 image)
     - Genymotion also works
     - Physical device must be rooted

   STEP 3: Download frida-server for your emulator's arch
     - Go to: https://github.com/frida/frida/releases
     - Download frida-server-<version>-android-<arch>.xz
     - Extract it (use 7zip on Windows, xz -d on Linux)

   STEP 4: Push frida-server to the device
     adb push frida-server /data/local/tmp/
     adb shell chmod +x /data/local/tmp/frida-server

   STEP 5: Start frida-server on the device
     adb shell "/data/local/tmp/frida-server &"

   STEP 6: Set up port forwarding
     adb forward tcp:27042 tcp:27042

   STEP 7: Verify connection
     frida-ps -U
     (should show running processes on the device)

   You can automate steps 4-6 using this tool's options 2 and 3.
  ============================================================""")


def _frida_device_setup(runner: FridaRunner) -> None:
    print("\n[*] Connected devices:")
    try:
        devices = runner.list_devices()
        print(devices)
    except ToolNotFoundError as exc:
        print(f"[!] {exc}")
        return

    server_path = input("\n  Path to frida-server binary (or Enter to skip push): ").strip()
    if server_path:
        if not Path(server_path).exists():
            print(f"[!] File not found: {server_path}")
            return
        print(f"[*] Pushing {server_path} to device...")
        try:
            dest = runner.push_frida_server(server_path)
            print(f"[+] Pushed to {dest}")
        except Exception as exc:
            print(f"[!] Push failed: {exc}")
            return

    print("[*] Setting up port forwarding (27042)...")
    try:
        runner.forward_port()
        print("[+] Port forwarding active.")
    except Exception as exc:
        print(f"[!] Port forwarding failed: {exc}")


def _frida_start_server(runner: FridaRunner) -> None:
    print("[*] Starting frida-server on device...")
    try:
        runner.start_frida_server()
        print("[+] frida-server started (if it was already running, this is fine).")
    except Exception as exc:
        print(f"[!] Failed to start: {exc}")
        print("    Try manually: adb shell \"/data/local/tmp/frida-server &\"")


def _frida_list_processes(runner: FridaRunner) -> None:
    print("[*] Listing processes on device...\n")
    try:
        procs = runner.list_processes()
        print(procs)
    except Exception as exc:
        print(f"[!] Failed: {exc}")
        print("    Is frida-server running? Try option 3 first.")


def _frida_run_builtin(runner: FridaRunner) -> None:
    scripts = runner.list_scripts()

    print("\n  Available scripts:")
    for i, s in enumerate(scripts, 1):
        print(f"    {i}) {s['label']} - {s['description']}")
    print(f"    {len(scripts) + 1}) Back")

    choice = input(f"  Choice [1-{len(scripts) + 1}]: ").strip()
    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Invalid option.")
        return
    if idx < 0 or idx >= len(scripts):
        return

    script_key = scripts[idx]["key"]
    _configure_script_variables(runner, script_key)

    process_name = input("  Target process/app name (e.g., com.example.app): ").strip()
    if not process_name:
        print("[!] No process name provided.")
        return

    print(f"\n[*] Running {scripts[idx]['label']} on {process_name}...")
    print("    (Press Ctrl+C to stop)\n")

    try:
        result = runner.run_script(process_name, script_key)
        if result["stdout"]:
            print(result["stdout"])
        if result["stderr"]:
            print("[stderr]", result["stderr"])
    except KeyboardInterrupt:
        print("\n[*] Script interrupted.")
    except Exception as exc:
        print(f"[!] Error: {exc}")


def _configure_script_variables(runner: FridaRunner, script_key: str) -> None:
    """Prompt user for script-specific variables and inject them."""
    if script_key == "list_classes":
        pkg = input("  Filter by package name (e.g., com.example) or Enter for all: ").strip()
        if pkg:
            _inject_var(runner, script_key, "FILTER", f'"{pkg}"')
    elif script_key == "hook_all_methods":
        classes = input("  Class names to hook (comma-separated): ").strip()
        if classes:
            class_list = [f'"{c.strip()}"' for c in classes.split(",")]
            _inject_var(runner, script_key, "TARGET_CLASSES", f"[{', '.join(class_list)}]")
    elif script_key == "hook_method":
        cls = input("  Full class name (e.g., com.example.MyClass): ").strip()
        meth = input("  Method name (e.g., myMethod): ").strip()
        if cls:
            _inject_var(runner, script_key, "TARGET_CLASS", f'"{cls}"')
        if meth:
            _inject_var(runner, script_key, "TARGET_METHOD", f'"{meth}"')


def _inject_var(runner: FridaRunner, script_key: str, var_name: str, value: str) -> None:
    """Prepend a variable declaration to the script file (idempotent)."""
    path = runner.get_script_path(script_key)
    content = path.read_text(encoding="utf-8")
    declaration = f"const {var_name} = {value};\n"

    # Remove any previous injection of this variable
    lines = content.splitlines(True)
    lines = [l for l in lines if not l.startswith(f"const {var_name} = ")]
    content = "".join(lines)

    path.write_text(declaration + content, encoding="utf-8")


def _frida_run_custom(runner: FridaRunner) -> None:
    script_path = input("  Path to your .js script: ").strip()
    if not script_path or not Path(script_path).exists():
        print("[!] Script file not found.")
        return

    process_name = input("  Target process/app name: ").strip()
    if not process_name:
        print("[!] No process name provided.")
        return

    print(f"\n[*] Running custom script on {process_name}...")
    print("    (Press Ctrl+C to stop)\n")

    try:
        result = runner.run_script(process_name, "", custom_script_path=script_path)
        if result["stdout"]:
            print(result["stdout"])
        if result["stderr"]:
            print("[stderr]", result["stderr"])
    except KeyboardInterrupt:
        print("\n[*] Script interrupted.")
    except Exception as exc:
        print(f"[!] Error: {exc}")


def _frida_spawn_app(runner: FridaRunner) -> None:
    scripts = runner.list_scripts()

    print("\n  Available scripts:")
    for i, s in enumerate(scripts, 1):
        print(f"    {i}) {s['label']} - {s['description']}")
    custom_idx = len(scripts) + 1
    print(f"    {custom_idx}) Use a custom script")
    print(f"    {custom_idx + 1}) Back")

    choice = input(f"  Choice [1-{custom_idx + 1}]: ").strip()
    try:
        idx = int(choice) - 1
    except ValueError:
        print("[!] Invalid option.")
        return
    if idx == custom_idx:
        return
    if idx < 0 or idx > len(scripts):
        return

    custom_path = None
    script_key = ""
    if idx == custom_idx - 1:
        custom_path = input("  Path to your .js script: ").strip()
        if not custom_path or not Path(custom_path).exists():
            print("[!] Script file not found.")
            return
    else:
        script_key = scripts[idx]["key"]
        _configure_script_variables(runner, script_key)

    package_name = input("  Package name to spawn (e.g., com.example.app): ").strip()
    if not package_name:
        print("[!] No package name provided.")
        return

    print(f"\n[*] Spawning {package_name} with script...")
    print("    (Press Ctrl+C to stop)\n")

    try:
        result = runner.spawn_and_run(package_name, script_key, custom_script_path=custom_path)
        if result["stdout"]:
            print(result["stdout"])
        if result["stderr"]:
            print("[stderr]", result["stderr"])
    except KeyboardInterrupt:
        print("\n[*] Script interrupted.")
    except Exception as exc:
        print(f"[!] Error: {exc}")


# ── Mode 6: Generate Report ──────────────────────────────────────


def _handle_report(config: SessionConfig) -> None:
    print("\n  --- Report Generation ---")
    has_data = any(v is not None for v in config.collected.values())

    if has_data:
        print("  Data collected this session:")
        for section, data in config.collected.items():
            status = "available" if data else "none"
            print(f"    {section}: {status}")
    else:
        print("  No analysis data collected yet in this session.")

    print("\n  Report options:")
    print("    1) Generate from this session's data")
    print("    2) Generate from saved JSON files")
    print("    3) Back to main menu")

    choice = input("  Choice [1-3]: ").strip()

    if choice == "1":
        if not has_data:
            print("[!] No data collected yet. Run a scan, capture, or SSL analysis first.")
            return
        _report_from_session(config)
    elif choice == "2":
        _report_from_files(config)


def _report_from_session(config: SessionConfig) -> None:
    fmt = _pick_format()
    if not fmt:
        return

    generator = ReportGenerator()
    if config.collected["traffic"]:
        generator.add_traffic_results(config.collected["traffic"])
    if config.collected["ssl"]:
        generator.add_ssl_results(config.collected["ssl"])
    if config.collected["scan"]:
        generator.add_scan_results(config.collected["scan"])

    ext = {"json": ".json", "html": ".html", "csv": ".csv"}[fmt]
    output_path = str(Path(config.output_dir) / f"full_report{ext}")
    generator.generate(fmt, output_path)
    print(f"[+] Report saved to: {output_path}")


def _report_from_files(config: SessionConfig) -> None:
    print("  Enter paths to JSON analysis files (one per line, empty line to finish):")
    files = []
    while True:
        line = input("    > ").strip()
        if not line:
            break
        p = Path(line)
        if p.is_dir():
            found = sorted(p.glob("*.json"))
            files.extend(found)
            print(f"    Found {len(found)} JSON files in directory")
        elif p.exists():
            files.append(p)
        else:
            print(f"    [!] Not found: {line}")

    if not files:
        print("[!] No files provided.")
        return

    fmt = _pick_format()
    if not fmt:
        return

    generator = ReportGenerator()
    for f in files:
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
            section = _infer_section(payload, f.name)
            if section == "traffic":
                generator.add_traffic_results(payload)
            elif section == "ssl":
                generator.add_ssl_results(payload)
            else:
                generator.add_scan_results(payload)
            print(f"    Loaded {f.name} as {section}")
        except Exception as exc:
            print(f"    [!] Failed to load {f.name}: {exc}")

    ext = {"json": ".json", "html": ".html", "csv": ".csv"}[fmt]
    output_path = str(Path(config.output_dir) / f"full_report{ext}")
    generator.generate(fmt, output_path)
    print(f"[+] Report saved to: {output_path}")


def _infer_section(payload: dict, filename: str) -> str:
    metadata = payload.get("metadata", {})
    findings = payload.get("findings", {})
    source = metadata.get("source", "")
    if "packet_count" in metadata or "pcap" in source or "traffic" in filename:
        return "traffic"
    if metadata.get("target") or "security_findings" in findings or "ssl" in filename:
        return "ssl"
    return "scan"


def _pick_format() -> Optional[str]:
    print("\n  Output format:")
    print("    1) JSON")
    print("    2) HTML")
    print("    3) CSV")
    print("    4) Cancel")
    choice = input("  Choice [1-4]: ").strip()
    return {"1": "json", "2": "html", "3": "csv"}.get(choice)


# ── Mode 7: Reconfigure ──────────────────────────────────────────


def _handle_reconfigure(config: SessionConfig) -> None:
    print("\n  --- Reconfigure Session ---")
    print(f"  Current Router IP:     {config.router_ip or 'Not set'}")
    print(f"  Current IoT Device IP: {config.target_ip or 'Not set'}")
    print(f"  Current Interface:     {config.interface or 'Not set'}")
    print(f"  Output Dir:            {config.output_dir}")
    print()

    val = input("  New Router IP (Enter to keep): ").strip()
    if val:
        config.router_ip = val
    val = input("  New IoT Device IP (Enter to keep): ").strip()
    if val:
        config.target_ip = val
    val = input("  New Interface (Enter to keep): ").strip()
    if val:
        config.interface = val

    print(f"\n  Router IP:     {config.router_ip or 'Not set'}")
    print(f"  IoT Device IP: {config.target_ip or 'Not set'}")
    print(f"  Interface:     {config.interface or 'Not set'}")
    print("[+] Configuration updated.")


# ── Helpers ────────────────────────────────────────────────────────


def _print_summary(section_name: str, analysis: dict) -> None:
    print(f"\n--- {section_name} Results ---")
    for key, value in analysis.get("summary", {}).items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k2, v2 in value.items():
                print(f"    {k2}: {v2}")
        else:
            print(f"  {key}: {value}")
    indicators = analysis.get("risk_indicators", [])
    if indicators:
        print(f"  Risk indicators: {len(indicators)}")
        for ind in indicators[:5]:
            print(f"    [{ind.get('severity', '?')}] {ind.get('title', '')}")


def _auto_report(analysis: dict, section: str, output_dir: str) -> None:
    generator = ReportGenerator()
    if section == "traffic":
        generator.add_traffic_results(analysis)
    elif section == "ssl":
        generator.add_ssl_results(analysis)
    elif section == "scan":
        generator.add_scan_results(analysis)

    output_path = str(Path(output_dir) / f"{section}_report.json")
    generator.generate("json", output_path)
    print(f"[+] Report saved to: {output_path}")
