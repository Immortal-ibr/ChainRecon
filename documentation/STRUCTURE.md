# ChainRecon Directory Structure

This is a rough map of what's where and why. If you're looking for a specific piece of logic, this should save you some searching.

## Top-level files

- `chainrecon.py` — CLI entry point. Handles subcommands: `tui`, `analyze-traffic`, `analyze-ssl`, `analyze-scan`, `report`.
- `interactive.py` — Older interactive CLI that predates the TUI. Still works but the TUI is the main interface now.
- `requirements.txt` — Python dependencies. Install with `pip install -r requirements.txt`.
- `Recon script.sh` — Original bash script for Linux network setup and data collection. The Python/TUI layer replaces most of this, but it's still useful for the iptables setup on Linux.

## analysis/

The core analysis modules. Each one takes either a file path or a network target and returns a dict.

- `traffic.py` — Parses pcap files using Scapy. Extracts DNS queries, TLS SNI, HTTP requests, external IPs, protocol statistics, conversations, and WebRTC/STUN activity. Also has credential detection for cleartext traffic.
- `apk_analyzer.py` — APK static analysis. Calls jadx to decompile, then inspects the manifest, source code, and resources for permissions, exported components, hardcoded credentials, cert pinning, and third-party SDKs.
- `ssl_analyzer.py` — SSL/TLS analysis. Connects to a host/port, reads the certificate chain, checks cipher suites and TLS version support, optionally does JA3-style fingerprinting from a pcap.
- `scanner.py` — Parses nmap XML output into structured host/port/service data. Optionally enriches with Shodan if an API key is set.
- `report_generator.py` — Aggregates results from whichever analyzers ran and passes them to an output plugin.
- `endpoint_analyzer.py` — Attributing IP addresses to cloud providers (AWS, GCP, Azure, Cloudflare, Akamai, Fastly) and identifying risky ports/protocols.
- `pcap_stats.py` — Lower-level pcap statistics: packet counts, byte totals, protocol distribution, top talkers.
- `webrtc_analyzer.py` — Detects STUN, DTLS, and SRTP traffic in a packet list, which indicates video/audio streaming.

## runners/

Subprocess wrappers. The goal is one consistent place that handles timeouts, encoding, and error handling for all external tool calls.

- `base.py` — `run_subprocess()` with UTF-8 encoding and error replacement, `check_tool()` for verifying tool availability, and `make_output_dir()` for timestamped output directories.
- `nmap_runner.py` — Builds nmap command lines for the different scan profiles and invokes them.
- `frida_runner.py` — Manages frida-server connections and script injection.
- `capture_runner.py` — Handles tshark/tcpdump captures with duration limits and file rotation.
- `frida_scripts/` — JavaScript snippets loaded by the frida runner: SSL pinning bypass, crypto monitor, method hooks, class listing.

## tui/

The Textual TUI application.

- `app.py` — Entry point. Registers screens, applies CSS including the ASCII fallback for conhost.exe, and detects whether to use Unicode or ASCII borders based on the `WT_SESSION` environment variable.
- `screens/` — One file per screen:
  - `welcome.py` — OS mode selection at startup (Windows vs Linux)
  - `dashboard.py` — Main menu with tool status indicators
  - `scan.py` — Nmap scan configuration and results
  - `capture.py` — Traffic capture setup
  - `analyze.py` — Pcap file analysis
  - `apk.py` — APK static analysis
  - `frida.py` — Frida runtime analysis
  - `network_setup.py` — Network bridge configuration
  - `settings.py` — Tool status and config viewer, includes setup instructions for jadx and apktool
  - `reports.py` — Report generation
  - `custom_script.py` — Run user-supplied analysis scripts against a target
  - `help_screen.py` — Generic scrollable help modal
- `widgets/` — Reusable widgets:
  - `log_viewer.py` — Scrollable log with `y` to copy all and `e` to open a selectable TextArea modal
  - `pasteable_input.py` — Input subclass that reads from the Win32 clipboard on Ctrl+V (works in conhost.exe where standard paste doesn't)

## plugins/

Report output plugins. The `ReportGenerator` takes structured analyzer output and passes it to whichever plugin is requested.

- `base.py` — Abstract base class `ReportPlugin` with a single `render(data) -> str` method
- `json_report.py` — Pretty-printed JSON
- `html_report.py` — Self-contained HTML with inline CSS
- `csv_export.py` — CSV of findings

## config/

- `default.yaml` — Full config schema with defaults. Don't edit this.
- `local.yaml` — Your overrides (tool paths, interface names, API keys). Create this if it doesn't exist.
- `apk_patterns.yaml` — Regex patterns for credential detection and dangerous permissions in APK analysis.

## tests/

454 tests covering the analysis layer, runners, CLI, TUI screens, and plugins. All offline — no real network or tools needed.

- `test_analysis.py` — Analyzer unit tests
- `test_apk.py` — APK analyzer tests
- `test_runners.py` — Runner subprocess wrappers
- `test_cli.py` — CLI dispatch
- `test_tui.py` — TUI screen composition
- `test_plugins.py` — Report plugin rendering
- `test_report.py` — Report generator aggregation
- `test_frida.py` — Frida runner
- `test_interactive.py` — Interactive CLI
- `test_platform.py` — Tool detection across platforms
- `test_phase5.py` — End-to-end integration scenarios
- `test_pcap_enhanced.py` — Extended pcap analysis coverage
- `test_network.py` — Network setup utilities
- `test_logging.py` — Logging config
- `test_config.py` — Config loading and cascade

## scripts/

Bash helper scripts, primarily for Linux. Not needed on Windows.

- `setup.sh` — Installs Linux dependencies
- `network_setup.sh` — Sets up iptables and IP forwarding
- `capture.sh` — tshark capture wrapper
- `scan.sh` — nmap scan wrapper
- `ssl.sh` — OpenSSL cert and cipher analysis
- `main.sh` — Menu-driven wrapper around the above

## Frida Scripts/

Frida JavaScript snippets for manual use (loaded via the Frida screen in the TUI or with `frida -l`):

- `hookClasses.js` — Hook all methods in a specified class
- `HookImplementation.js` — Target a specific method implementation
- `listAllClassesLoaded.js` — Enumerate loaded classes
- `framesBuffer.js` / `simpleHook.js` — Low-level frame buffer and generic hook helpers

