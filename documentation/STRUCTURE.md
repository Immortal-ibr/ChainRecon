# ChainRecon Directory Structure

This is a rough map of what's where and why. If you're looking for a specific piece of logic, this should save you some searching.

## Top-level files

- `chainrecon.py` -- CLI entry point. Handles subcommands: `tui`, `analyze-traffic`, `scan`, `capture`, `apk`, `firmware`, `workflow`, `report`.
- `interactive.py` -- Older interactive CLI that predates the TUI. Still works but the TUI is the main interface now.
- `requirements.txt` -- Python dependencies. Install with `pip install -r requirements.txt`.
- `Recon script.sh` -- Original bash script for Linux network setup and data collection. The Python/TUI layer replaces most of this, but it is kept for historical reference.

## analysis/

The core analysis modules. Each one takes either a file path or a network target and returns a dict.

- `traffic.py` -- Parses pcap files using Scapy. Extracts DNS queries, TLS SNI, HTTP requests, external IPs, protocol statistics, conversations, and WebRTC/STUN activity. Also has credential detection for cleartext traffic.
- `apk_analyzer.py` -- APK static analysis. Calls jadx to decompile, then inspects the manifest, source code, and resources for permissions, exported components, hardcoded credentials, cert pinning, and third-party SDKs.
- `ssl_analyzer.py` -- SSL/TLS analysis. Connects to a host/port, reads the certificate chain, checks cipher suites and TLS version support, optionally does JA3-style fingerprinting from a pcap.
- `scanner.py` -- Parses nmap XML output into structured host/port/service data. Optionally enriches with Shodan if an API key is set.
- `report_generator.py` -- Aggregates results from whichever analyzers ran and passes them to an output plugin.
- `endpoint_analyzer.py` -- Attributing IP addresses to cloud providers (AWS, GCP, Azure, Cloudflare, Akamai, Fastly) and identifying risky ports/protocols.
- `pcap_stats.py` -- Lower-level pcap statistics: packet counts, byte totals, protocol distribution, top talkers.
- `webrtc_analyzer.py` -- Detects STUN, DTLS, and SRTP traffic in a packet list, which indicates video/audio streaming.
- `entropy_analyzer.py` -- Shannon entropy analysis per packet and per stream. Classifies traffic as plaintext/structured/compressed/encrypted and flags anomalies like low entropy on encrypted ports.
- `rtp_analyzer.py` -- RTP/SRTP stream identification from UDP payloads. Protocol classification by first-byte heuristics (STUN, DTLS, RTP, TURN). H.264 NAL unit detection. Codec identification and packet loss estimation.
- `cert_analyzer.py` -- Extracts DER-encoded X.509 certificates from TLS/DTLS handshakes in pcap. Checks RSA key size, signature algorithm, expiry, self-signed status, and Fermat factorisation vulnerability.
- `mqtt_analyzer.py` -- MQTT traffic analysis including deep byte-level parsing of CONNECT/PUBLISH/SUBSCRIBE from raw TCP, and XOR key detection on opaque payloads.
- `firmware_analyzer.py` -- Early-stage firmware triage. Uses binwalk when available, falls back to direct image scanning when extraction is unavailable, and looks for credentials, keys, certificates, endpoints, and profile rule hits. This module is expected to expand later.

## runners/

Subprocess wrappers. The goal is one consistent place that handles timeouts, encoding, and error handling for all external tool calls.

- `base.py` -- `run_subprocess()` with UTF-8 encoding and error replacement, `check_tool()` for verifying tool availability, and `make_output_dir()` for timestamped output directories.
- `nmap_runner.py` -- Builds nmap command lines for the different scan profiles and invokes them. Now outputs both .txt and .xml for every scan.
- `extended_scanner.py` -- Active service fingerprinting helpers for already-identified ports. Retired Python TCP connect and ARP discovery helpers now live under `legacy/` compatibility wrappers.
- `frida_runner.py` -- Manages frida-server connections, app launch/wake-up, script rendering, long-running sessions, stoppable device-wide class census, and Frida summary artifacts.
- `capture_runner.py` -- Handles tshark/tcpdump captures with duration limits and file rotation.
- `frida_scripts/` -- JavaScript snippets loaded by the Frida runner: class listing, live loaded-class monitoring, device-wide census, SSL pinning bypass, HTTP/socket/crypto/preference/MQTT monitoring, and targeted method hooks.

## tui/

The Textual TUI application.

- `app.py` -- Entry point. Registers screens, applies CSS including the ASCII fallback for conhost.exe, and detects whether to use Unicode or ASCII borders based on the `WT_SESSION` environment variable.
- `screens/` -- One file per screen:
  - `welcome.py` -- OS mode selection at startup (Windows vs Linux)
  - `dashboard.py` -- Main menu with tool status indicators
  - `scan.py` -- Nmap scan configuration and results
  - `capture.py` -- Traffic capture setup
  - `analyze.py` -- Pcap file analysis
  - `apk.py` -- APK static analysis
  - `frida.py` -- Frida runtime analysis
  - `network_setup.py` -- Network bridge configuration
  - `settings.py` -- Tool status and config viewer, includes setup instructions for jadx and apktool
  - `reports.py` -- Report generation with current-session or all-output-file source modes
  - `custom_script.py` -- Run user-supplied analysis scripts against a target
  - `help_screen.py` -- Generic scrollable help modal. Long help text is rendered through a read-only text area so detailed Frida help remains responsive.
- `widgets/` -- Reusable widgets:
  - `log_viewer.py` -- Bounded output panel with clear, copy, save, and open controls
  - `pasteable_input.py` -- Input subclass that normalizes Ctrl+V, Ctrl+Shift+V, Shift+Insert, quoted paths, and file URLs

## plugins/

Report output plugins. The `ReportGenerator` takes structured analyzer output and passes it to whichever plugin is requested.

- `base.py` -- Abstract base class `ReportPlugin` with a single `render(data) -> str` method
- `json_report.py` -- Pretty-printed JSON
- `html_report.py` -- Self-contained HTML with inline CSS
- `csv_export.py` -- CSV of findings

## config/

- `default.yaml` -- Full config schema with defaults. Don't edit this.
- `local.yaml` -- Your overrides (tool paths, interface names, API keys). Create this if it doesn't exist.
- `apk_patterns.yaml` -- Regex patterns for credential detection and dangerous permissions in APK analysis.

## profiles/

- `devices/nooie.yaml` -- Authoritative Nooie device profile. The Profiles, Workflow, and Firmware screens use this profile when `nooie` is selected.
- `devices/*.yaml` -- Other shareable device profiles. These are device facts and defaults, not local runtime settings.

Runtime config under `config/` does not override the Nooie profile. Use `config/local.yaml` for machine-specific values such as tool paths, output directory, network interfaces, and preferred Frida device.

## tests/

Tests cover the analysis layer, runners, CLI, TUI screens, workflows, reports, and plugins. The default suite is offline; emulator and Nooie hardware checks are manual validation steps documented in `documentation/testing.md`.

- `test_analysis.py` -- Analyzer unit tests
- `test_apk.py` -- APK analyzer tests
- `test_runners.py` -- Runner subprocess wrappers
- `test_cli.py` -- CLI dispatch
- `test_tui.py` -- TUI screen composition
- `test_plugins.py` -- Report plugin rendering
- `test_report.py` -- Report generator aggregation
- `test_frida.py` -- Frida runner
- `test_interactive.py` -- Interactive CLI
- `test_platform.py` -- Tool detection across platforms
- `test_phase5.py` -- End-to-end integration scenarios
- `test_pcap_enhanced.py` -- Extended pcap analysis coverage
- `test_network.py` -- Network setup utilities
- `test_logging.py` -- Logging config
- `test_config.py` -- Config loading and cascade

## scripts/

Active helper scripts used by the TUI and local validation.

- `network_setup.ps1` -- Windows NAT/routing setup used by the Network Setup screen.
- `network_setup.sh` -- Linux equivalent for NAT/routing setup. It is non-interactive and accepts the same interface/static-IP values from the TUI.
- `diagnose_environment.ps1` -- Windows environment diagnostics.
- `run_offline_tests.ps1` -- Windows test runner helper.
- `run_live_nooie_tests.ps1` -- Windows live Nooie validation helper.

## legacy/

Manual assets that are not part of the active runner surface.

- `extended_scanner.py` -- Retired Python TCP connect and ARP discovery scans kept for compatibility and reference.
- `scan_compat.py` -- Retired `analyze-ssl` and `analyze-scan` logic kept outside the active CLI surface.
- `manual_frida_scripts/` -- Older standalone Frida snippets moved from the former top-level `Frida Scripts/` directory. Active TUI scripts live in `runners/frida_scripts/`.
- `manual_shell_scripts/network_setup.sh` -- Older interactive Linux network setup retained for reference. The active Linux path is `scripts/network_setup.sh`.

