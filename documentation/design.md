## What ChainRecon is

ChainRecon is an IoT security analysis tool. The core idea is that when you're researching an IoT device, you always end up running the same set of tools in the same order -- nmap to find open ports, tshark to capture traffic, jadx to look at the APK, frida to hook interesting functions at runtime. Doing that manually for every new device is tedious, so ChainRecon ties it all together into a single TUI that keeps results organized and lets you jump between analysis steps without having to remember every command.

The tool is designed to be used with a physical man-in-the-middle setup: the IoT device connects through a router, the router connects to your computer over Ethernet, and your computer bridges to Wi-Fi. That puts you in a position to see everything the device sends and receives without modifying it.

## Requirements

**Core behavior:**
- Accept a target device IP, router IP, and network interface names from the user (with sensible defaults where possible)
- Support four main modes: network setup, device scanning, traffic capture/analysis, and SSL/TLS analysis
- Operate without root for most analysis tasks; only the network setup requires elevated privileges
- Gracefully handle missing tools -- warn the user and skip that feature rather than crashing
- Save all output to timestamped directories so nothing gets overwritten

**Traffic analysis must produce:**
- DNS queries and the IPs they resolve to
- TLS SNI hostnames from HTTPS connections
- Any plaintext HTTP traffic (headers, bodies, anything unencrypted)
- Protocol distribution statistics
- List of external IPs with cloud provider attribution
- Conversation-level view (who talked to whom, how much data)

**APK analysis must produce:**
- Declared permissions from the manifest, flagging dangerous ones
- Exported components (activities, services, receivers, providers) that could be entry points
- Whether cleartext traffic is permitted
- Any certificate pinning found in the code
- Hardcoded credentials, API keys, AWS config in the Java source
- Third-party SDKs detected (Tuya, Firebase, AWS IoT, etc.)

**SSL/TLS analysis must produce:**
- Certificate chain details (CN, SANs, expiry, key size)
- Cipher suite support with flags for weak/deprecated ciphers
- TLS version support (flag anything below TLS 1.2)

**Reports:**
- XLSX as the default user-facing report format, with JSON still available for automation
- HTML and CSV outputs through the plugin system
- Plugins should be swappable -- provide a base class and let users write their own
- The TUI report screen must let users choose current-session results or top-level ChainRecon JSON analysis files in the configured output directory; generated multi-section reports and decompiled APK asset JSON files must not be recursively imported
- Reports are still not a finished surface. They work, but they still need improvement in formatting, cross-session comparison, and large-result navigation.

**Frida runtime analysis must produce:**
- A default class-discovery path when the Frida screen opens
- Managed attach/spawn behavior that launches app packages when they are not running
- A stoppable device-wide class census that records a clean user stop instead of `unexpected_exit`
- A live loaded-class monitor for classes loaded or requested through `Class.forName(...)` after hook start
- Networking and storage hooks that keep their default Android/OkHttp/MQTT/SharedPreferences coverage while accepting user-added classes

## Non-functional requirements

- Modular design so analyzers can be used independently from the CLI or imported as a library
- The TUI should work in Windows Terminal and admin PowerShell
- Tests should run offline with no real network access or external tools required
- Config should cascade: built-in defaults < local overrides < environment variables

## Architecture

The tool has three layers:

**Bash scripts** (`scripts/`) handle anything that needs system-level access on Linux: setting up iptables rules, enabling IP forwarding, running tshark captures. These are intentionally separate from the Python code so the analysis layer can run on Windows without needing bash.

**Python analysis layer** (`analysis/`, `runners/`) does all the heavy lifting. Each analyzer takes either a file (pcap, nmap XML, APK) or a network target and returns a structured dict. The `runners/` directory wraps subprocess calls to external tools so that the timeout handling, encoding, and error handling is consistent everywhere.

**TUI** (`tui/`) is a Textual application that wraps the analysis layer. Each screen corresponds to one analysis mode and runs its work in a background thread, streaming output to a LogViewer widget as it comes in.

The report plugin system (`plugins/`) sits at the end of the pipeline. The `ReportGenerator` collects results from whichever analyzers were run and passes them to whatever output plugin is selected.

Device profiles live outside normal runtime config. `profiles/devices/nooie.yaml` is the source of truth for the Nooie profile used by the Profiles, Workflow, and Firmware screens. `config/default.yaml` and `config/local.yaml` hold local runtime defaults such as output directory, interface names, tool paths, and the preferred Frida device.

## Configuration

Config is stored in YAML under `config/`. `default.yaml` has the full set of keys with conservative defaults. Users create `config/local.yaml` with just their overrides -- tool paths, interface names, API keys, etc. Environment variables (e.g. `CHAINRECON_JADX_PATH`) override everything.

## Decisions made along the way

**Scapy instead of pyshark for traffic analysis:** pyshark requires tshark to be installed and is much slower for offline pcap analysis. Scapy is pure Python, faster for packet-by-packet inspection, and handles the same protocols we care about (DNS, TLS, HTTP, STUN/WebRTC).

**Streaming jadx output:** jadx on a large APK can take several minutes and generates a lot of console output. Running it with `subprocess.run(capture_output=True)` fills the pipe buffer and deadlocks on Windows. The fix is to use `Popen` and read line-by-line, forwarding each line to the TUI log viewer so the user can see progress.

**ASCII border fallback for conhost.exe:** Textual uses Unicode box-drawing characters for widget borders. These don't render in Windows admin PowerShell (conhost.exe) even with VT mode enabled. The app detects this by checking whether `WT_SESSION` is set (Windows Terminal sets it, conhost does not) and applies a CSS class that switches all borders to ASCII (`+`, `-`, `|`).

**PasteableInput widget:** On conhost.exe, Ctrl+V may be consumed by the terminal and never reach the Textual app. The `PasteableInput` widget reads from the Win32 clipboard directly via ctypes so pasting always works in input fields.

**Bounded output boxes:** Long jadx, nmap, and Frida output can make a terminal UI sluggish. The LogViewer keeps the visible/retained log bounded, tells the user when old lines are dropped, and relies on analyzer output files for full artifacts. The saved log files are important because they preserve the full execution stream even when the visible TUI log is intentionally capped.

**No stale live-tool results:** Scan and Frida features must distinguish live observations from cached or assumed state. ARP-table fallback is labeled as cached local data, nmap `-Pn` is labeled as "assume host up", and Frida validates an online adb device before listing processes or injecting scripts.

**SSL reachability wording:** SSL analysis reports reachability per port. A refused or filtered TLS port is not the same as a dead host, and DNS `getaddrinfo` failures are reported as target-name problems rather than generic network failures.

**Frida help rendering:** The Frida help text is intentionally detailed, so the modal renders it as plain read-only text instead of a large Rich `Static`. The content stays available, but opening the help screen no longer forces Textual to parse and lay out a large markup block.

**Firmware scope:** Firmware analysis is intentionally early-stage. It extracts with binwalk when a working extractor is available, falls back to direct image scanning when extraction is not available, and records that state clearly. The module is expected to grow into deeper filesystem unpacking, architecture detection, vendor config parsing, and binary triage.
