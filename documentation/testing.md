# ChainRecon Testing Guide

This document separates offline tests from live Nooie validation so test results are easy to interpret.

## Offline Suite

Run this before every change:

```bash
python -m pytest --tb=short -q
```

The offline suite must not require real network access, Android devices, Nmap, tshark, jadx, or Frida. External tools are mocked at the runner boundary.

Current baseline after the stabilization pass:

```text
484 passed
```

Coverage command:

```powershell
python -m pytest --cov=analysis --cov=runners --cov=tui --cov=plugins --cov=utils --cov-report=term-missing -q
```

Latest measured coverage after the stabilization pass is 49%. The strongest covered areas are report generation, Frida device validation, traffic parsing helpers, platform/config utilities, and scanner parsing. Remaining low-coverage areas are older specialty analyzers and TUI event-heavy screen methods.

## Test Categories

- Unit tests: analyzers, parser edge cases, path/paste normalization, SSL error normalization, Frida device-state parsing, log retention, report helpers, and plugin rendering.
- Integration tests: CLI dispatch, runner command construction, report aggregation, config cascade, and parser-to-report flows using temporary files.
- End-to-end TUI tests: Textual app registration, screen imports, shared widgets, and behavior helpers. Use Textual pilot tests for future high-risk UI workflows.
- Requirement tests: Windows/admin PowerShell compatibility, no stale ARP or Frida output presented as live truth, selected report source behavior, and offline-only default execution.

## Live Nooie Validation

Live validation is intentionally separate because it depends on the lab network, the Nooie target, Android emulator state, and installed tools.

Configured target in this workspace:

```text
router_ip: 192.168.123.99
target_ip: 192.168.123.99
eth_interface: Ethernet
internet_interface: Wi-Fi
output.directory: ./nooie_analysis
```

Use these commands for the full live pass:

```powershell
python -m pytest --tb=short -q
nmap -sn 192.168.123.99
python chainrecon.py scan 192.168.123.99 --profile quick --format json --output nooie_analysis/live_scan_quick.json
python chainrecon.py scan 192.168.123.99 --profile iot --format json --output nooie_analysis/live_scan_iot.json
python chainrecon.py scan 192.168.123.99 --profile full --format json --output nooie_analysis/live_scan_full.json
python chainrecon.py scan 192.168.123.99 --profile vuln --format json --output nooie_analysis/live_scan_vuln.json
python chainrecon.py scan 192.168.123.99 --profile ssl --format json --output nooie_analysis/live_ssl.json
python chainrecon.py analyze-traffic nooie_analysis/traffic.pcap --format json --output nooie_analysis/live_traffic.json
python chainrecon.py capture Ethernet --mode basic --duration 10 --target-ip 192.168.123.99 --format json --output nooie_analysis/live_capture.json
python chainrecon.py apk "nooie_analysis/The APKs/nooie_base_apk.apk" --format json --output nooie_analysis/live_apk.json
adb devices
frida-ps -U
adb shell monkey -p com.android.settings 1
frida -U -N com.android.settings -l runners/frida_scripts/network_traffic_monitor.js -q -t 10 --exit-on-error
python chainrecon.py report nooie_analysis --format html --output nooie_analysis/live_report.html
python chainrecon.py report nooie_analysis --format json --output nooie_analysis/live_report.json
python chainrecon.py report nooie_analysis --format csv --output nooie_analysis/live_report.csv
```

## Latest Live Run - 2026-04-22

Machine: Windows, PowerShell, configured output directory `./nooie_analysis`.

Offline verification:

```text
python -m pytest -q
484 passed

python -m pytest --cov=analysis --cov=runners --cov=tui --cov=plugins --cov=utils --cov-report=term-missing -q
484 passed, total measured coverage 49%
```

Live target status:

```text
nmap -sn 192.168.123.99
Host is up, MAC C6:41:1E:37:B4:F8
```

Live scan outputs:

- `nooie_analysis/live_scan_quick.json`: 1 host up, 0 open ports, 1000 closed TCP ports, exact Nmap command and `-Pn` note recorded.
- `nooie_analysis/live_scan_iot.json`: 1 host up, 16 checked IoT TCP/UDP ports, all closed.
- `nooie_analysis/live_scan_full.json`: 1 host up, 0 open ports, 65535 closed TCP ports. Runtime was about 43m50s.
- `nooie_analysis/live_scan_vuln.json`: 1 host up, 0 open ports, 1000 closed TCP ports, no vulnerability findings because no services were open.

SSL validation:

- `nooie_analysis/live_ssl.json`: ports 443, 8443, 8883, and 8080 all returned `error_type: tcp_connection_failed` with Windows connection-refused details. This confirms `reachable: false` is a per-port TLS reachability result, not a host-liveness result.

Traffic validation:

- `nooie_analysis/live_traffic.json`: saved Nooie pcap parsed 4048 packets, DNS/SNI included `app.us.nooie.com` and `nooie-us-5.s3.us-east-005.backblazeb2.com`; external IP count 7.
- `nooie_analysis/live_capture.json`: 10-second live capture on `Ethernet` succeeded and saw TCP traffic between `192.168.123.99` and `3.224.238.60:8883`.

APK validation:

- `nooie_analysis/live_apk.json`: Nooie base APK analysis completed. Summary: 45 permissions, 5 dangerous permissions, 15 exported components, 39 credential-like findings, 6 SDKs, pinning indicators detected, 39 JADX warnings, 6 risk indicators.

Frida validation:

- `adb devices`: `emulator-5554 device`.
- `frida-ps -U`: listed live emulator processes.
- `FridaRunner().get_device_state()`: `online: True`, serial `emulator-5554`.
- `adb shell monkey -p com.android.settings 1`: launched Settings successfully.
- `frida -U -N com.android.settings -l runners/frida_scripts/network_traffic_monitor.js -q -t 10 --exit-on-error`: loaded hooks for `URL.openConnection` and `Socket.connect`; OkHttp was not present in Settings, which is expected.

Report validation:

- Current-session reports:
  - `nooie_analysis/live_report_current.html`
  - `nooie_analysis/live_report_current.json`
  - `nooie_analysis/live_report_current.csv`
- All top-level output JSON reports:
  - `nooie_analysis/live_report_all.html`
  - `nooie_analysis/live_report_all.json`
  - `nooie_analysis/live_report_all.csv`
- `live_report_current.json` included 1 APK source with 6 risk indicators, 4 scan sources, 1 SSL source, and 2 traffic sources.
- `live_report_all.json` included top-level saved analysis artifacts only; generated multi-section reports and decompiled APK asset JSON files were skipped to avoid recursive or irrelevant report data.

Environmental notes:

- `tshark` was installed at `C:\Program Files\Wireshark\tshark.exe` but was not visible to the non-profile shell PATH. ChainRecon resolved it through its platform-aware tool lookup and the live capture succeeded.
- A user PowerShell profile execution-policy warning appeared when commands were run through a profile-loading shell. It is outside ChainRecon; using a no-profile shell avoids that startup noise.

Expected interpretation:

- ICMP success with closed TCP ports means the host/router is reachable but those services are not listening.
- SSL `reachable: false` on a port means that port refused, timed out, was filtered, or did not complete TLS. It does not prove the host is offline.
- ARP-table fallback results are cached local observations and must not be treated as fresh liveness proof.
- Frida process listing must fail clearly when adb has no online device, an offline device, or an unauthorized device.

## Recording Results

After live validation, record:

- Date/time and machine.
- Exact commands run.
- Output files generated under `nooie_analysis`.
- Any failed commands and whether the failure is environmental or application-level.
- The final `pytest` result.
