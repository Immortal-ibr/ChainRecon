# ChainRecon

A network security analysis tool built for the Purdue ChainVisor project. The goal is to figure out what an IoT device actually does on the network -- what servers it connects to, what protocols it uses, whether its traffic is encrypted, and whether the APK has anything sketchy in it.

This was written because manually running nmap, tshark, jadx, and frida on every new device gets old fast. ChainRecon wraps all of that into a single TUI that you can navigate with a keyboard.

## Setup

You need Python 3.10+ and pip. On Windows, run from PowerShell (admin or Windows Terminal):

```bash
pip install -r requirements.txt
```

Then launch the TUI:

```bash
python chainrecon.py tui
```

Or use the CLI directly:

```bash
python chainrecon.py analyze-traffic captures/device.pcap --format html
python chainrecon.py analyze-ssl 192.168.1.50 --ports 443 8443
python chainrecon.py analyze-scan scans/device.xml
```

## How the network setup works

Classic man-in-the-middle position -- your computer sits between the IoT device and the internet:

1. Connect the IoT device to a dedicated router (not your main one)
2. Plug that router into your computer via Ethernet
3. Your computer forwards the traffic out through Wi-Fi to the internet
4. ChainRecon captures and analyzes everything going through that bridge

No rooting or installing anything on the device. You're watching at the network layer.

## What it analyzes

### Traffic analysis (from .pcap or live capture)

- **DNS queries** -- what domains the device looks up at startup and during use
- **TLS SNI** -- where it actually connects (even HTTPS leaks the hostname in ClientHello)
- **HTTP** -- unencrypted requests including headers and POST data
- **External IPs** with cloud provider attribution (AWS, GCP, Azure, Cloudflare, Akamai)
- **Protocol breakdown** and conversation statistics
- **WebRTC/STUN** -- ICE candidates, DTLS handshakes, SRTP stream detection
- **Cleartext credentials** -- passwords, tokens, API keys in unencrypted traffic

### Entropy analysis

Computes Shannon entropy (bits per byte, 0-8) for every payload in the pcap. Classifies packets and streams as plaintext, structured, compressed, or encrypted. Flags anomalies like low entropy on ports that should be encrypted (443, 8443), and detects near-perfect entropy that may indicate XOR obfuscation.

### RTP / protocol classification

Identifies UDP protocols by first-byte heuristics: STUN (RFC 5389 magic cookie), DTLS (content types 20-25), RTP/SRTP (version 2 header), TURN channel data. Groups RTP packets by SSRC to identify media streams, extracts payload types (H.264, Opus, PCMU), estimates packet loss from sequence gaps. Detects H.264 NAL units in RTP payloads.

### Certificate extraction from pcap

Scans TLS and DTLS handshakes for DER-encoded X.509 certificates. Parses each one and checks RSA key size, signature algorithm (SHA-1/MD5 = weak), expiry, self-signed status, and Fermat factorisation vulnerability (p close to q). Needs the `cryptography` package.

### MQTT deep parsing

Decodes MQTT from raw TCP payloads:
- **CONNECT** -- client ID, username, password (flagged if sent unencrypted on port 1883)
- **PUBLISH** -- topic names and payloads with JSON detection
- **SUBSCRIBE** -- topic filters and QoS levels
- **XOR detection** -- tries common single-byte XOR keys against opaque payloads

### APK static analysis

- Decompiles with jadx, inspects the Java source
- Reads AndroidManifest.xml for permissions and exported components
- Checks network_security_config.xml for cleartext traffic and cert pins
- Scans for hardcoded credentials, API keys, AWS config
- Identifies SDKs: Tuya, AWS IoT, Firebase, Paho MQTT, OkHttp, Agora, WebRTC

### SSL/TLS (live probing)

- Connects to open ports and reads the certificate chain
- Flags weak ciphers (RC4, DES, export) and outdated TLS (1.0, 1.1)
- Checks key sizes and signature algorithms
- JA3 fingerprinting from a saved pcap

### Network scanning

**nmap profiles** (6 built-in):
- Quick -- top 1000 ports with service detection
- Gentle -- full TCP connect, slow timing (safe for fragile IoT devices)
- Full -- all 65535 ports + OS detection + traceroute (2-hour timeout)
- IoT -- TCP + UDP on MQTT, UPnP, mDNS, CoAP, Modbus ports
- Vulnerability -- NSE vuln scripts (EternalBlue, Heartbleed, default creds)
- SSL/Cert -- ssl-cert + ssl-enum-ciphers on HTTPS/MQTT-TLS ports

**Python-native scans** (no nmap required):
- TCP Connect -- socket-based port scan with banner grabbing on IoT ports
- ARP Discovery -- find devices on the local network via Scapy or ARP cache
- Service Fingerprint -- deep probe with HTTP/RTSP/MQTT protocol handshakes

## External tools

The TUI shows which tools are found on startup. Most features work without everything installed.

| Tool | What it's for | Where to get it |
|------|--------------|----------------|
| nmap | Device scanning | nmap.org |
| tshark | Live capture | wireshark.org |
| jadx | APK decompilation | github.com/skylot/jadx/releases |
| apktool | APK resource decoding | apktool.org |
| frida | Runtime instrumentation | frida.re |
| adb | Android device communication | developer.android.com |

For jadx and apktool on Windows, set the paths in `config/local.yaml`:

```yaml
tools:
  jadx: 'C:\path\to\jadx-1.5.5\bin\jadx.bat'
  apktool: 'C:\path\to\apktool\apktool.jar'
```

Use single quotes -- double-quoted YAML strings treat backslashes as escape sequences.

## Setup verification

Run these checks after installation. They verify the local Python environment, optional external tools, and Frida device setup.

### 1. Verify Python dependencies

```bash
python --version
python -m pip install -r requirements.txt
python -c "import textual, rich, yaml, requests; print('Python dependencies OK')"
```

Then run the offline test suite:

```bash
python -m pytest --tb=short -q
```

### 2. Verify external tools

On Windows PowerShell:

```powershell
Get-Command nmap,tshark,adb,frida,frida-ps -ErrorAction SilentlyContinue
```

On Linux/macOS:

```bash
command -v nmap tshark adb frida frida-ps
```

Missing tools only affect their matching features. For example, traffic capture needs `tshark`, Nmap profiles need `nmap`, and Frida instrumentation needs `adb`, `frida`, and `frida-ps`.

### 3. Verify APK tooling

Set `jadx` and `apktool` paths in `config/local.yaml` if they are not on `PATH`:

```yaml
tools:
  jadx: 'C:\path\to\jadx-1.5.5\bin\jadx.bat'
  apktool: 'C:\path\to\apktool\apktool.jar'
```

Then verify them:

```powershell
python -c "from utils.config import get_tool_path; print('jadx =', get_tool_path('jadx')); print('apktool =', get_tool_path('apktool'))"
```

If you have a test APK available, run:

```bash
python chainrecon.py apk path/to/app.apk --format json --output output/apk_smoke_test.json
```

### 4. Verify Frida setup

Install Frida tools:

```bash
python -m pip install frida-tools
```

Recommended test device: an Android 15 / API 35 Google APIs x86_64 emulator. This image supports `adb root` and works with Frida Java hooks.

Install Android command-line tools if `sdkmanager` is missing. On Windows, download Command Line Tools from the Android Studio downloads page, extract it to:

```text
%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest
```

If `sdkmanager.bat` has trouble with a newer Java version, install Java 17 and point the current shell at it:

```powershell
winget install --id EclipseAdoptium.Temurin.17.JDK --source winget
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot'
$env:Path = "$env:JAVA_HOME\bin;$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin;$env:LOCALAPPDATA\Android\Sdk\emulator;$env:LOCALAPPDATA\Android\Sdk\platform-tools;$env:Path"
```

Install the emulator image and create the AVD:

```powershell
$sdk = "$env:LOCALAPPDATA\Android\Sdk"
sdkmanager --sdk_root=$sdk "platform-tools" "emulator" "platforms;android-35" "system-images;android-35;google_apis;x86_64"
avdmanager create avd --force --name ChainRecon_API35 --package "system-images;android-35;google_apis;x86_64" --device "Nexus 5X"
emulator -avd ChainRecon_API35 -no-window -no-audio -no-snapshot -gpu swiftshader_indirect
```

Wait until Android boots:

```bash
adb devices
adb shell getprop sys.boot_completed
```

`adb devices` should show `emulator-5554 device`, and `sys.boot_completed` should return `1`.

Restart ADB as root and confirm the emulator architecture:

```bash
adb root
adb shell id
adb shell getprop ro.product.cpu.abi
```

The recommended emulator returns `x86_64`. Download the matching `frida-server` from the Frida release that matches your local Frida tools:

```powershell
$version = (frida --version).Trim()
$url = "https://github.com/frida/frida/releases/download/$version/frida-server-$version-android-x86_64.xz"
curl.exe -L -o "$env:TEMP\frida-server.xz" $url
python -c "import lzma, os; open(os.environ['TEMP'] + r'\frida-server', 'wb').write(lzma.open(os.environ['TEMP'] + r'\frida-server.xz', 'rb').read())"
```

Push and start `frida-server` on the emulator:

```bash
adb push %TEMP%\frida-server /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
adb forward tcp:27042 tcp:27042
```

Verify Frida can list device processes:

```bash
frida-ps -U
```

Start a test app and verify Frida can attach by package identifier:

```bash
adb shell monkey -p com.android.settings 1
frida -U -N com.android.settings -l runners/frida_scripts/network_traffic_monitor.js -q -t 10 --exit-on-error
```

Verify ChainRecon can build every built-in Frida command:

```bash
python -m pytest tests/test_frida.py -q
```

To run a built-in script from the TUI, open `Frida`, enter the package/process name such as `com.nooie.home`, choose a built-in script, choose `Attach` or `Spawn`, and press `Run`.

## Configuration

`config/default.yaml` has built-in defaults. Put overrides in `config/local.yaml`:

```yaml
network:
  eth_interface: Ethernet
  internet_interface: Wi-Fi
  router_ip: 192.168.123.1
  target_ip: 192.168.123.50

tools:
  jadx: 'D:\tools\jadx\bin\jadx.bat'

api_keys:
  shodan: your_key_here
```

Environment variables also work: `CHAINRECON_JADX_PATH`, `CHAINRECON_APKTOOL_PATH`, etc.

## Running tests

```bash
python -m pytest --tb=short -q
```

479 tests covering analyzers, runners, CLI, TUI screens, and plugins. All offline by default.
See `documentation/testing.md` for the unit, integration, end-to-end, requirement, and live Nooie verification workflow.

## TUI reliability notes

Admin PowerShell uses the older conhost terminal host. ChainRecon now keeps TUI-visible text ASCII-safe and switches Textual borders to ASCII when Windows Terminal is not detected. `Ctrl+C` and `Ctrl+Shift+C` copy from the focused output box or text widget instead of terminating the session; use `q` or `Ctrl+Q` to quit.

All single-line input fields use the same paste handling. `Ctrl+V`, `Ctrl+Shift+V`, and `Shift+Insert` normalize quoted Windows paths, multiline clipboard text, and `file://` URLs before inserting them.

Output boxes are bounded to the last 1000 retained lines. When older lines are dropped, the log says so. Analyzer and tool artifacts are still written to the configured output directory, and each output box has controls for Clear, Copy, Save Log, Open File, and Open Folder.

## Scan and SSL semantics

Nmap-backed profiles run the real `nmap` executable and save both raw output and structured JSON. The structured result records the exact command, return code, output files, preflight reachability context, host-state, open ports, closed ports, and filtered ports.

The `-Pn` flag means nmap scans even if host discovery is inconclusive; it does not prove the target is alive. Python-native ARP fallback reads the local ARP table and is explicitly labeled as cached data because old entries can outlive the current device state.

SSL `reachable: false` is per port. It means that specific TCP/TLS probe failed, not necessarily that the host is down. `getaddrinfo failed` means name resolution failed, usually because the target field contains an invalid hostname, a URL where a host was expected, or a pasted file path.

## Report sources

The report screen has two source modes:

- `Current session only`: includes results produced in the current TUI session and avoids stale files.
- `All JSON files in configured output directory`: imports top-level ChainRecon `*.json` analysis artifacts from the configured output directory and annotates each section with its source filename. Generated multi-section reports and decompiled APK asset JSON files are skipped so reports do not recursively include themselves.

The default report path is based on `output.directory` from configuration, which is `./nooie_analysis` in this repo.

## Project layout

```
chainrecon.py        CLI entry point
interactive.py       Interactive CLI (pre-TUI version)
analysis/            Traffic, SSL, APK, entropy, RTP, cert, MQTT analyzers
runners/             Subprocess wrappers for nmap, frida, tshark + native scans
tui/                 Textual TUI app and screens
plugins/             Report output plugins (JSON, HTML, CSV)
tests/               Test suite
config/              Default and local configuration files
scripts/             Bash helper scripts (Linux-focused)
legacy/              Manual legacy assets not used by active runners
```

## Troubleshooting

**Question marks (?) in TUI borders** -- Happens in admin PowerShell / conhost.exe. ChainRecon detects this and switches to ASCII borders. If you still see garbled output, use Windows Terminal.

**jadx not found** -- Set the path in `config/local.yaml` as shown above.

**APK analysis seems stuck** -- Large APKs take 3-5 minutes to decompile. The TUI shows jadx progress as it runs.

**Full nmap scan times out** -- Scanning all 65535 ports with `-A` can take over an hour. The timeout is 2 hours but on slow networks it may not be enough. Run nmap from the command line directly if the TUI times out.

**No traffic captured** -- Check the interface name in config matches your Ethernet adapter. Run `ipconfig` (Windows) or `ip link` (Linux) to check.
