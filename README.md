# ChainRecon

A network security analysis tool built for the Purdue ChainVisor project. The goal is to figure out what an IoT device actually does on the network â€” what servers it connects to, what protocols it uses, whether its traffic is encrypted, and whether the APK has anything sketchy in it.

This was written because manually running nmap, tshark, jadx, and frida on every new device gets old fast. ChainRecon wraps all of that into a single TUI that you can actually navigate with a keyboard.

## Setup

You need Python 3.10+ and pip. On Windows, run from PowerShell (admin or Windows Terminal):

```bash
pip install -r requirements.txt
```

Then launch the TUI:

```bash
python chainrecon.py tui
```

Or use the CLI directly if you don't want the TUI:

```bash
python chainrecon.py analyze-traffic captures/device.pcap --format html
python chainrecon.py analyze-ssl 192.168.1.50 --ports 443 8443
python chainrecon.py analyze-scan scans/device.xml
```

## How the network setup works

The idea is a classic man-in-the-middle position â€” your computer sits between the IoT device and the router so you can see all the traffic:

1. Connect the IoT device to a physical router
2. Connect that router to your computer via Ethernet
3. Your computer forwards traffic to Wi-Fi (so the device can reach the internet)
4. ChainRecon captures and analyzes everything going through that bridge

This doesn't require rooting the device or installing anything on it. You're just watching at the network layer.

## What it analyzes

**Traffic (from a .pcap file or live capture)**
- DNS queries â€” what domains the device looks up
- TLS SNI â€” where it actually connects (even HTTPS leaks the hostname)
- HTTP â€” any unencrypted requests, including headers and POST data
- External IPs with cloud provider attribution (AWS, GCP, Azure, etc.)
- Protocol breakdown and conversation statistics
- WebRTC/STUN activity (common in cameras and video devices)
- Cleartext credentials (passwords, tokens, API keys in unencrypted traffic)

**APK static analysis**
- Decompiles with jadx and inspects the Java source
- Reads the AndroidManifest.xml for permissions and exported components
- Checks network_security_config.xml for cleartext traffic settings and cert pins
- Scans for hardcoded credentials, API keys, and AWS config in the source
- Identifies SDKs: Tuya, AWS IoT, Firebase, Paho MQTT, OkHttp, Agora, WebRTC

**SSL/TLS**
- Connects to open ports and reads the certificate chain
- Flags weak ciphers (RC4, DES, export) and outdated TLS versions (1.0, 1.1)
- Checks key sizes and signature algorithms
- Optional JA3-style fingerprinting from a saved pcap

**Device scanning (via nmap)**
- Five scan profiles: quick, gentle, full, IoT-specific ports, vulnerability
- IoT-specific: checks MQTT (1883), CoAP (5683), UPnP (1900), mDNS (5353), etc.
- Optional Shodan enrichment if you have an API key

## External tools

The TUI will tell you which tools are found on startup. Most work fine without everything installed â€” you only need jadx if you're doing APK analysis, frida if you're doing runtime hooking, etc.

| Tool | What it's for | Where to get it |
|------|--------------|----------------|
| nmap | Device scanning | nmap.org |
| tshark | Live capture, pcap parsing | wireshark.org |
| jadx | APK decompilation | github.com/skylot/jadx/releases |
| apktool | APK resource decoding | apktool.org |
| frida | Runtime instrumentation | frida.re |
| adb | Android device communication | developer.android.com |

For jadx and apktool on Windows, you need to point ChainRecon at the files since they probably won't be on your PATH. Add this to `config/local.yaml` (create it if it doesn't exist):

```yaml
tools:
  jadx: 'C:\path\to\jadx-1.5.5\bin\jadx.bat'
  apktool: 'C:\path\to\apktool\apktool.jar'
```

Use single quotes for Windows paths â€” double-quoted YAML strings treat backslashes as escape sequences. apktool is a JAR file so you need Java installed; ChainRecon handles the `java -jar` part automatically.

## Configuration

All config lives in the `config/` directory. `config/default.yaml` has the built-in defaults â€” don't edit that one. Put your overrides in `config/local.yaml`:

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

Environment variables also work and take highest priority:
`CHAINRECON_JADX_PATH`, `CHAINRECON_APKTOOL_PATH`, etc.

## Running tests

```bash
python -m pytest --tb=short -q
```

454 tests covering analyzers, runners, CLI, TUI screens, and plugins. They're all offline â€” no real network access or tools needed.

## Project layout

```
chainrecon.py        CLI entry point
interactive.py       Interactive CLI (pre-TUI version)
analysis/            Traffic, SSL, APK, scan analyzers
runners/             Subprocess wrappers for nmap, frida, tshark, etc.
tui/                 Textual TUI app and screens
plugins/             Report output plugins (JSON, HTML, CSV)
tests/               Test suite
config/              Default and local configuration files
scripts/             Bash helper scripts (Linux-focused)
```

## Troubleshooting

**Question marks (?) showing up in the TUI borders** â€” This happens in admin PowerShell / cmd.exe (conhost.exe) because Unicode box-drawing characters don't render. Use Windows Terminal instead, or ChainRecon will automatically detect this and switch to ASCII borders.

**jadx not found** â€” Set the path in `config/local.yaml` as described above. The Settings screen in the TUI also has instructions.

**APK analysis seems stuck** â€” Large APKs can take 3-5 minutes to decompile. The TUI now shows jadx progress lines as it runs so you can see it's actually working.

**UTF-8 decode errors in analysis output** â€” Fixed in the current version. If you see these, make sure you're running the latest code.

**No traffic captured** â€” Check that the interface name in config matches your actual Ethernet adapter name. `ipconfig` on Windows or `ip link` on Linux will show you.


