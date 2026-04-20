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

454 tests covering analyzers, runners, CLI, TUI screens, and plugins. All offline.

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
```

## Troubleshooting

**Question marks (?) in TUI borders** -- Happens in admin PowerShell / conhost.exe. ChainRecon detects this and switches to ASCII borders. If you still see garbled output, use Windows Terminal.

**jadx not found** -- Set the path in `config/local.yaml` as shown above.

**APK analysis seems stuck** -- Large APKs take 3-5 minutes to decompile. The TUI shows jadx progress as it runs.

**Full nmap scan times out** -- Scanning all 65535 ports with `-A` can take over an hour. The timeout is 2 hours but on slow networks it may not be enough. Run nmap from the command line directly if the TUI times out.

**No traffic captured** -- Check the interface name in config matches your Ethernet adapter. Run `ipconfig` (Windows) or `ip link` (Linux) to check.
