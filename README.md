# ChainRecon

> A framework for IoT device reconnaissance and security analysis, built for the Purdue ChainVisor project.

## What is this?

ChainRecon is a bash script I built to help analyze IoT devices during security research. Instead of running a bunch of different commands manually every time I want to test a device, this script automates the whole process - from network setup to traffic capture to SSL analysis.

The main goal is to figure out what an IoT device is doing on the network: what servers it talks to, what protocols it uses, and whether it has any obvious security issues.

## How it works

The setup is pretty straightforward:
1. Connect your IoT device to a physical router
2. Connect that router to your computer via Ethernet
3. Your computer forwards traffic to WiFi (so the IoT device can reach the internet)
4. Run this script to capture and analyze everything

This gives you a "man-in-the-middle" position where you can see all the traffic without breaking anything.

## Features

### Mode 1: Network Setup
- Automatically detects available network interfaces
- Guides you through setting up IP forwarding and NAT
- Configures iptables rules (including Docker support)
- Prompts for router IP, IoT device IP, and interface names with helpful instructions

### Mode 2: Device Scanning (Nmap)
Choose from 5 different scan modes:
- **Quick Scan** - Fast scan of top 1000 ports (good for initial discovery)
- **Gentle Scan** - Slow, careful scan that won't crash fragile IoT devices
- **Full Scan** - Comprehensive scan of all 65535 ports with OS detection
- **IoT Protocol Scan** - Targets common IoT ports (MQTT, CoAP, UPnP, mDNS, etc.)
- **Vulnerability Scan** - Uses Nmap NSE scripts to find known vulnerabilities (supports vulners.nse)

### Mode 3: Traffic Capture & Analysis
This is where tshark really shines. Pick from:
- **Basic Capture** - Just save raw packets to a pcap file for Wireshark
- **Live Analysis** - Watch traffic in real-time as it happens
- **DNS Extraction** - See every domain the device contacts
- **HTTP Analysis** - Find unencrypted API calls, user-agents, POST data
- **Protocol Stats** - Get a breakdown of what protocols are being used
- **Full Analysis** - Does everything above and generates a comprehensive report

The full analysis mode is probably what you want most of the time - it captures everything and then extracts:
- All DNS queries and resolved IPs
- HTTP requests (if any unencrypted traffic exists)
- TLS/HTTPS destinations (via SNI)
- External IPs the device contacts
- Protocol hierarchy and conversation statistics

### Mode 4: SSL/TLS Analysis
Deep dive into the device's SSL/TLS implementation:
- **Certificate Probe** - Extract certificates from common ports
- **Cipher Analysis** - Check for weak ciphers and outdated TLS versions
- **TLS Fingerprinting** - Identify the SSL library (OpenSSL, mbedTLS, wolfSSL, etc.)
- **RSA Key Analysis** - Check for weak keys using RsaCtfTool (detects ROCA vulnerability)

The TLS fingerprinting is based on research showing that many IoT devices use customized or outdated SSL libraries, which can be identified by their cipher suite ordering and TLS handshake parameters.

## Requirements

**Must have:**
- Linux (tested on Kali/Ubuntu)
- Root access (`sudo`)
- `nmap`
- `tcpdump`
- `openssl`
- `iptables`

**Recommended:**
- `tshark` (for advanced traffic analysis) - `apt install tshark`
- `RsaCtfTool` (for RSA key weakness detection) - `git clone https://github.com/RsaCtfTool/RsaCtfTool.git`
- `vulners.nse` (for better vulnerability scanning) - Download from [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners)

The script will work without the optional tools, but you'll get way better results with them installed.

## Usage

1. **Make it executable:**
   ```bash
   chmod +x "Recon script.sh"
   ```

2. **Run as root:**
   ```bash
   sudo ./Recon\ script.sh
   ```

3. **Follow the prompts:**
   - Enter your router IP (e.g., 192.168.123.1)
   - Enter the IoT device IP (or leave blank to scan for it later)
   - Choose which mode you want to run

4. **Typical workflow:**
   - Start with Mode 1 to set up networking
   - Run Mode 2 (Quick or IoT Protocol scan) to find open ports
   - Use Mode 3 (Full Analysis) while interacting with the device
   - Run Mode 4 if you found SSL/TLS services

## Output

Everything gets saved to a timestamped directory like `iot_recon_20260203_220000/`:
- Nmap scan results (`.txt` files)
- Packet captures (`.pcap` files)
- Traffic analysis reports (`.txt` files)
- SSL certificates (`.pem` files)
- TLS fingerprint data
- RSA key analysis results

## Tips

- **For Mode 3:** Interact with the device during capture (open the app, trigger notifications, etc.) to see more traffic
- **DNS is gold:** Even if everything is encrypted, DNS queries reveal what services the device uses
- **Check TLS SNI:** Modern HTTPS still leaks the destination hostname via Server Name Indication
- **Watch for HTTP:** Some IoT devices still send data unencrypted - Mode 3 will catch this
- **Gentle scans:** If the device is acting weird or crashing, use the Gentle Scan mode

## Research Background

This tool incorporates findings from IoT security research, particularly:
- TLS fingerprinting techniques for identifying SSL libraries
- Common IoT vulnerabilities (weak ciphers, self-signed certs, outdated TLS)
- IoT-specific protocols and port scanning strategies
- Traffic analysis patterns for device identification

## Troubleshooting

**"No interface set"** - Run Mode 1 first to configure networking

**"tshark not found"** - Install with `apt install tshark`, or the script will fall back to basic tcpdump

**"Permission denied"** - Make sure you're running with `sudo`

**Device can't reach internet** - Check that IP forwarding is enabled and iptables rules are correct (Mode 1 does this)

**No traffic captured** - Verify the interface name is correct and the device is actually sending traffic
