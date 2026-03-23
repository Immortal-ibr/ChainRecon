## Purpose
ChainRecon is a system designed to help analyze IoT devices for security research. Instead of running a bunch of different commands manually every time to test a device, this script automates the whole process - from network setup to traffic capture to SSL analysis.

The main goal is to figure out what an IoT device is doing on the network: what servers it talks to, what protocols it uses, and whether it has any obvious security issues.

## Requirements

### 1. User Interface
- CLI entry point with named subcommands for each analysis type
- Interactive menu-driven mode launched when no subcommand is given
- Session state persists across analysis runs within a session (interface, router IP, target IP, output directory)
- Preset/default values for all session variables if not specified by the user
- Logs steps taken during each process for traceability
- Graceful error handling: prompts user and exits cleanly with a helpful resolution message on failure
- Report generation in multiple formats (JSON, HTML, CSV) via a plugin interface
- Plugin base class allowing user-defined report formats

### 2. Network Setup
- Prompts user for the network interface connected to the router and the interface connected to the internet
- Enables IP forwarding on the host machine
- Configures NAT via iptables to establish a man-in-the-middle position
- Leaves the network in a state where external tools (e.g. Wireshark, tcpdump) can passively capture all device traffic

### 3. Device Scan
- Executes nmap with selectable scan profiles: quick, gentle, full, IoT-focused, and vulnerability
- Gentle profile (-T2, full TCP connect) for fragile or sensitive IoT devices
- IoT protocol awareness: identifies services on MQTT, CoAP, UPnP, mDNS, BACnet, and similar ports
- Flags CVE-relevant exposures (telnet, FTP, unprotected HTTP, UPnP)
- Optional Shodan API enrichment for additional host context
- Parses and structures nmap output (XML/text) for use in reports

### 4. Traffic Analysis
- Captures network traffic to a PCAP file for later analysis
- Extracts DNS queries (query name, type, source IP)
- Extracts HTTP requests (method, host, URI, user-agent, source IP)
- Extracts TLS Server Name Indication (SNI) from handshakes
- Computes protocol distribution statistics (TCP, UDP, ICMP, DNS, TLS, etc.)
- Identifies external (non-RFC1918) destination IPs
- Tracks conversations (source/destination pairs and byte counts)
- Flags unencrypted HTTP traffic as a risk finding
- Filters analysis to a specific target IP when provided

### 5. TLS Analysis
- Probes a configurable list of ports on the target for TLS/SSL services
- Extracts certificate details: subject, issuer, serial, validity dates, version
- Detects self-signed and expired certificates
- Tests for weak cipher suites (export ciphers, DES, RC4, NULL)
- Tests for outdated protocol versions (SSLv3, TLSv1.0)
- Produces a risk rating (critical / high / medium / low) with per-finding detail
- Computes JA3 fingerprints from captured TLS handshakes for client library identification
- Bypasses SSL pinning in Android companion apps (via Frida instrumentation) to capture otherwise-hidden traffic

## Non-Functional Requirements
- Modular and extensible: new analysis techniques can be added without modifying existing modules
- Run with least privilege; prompt for elevated access only where required (network setup)

## Future Features
- Ability to resume interrupted sessions or re-run specific steps without starting over

## Design
The tool will use bash scripting for the main CLI interface and network setup, while Python will be used for the analysis and report generation components. This allows us to leverage powerful libraries for network analysis and report generation while keeping the user interface simple and accessible. The modular design will allow for easy maintenance and future expansion, with clear separation between the different components of the tool.