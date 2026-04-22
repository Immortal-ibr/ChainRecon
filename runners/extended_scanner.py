"""Extended scan runners for ChainRecon.

Provides scanning capabilities beyond nmap:
- ARP scan for local network device discovery
- TCP banner grabbing for service identification
- Python-native port scan (no external tools required)
"""

from __future__ import annotations

import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from runners.base import make_output_dir
from utils.logging_config import get_logger

logger = get_logger("extended_scan")

# Common IoT ports to check
IOT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 443, 502, 554, 1080, 1883, 3000,
    3478, 4443, 5000, 5353, 5555, 5683, 6668, 8000, 8008, 8080,
    8081, 8443, 8554, 8883, 9090, 9100, 32768, 49152,
]

# Service identification by banner patterns
_BANNER_PATTERNS = {
    b"SSH-": "SSH",
    b"220 ": "FTP/SMTP",
    b"HTTP/": "HTTP",
    b"+OK": "POP3",
    b"* OK": "IMAP",
    b"RTSP/": "RTSP",
    b"\x10": "MQTT CONNACK",
    b"<?xml": "XML/UPnP",
}


class ExtendedScanner:
    """Scanning without external tool dependencies."""

    def __init__(self, progress_cb: Optional[Callable[[str], None]] = None):
        self._progress = progress_cb or (lambda msg: None)

    # -- TCP connect scan ---------------------------------------------

    def tcp_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        max_workers: int = 50,
    ) -> Dict[str, Any]:
        """Scan TCP ports using connect(). Returns open ports with banners."""
        ports = ports or IOT_PORTS
        self._progress(f"Scanning {len(ports)} TCP ports on {target}...")
        open_ports: List[Dict[str, Any]] = []
        lock = threading.Lock()

        def _check(port: int) -> Optional[Dict[str, Any]]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((target, port))
                    banner = self._grab_banner(s)
                    service = self._identify_service(port, banner)
                    return {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner.decode("utf-8", errors="replace").strip()[:200] if banner else "",
                    }
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_check, p): p for p in ports}
            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                if done_count % 10 == 0:
                    self._progress(f"  {done_count}/{len(ports)} ports checked...")
                result = future.result()
                if result:
                    with lock:
                        open_ports.append(result)
                    self._progress(f"  Port {result['port']} OPEN ({result['service']})")

        open_ports.sort(key=lambda x: x["port"])
        return {
            "metadata": {"target": target, "ports_scanned": len(ports), "scanner": "tcp_connect"},
            "findings": {"open_ports": open_ports},
            "summary": {"open_count": len(open_ports)},
            "risk_indicators": self._assess_risks(open_ports),
        }

    @staticmethod
    def _grab_banner(sock: socket.socket) -> Optional[bytes]:
        """Try to read a banner. Send an HTTP probe if nothing comes back."""
        try:
            sock.settimeout(1.5)
            data = sock.recv(1024)
            if data:
                return data
        except (socket.timeout, OSError):
            pass
        # HTTP probe
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            sock.settimeout(2.0)
            return sock.recv(2048)
        except (socket.timeout, OSError):
            return None

    @staticmethod
    def _identify_service(port: int, banner: Optional[bytes]) -> str:
        if banner:
            for pattern, name in _BANNER_PATTERNS.items():
                if banner.startswith(pattern):
                    return name
        # Port-based fallback
        known = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 443: "HTTPS", 502: "Modbus", 554: "RTSP",
            1883: "MQTT", 3478: "STUN", 5353: "mDNS", 5555: "ADB",
            5683: "CoAP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            8554: "RTSP-Alt", 8883: "MQTT-TLS", 9100: "Printer",
        }
        return known.get(port, "unknown")

    def _assess_risks(self, open_ports: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        risks: List[Dict[str, str]] = []
        risky = {
            23: ("high", "Telnet is open -- credentials sent in plaintext"),
            21: ("medium", "FTP is open -- often allows anonymous or weak auth"),
            5555: ("critical", "ADB port open -- full device shell access without auth"),
            502: ("high", "Modbus is open -- industrial protocol with no built-in auth"),
            9100: ("medium", "Printer port open -- may leak info or allow RCE"),
            554: ("medium", "RTSP is open -- video stream may be accessible"),
        }
        for p in open_ports:
            if p["port"] in risky:
                sev, detail = risky[p["port"]]
                risks.append({"severity": sev, "title": f"Port {p['port']} ({p['service']})", "details": detail})
        if len(open_ports) > 15:
            risks.append({
                "severity": "medium",
                "title": f"Large attack surface ({len(open_ports)} open ports)",
                "details": "IoT devices should expose minimal services.",
            })
        return risks

    # -- ARP discovery ------------------------------------------------

    def arp_scan(self, interface: str = "Ethernet", subnet: str = "192.168.1.0/24") -> Dict[str, Any]:
        """Discover devices on the local network via ARP requests.

        Uses scapy if available, otherwise falls back to reading the ARP table.
        """
        self._progress(f"ARP scan on {subnet}...")
        try:
            return self._arp_scapy(subnet)
        except Exception:
            logger.debug("Scapy ARP failed, falling back to ARP table")
            self._progress("  Live ARP probe failed; reading local ARP cache instead.")
            return self._arp_table()

    def _arp_scapy(self, subnet: str) -> Dict[str, Any]:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=3, verbose=0)
        hosts = []
        for _, rcv in ans:
            hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
            self._progress(f"  Found {rcv.psrc} ({rcv.hwsrc})")
        return {
            "metadata": {"subnet": subnet, "scanner": "arp_scapy", "fresh": True, "live_reachability": True},
            "findings": {"hosts": hosts},
            "summary": {"host_count": len(hosts)},
            "risk_indicators": [],
        }

    def _arp_table(self) -> Dict[str, Any]:
        """Read local ARP cache (works without admin on Windows/Linux)."""
        import subprocess
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=10,
            )
            hosts = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0].strip("()")
                    # Accept lines that look like IP addresses
                    if ip.count(".") == 3 and ip[0].isdigit():
                        mac = parts[1] if "-" in parts[1] or ":" in parts[1] else (parts[2] if len(parts) > 2 else "")
                        if mac and mac != "ff-ff-ff-ff-ff-ff":
                            hosts.append({"ip": ip, "mac": mac})
            return {
                "metadata": {
                    "scanner": "arp_table",
                    "fresh": False,
                    "live_reachability": False,
                    "source": "local_arp_cache",
                    "warning": "ARP table entries may be stale and do not prove the host is currently reachable.",
                },
                "findings": {"hosts": hosts},
                "summary": {"host_count": len(hosts)},
                "risk_indicators": [],
            }
        except Exception as exc:
            return {
                "metadata": {
                    "scanner": "arp_table",
                    "fresh": False,
                    "live_reachability": False,
                    "source": "local_arp_cache",
                    "error": str(exc),
                },
                "findings": {"hosts": []},
                "summary": {"host_count": 0},
                "risk_indicators": [],
            }

    # -- Service fingerprinting ---------------------------------------

    def fingerprint_services(
        self, target: str, ports: List[int], timeout: float = 3.0
    ) -> Dict[str, Any]:
        """Deep banner grab + protocol probes on known-open ports."""
        self._progress(f"Fingerprinting {len(ports)} services on {target}...")
        services: List[Dict[str, Any]] = []

        probes = [
            ("HTTP", b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"),
            ("RTSP", b"OPTIONS rtsp://target RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
            ("MQTT", b"\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"),  # CONNECT
        ]

        for port in ports:
            info = {"port": port, "banners": []}
            for name, probe_data in probes:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((target, port))
                        s.sendall(probe_data)
                        resp = s.recv(4096)
                        if resp:
                            info["banners"].append({
                                "probe": name,
                                "response_preview": resp[:200].decode("utf-8", errors="replace"),
                            })
                except (socket.timeout, ConnectionRefusedError, OSError):
                    continue
            if info["banners"]:
                services.append(info)
                self._progress(f"  Port {port}: {len(info['banners'])} probe(s) responded")

        return {
            "metadata": {"target": target, "scanner": "fingerprint"},
            "findings": {"services": services},
            "summary": {"fingerprinted_count": len(services)},
            "risk_indicators": [],
        }
