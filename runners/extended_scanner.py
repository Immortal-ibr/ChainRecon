"""Active extended scan helpers for ChainRecon.

The supported active surface is protocol fingerprinting on already-identified
ports. Historical Python-native TCP connect and ARP discovery helpers remain
available through legacy wrappers only.
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from legacy.extended_scanner import LegacyExtendedScanner
from runners.base import make_output_dir
from utils.logging_config import get_logger

logger = get_logger("extended_scan")

class ExtendedScanner:
    """Active helper for service fingerprinting plus legacy delegation."""

    def __init__(self, progress_cb: Optional[Callable[[str], None]] = None):
        self._progress = progress_cb or (lambda msg: None)

    def tcp_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
        max_workers: int = 50,
    ) -> Dict[str, Any]:
        """Legacy compatibility wrapper for the retired Python TCP connect scan."""
        return LegacyExtendedScanner(progress_cb=self._progress).tcp_scan(
            target,
            ports=ports,
            timeout=timeout,
            max_workers=max_workers,
        )

    def arp_scan(self, interface: str = "Ethernet", subnet: str = "192.168.1.0/24") -> Dict[str, Any]:
        """Legacy compatibility wrapper for the retired Python ARP discovery scan."""
        return LegacyExtendedScanner(progress_cb=self._progress).arp_scan(interface=interface, subnet=subnet)

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
