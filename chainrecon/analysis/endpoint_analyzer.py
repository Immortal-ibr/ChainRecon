"""Endpoint inventory from observed packet addresses and transport ports."""

from __future__ import annotations

import collections
import ipaddress
import socket
from typing import Any, Dict, List, Optional

from chainrecon.utils.logging_config import get_logger

logger = get_logger("endpoint")

# Common port -> service hint; the packet payload may use another protocol.
_PORT_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 993: "IMAPS", 995: "POP3S", 1883: "MQTT", 3306: "MySQL",
    3478: "STUN", 3479: "STUN", 4840: "OPC-UA", 5222: "XMPP",
    5353: "mDNS", 5683: "CoAP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8883: "MQTT/TLS", 1900: "UPnP/SSDP", 9000: "HTTP-api", 9001: "HTTP-api",
}

def _is_private(ip: str) -> bool:
    """Compatibility field: true for every address that is not global."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def _identify_cloud(ip: str) -> Optional[str]:
    """Cloud ownership needs an attributed, dated registry; prefixes are insufficient."""
    return None


def _reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Best-effort reverse DNS lookup (returns None on failure)."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


class EndpointAnalyzer:
    """Extract and attribute all network endpoints from a packet list."""

    def __init__(self, resolve_dns: bool = False):
        """
        Parameters
        ----------
        resolve_dns:
            When True, perform reverse-DNS lookups for external IPs.
            Disabled by default to keep analysis fast.
        """
        self.resolve_dns = resolve_dns

    def analyze(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyse a list of (adapter/pyshark-style) packets."""
        logger.info("Extracting endpoints from %d packets", len(packets))

        # Collect per-IP stats
        ip_stats: Dict[str, Dict[str, Any]] = {}
        port_set: Dict[str, set] = collections.defaultdict(set)

        for pkt in packets:
            ip_layer = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
            if ip_layer is None:
                continue
            src = str(getattr(ip_layer, "src", "") or "")
            dst = str(getattr(ip_layer, "dst", "") or "")
            pkt_len = int(getattr(pkt, "length", 0) or 0)

            for ip in (src, dst):
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "ip": ip,
                        "packet_count": 0,
                        "bytes": 0,
                        "is_private": _is_private(ip),
                        "is_global": not _is_private(ip),
                        "cloud_provider": _identify_cloud(ip),
                        "hostname": None,
                        "ports": [],
                        "services": [],
                        "service_hints": [],
                    }
                ip_stats[ip]["packet_count"] += 1
                ip_stats[ip]["bytes"] += pkt_len

            # Collect ports
            for layer_name in ("tcp", "udp"):
                layer = getattr(pkt, layer_name, None)
                if layer is None:
                    continue
                for port_attr in ("dstport", "srcport"):
                    port_val = getattr(layer, port_attr, None)
                    if port_val:
                        try:
                            port_set[dst if port_attr == "dstport" else src].add(int(port_val))
                        except (TypeError, ValueError):
                            pass

        # A port name is a hint, not protocol identification.
        for ip, ports in port_set.items():
            if ip in ip_stats:
                ip_stats[ip]["ports"] = sorted(ports)
                ip_stats[ip]["service_hints"] = [
                    _PORT_SERVICES[p] for p in sorted(ports) if p in _PORT_SERVICES
                ]

        # Optional reverse-DNS for external IPs
        if self.resolve_dns:
            for ip, info in ip_stats.items():
                if not info["is_private"] and info["hostname"] is None:
                    info["hostname"] = _reverse_dns(ip)

        # Sort by packet count desc
        endpoints = sorted(ip_stats.values(), key=lambda x: x["packet_count"], reverse=True)
        external = [e for e in endpoints if not e["is_private"]]
        internal = [e for e in endpoints if e["is_private"]]

        cloud_summary: Dict[str, int] = collections.Counter(
            e["cloud_provider"] for e in external if e["cloud_provider"]
        )

        return {
            "metadata": {
                "packet_count": len(packets),
                "analyzer": self.__class__.__name__,
                "total_endpoints": len(endpoints),
                "external_endpoints": len(external),
                "internal_endpoints": len(internal),
            },
            "findings": {
                "endpoints": endpoints,
                "external_endpoints": external,
                "internal_endpoints": internal,
                "cloud_summary": dict(cloud_summary),
            },
            "summary": {
                "total_unique_ips": len(endpoints),
                "external_ips": len(external),
                "cloud_providers": list(cloud_summary.keys()),
                "top_external": external[0]["ip"] if external else None,
            },
            "risk_indicators": [],
        }
