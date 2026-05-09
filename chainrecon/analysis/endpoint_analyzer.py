"""Endpoint extraction and attribution for ChainRecon.

Extracts all unique IP endpoints from a pcap, identifies cloud providers,
performs reverse-DNS lookups, and maps well-known ports to services.
"""

from __future__ import annotations

import collections
import socket
from typing import Any, Dict, List, Optional

from chainrecon.utils.logging_config import get_logger

logger = get_logger("endpoint")

# Cloud provider IP prefix heuristics
_CLOUD_PREFIXES: Dict[str, List[str]] = {
    "AWS": ["3.", "13.", "15.", "18.", "34.", "35.", "52.", "54.", "99.", "100.20.", "100.21."],
    "GCP": ["8.34.", "8.35.", "34.64.", "34.65.", "34.66.", "34.67.", "34.80.", "34.96.", "35."],
    "Azure": ["20.", "40.", "51.", "52."],
    "Cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.65.", "1.1.1.", "1.0.0."],
    "Akamai": ["23.", "96.", "104.", "184.", "2.16.", "2.17.", "2.18.", "2.19.", "2.20.", "2.21.", "2.22."],
    "Fastly": ["151.101.", "199.27.", "23.235."],
}

# Common port -> service name
_PORT_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 993: "IMAPS", 995: "POP3S", 1883: "MQTT", 3306: "MySQL",
    3478: "STUN", 3479: "STUN", 4840: "OPC-UA", 5222: "XMPP",
    5353: "mDNS", 5683: "CoAP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8883: "MQTT/TLS", 1900: "UPnP/SSDP", 9000: "HTTP-api", 9001: "HTTP-api",
}

# Private IP ranges (CIDR prefix)
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "169.254.", "::1", "fc", "fd",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _identify_cloud(ip: str) -> Optional[str]:
    for provider, prefixes in _CLOUD_PREFIXES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None


def _reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Best-effort reverse DNS lookup (returns None on failure)."""
    import socket
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
            ip_layer = getattr(pkt, "ip", None)
            if ip_layer is None:
                continue
            src = str(getattr(ip_layer, "src", "") or "")
            dst = str(getattr(ip_layer, "dst", "") or "")
            pkt_len = int(getattr(pkt, "length", 0) or 0)

            for ip in (src, dst):
                if not ip:
                    continue
                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "ip": ip,
                        "packet_count": 0,
                        "bytes": 0,
                        "is_private": _is_private(ip),
                        "cloud_provider": _identify_cloud(ip),
                        "hostname": None,
                        "ports": [],
                        "services": [],
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

        # Attach ports and services
        for ip, ports in port_set.items():
            if ip in ip_stats:
                ip_stats[ip]["ports"] = sorted(ports)
                ip_stats[ip]["services"] = [
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
            "risk_indicators": self._assess_risks(external),
        }

    @staticmethod
    def _assess_risks(external_endpoints: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        risks = []
        unencrypted_ports = {80, 23, 21, 1883}
        for ep in external_endpoints:
            risky = [p for p in ep.get("ports", []) if p in unencrypted_ports]
            if risky:
                services = [_PORT_SERVICES.get(p, str(p)) for p in risky]
                risks.append({
                    "severity": "medium",
                    "title": f"Unencrypted protocol to external IP {ep['ip']}",
                    "details": f"Ports used: {', '.join(map(str, risky))} ({', '.join(services)})",
                })
        return risks
