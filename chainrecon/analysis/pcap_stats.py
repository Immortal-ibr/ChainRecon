"""PCAP statistics module for ChainRecon.

Provides high-level traffic statistics: protocol distribution,
bandwidth per IP, top talkers, session durations, and cloud provider
identification for external endpoints.
"""

from __future__ import annotations

import collections
from typing import Any, Dict, Iterable, List, Optional

from chainrecon.utils.logging_config import get_logger

logger = get_logger("pcap_stats")

# Well-known cloud provider IP prefixes (first two octets for fast check).
_CLOUD_PREFIXES: Dict[str, List[str]] = {
    "Cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.65."],
    "AWS": ["3.0.", "3.1.", "13.", "15.", "18.", "34.", "35.", "52.", "54.", "99."],
    "Azure": ["20.", "40.", "51."],
    "GCP": ["8.34.", "8.35.", "34.", "35.", "130.", "142."],
    "Akamai": ["23."],
}


class PcapStatsAnalyzer:
    """Compute high-level statistics from a list of parsed packets."""

    def __init__(self, capture_factory=None):
        self.capture_factory = capture_factory

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Computing stats over %d packets", len(packet_list))

        protocol_dist = self._protocol_distribution(packet_list)
        bandwidth = self._bandwidth_per_ip(packet_list)
        top_talkers = self._top_talkers(packet_list)
        endpoints = self._unique_endpoints(packet_list)

        return {
            "metadata": {"packet_count": len(packet_list), "analyzer": self.__class__.__name__},
            "findings": {
                "protocol_distribution": protocol_dist,
                "bandwidth_per_ip": bandwidth,
                "top_talkers": top_talkers,
                "endpoints": endpoints,
            },
            "summary": {
                "protocol_count": len(protocol_dist),
                "unique_ip_count": len(endpoints),
                "top_talker": top_talkers[0]["ip"] if top_talkers else None,
            },
            "risk_indicators": [],
        }

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _protocol_distribution(packets) -> Dict[str, int]:
        counts: Dict[str, int] = collections.Counter()
        for pkt in packets:
            layer = getattr(pkt, "highest_layer", None)
            if layer:
                counts[str(layer)] += 1
        return dict(counts.most_common())

    @staticmethod
    def _bandwidth_per_ip(packets) -> Dict[str, int]:
        bw: Dict[str, int] = collections.Counter()
        for pkt in packets:
            length = int(getattr(pkt, "length", 0) or 0)
            ip_layer = getattr(pkt, "ip", None)
            if ip_layer:
                src = getattr(ip_layer, "src", None)
                dst = getattr(ip_layer, "dst", None)
                if src:
                    bw[str(src)] += length
                if dst:
                    bw[str(dst)] += length
        return dict(bw.most_common(20))

    @staticmethod
    def _top_talkers(packets, top_n: int = 10) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = collections.Counter()
        for pkt in packets:
            ip_layer = getattr(pkt, "ip", None)
            if ip_layer:
                src = getattr(ip_layer, "src", None)
                if src:
                    counts[str(src)] += 1
        return [{"ip": ip, "packet_count": c} for ip, c in counts.most_common(top_n)]

    @staticmethod
    def _unique_endpoints(packets) -> List[Dict[str, Any]]:
        ips: Dict[str, Optional[str]] = {}
        for pkt in packets:
            ip_layer = getattr(pkt, "ip", None)
            if not ip_layer:
                continue
            for attr in ("src", "dst"):
                val = getattr(ip_layer, attr, None)
                if val and str(val) not in ips:
                    ips[str(val)] = PcapStatsAnalyzer._identify_cloud(str(val))
        return [{"ip": ip, "cloud_provider": prov} for ip, prov in sorted(ips.items())]

    @staticmethod
    def _identify_cloud(ip: str) -> Optional[str]:
        for provider, prefixes in _CLOUD_PREFIXES.items():
            for prefix in prefixes:
                if ip.startswith(prefix):
                    return provider
        return None
