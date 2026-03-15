"""Traffic analysis helpers for ChainRecon."""

from __future__ import annotations

import collections
import ipaddress
from typing import Any, Dict, Iterable, List, Optional

try:
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover
    pyshark = None


class TrafficAnalyzer:
    """Parse packet captures into structured traffic intelligence."""

    def __init__(self, capture_factory=None):
        self.capture_factory = capture_factory or self._default_capture_factory

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        packets, capture = self._load_packets(pcap_path)
        try:
            dns_queries = self.extract_dns(packets)
            http_requests = self.extract_http(packets)
            tls_sni = self.extract_tls_sni(packets)
            protocol_stats = self.get_protocol_stats(packets)
            external_ips = self.get_external_ips(packets)
            conversations = self.get_conversations(packets)
        finally:
            if hasattr(capture, "close"):
                capture.close()

        insecure_http = sum(1 for request in http_requests if request.get("host"))
        return {
            "metadata": {
                "source": pcap_path,
                "packet_count": len(packets),
                "analyzer": self.__class__.__name__,
            },
            "findings": {
                "dns_queries": dns_queries,
                "http_requests": http_requests,
                "tls_sni": tls_sni,
                "external_ips": external_ips,
                "conversations": conversations,
            },
            "summary": {
                "protocol_stats": protocol_stats,
                "dns_query_count": len(dns_queries),
                "http_request_count": len(http_requests),
                "tls_sni_count": len(tls_sni),
                "external_ip_count": len(external_ips),
                "conversation_count": len(conversations),
            },
            "risk_indicators": [
                {
                    "severity": "medium",
                    "title": "Unencrypted HTTP traffic observed",
                    "details": f"{insecure_http} HTTP requests were captured.",
                }
                for _ in [None]
                if insecure_http
            ],
        }

    def extract_dns(self, packets: Iterable[Any]) -> List[Dict[str, Any]]:
        queries = {}
        for packet in packets:
            if not self._has_layer(packet, "DNS"):
                continue
            dns_layer = self._get_layer(packet, "dns")
            query_name = self._get_field(dns_layer, "qry_name")
            if not query_name:
                continue
            queries[query_name] = {
                "query": query_name,
                "query_type": self._get_field(dns_layer, "qry_type"),
                "src_ip": self._get_ip(packet, "ip", "src"),
                "dst_ip": self._get_ip(packet, "ip", "dst"),
            }
        return sorted(queries.values(), key=lambda item: item["query"])

    def extract_http(self, packets: Iterable[Any]) -> List[Dict[str, Any]]:
        requests = []
        for packet in packets:
            if not self._has_layer(packet, "HTTP"):
                continue
            http_layer = self._get_layer(packet, "http")
            method = self._get_field(http_layer, "request_method")
            host = self._get_field(http_layer, "host")
            uri = self._get_field(http_layer, "request_uri")
            if not any((method, host, uri)):
                continue
            requests.append(
                {
                    "method": method,
                    "host": host,
                    "uri": uri,
                    "src_ip": self._get_ip(packet, "ip", "src"),
                    "dst_ip": self._get_ip(packet, "ip", "dst"),
                }
            )
        return requests

    def extract_tls_sni(self, packets: Iterable[Any]) -> List[Dict[str, Any]]:
        sni_entries = {}
        for packet in packets:
            if not self._has_layer(packet, "TLS"):
                continue
            tls_layer = self._get_layer(packet, "tls")
            server_name = self._get_field(
                tls_layer,
                "handshake_extensions_server_name",
                "handshake_extension_server_name",
            )
            if not server_name:
                continue
            sni_entries[server_name] = {
                "server_name": server_name,
                "src_ip": self._get_ip(packet, "ip", "src"),
                "dst_ip": self._get_ip(packet, "ip", "dst"),
            }
        return sorted(sni_entries.values(), key=lambda item: item["server_name"])

    def get_protocol_stats(self, packets: Iterable[Any]) -> Dict[str, int]:
        counts = collections.Counter()
        for packet in packets:
            highest_layer = getattr(packet, "highest_layer", None)
            if highest_layer:
                counts[str(highest_layer)] += 1
        return dict(counts.most_common())

    def get_external_ips(self, packets: Iterable[Any]) -> List[str]:
        ips = set()
        for packet in packets:
            for attr in ("src", "dst"):
                ip_value = self._get_ip(packet, "ip", attr)
                if ip_value and self._is_external_ip(ip_value):
                    ips.add(ip_value)
        return sorted(ips)

    def get_conversations(self, packets: Iterable[Any]) -> List[Dict[str, Any]]:
        conversations = collections.Counter()
        for packet in packets:
            src_ip = self._get_ip(packet, "ip", "src")
            dst_ip = self._get_ip(packet, "ip", "dst")
            if not src_ip or not dst_ip:
                continue
            transport = "tcp" if self._has_layer(packet, "TCP") else "udp" if self._has_layer(packet, "UDP") else None
            src_port = self._get_port(packet, transport, "srcport") if transport else None
            dst_port = self._get_port(packet, transport, "dstport") if transport else None
            conversations[(src_ip, dst_ip, src_port, dst_port, transport)] += 1

        return [
            {
                "src_ip": key[0],
                "dst_ip": key[1],
                "src_port": key[2],
                "dst_port": key[3],
                "transport": key[4],
                "packet_count": count,
            }
            for key, count in conversations.most_common()
        ]

    def _load_packets(self, pcap_path: str):
        capture = self.capture_factory(pcap_path)
        return list(capture), capture

    def _default_capture_factory(self, pcap_path: str):
        if pyshark is None:
            raise RuntimeError("pyshark is required to analyze pcap files")
        return pyshark.FileCapture(pcap_path, only_summaries=False)

    def _has_layer(self, packet: Any, layer_name: str) -> bool:
        try:
            return layer_name in packet
        except Exception:
            return hasattr(packet, layer_name.lower())

    def _get_layer(self, packet: Any, layer_name: str) -> Any:
        return getattr(packet, layer_name, None)

    def _get_field(self, layer: Any, *field_names: str) -> Optional[str]:
        if layer is None:
            return None
        for field_name in field_names:
            if hasattr(layer, "get_field_value"):
                try:
                    value = layer.get_field_value(field_name)
                    if value not in (None, ""):
                        return str(value)
                except Exception:
                    pass
            if hasattr(layer, "get"):
                try:
                    value = layer.get(field_name, None)
                    if value not in (None, ""):
                        return str(value)
                except Exception:
                    pass
            value = getattr(layer, field_name, None)
            if value not in (None, ""):
                return str(value)
        return None

    def _get_ip(self, packet: Any, layer_name: str, field_name: str) -> Optional[str]:
        return self._get_field(self._get_layer(packet, layer_name), field_name)

    def _get_port(self, packet: Any, layer_name: Optional[str], field_name: str) -> Optional[int]:
        if not layer_name:
            return None
        value = self._get_field(self._get_layer(packet, layer_name), field_name)
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _is_external_ip(self, ip_value: str) -> bool:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError:
            return False
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        )
