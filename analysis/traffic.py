"""Traffic analysis helpers for ChainRecon."""

from __future__ import annotations

import collections
import ipaddress
import math
import struct
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

from utils.logging_config import get_logger

logger = get_logger("traffic")

try:
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover
    pyshark = None

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw as ScapyRaw  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Scapy → pyshark-style adapter
# ---------------------------------------------------------------------------

def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """Extract SNI hostname from raw TLS ClientHello bytes."""
    try:
        if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        idx = 9   # past record header (5) + handshake header (4)
        idx += 2  # ProtocolVersion
        idx += 32  # Random
        if idx >= len(payload):
            return None
        session_len = payload[idx]
        idx += 1 + session_len
        if idx + 2 > len(payload):
            return None
        cipher_len = struct.unpack(">H", payload[idx : idx + 2])[0]
        idx += 2 + cipher_len
        if idx >= len(payload):
            return None
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return None
        ext_total = struct.unpack(">H", payload[idx : idx + 2])[0]
        idx += 2
        end = idx + ext_total
        while idx + 4 <= end and idx + 4 <= len(payload):
            ext_type = struct.unpack(">H", payload[idx : idx + 2])[0]
            ext_len = struct.unpack(">H", payload[idx + 2 : idx + 4])[0]
            idx += 4
            if ext_type == 0x0000 and idx + 5 <= len(payload):
                name_len = struct.unpack(">H", payload[idx + 3 : idx + 5])[0]
                return payload[idx + 5 : idx + 5 + name_len].decode("utf-8", errors="ignore")
            idx += ext_len
    except Exception:
        pass
    return None


class ScapyPacketAdapter:
    """Wraps a Scapy packet to expose a pyshark-compatible attribute interface.

    This lets the existing TrafficAnalyzer extraction methods work unchanged
    regardless of whether packets come from pyshark or Scapy.
    """

    _HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")

    def __init__(self, scapy_pkt: Any) -> None:
        self._pkt = scapy_pkt
        self._layer_names: set = set()
        self._build()

    def _build(self) -> None:
        pkt = self._pkt
        self.length = len(pkt)

        if pkt.haslayer(IP):
            ip = pkt[IP]
            self.ip = SimpleNamespace(src=ip.src, dst=ip.dst, ttl=str(ip.ttl))
            self._layer_names.add("ip")

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            ns = SimpleNamespace(
                srcport=str(tcp.sport), dstport=str(tcp.dport), stream=None
            )
            if pkt.haslayer(ScapyRaw):
                ns.payload = pkt[ScapyRaw].load.hex()
            self.tcp = ns
            self._layer_names.add("tcp")

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            ns = SimpleNamespace(srcport=str(udp.sport), dstport=str(udp.dport))
            if pkt.haslayer(ScapyRaw):
                ns.payload = pkt[ScapyRaw].load.hex()
            self.udp = ns
            self._layer_names.add("udp")

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            qname = qtype = None
            if dns.qd is not None:
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    qtype = str(dns.qd.qtype)
                except Exception:
                    pass
            self.dns = SimpleNamespace(qry_name=qname, qry_type=qtype)
            self._layer_names.add("dns")

        if pkt.haslayer(ScapyRaw):
            raw = pkt[ScapyRaw].load

            # HTTP detection
            if any(raw.startswith(m) for m in self._HTTP_METHODS):
                try:
                    text = raw.decode("utf-8", errors="ignore")
                    lines = text.split("\r\n")
                    parts = lines[0].split(" ")
                    method = parts[0] if parts else None
                    uri = parts[1] if len(parts) > 1 else None
                    host = None
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break
                    self.http = SimpleNamespace(
                        request_method=method, host=host, request_uri=uri
                    )
                    self._layer_names.add("http")
                except Exception:
                    pass

            # TLS SNI detection
            sni = _parse_tls_sni(raw)
            if sni:
                self.tls = SimpleNamespace(handshake_extensions_server_name=sni)
                self._layer_names.add("tls")

            # Raw data layer (for entropy / credential scan)
            self.data = SimpleNamespace(data_data=raw.hex())
            self._layer_names.add("data")

        # Determine highest_layer label
        if "dns" in self._layer_names:
            self.highest_layer = "DNS"
        elif "http" in self._layer_names:
            self.highest_layer = "HTTP"
        elif "tls" in self._layer_names:
            self.highest_layer = "TLS"
        elif "tcp" in self._layer_names:
            self.highest_layer = "TCP"
        elif "udp" in self._layer_names:
            self.highest_layer = "UDP"
        elif "ip" in self._layer_names:
            self.highest_layer = "IP"
        else:
            self.highest_layer = type(pkt.lastlayer()).__name__.upper()

    def __contains__(self, item: str) -> bool:
        return item.lower() in self._layer_names

    def __len__(self) -> int:
        return self.length


class TrafficAnalyzer:
    """Parse packet captures into structured traffic intelligence."""

    def __init__(self, capture_factory=None):
        self.capture_factory = capture_factory or self._default_capture_factory

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        logger.info("Analyzing pcap: %s", pcap_path)
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
        packets = list(capture)
        # Ensure a close-able handle is always returned
        if not hasattr(capture, "close"):
            capture = type("_NullCapture", (), {"close": lambda self=None: None, "closed": False})()
        return packets, capture

    # ── Entropy & plaintext helpers ──────────────────────────────────

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy of *data* in bits per byte (0-8)."""
        if not data:
            return 0.0
        freq = collections.Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def detect_encrypted_payloads(
        self, packets: Iterable[Any], threshold: float = 7.2
    ) -> List[Dict[str, Any]]:
        """Return packets whose payload entropy exceeds *threshold*."""
        results: List[Dict[str, Any]] = []
        for packet in packets:
            raw = self._get_raw_payload(packet)
            if raw is None or len(raw) < 16:
                continue
            ent = self.shannon_entropy(raw)
            if ent >= threshold:
                results.append({
                    "src_ip": self._get_ip(packet, "ip", "src"),
                    "dst_ip": self._get_ip(packet, "ip", "dst"),
                    "length": len(raw),
                    "entropy": round(ent, 4),
                })
        return results

    def detect_plaintext_credentials(
        self, packets: Iterable[Any]
    ) -> List[Dict[str, Any]]:
        """Scan payloads for common plaintext credential patterns."""
        import re

        patterns = [
            ("password", re.compile(rb"(?i)password[=:]\s*\S+")),
            ("auth_token", re.compile(rb"(?i)(auth|token|bearer)[=:\s]+\S{8,}")),
            ("basic_auth", re.compile(rb"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]+")),
        ]
        findings: List[Dict[str, Any]] = []
        for packet in packets:
            raw = self._get_raw_payload(packet)
            if raw is None or len(raw) < 8:
                continue
            for name, regex in patterns:
                if regex.search(raw):
                    findings.append({
                        "type": name,
                        "src_ip": self._get_ip(packet, "ip", "src"),
                        "dst_ip": self._get_ip(packet, "ip", "dst"),
                        "length": len(raw),
                    })
                    break  # one match per packet is enough
        return findings

    def _get_raw_payload(self, packet: Any) -> Optional[bytes]:
        """Best-effort extraction of the raw payload bytes from a packet."""
        for layer_name in ("DATA", "data", "TCP", "tcp", "UDP", "udp"):
            layer = self._get_layer(packet, layer_name)
            if layer is None:
                continue
            for field in ("data_data", "payload", "data"):
                raw_hex = self._get_field(layer, field)
                if raw_hex:
                    try:
                        return bytes.fromhex(raw_hex.replace(":", ""))
                    except ValueError:
                        continue
        return None

    def _default_capture_factory(self, pcap_path: str):
        if _SCAPY_AVAILABLE:
            raw_packets = rdpcap(pcap_path)
            return [ScapyPacketAdapter(p) for p in raw_packets]
        if pyshark is not None:
            return pyshark.FileCapture(pcap_path, only_summaries=False)
        raise RuntimeError(
            "Neither scapy nor pyshark is installed. "
            "Install scapy: pip install scapy"
        )

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
