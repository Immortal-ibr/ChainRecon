"""Traffic analysis helpers for ChainRecon."""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import math
import shutil
import struct
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

from chainrecon.utils.logging_config import get_logger

logger = get_logger("traffic")

try:
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover
    pyshark = None

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, Raw as ScapyRaw  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Scapy -> pyshark-style adapter
# ---------------------------------------------------------------------------

_MAX_BATCH_PACKETS = 10_000


class PacketBatch(list):
    """Legacy packet-list adapter with an explicit coverage limit."""

    truncated: bool = False


class _ScapyCapture:
    def __init__(self, path: str):
        self.reader = PcapReader(path)

    def __iter__(self):
        return (ScapyPacketAdapter(packet) for packet in self.reader)

    def close(self) -> None:
        self.reader.close()


class _PysharkCapture:
    """Own a dedicated event loop for PyShark on Python 3.13 and worker threads."""

    def __init__(self, path: str, **kwargs: Any):
        self.loop = asyncio.new_event_loop()
        try:
            self.capture = pyshark.FileCapture(path, eventloop=self.loop, **kwargs)
        except BaseException:
            self.loop.close()
            raise

    def __iter__(self):
        return iter(self.capture)

    def close(self) -> None:
        try:
            self.capture.close()
        finally:
            self.loop.close()

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


def _parse_mqtt(payload: bytes) -> dict[str, Any] | None:
    """Decode a complete MQTT control frame, never infer MQTT from a port alone."""
    if len(payload) < 2:
        return None
    message_type = payload[0] >> 4
    if message_type not in {1, 2, 3, 8, 9, 10, 11, 12, 13, 14}:
        return None
    length = 0
    multiplier = 1
    offset = 1
    for _ in range(4):
        if offset >= len(payload):
            return None
        byte = payload[offset]
        offset += 1
        length += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128
    else:
        return None
    if offset + length > len(payload):
        return None
    body = payload[offset:offset + length]
    if message_type == 1:
        if len(body) < 8:
            return None
        name_length = int.from_bytes(body[:2], "big")
        if body[2:2 + name_length] not in {b"MQTT", b"MQIsdp"}:
            return None
    if message_type == 3:
        if len(body) < 2:
            return None
        name_length = int.from_bytes(body[:2], "big")
        if not name_length or 2 + name_length > len(body):
            return None
        try:
            topic = body[2:2 + name_length].decode("utf-8")
        except UnicodeDecodeError:
            return None
        return {"msgtype": str(message_type), "topic": topic}
    if message_type == 2 and (len(body) != 2 or body[0] > 1 or body[1] > 5):
        return None
    if message_type in {8, 10} and (payload[0] & 0x0F != 2 or len(body) < 5):
        return None
    if message_type in {12, 13, 14} and body:
        return None
    if message_type in {9, 11} and len(body) < 3:
        return None
    return {"msgtype": str(message_type), "topic": None}


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
        if pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            self.ipv6 = SimpleNamespace(src=ip6.src, dst=ip6.dst)
            self._layer_names.add("ipv6")

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
                    question = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
                    qname = question.qname.decode("utf-8", errors="ignore").rstrip(".")
                    qtype = str(question.qtype)
                except (AttributeError, IndexError, TypeError, ValueError):
                    pass
            self.dns = SimpleNamespace(qry_name=qname, qry_type=qtype)
            answers = []
            try:
                for index in range(int(dns.ancount or 0)):
                    record = dns.an[index]
                    if int(record.type) in (1, 28):
                        answers.append({"name": bytes(record.rrname).decode("utf-8", errors="replace").rstrip("."), "address": str(record.rdata)})
            except (AttributeError, IndexError, TypeError, ValueError):
                pass
            self.dns.answers = answers
            self._layer_names.add("dns")

        if pkt.haslayer(ScapyRaw):
            raw = pkt[ScapyRaw].load

            # STUN has a fixed magic cookie and a four-byte-aligned body length.
            if ("udp" in self._layer_names and len(raw) >= 20 and raw[0] & 0xC0 == 0
                    and raw[4:8] == b"\x21\x12\xa4\x42"
                    and int.from_bytes(raw[2:4], "big") % 4 == 0
                    and 20 + int.from_bytes(raw[2:4], "big") <= len(raw)):
                self.stun = SimpleNamespace(message_type=str(int.from_bytes(raw[:2], "big")))
                self._layer_names.add("stun")

            if "tcp" in self._layer_names and 1883 in {int(self.tcp.srcport), int(self.tcp.dstport)}:
                mqtt = _parse_mqtt(raw)
                if mqtt:
                    self.mqtt = SimpleNamespace(**mqtt)
                    self._layer_names.add("mqtt")

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
        elif "mqtt" in self._layer_names:
            self.highest_layer = "MQTT"
        elif "http" in self._layer_names:
            self.highest_layer = "HTTP"
        elif "tls" in self._layer_names:
            self.highest_layer = "TLS"
        elif "stun" in self._layer_names:
            self.highest_layer = "STUN"
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
        self._injected_capture_factory = capture_factory is not None

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        logger.info("Analyzing pcap: %s", pcap_path)
        if not self._injected_capture_factory:
            return self._analyze_streaming(pcap_path)
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
                "capture_truncated": packets.truncated,
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
                "result_truncated": packets.truncated,
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

    def _analyze_streaming(self, pcap_path: str) -> Dict[str, Any]:
        """Single-pass analysis with bounded result collections and parser state."""
        from pathlib import Path

        if not Path(pcap_path).is_file():
            raise FileNotFoundError(pcap_path)
        tshark = shutil.which("tshark")
        capture = None
        if pyshark is not None and tshark:
            capture = _PysharkCapture(pcap_path, keep_packets=False, tshark_path=tshark)
            packets = iter(capture)
            backend = "tshark"
        elif _SCAPY_AVAILABLE:
            capture = PcapReader(pcap_path)
            packets = (ScapyPacketAdapter(packet) for packet in capture)
            backend = "scapy"
        else:
            raise RuntimeError("Install Tshark/PyShark or Scapy to analyze packet captures")
        protocols: collections.Counter[str] = collections.Counter()
        conversations: collections.Counter[tuple[Any, ...]] = collections.Counter()
        dns_queries: dict[str, dict[str, Any]] = {}
        dns_answers: dict[tuple[str, str], dict[str, str]] = {}
        tls_sni: dict[str, dict[str, Any]] = {}
        http_requests: list[dict[str, Any]] = []
        mqtt_events: list[dict[str, Any]] = []
        media_events: list[dict[str, Any]] = []
        external_ips: set[str] = set()
        packet_count = 0
        truncated = False
        try:
            for packet in packets:
                packet_count += 1
                layer = str(getattr(packet, "highest_layer", "UNKNOWN"))
                protocols[layer] += 1
                src = self._get_ip(packet, "ip", "src") or self._get_ip(packet, "ipv6", "src")
                dst = self._get_ip(packet, "ip", "dst") or self._get_ip(packet, "ipv6", "dst")
                for address in (src, dst):
                    if address and self._is_external_ip(address):
                        if address in external_ips or len(external_ips) < 50_000:
                            external_ips.add(address)
                        else:
                            truncated = True
                transport = "tcp" if self._has_layer(packet, "TCP") else "udp" if self._has_layer(packet, "UDP") else None
                src_port = self._get_port(packet, transport, "srcport") if transport else None
                dst_port = self._get_port(packet, transport, "dstport") if transport else None
                if src and dst:
                    key = (src, dst, src_port, dst_port, transport)
                    if key in conversations or len(conversations) < 50_000:
                        conversations[key] += 1
                    else:
                        truncated = True
                if self._has_layer(packet, "DNS"):
                    dns = self._get_layer(packet, "dns")
                    name = self._get_field(dns, "qry_name")
                    if name:
                        if name in dns_queries or len(dns_queries) < 10_000:
                            dns_queries[name] = {"query": name, "query_type": self._get_field(dns, "qry_type"), "src_ip": src, "dst_ip": dst}
                        else:
                            truncated = True
                    answers = getattr(dns, "answers", [])
                    if not answers:
                        answer_name = self._get_field(dns, "resp_name")
                        address = self._get_field(dns, "a", "aaaa")
                        answers = [{"name": answer_name or name, "address": address}] if address else []
                    for answer in answers:
                        key = (str(answer.get("name") or ""), str(answer.get("address") or ""))
                        if key in dns_answers or len(dns_answers) < 10_000:
                            dns_answers[key] = {"name": key[0], "address": key[1]}
                        else:
                            truncated = True
                if self._has_layer(packet, "TLS"):
                    tls = self._get_layer(packet, "tls")
                    name = self._get_field(tls, "handshake_extensions_server_name", "handshake_extension_server_name")
                    if name:
                        if name in tls_sni or len(tls_sni) < 10_000:
                            tls_sni[name] = {"server_name": name, "src_ip": src, "dst_ip": dst}
                        else:
                            truncated = True
                if self._has_layer(packet, "HTTP"):
                    http = self._get_layer(packet, "http")
                    method = self._get_field(http, "request_method")
                    if method:
                        if len(http_requests) < 10_000:
                            http_requests.append({"method": method, "host": self._get_field(http, "host"), "uri": self._get_field(http, "request_uri"), "src_ip": src, "dst_ip": dst})
                        else:
                            truncated = True
                if self._has_layer(packet, "MQTT"):
                    if len(mqtt_events) < 10_000:
                        mqtt = self._get_layer(packet, "mqtt")
                        mqtt_events.append({"type": self._get_field(mqtt, "msgtype"), "topic": self._get_field(mqtt, "topic"), "src_ip": src, "dst_ip": dst})
                    else:
                        truncated = True
                for media_protocol in ("STUN", "TURN", "RTP", "RTCP", "SRTP", "DTLS"):
                    if self._has_layer(packet, media_protocol):
                        if len(media_events) < 10_000:
                            media_events.append({"protocol": media_protocol, "packet_number": packet_count, "src_ip": src, "dst_ip": dst, "src_port": src_port, "dst_port": dst_port})
                        else:
                            truncated = True
                        break
        finally:
            if capture is not None:
                capture.close()
        return {
            "metadata": {"source": pcap_path, "packet_count": packet_count, "analyzer": self.__class__.__name__, "backend": backend, "streaming": True},
            "findings": {
                "dns_queries": sorted(dns_queries.values(), key=lambda item: item["query"]),
                "dns_answers": sorted(dns_answers.values(), key=lambda item: (item["name"], item["address"])),
                "http_requests": http_requests,
                "tls_sni": sorted(tls_sni.values(), key=lambda item: item["server_name"]),
                "external_ips": sorted(external_ips),
                "conversations": [{"src_ip": key[0], "dst_ip": key[1], "src_port": key[2], "dst_port": key[3], "transport": key[4], "packet_count": count} for key, count in conversations.most_common()],
                "mqtt_events": mqtt_events,
                "media_events": media_events,
            },
            "summary": {"protocol_stats": dict(protocols), "dns_query_count": len(dns_queries), "dns_answer_count": len(dns_answers), "http_request_count": len(http_requests), "tls_sni_count": len(tls_sni), "external_ip_count": len(external_ips), "conversation_count": len(conversations), "mqtt_event_count": len(mqtt_events), "media_event_count": len(media_events), "result_truncated": truncated},
            "risk_indicators": [],
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
        packets = PacketBatch()
        try:
            for packet in capture:
                if len(packets) == _MAX_BATCH_PACKETS:
                    packets.truncated = True
                    break
                packets.append(packet)
        except BaseException:
            if hasattr(capture, "close"):
                capture.close()
            raise
        # Ensure a close-able handle is always returned
        if not hasattr(capture, "close"):
            capture = type("_NullCapture", (), {"close": lambda self=None: None, "closed": False})()
        return packets, capture

    # -- Entropy & plaintext helpers ----------------------------------

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
            return _ScapyCapture(pcap_path)
        if pyshark is not None:
            return _PysharkCapture(pcap_path, only_summaries=False, keep_packets=False)
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
