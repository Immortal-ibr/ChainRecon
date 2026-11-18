"""MQTT traffic analysis module for ChainRecon.

Summarizes decoded MQTT packets and complete raw control frames from the
bounded packet batch used by legacy workflows. Port numbers, printable
payloads, and incomplete captures do not establish security properties.
"""

from __future__ import annotations

import collections
import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from chainrecon.utils.logging_config import get_logger
from chainrecon.utils.redaction import redact_text

logger = get_logger("mqtt")


class MQTTAnalyzer:
    """Identify and parse MQTT traffic from a packet list."""

    # Standard MQTT ports
    MQTT_PORTS = {1883, 8883}

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Scanning %d packets for MQTT traffic", len(packet_list))

        topics = self._extract_topics(packet_list)
        payloads = self._extract_payloads(packet_list)
        deep_packets = self._deep_parse_raw(packet_list)
        auth_status = self._check_authentication(packet_list, deep_packets)
        tls_status = self._check_tls(packet_list)
        indicators: List[Dict[str, str]] = []
        if any(item.get("type") == "CONNECT" and item.get("password_present")
               and item.get("plaintext_segment") for item in deep_packets):
            indicators.append({
                "severity": "medium",
                "title": "MQTT password field on captured plaintext segment",
                "details": "A complete CONNECT frame has its password flag set in a segment without a TLS layer. Review the capture and flow.",
            })

        return {
            "metadata": {
                "packet_count": len(packet_list),
                "analyzer": self.__class__.__name__,
                "coverage_limit": "Packet-level parsing does not reassemble TCP streams or prove broker policy.",
            },
            "findings": {
                "topics": topics,
                "payloads": payloads[:50],
                "authentication": auth_status,
                "tls": tls_status,
                "deep_parsed": deep_packets[:100],
            },
            "summary": {
                "topic_count": len(topics),
                "payload_count": len(payloads),
                "authenticated": None,
                "encrypted": None,
                "deep_parsed_count": len(deep_packets),
            },
            "risk_indicators": indicators,
        }

    # -- detection methods --------------------------------------------

    @staticmethod
    def _has_layer(packet: Any, layer_name: str) -> bool:
        try:
            return layer_name in packet
        except (TypeError, AttributeError):
            return hasattr(packet, layer_name.lower())

    def _extract_topics(self, packets) -> List[Dict[str, Any]]:
        topic_counts: Dict[str, int] = collections.Counter()
        for pkt in packets:
            mqtt = self._get_mqtt_layer(pkt)
            if mqtt is None:
                continue
            topic = getattr(mqtt, "topic", None)
            if topic:
                topic_counts[str(topic)] += 1
        return [{"topic": t, "count": c} for t, c in topic_counts.most_common()]

    def _extract_payloads(self, packets) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            mqtt = self._get_mqtt_layer(pkt)
            if mqtt is None:
                continue
            topic = str(getattr(mqtt, "topic", "")) or None
            payload_hex = getattr(mqtt, "msg", None) or getattr(mqtt, "payload", None)
            if not payload_hex:
                continue
            try:
                payload_bytes = payload_hex if isinstance(payload_hex, bytes) else bytes.fromhex(str(payload_hex).replace(":", ""))
            except ValueError:
                payload_bytes = str(payload_hex).encode("utf-8", errors="replace")
            payload_text = payload_bytes.decode("utf-8", errors="replace")

            qos = getattr(mqtt, "qos", None)
            is_json = self._is_json(payload_text)
            try:
                qos_value = int(str(qos)) if qos is not None else None
            except ValueError:
                qos_value = None
            results.append({
                "topic": redact_text(topic) if topic else None,
                "payload_length": len(payload_bytes),
                "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "qos": qos_value,
                "is_json": is_json,
            })
        return results

    def _check_authentication(self, packets, deep_packets) -> Dict[str, Any]:
        connects = [item for item in deep_packets if item.get("type") == "CONNECT"]
        for pkt in packets:
            mqtt = self._get_mqtt_layer(pkt)
            if mqtt is None:
                continue
            # CONNECT message type = 1
            msg_type = getattr(mqtt, "msgtype", None) or getattr(mqtt, "hdrflags", None)
            try:
                if int(str(msg_type)) & 0xF0 == 0x10 or str(msg_type) == "1":
                    username = getattr(mqtt, "username", None) or getattr(mqtt, "user", None)
                    connects.append({"username_present": bool(username)})
            except (ValueError, TypeError):
                continue
        return {
            "authenticated": None,
            "connect_observed": bool(connects),
            "username_present": any(item.get("username_present") for item in connects) if connects else None,
            "reason": "A CONNECT packet does not prove the broker authentication policy.",
        }

    def _check_tls(self, packets) -> Dict[str, Any]:
        decoded_plaintext = False
        observed_tls = False
        has_8883 = False
        for pkt in packets:
            tcp = getattr(pkt, "tcp", None)
            if tcp is None:
                continue
            sport = str(getattr(tcp, "srcport", ""))
            dport = str(getattr(tcp, "dstport", ""))
            if self._get_mqtt_layer(pkt) is not None and not self._has_layer(pkt, "TLS"):
                decoded_plaintext = True
            if sport == "8883" or dport == "8883":
                has_8883 = True
                if self._has_layer(pkt, "TLS"):
                    observed_tls = True

        return {
            "encrypted": None,
            "plaintext_mqtt_observed": decoded_plaintext,
            "tls_on_port_8883_observed": observed_tls,
            "port_8883_observed": has_8883,
            "reason": "TLS on a port does not establish encryption for every MQTT flow.",
        }

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _get_mqtt_layer(pkt) -> Any:
        try:
            if "MQTT" in pkt:
                return getattr(pkt, "mqtt", None)
        except Exception:
            pass
        return getattr(pkt, "mqtt", None)

    @staticmethod
    def _is_json(text: str) -> bool:
        text = text.strip()
        if not text or text[0] not in ("{", "["):
            return False
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    # -- deep byte-level MQTT parsing ---------------------------------

    # MQTT control packet types (upper 4 bits of byte 0)
    _PKT_NAMES = {
        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
        5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
        9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
        12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH",
    }

    def _deep_parse_raw(self, packets) -> List[Dict[str, Any]]:
        """Parse complete MQTT frames; TCP reassembly belongs to the decoder."""
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            raw = self._get_tcp_payload(pkt)
            if raw is None or len(raw) < 2:
                continue
            tcp = getattr(pkt, "tcp", None)
            if tcp is None:
                continue
            sport = str(getattr(tcp, "srcport", ""))
            dport = str(getattr(tcp, "dstport", ""))
            if sport != "1883" and dport != "1883" and self._get_mqtt_layer(pkt) is None:
                continue
            try:
                pkt_type, body, end = self._frame_body(raw)
                info: Dict[str, Any] = {
                    "type": self._PKT_NAMES[pkt_type],
                    "frame_length": end,
                    "trailing_bytes_unparsed": len(raw) - end,
                    "plaintext_segment": not self._has_layer(pkt, "TLS"),
                }
                if pkt_type == 1:
                    info.update(self._parse_connect(body))
                elif pkt_type == 3:
                    info.update(self._parse_publish(raw[0], body))
            except (ValueError, UnicodeDecodeError):
                continue
            ip = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
            info["src_ip"] = str(getattr(ip, "src", "")) if ip else None
            info["dst_ip"] = str(getattr(ip, "dst", "")) if ip else None
            results.append(info)
        return results

    @staticmethod
    def _decode_remaining_length(data: bytes, offset: int) -> Tuple[int, int]:
        """Decode MQTT variable-length encoding. Returns (value, bytes_consumed)."""
        value = 0
        multiplier = 1
        for count in range(4):
            idx = offset + count
            if idx >= len(data):
                raise ValueError("truncated MQTT remaining length")
            encoded = data[idx]
            value += (encoded & 0x7F) * multiplier
            if (encoded & 0x80) == 0:
                return value, count + 1
            multiplier *= 128
        raise ValueError("MQTT remaining length exceeds four bytes")

    @classmethod
    def _frame_body(cls, data: bytes) -> Tuple[int, bytes, int]:
        pkt_type = data[0] >> 4
        flags = data[0] & 0x0F
        if pkt_type not in cls._PKT_NAMES:
            raise ValueError("unknown MQTT control type")
        if (pkt_type in {6, 8, 10} and flags != 2) or (pkt_type not in {3, 6, 8, 10} and flags != 0):
            raise ValueError("invalid MQTT fixed-header flags")
        if pkt_type == 3 and ((flags >> 1) & 3) == 3:
            raise ValueError("invalid MQTT PUBLISH QoS")
        length, consumed = cls._decode_remaining_length(data, 1)
        end = 1 + consumed + length
        if end > len(data):
            raise ValueError("truncated MQTT frame")
        body = data[1 + consumed:end]
        if pkt_type == 2 and len(body) < 2:
            raise ValueError("short MQTT CONNACK")
        if pkt_type in {4, 5, 6, 7, 9, 11} and len(body) < 2:
            raise ValueError("short MQTT acknowledgment")
        if pkt_type in {8, 10} and len(body) < 5:
            raise ValueError("short MQTT subscribe frame")
        if pkt_type in {12, 13} and body:
            raise ValueError("MQTT ping frame has a body")
        return pkt_type, body, end

    @staticmethod
    def _read_field(body: bytes, offset: int) -> Tuple[bytes, int]:
        if offset + 2 > len(body):
            raise ValueError("missing MQTT field length")
        length = int.from_bytes(body[offset:offset + 2], "big")
        end = offset + 2 + length
        if end > len(body):
            raise ValueError("truncated MQTT field")
        return body[offset + 2:end], end

    @classmethod
    def _parse_connect(cls, body: bytes) -> Dict[str, Any]:
        protocol, pos = cls._read_field(body, 0)
        if protocol not in {b"MQTT", b"MQIsdp"} or pos + 4 > len(body):
            raise ValueError("invalid MQTT CONNECT header")
        level = body[pos]
        if level not in {3, 4, 5}:
            raise ValueError("unsupported MQTT CONNECT level")
        flags = body[pos + 1]
        will = bool(flags & 4)
        if flags & 1 or (not will and flags & 0x38) or ((flags >> 3) & 3) == 3:
            raise ValueError("reserved MQTT CONNECT flag set")
        pos += 4
        if level == 5:
            property_length, consumed = cls._decode_remaining_length(body, pos)
            pos += consumed + property_length
            if pos > len(body):
                raise ValueError("truncated MQTT CONNECT properties")
        _, pos = cls._read_field(body, pos)  # client ID, never returned
        if will:
            if level == 5:
                property_length, consumed = cls._decode_remaining_length(body, pos)
                pos += consumed + property_length
                if pos > len(body):
                    raise ValueError("truncated MQTT will properties")
            _, pos = cls._read_field(body, pos)
            _, pos = cls._read_field(body, pos)
        if flags & 0x80:
            _, pos = cls._read_field(body, pos)
        if flags & 0x40:
            _, pos = cls._read_field(body, pos)
        if pos != len(body):
            raise ValueError("unexpected trailing MQTT CONNECT bytes")
        return {
            "protocol_level": level,
            "clean_start": bool(flags & 2),
            "username_present": bool(flags & 0x80),
            "password_present": bool(flags & 0x40),
        }

    @classmethod
    def _parse_publish(cls, header: int, body: bytes) -> Dict[str, Any]:
        topic, pos = cls._read_field(body, 0)
        if not topic:
            raise ValueError("empty MQTT PUBLISH topic")
        qos = (header >> 1) & 3
        if qos:
            if pos + 2 > len(body):
                raise ValueError("missing MQTT packet identifier")
            pos += 2
        payload = body[pos:]
        return {
            "topic": redact_text(topic.decode("utf-8")),
            "qos": qos,
            "payload_length": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }

    @staticmethod
    def _get_tcp_payload(pkt) -> Optional[bytes]:
        for layer_name in ("data", "DATA", "tcp", "TCP"):
            layer = getattr(pkt, layer_name, None)
            if layer is None:
                continue
            for field in ("data_data", "payload"):
                raw_hex = getattr(layer, field, None)
                if raw_hex:
                    if isinstance(raw_hex, bytes):
                        return raw_hex
                    try:
                        return bytes.fromhex(str(raw_hex).replace(":", ""))
                    except ValueError:
                        continue
        return None
