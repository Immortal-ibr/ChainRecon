"""MQTT traffic analysis module for ChainRecon.

Extracts MQTT topics, payloads, QoS levels, authentication status,
and TLS usage from packet captures.  Also performs deep byte-level
parsing of MQTT control packets (CONNECT credentials, PUBLISH topics,
SUBSCRIBE filters) and attempts XOR-key detection on opaque payloads.
"""

from __future__ import annotations

import collections
import json
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils.logging_config import get_logger

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
        auth_status = self._check_authentication(packet_list)
        tls_status = self._check_tls(packet_list)
        deep_packets = self._deep_parse_raw(packet_list)
        xor_results = self._xor_key_scan(packet_list)

        indicators: List[Dict[str, str]] = []
        if not tls_status["encrypted"] and topics:
            indicators.append({
                "severity": "high",
                "title": "MQTT traffic is not encrypted",
                "details": "MQTT messages observed on port 1883 without TLS.",
            })
        if not auth_status.get("authenticated"):
            indicators.append({
                "severity": "medium",
                "title": "MQTT broker may allow anonymous access",
                "details": "No CONNECT packet with username/password observed.",
            })
        if auth_status.get("authenticated") and not tls_status.get("encrypted"):
            indicators.append({
                "severity": "critical",
                "title": "MQTT credentials sent in plaintext",
                "details": f"Username '{auth_status.get('username')}' sent over unencrypted MQTT.",
            })
        if xor_results:
            indicators.append({
                "severity": "medium",
                "title": "Possible XOR-encrypted MQTT payloads",
                "details": f"{len(xor_results)} payload(s) may use simple XOR obfuscation.",
            })

        return {
            "metadata": {"packet_count": len(packet_list), "analyzer": self.__class__.__name__},
            "findings": {
                "topics": topics,
                "payloads": payloads[:50],
                "authentication": auth_status,
                "tls": tls_status,
                "deep_parsed": deep_packets[:100],
                "xor_candidates": xor_results[:20],
            },
            "summary": {
                "topic_count": len(topics),
                "payload_count": len(payloads),
                "authenticated": auth_status.get("authenticated", False),
                "encrypted": tls_status.get("encrypted", False),
                "deep_parsed_count": len(deep_packets),
                "xor_candidate_count": len(xor_results),
            },
            "risk_indicators": indicators,
        }

    # -- detection methods --------------------------------------------

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
                payload_bytes = bytes.fromhex(str(payload_hex).replace(":", ""))
                payload_text = payload_bytes.decode("utf-8", errors="replace")
            except ValueError:
                payload_text = str(payload_hex)

            qos = getattr(mqtt, "qos", None)
            is_json = self._is_json(payload_text)
            results.append({
                "topic": topic,
                "payload_preview": payload_text[:200],
                "qos": int(qos) if qos is not None else None,
                "is_json": is_json,
            })
        return results

    def _check_authentication(self, packets) -> Dict[str, Any]:
        for pkt in packets:
            mqtt = self._get_mqtt_layer(pkt)
            if mqtt is None:
                continue
            # CONNECT message type = 1
            msg_type = getattr(mqtt, "msgtype", None) or getattr(mqtt, "hdrflags", None)
            try:
                if int(str(msg_type)) & 0xF0 == 0x10 or str(msg_type) == "1":
                    username = getattr(mqtt, "username", None) or getattr(mqtt, "user", None)
                    if username:
                        return {"authenticated": True, "username": str(username)}
                    return {"authenticated": False}
            except (ValueError, TypeError):
                continue
        return {"authenticated": None}  # no CONNECT observed

    def _check_tls(self, packets) -> Dict[str, Any]:
        has_1883 = False
        has_8883 = False
        for pkt in packets:
            tcp = getattr(pkt, "tcp", None)
            if tcp is None:
                continue
            sport = str(getattr(tcp, "srcport", ""))
            dport = str(getattr(tcp, "dstport", ""))
            if sport == "1883" or dport == "1883":
                has_1883 = True
            if sport == "8883" or dport == "8883":
                has_8883 = True

        if has_8883:
            return {"encrypted": True, "port": 8883}
        if has_1883:
            return {"encrypted": False, "port": 1883}
        return {"encrypted": None}

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
        12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
    }

    def _deep_parse_raw(self, packets) -> List[Dict[str, Any]]:
        """Parse MQTT packets from raw TCP payloads on ports 1883/8883."""
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
            if sport not in ("1883", "8883") and dport not in ("1883", "8883"):
                continue

            pkt_type = (raw[0] >> 4) & 0x0F
            name = self._PKT_NAMES.get(pkt_type, f"UNKNOWN({pkt_type})")
            info: Dict[str, Any] = {"type": name}

            if pkt_type == 1:  # CONNECT
                info.update(self._parse_connect(raw))
            elif pkt_type == 3:  # PUBLISH
                info.update(self._parse_publish(raw))
            elif pkt_type == 8:  # SUBSCRIBE
                info.update(self._parse_subscribe(raw))

            ip = getattr(pkt, "ip", None)
            info["src_ip"] = str(getattr(ip, "src", "")) if ip else None
            info["dst_ip"] = str(getattr(ip, "dst", "")) if ip else None
            results.append(info)
        return results

    @staticmethod
    def _decode_remaining_length(data: bytes, offset: int) -> Tuple[int, int]:
        """Decode MQTT variable-length encoding. Returns (value, bytes_consumed)."""
        multiplier = 1
        value = 0
        idx = offset
        while idx < len(data):
            encoded = data[idx]
            value += (encoded & 0x7F) * multiplier
            idx += 1
            if (encoded & 0x80) == 0:
                break
            multiplier *= 128
        return value, idx - offset

    def _parse_connect(self, data: bytes) -> Dict[str, Any]:
        """Extract client ID, username, password from CONNECT packet."""
        result: Dict[str, Any] = {}
        try:
            _, consumed = self._decode_remaining_length(data, 1)
            pos = 1 + consumed
            # Protocol name (skip length-prefixed string)
            if pos + 2 > len(data):
                return result
            proto_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2 + proto_len
            if pos + 4 > len(data):
                return result
            # Protocol level + connect flags + keep alive
            result["protocol_level"] = data[pos]
            flags = data[pos + 1]
            result["clean_session"] = bool(flags & 0x02)
            has_will = bool(flags & 0x04)
            has_username = bool(flags & 0x80)
            has_password = bool(flags & 0x40)
            pos += 4  # skip protocol level + flags + 2-byte keepalive

            # Client ID
            if pos + 2 <= len(data):
                cid_len = struct.unpack("!H", data[pos:pos+2])[0]
                pos += 2
                if pos + cid_len <= len(data):
                    result["client_id"] = data[pos:pos+cid_len].decode("utf-8", errors="replace")
                    pos += cid_len

            # Will topic + message (skip)
            if has_will:
                for _ in range(2):
                    if pos + 2 <= len(data):
                        slen = struct.unpack("!H", data[pos:pos+2])[0]
                        pos += 2 + slen

            if has_username and pos + 2 <= len(data):
                ulen = struct.unpack("!H", data[pos:pos+2])[0]
                pos += 2
                if pos + ulen <= len(data):
                    result["username"] = data[pos:pos+ulen].decode("utf-8", errors="replace")
                    pos += ulen

            if has_password and pos + 2 <= len(data):
                plen = struct.unpack("!H", data[pos:pos+2])[0]
                pos += 2
                if pos + plen <= len(data):
                    result["password_present"] = True
                    # Don't log the actual password, just note its length
                    result["password_length"] = plen
        except Exception:
            pass
        return result

    def _parse_publish(self, data: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        try:
            qos = (data[0] >> 1) & 0x03
            result["qos"] = qos
            _, consumed = self._decode_remaining_length(data, 1)
            pos = 1 + consumed
            if pos + 2 > len(data):
                return result
            topic_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            if pos + topic_len <= len(data):
                result["topic"] = data[pos:pos+topic_len].decode("utf-8", errors="replace")
                pos += topic_len
            if qos > 0:
                pos += 2  # packet identifier
            payload = data[pos:]
            if payload:
                result["payload_preview"] = payload[:100].decode("utf-8", errors="replace")
                result["payload_length"] = len(payload)
        except Exception:
            pass
        return result

    def _parse_subscribe(self, data: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {"filters": []}
        try:
            _, consumed = self._decode_remaining_length(data, 1)
            pos = 1 + consumed + 2  # skip packet identifier
            while pos + 2 < len(data):
                flen = struct.unpack("!H", data[pos:pos+2])[0]
                pos += 2
                if pos + flen > len(data):
                    break
                filt = data[pos:pos+flen].decode("utf-8", errors="replace")
                pos += flen
                qos = data[pos] if pos < len(data) else 0
                pos += 1
                result["filters"].append({"filter": filt, "qos": qos})
        except Exception:
            pass
        return result

    # -- XOR key detection --------------------------------------------

    _COMMON_XOR_KEYS = [0x00, 0xFF, 0xAA, 0x55, 0x5A, 0xA5, 0x01, 0x42]

    def _xor_key_scan(self, packets) -> List[Dict[str, Any]]:
        """Try common single-byte XOR keys on opaque MQTT payloads."""
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            raw = self._get_tcp_payload(pkt)
            if raw is None or len(raw) < 10:
                continue
            tcp = getattr(pkt, "tcp", None)
            if tcp is None:
                continue
            sport = str(getattr(tcp, "srcport", ""))
            dport = str(getattr(tcp, "dstport", ""))
            if sport not in ("1883", "8883") and dport not in ("1883", "8883"):
                continue

            # Only try XOR on PUBLISH payloads that look opaque
            pkt_type = (raw[0] >> 4) & 0x0F
            if pkt_type != 3:
                continue
            pub = self._parse_publish(raw)
            payload_start = raw.find(pub.get("topic", b"").encode() if isinstance(pub.get("topic"), str) else b"")
            if payload_start == -1:
                continue

            # Get just the payload portion
            try:
                _, consumed = self._decode_remaining_length(raw, 1)
                pos = 1 + consumed
                topic_len = struct.unpack("!H", raw[pos:pos+2])[0]
                pos += 2 + topic_len
                if pub.get("qos", 0) > 0:
                    pos += 2
                payload = raw[pos:]
            except Exception:
                continue

            if len(payload) < 8:
                continue

            for key in self._COMMON_XOR_KEYS:
                if key == 0:
                    continue
                decoded = bytes(b ^ key for b in payload[:64])
                try:
                    text = decoded.decode("ascii")
                    if text.isprintable() and len(text) > 4:
                        ip = getattr(pkt, "ip", None)
                        results.append({
                            "xor_key": hex(key),
                            "preview": text[:80],
                            "topic": pub.get("topic"),
                            "src_ip": str(getattr(ip, "src", "")) if ip else None,
                        })
                        break
                except (UnicodeDecodeError, ValueError):
                    continue
        return results

    @staticmethod
    def _get_tcp_payload(pkt) -> Optional[bytes]:
        for layer_name in ("data", "DATA", "tcp", "TCP"):
            layer = getattr(pkt, layer_name, None)
            if layer is None:
                continue
            for field in ("data_data", "payload"):
                raw_hex = getattr(layer, field, None)
                if raw_hex:
                    try:
                        return bytes.fromhex(str(raw_hex).replace(":", ""))
                    except ValueError:
                        continue
        return None
