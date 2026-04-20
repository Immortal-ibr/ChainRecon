"""MQTT traffic analysis module for ChainRecon.

Extracts MQTT topics, payloads, QoS levels, authentication status,
and TLS usage from packet captures — essential for IoT device analysis.
"""

from __future__ import annotations

import collections
import json
from typing import Any, Dict, Iterable, List, Optional

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

        return {
            "metadata": {"packet_count": len(packet_list), "analyzer": self.__class__.__name__},
            "findings": {
                "topics": topics,
                "payloads": payloads[:50],  # cap to avoid huge output
                "authentication": auth_status,
                "tls": tls_status,
            },
            "summary": {
                "topic_count": len(topics),
                "payload_count": len(payloads),
                "authenticated": auth_status.get("authenticated", False),
                "encrypted": tls_status.get("encrypted", False),
            },
            "risk_indicators": indicators,
        }

    # ── detection methods ────────────────────────────────────────────

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

    # ── helpers ──────────────────────────────────────────────────────

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
