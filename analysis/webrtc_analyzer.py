"""WebRTC traffic analysis module for ChainRecon.

Detects STUN/TURN packets, DTLS handshakes, SRTP streams,
and ICE candidates in a packet capture -- useful for analysing
IoT cameras and video doorbells that use WebRTC for streaming.
"""

from __future__ import annotations

import collections
import re
from typing import Any, Dict, Iterable, List, Optional

from utils.logging_config import get_logger

logger = get_logger("webrtc")

# STUN magic cookie (RFC 5389)
_STUN_MAGIC = bytes.fromhex("2112a442")


class WebRTCAnalyzer:
    """Identify WebRTC-related traffic in a packet list."""

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Scanning %d packets for WebRTC indicators", len(packet_list))

        stun_packets = self._find_stun(packet_list)
        dtls_handshakes = self._find_dtls(packet_list)
        srtp_streams = self._find_srtp(packet_list)
        ice_candidates = self._extract_ice_candidates(packet_list)

        indicators: List[Dict[str, str]] = []
        if stun_packets:
            indicators.append({
                "severity": "info",
                "title": "STUN traffic detected",
                "details": f"{len(stun_packets)} STUN packets found.",
            })
        if not dtls_handshakes and srtp_streams:
            indicators.append({
                "severity": "high",
                "title": "SRTP without DTLS handshake",
                "details": "Media traffic may not be properly encrypted.",
            })

        return {
            "metadata": {"packet_count": len(packet_list), "analyzer": self.__class__.__name__},
            "findings": {
                "stun_packets": stun_packets,
                "dtls_handshakes": dtls_handshakes,
                "srtp_streams": srtp_streams,
                "ice_candidates": ice_candidates,
            },
            "summary": {
                "stun_count": len(stun_packets),
                "dtls_count": len(dtls_handshakes),
                "srtp_count": len(srtp_streams),
                "ice_candidate_count": len(ice_candidates),
            },
            "risk_indicators": indicators,
        }

    # -- detection methods --------------------------------------------

    def _find_stun(self, packets) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            if self._has_layer(pkt, "STUN"):
                results.append(self._basic_info(pkt, "STUN"))
                continue
            # Fallback: check raw UDP payload for STUN magic cookie
            raw = self._get_udp_payload(pkt)
            if raw and len(raw) >= 8 and raw[4:8] == _STUN_MAGIC:
                results.append(self._basic_info(pkt, "STUN (raw)"))
        return results

    def _find_dtls(self, packets) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            if self._has_layer(pkt, "DTLS"):
                info = self._basic_info(pkt, "DTLS")
                dtls = getattr(pkt, "dtls", None)
                if dtls:
                    info["handshake_type"] = getattr(dtls, "handshake_type", None)
                results.append(info)
                continue
            # Content type 0x16 = handshake in DTLS
            raw = self._get_udp_payload(pkt)
            if raw and len(raw) >= 13 and raw[0:1] == b"\x16":
                results.append(self._basic_info(pkt, "DTLS (raw)"))
        return results

    def _find_srtp(self, packets) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        seen: set = set()
        for pkt in packets:
            if self._has_layer(pkt, "SRTP") or self._has_layer(pkt, "RTP"):
                key = self._stream_key(pkt)
                if key not in seen:
                    seen.add(key)
                    results.append(self._basic_info(pkt, "SRTP/RTP"))
                continue
            # Heuristic: UDP payload starting with 0x80-0xBF + valid PT
            raw = self._get_udp_payload(pkt)
            if raw and len(raw) >= 12:
                first = raw[0]
                if 0x80 <= first <= 0xBF:
                    key = self._stream_key(pkt)
                    if key not in seen:
                        seen.add(key)
                        results.append(self._basic_info(pkt, "RTP (heuristic)"))
        return results

    def _extract_ice_candidates(self, packets) -> List[Dict[str, Any]]:
        """Extract ICE candidates from SDP payloads or STUN attributes."""
        candidates: List[Dict[str, Any]] = []
        seen: set = set()
        ice_re = re.compile(rb"a=candidate:(\S+ \d+ \S+ \d+ \S+ \d+ typ \S+)")
        for pkt in packets:
            raw = self._get_tcp_payload(pkt) or self._get_udp_payload(pkt)
            if not raw:
                continue
            for m in ice_re.finditer(raw):
                candidate = m.group(1).decode("utf-8", errors="replace")
                if candidate not in seen:
                    seen.add(candidate)
                    candidates.append({"candidate": candidate})
        return candidates

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _has_layer(pkt, name: str) -> bool:
        try:
            return name in pkt
        except Exception:
            return hasattr(pkt, name.lower())

    @staticmethod
    def _basic_info(pkt, proto: str) -> Dict[str, Any]:
        ip = getattr(pkt, "ip", None)
        return {
            "protocol": proto,
            "src_ip": str(getattr(ip, "src", "")) if ip else None,
            "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
        }

    @staticmethod
    def _stream_key(pkt) -> tuple:
        ip = getattr(pkt, "ip", None)
        udp = getattr(pkt, "udp", None)
        return (
            getattr(ip, "src", None) if ip else None,
            getattr(ip, "dst", None) if ip else None,
            getattr(udp, "srcport", None) if udp else None,
            getattr(udp, "dstport", None) if udp else None,
        )

    @staticmethod
    def _get_udp_payload(pkt) -> Optional[bytes]:
        layer = getattr(pkt, "udp", None) or getattr(pkt, "data", None)
        if layer is None:
            return None
        for field in ("payload", "data_data", "data"):
            val = getattr(layer, field, None)
            if val:
                try:
                    return bytes.fromhex(str(val).replace(":", ""))
                except ValueError:
                    continue
        return None

    @staticmethod
    def _get_tcp_payload(pkt) -> Optional[bytes]:
        layer = getattr(pkt, "tcp", None) or getattr(pkt, "data", None)
        if layer is None:
            return None
        for field in ("payload", "data_data", "data"):
            val = getattr(layer, field, None)
            if val:
                try:
                    return bytes.fromhex(str(val).replace(":", ""))
                except ValueError:
                    continue
        return None
