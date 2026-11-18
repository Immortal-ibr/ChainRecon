"""Packet header hints for RTP-like media without inferring encryption."""

from __future__ import annotations

import collections
import struct
from typing import Any, Dict, Iterable, List, Optional

from chainrecon.utils.logging_config import get_logger

logger = get_logger("rtp_analyzer")

# RTP payload type -> codec name (common assignments)
_PT_CODECS = {
    0: "PCMU", 3: "GSM", 4: "G.723", 8: "PCMA", 9: "G.722",
    10: "L16-stereo", 11: "L16-mono", 14: "MPA", 26: "JPEG",
    31: "H.261", 32: "MPV", 33: "MP2T", 34: "H.263",
}

# STUN magic cookie (RFC 5389)
_STUN_MAGIC = bytes.fromhex("2112a442")

class RTPAnalyzer:
    """Extract RTP-like header evidence; SRTP needs negotiation evidence."""

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Protocol analysis on %d packets", len(packet_list))

        classified = self._classify_all(packet_list)
        rtp_streams = self._extract_rtp_streams(packet_list)
        protocol_dist = self._protocol_distribution(classified)
        h264_indicators = self._detect_h264(packet_list)

        return {
            "metadata": {
                "packet_count": len(packet_list),
                "analyzer": self.__class__.__name__,
            },
            "findings": {
                "protocol_classification": protocol_dist,
                "rtp_streams": rtp_streams,
                "classified_packets": classified[:200],
                "h264_packets": h264_indicators[:50],
            },
            "summary": {
                "rtp_stream_count": len(rtp_streams),
                "unknown_encryption_stream_count": len(rtp_streams),
                "h264_packet_count": len(h264_indicators),
                **protocol_dist,
            },
            "risk_indicators": [],
        }

    # -- protocol classification --------------------------------------

    def _classify_all(self, packets) -> List[Dict[str, Any]]:
        """Classify each UDP packet by first-byte heuristics."""
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            raw = self._get_udp_payload(pkt)
            if raw is None or len(raw) < 2:
                continue
            proto = self._identify_protocol(raw)
            ip = getattr(pkt, "ip", None)
            udp = getattr(pkt, "udp", None)
            results.append({
                "protocol": proto,
                "src_ip": str(getattr(ip, "src", "")) if ip else None,
                "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
                "src_port": int(str(getattr(udp, "srcport", 0))) if udp else None,
                "dst_port": int(str(getattr(udp, "dstport", 0))) if udp else None,
                "length": len(raw),
            })
        return results

    @staticmethod
    def _identify_protocol(data: bytes) -> str:
        """Classify UDP payload by first-byte patterns (RFC heuristics)."""
        if len(data) < 2:
            return "unknown"
        first = data[0]
        # STUN: first byte 0x00 or 0x01 + magic cookie at offset 4
        if first in (0x00, 0x01) and len(data) >= 8 and data[4:8] == _STUN_MAGIC:
            return "STUN"
        # DTLS: content type 20-25 (ChangeCipherSpec, Alert, Handshake, AppData)
        if 20 <= first <= 25 and len(data) >= 13:
            return "DTLS"
        if 0x80 <= first <= 0xBF and len(data) >= 12:
            if 200 <= data[1] <= 211:
                return "RTCP candidate"
            if RTPAnalyzer._parse_rtp_header(data) is not None:
                return "RTP/SRTP candidate"
        # TURN ChannelData: 0x40-0x4F
        if 0x40 <= first <= 0x4F:
            return "TURN-Channel"
        return "unknown"

    def _protocol_distribution(self, classified: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = collections.Counter()
        for c in classified:
            counts[c["protocol"]] += 1
        return dict(counts.most_common())

    # -- RTP stream extraction ----------------------------------------

    def _extract_rtp_streams(self, packets) -> List[Dict[str, Any]]:
        """Group RTP packets by SSRC and extract stream metadata."""
        streams: Dict[tuple, Dict[str, Any]] = {}

        for pkt in packets:
            raw = self._get_udp_payload(pkt)
            if raw is None or len(raw) < 12:
                continue
            rtp = self._parse_rtp_header(raw)
            if rtp is None:
                continue

            ip = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
            udp = getattr(pkt, "udp", None)
            key = (
                str(getattr(ip, "src", "")) if ip else None,
                str(getattr(ip, "dst", "")) if ip else None,
                str(getattr(udp, "srcport", "")) if udp else None,
                str(getattr(udp, "dstport", "")) if udp else None,
                rtp["ssrc"],
            )
            if key not in streams:
                streams[key] = {
                    "ssrc": rtp["ssrc"],
                    "src_ip": str(getattr(ip, "src", "")) if ip else None,
                    "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
                    "src_port": int(str(getattr(udp, "srcport", 0))) if udp else None,
                    "dst_port": int(str(getattr(udp, "dstport", 0))) if udp else None,
                    "payload_types": set(),
                    "packet_count": 0,
                    "total_bytes": 0,
                    "seq_numbers": [],
                }
            s = streams[key]
            s["payload_types"].add(rtp["pt"])
            s["packet_count"] += 1
            s["total_bytes"] += len(raw)
            s["seq_numbers"].append(rtp["seq"])

        results: List[Dict[str, Any]] = []
        for s in streams.values():
            codecs = [_PT_CODECS.get(pt, f"Dynamic PT {pt} (requires SDP)" if pt >= 96 else f"PT-{pt}") for pt in sorted(s["payload_types"])]
            gaps = self._observed_sequence_gaps(s["seq_numbers"])
            results.append({
                "ssrc": hex(s["ssrc"]),
                "src_ip": s["src_ip"],
                "dst_ip": s["dst_ip"],
                "src_port": s["src_port"],
                "dst_port": s["dst_port"],
                "codecs": codecs,
                "packet_count": s["packet_count"],
                "total_bytes": s["total_bytes"],
                "observed_sequence_gaps": gaps,
                "encryption_status": "unknown",
            })
        results.sort(key=lambda x: x["packet_count"], reverse=True)
        return results

    @staticmethod
    def _parse_rtp_header(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse an RTP header. Returns None if this isn't valid RTP."""
        if len(data) < 12:
            return None
        first = data[0]
        version = (first >> 6) & 0x03
        if version != 2:
            return None
        if 200 <= data[1] <= 211:
            return None
        cc = first & 0x0F
        offset = 12 + cc * 4
        if len(data) < offset:
            return None
        if first & 0x10:
            if len(data) < offset + 4:
                return None
            extension_words = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4 + extension_words * 4
            if len(data) < offset:
                return None
        if first & 0x20:
            padding_length = data[-1]
            if padding_length == 0 or padding_length > len(data) - offset:
                return None
        pt = data[1] & 0x7F
        seq = struct.unpack("!H", data[2:4])[0]
        timestamp = struct.unpack("!I", data[4:8])[0]
        ssrc = struct.unpack("!I", data[8:12])[0]
        return {"version": version, "pt": pt, "seq": seq, "timestamp": timestamp, "ssrc": ssrc, "payload_offset": offset}

    @staticmethod
    def _observed_sequence_gaps(seq_numbers: List[int]) -> int:
        """Count forward sequence gaps, including 16-bit wrap, in capture order."""
        gaps = 0
        for previous, current in zip(seq_numbers, seq_numbers[1:]):
            distance = (current - previous) & 0xFFFF
            if 1 < distance < 0x8000:
                gaps += distance - 1
        return gaps

    # -- H.264 / H.265 detection --------------------------------------

    # H.264 NAL types: 1=slice, 5=IDR, 6=SEI, 7=SPS, 8=PPS, 28=FU-A, 24=STAP-A
    _H264_NAL_TYPES = {1, 5, 6, 7, 8, 24, 28}
    # H.265 NAL unit type range in the VCL (0-31) and non-VCL (32-63)
    # H.265 first byte: forbidden_zero_bit(1) + nal_unit_type(6) + nuh_layer_id(6) + nuh_temporal_id(3)
    # Heuristic: if payload[0] top bit is 0 and bits 1-6 encode type 32-40, it's H.265 non-VCL
    _H265_NONVCL_TYPES = set(range(32, 41))  # VPS, SPS, PPS, AUD, SEI prefix/suffix

    def _detect_h264(self, packets) -> List[Dict[str, Any]]:
        """Detect H.264 and H.265 NAL units in RTP payloads."""
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            raw = self._get_udp_payload(pkt)
            if raw is None or len(raw) < 13:
                continue
            rtp = self._parse_rtp_header(raw)
            if rtp is None:
                continue
            payload = raw[rtp["payload_offset"]:]
            if len(payload) < 2:
                continue
            ip = getattr(pkt, "ip", None)
            # H.264: nal_type from lower 5 bits
            h264_nal = payload[0] & 0x1F
            if h264_nal in self._H264_NAL_TYPES:
                results.append({
                    "ssrc": hex(rtp["ssrc"]),
                    "nal_type": h264_nal,
                    "codec_hint": "H.264",
                    "confidence": "low",
                    "src_ip": str(getattr(ip, "src", "")) if ip else None,
                    "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
                })
                continue
            # H.265 heuristic: forbidden bit=0, NAL type in bits 1-6
            if (payload[0] & 0x80) == 0:
                h265_nal = (payload[0] >> 1) & 0x3F
                if h265_nal in self._H265_NONVCL_TYPES:
                    results.append({
                        "ssrc": hex(rtp["ssrc"]),
                        "nal_type": h265_nal,
                        "codec_hint": "H.265",
                        "confidence": "low",
                        "src_ip": str(getattr(ip, "src", "")) if ip else None,
                        "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
                    })
        return results

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _get_udp_payload(pkt) -> Optional[bytes]:
        if getattr(pkt, "udp", None) is None and getattr(pkt, "UDP", None) is None:
            return None
        for layer_name in ("data", "DATA", "udp", "UDP"):
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
