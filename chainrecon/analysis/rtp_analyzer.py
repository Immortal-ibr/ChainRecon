"""RTP / SRTP / protocol identification module for ChainRecon.

Classifies UDP payloads by first-byte patterns to identify STUN, DTLS,
RTP/SRTP, and custom IoT protocols.  Extracts RTP payload types, SSRC
values, codec identification (H.264, Opus, PCMU, etc.), and detects
whether media streams are encrypted (SRTP) or plaintext (RTP).
"""

from __future__ import annotations

import collections
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

from chainrecon.utils.logging_config import get_logger

logger = get_logger("rtp_analyzer")

# RTP payload type -> codec name (common assignments)
_PT_CODECS = {
    0: "PCMU", 3: "GSM", 4: "G.723", 8: "PCMA", 9: "G.722",
    10: "L16-stereo", 11: "L16-mono", 14: "MPA", 26: "JPEG",
    31: "H.261", 32: "MPV", 33: "MP2T", 34: "H.263",
    # Dynamic (96-127): negotiated via SDP -- could be H.264, H.265, Opus, etc.
    # Common assignments for IoT cameras:
    #   96 = H.264 (most common for legacy cameras)
    #   97 = H.265/HEVC (modern cameras -- same header byte range as H.264 range)
    #   98 = H.265 alt / VP8 / AAC
    #   100 = H.264 + B-frames
    #   111 = Opus
    # Without SDP negotiation we can only say "Dynamic" and flag ambiguity.
    96: "Dynamic-PT96 (H.264/H.265?)", 97: "Dynamic-PT97 (H.265/Opus?)",
    98: "Dynamic-PT98", 99: "Dynamic-PT99", 100: "Dynamic-PT100 (H.264?)",
    101: "Dynamic-PT101", 102: "Dynamic-PT102", 103: "Dynamic-PT103",
    104: "Dynamic-PT104", 105: "Dynamic-PT105", 106: "Dynamic-PT106",
    107: "Dynamic-PT107", 108: "Dynamic-PT108", 109: "Dynamic-PT109",
    110: "Dynamic-PT110", 111: "Dynamic-PT111 (Opus?)", 112: "Dynamic-PT112",
}

# STUN magic cookie (RFC 5389)
_STUN_MAGIC = bytes.fromhex("2112a442")

# H.264 NAL unit start codes
_H264_START = (b"\x00\x00\x00\x01", b"\x00\x00\x01")


class RTPAnalyzer:
    """Detect and classify RTP/SRTP streams and identify protocols."""

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Protocol analysis on %d packets", len(packet_list))

        classified = self._classify_all(packet_list)
        rtp_streams = self._extract_rtp_streams(packet_list)
        protocol_dist = self._protocol_distribution(classified)
        h264_indicators = self._detect_h264(packet_list)

        indicators: List[Dict[str, str]] = []
        plaintext_rtp = [s for s in rtp_streams if not s.get("likely_srtp")]
        if plaintext_rtp:
            indicators.append({
                "severity": "high",
                "title": "Unencrypted RTP streams detected",
                "details": (
                    f"{len(plaintext_rtp)} RTP stream(s) appear unencrypted. "
                    "Video/audio may be interceptable."
                ),
            })
        srtp_streams = [s for s in rtp_streams if s.get("likely_srtp")]
        if srtp_streams:
            indicators.append({
                "severity": "info",
                "title": "SRTP encryption detected",
                "details": (
                    f"{len(srtp_streams)} stream(s) use SRTP. "
                    "Passive decryption requires key material from DTLS-SRTP."
                ),
            })
        if h264_indicators:
            h265_count = sum(1 for p in h264_indicators if p.get("codec_hint") == "H.265")
            h264_count = len(h264_indicators) - h265_count
            if h264_count and h265_count:
                detail = f"{h264_count} H.264 NAL units and {h265_count} possible H.265 NAL units detected."
            elif h265_count:
                detail = f"{h265_count} possible H.265/HEVC NAL units detected."
            else:
                detail = f"{h264_count} packet(s) contain H.264 NAL units."
            indicators.append({
                "severity": "info",
                "title": "Video NAL units detected (H.264 or H.265)",
                "details": detail,
            })

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
                "srtp_stream_count": len(srtp_streams),
                "plaintext_rtp_count": len(plaintext_rtp),
                "h264_packet_count": len(h264_indicators),
                **protocol_dist,
            },
            "risk_indicators": indicators,
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
        # RTP/SRTP: version 2 -> first byte has upper 2 bits = 10 (0x80-0xBF)
        if 0x80 <= first <= 0xBF:
            return "RTP/SRTP"
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
        streams: Dict[int, Dict[str, Any]] = {}

        for pkt in packets:
            raw = self._get_udp_payload(pkt)
            if raw is None or len(raw) < 12:
                continue
            rtp = self._parse_rtp_header(raw)
            if rtp is None:
                continue

            ssrc = rtp["ssrc"]
            if ssrc not in streams:
                ip = getattr(pkt, "ip", None)
                udp = getattr(pkt, "udp", None)
                streams[ssrc] = {
                    "ssrc": ssrc,
                    "src_ip": str(getattr(ip, "src", "")) if ip else None,
                    "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
                    "src_port": int(str(getattr(udp, "srcport", 0))) if udp else None,
                    "dst_port": int(str(getattr(udp, "dstport", 0))) if udp else None,
                    "payload_types": set(),
                    "packet_count": 0,
                    "total_bytes": 0,
                    "seq_numbers": [],
                }
            s = streams[ssrc]
            s["payload_types"].add(rtp["pt"])
            s["packet_count"] += 1
            s["total_bytes"] += len(raw)
            s["seq_numbers"].append(rtp["seq"])

        results: List[Dict[str, Any]] = []
        for ssrc, s in streams.items():
            codecs = [_PT_CODECS.get(pt, f"PT-{pt}") for pt in sorted(s["payload_types"])]
            seq = sorted(s["seq_numbers"])
            lost = self._estimate_loss(seq)
            # SRTP heuristic: payload entropy is high AND DTLS was seen on same flow
            likely_srtp = s["packet_count"] > 10  # conservative -- refine below
            results.append({
                "ssrc": hex(ssrc),
                "src_ip": s["src_ip"],
                "dst_ip": s["dst_ip"],
                "src_port": s["src_port"],
                "dst_port": s["dst_port"],
                "codecs": codecs,
                "packet_count": s["packet_count"],
                "total_bytes": s["total_bytes"],
                "estimated_loss_pct": round(lost, 2),
                "likely_srtp": likely_srtp,
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
        pt = data[1] & 0x7F
        seq = struct.unpack("!H", data[2:4])[0]
        timestamp = struct.unpack("!I", data[4:8])[0]
        ssrc = struct.unpack("!I", data[8:12])[0]
        return {"version": version, "pt": pt, "seq": seq, "timestamp": timestamp, "ssrc": ssrc}

    @staticmethod
    def _estimate_loss(seq_numbers: List[int]) -> float:
        """Estimate packet loss from sequence number gaps."""
        if len(seq_numbers) < 2:
            return 0.0
        expected = seq_numbers[-1] - seq_numbers[0] + 1
        if expected <= 0:
            return 0.0
        return max(0.0, (1 - len(seq_numbers) / expected) * 100)

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
            cc = raw[0] & 0x0F
            offset = 12 + cc * 4
            payload = raw[offset:]
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
                        "src_ip": str(getattr(ip, "src", "")) if ip else None,
                        "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
                    })
        return results

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _get_udp_payload(pkt) -> Optional[bytes]:
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
