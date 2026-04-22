"""Entropy-based encryption detection for ChainRecon.

Computes Shannon entropy per packet, per stream, and across the entire
capture to classify traffic as plaintext, compressed, or encrypted.
Also detects anomalies like low-entropy traffic on ports that should be
encrypted (e.g. port 443 with entropy < 5).
"""

from __future__ import annotations

import collections
import math
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils.logging_config import get_logger

logger = get_logger("entropy")

# Entropy thresholds (bits per byte, 0-8)
ENCRYPTED_THRESHOLD = 7.2    # highly random -- encrypted or compressed
COMPRESSED_THRESHOLD = 6.0   # moderately random -- likely compressed
PLAINTEXT_THRESHOLD = 4.5    # structured text (HTTP, JSON, XML)
# Below 4.5 is very structured or repetitive data

# Ports that SHOULD carry encrypted traffic
ENCRYPTED_PORTS = {443, 8443, 8883, 993, 995, 465, 636}


class EntropyAnalyzer:
    """Analyse payload entropy distribution across a packet capture."""

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Entropy analysis on %d packets", len(packet_list))

        per_packet = self._per_packet_entropy(packet_list)
        stream_entropy = self._per_stream_entropy(packet_list)
        distribution = self._entropy_distribution(per_packet)
        anomalies = self._detect_anomalies(per_packet)
        classification = self._classify_streams(stream_entropy)

        indicators: List[Dict[str, str]] = []
        low_on_secure = [a for a in anomalies if a["type"] == "low_entropy_on_secure_port"]
        if low_on_secure:
            indicators.append({
                "severity": "high",
                "title": "Plaintext on encrypted port",
                "details": (
                    f"{len(low_on_secure)} packet(s) with low entropy on "
                    "ports that should be encrypted (443, 8443, etc.)."
                ),
            })

        high_entropy_count = sum(1 for p in per_packet if p["entropy"] >= ENCRYPTED_THRESHOLD)
        plain_count = sum(1 for p in per_packet if p["entropy"] < PLAINTEXT_THRESHOLD)
        if plain_count and high_entropy_count:
            indicators.append({
                "severity": "info",
                "title": "Mixed encryption observed",
                "details": (
                    f"{high_entropy_count} encrypted payloads and "
                    f"{plain_count} plaintext payloads detected."
                ),
            })

        return {
            "metadata": {
                "packet_count": len(packet_list),
                "analysed_payloads": len(per_packet),
                "analyzer": self.__class__.__name__,
            },
            "findings": {
                "per_packet": per_packet[:200],  # cap for output size
                "stream_entropy": stream_entropy,
                "distribution": distribution,
                "anomalies": anomalies,
                "stream_classification": classification,
            },
            "summary": {
                "encrypted_payload_count": high_entropy_count,
                "compressed_payload_count": sum(
                    1 for p in per_packet
                    if COMPRESSED_THRESHOLD <= p["entropy"] < ENCRYPTED_THRESHOLD
                ),
                "plaintext_payload_count": plain_count,
                "anomaly_count": len(anomalies),
                "avg_entropy": (
                    round(sum(p["entropy"] for p in per_packet) / len(per_packet), 4)
                    if per_packet else 0.0
                ),
            },
            "risk_indicators": indicators,
        }

    # -- core methods -------------------------------------------------

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = collections.Counter(data)
        length = len(data)
        return -sum(
            (c / length) * math.log2(c / length) for c in freq.values()
        )

    def _get_payload(self, pkt: Any) -> Optional[bytes]:
        """Extract raw payload bytes from a packet."""
        for layer_name in ("data", "DATA", "tcp", "TCP", "udp", "UDP"):
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

    def _packet_meta(self, pkt: Any) -> Dict[str, Any]:
        ip = getattr(pkt, "ip", None)
        tcp = getattr(pkt, "tcp", None)
        udp = getattr(pkt, "udp", None)
        transport = tcp or udp
        return {
            "src_ip": str(getattr(ip, "src", "")) if ip else None,
            "dst_ip": str(getattr(ip, "dst", "")) if ip else None,
            "src_port": int(str(getattr(transport, "srcport", 0))) if transport else None,
            "dst_port": int(str(getattr(transport, "dstport", 0))) if transport else None,
        }

    def _per_packet_entropy(self, packets) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for pkt in packets:
            raw = self._get_payload(pkt)
            if raw is None or len(raw) < 16:
                continue
            ent = self.shannon_entropy(raw)
            meta = self._packet_meta(pkt)
            meta["entropy"] = round(ent, 4)
            meta["length"] = len(raw)
            meta["classification"] = self._classify_entropy(ent)
            # Detect transport protocol
            tcp = getattr(pkt, "tcp", None)
            udp = getattr(pkt, "udp", None)
            meta["protocol"] = "TCP" if tcp else ("UDP" if udp else "unknown")
            results.append(meta)
        return results

    def _per_stream_entropy(self, packets) -> List[Dict[str, Any]]:
        """Group packets into streams and compute aggregate entropy."""
        streams: Dict[Tuple, bytearray] = {}
        stream_counts: Dict[Tuple, int] = collections.Counter()
        stream_protocols: Dict[Tuple, str] = {}

        for pkt in packets:
            raw = self._get_payload(pkt)
            if raw is None or len(raw) < 8:
                continue
            meta = self._packet_meta(pkt)
            key = (
                meta["src_ip"], meta["dst_ip"],
                meta["src_port"], meta["dst_port"],
            )
            if key not in streams:
                streams[key] = bytearray()
                tcp = getattr(pkt, "tcp", None)
                udp = getattr(pkt, "udp", None)
                stream_protocols[key] = "TCP" if tcp else ("UDP" if udp else "unknown")
            # Sample up to 64KB per stream for entropy calculation
            if len(streams[key]) < 65536:
                streams[key].extend(raw)
            stream_counts[key] += 1

        results: List[Dict[str, Any]] = []
        for key, data in streams.items():
            ent = self.shannon_entropy(bytes(data))
            results.append({
                "src_ip": key[0], "dst_ip": key[1],
                "src_port": key[2], "dst_port": key[3],
                "protocol": stream_protocols.get(key, "unknown"),
                "entropy": round(ent, 4),
                "total_bytes": len(data),
                "packet_count": stream_counts[key],
                "classification": self._classify_entropy(ent),
            })
        results.sort(key=lambda x: x["entropy"], reverse=True)
        return results

    def _entropy_distribution(self, per_packet: List[Dict[str, Any]]) -> Dict[str, int]:
        """Bin entropy values into histogram buckets."""
        buckets = {f"{i}-{i+1}": 0 for i in range(8)}
        for p in per_packet:
            bucket_idx = min(int(p["entropy"]), 7)
            key = f"{bucket_idx}-{bucket_idx + 1}"
            buckets[key] += 1
        return buckets

    def _detect_anomalies(self, per_packet: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        for p in per_packet:
            dst_port = p.get("dst_port") or 0
            src_port = p.get("src_port") or 0
            # Low entropy on a port that should be encrypted
            if p["entropy"] < PLAINTEXT_THRESHOLD:
                if dst_port in ENCRYPTED_PORTS or src_port in ENCRYPTED_PORTS:
                    anomalies.append({
                        "type": "low_entropy_on_secure_port",
                        "src_ip": p["src_ip"],
                        "dst_ip": p["dst_ip"],
                        "port": dst_port if dst_port in ENCRYPTED_PORTS else src_port,
                        "entropy": p["entropy"],
                    })
            # Extremely uniform byte distribution (possible XOR with single key)
            if 7.99 <= p["entropy"] <= 8.0 and p.get("length", 0) > 100:
                anomalies.append({
                    "type": "perfectly_uniform",
                    "src_ip": p["src_ip"],
                    "dst_ip": p["dst_ip"],
                    "entropy": p["entropy"],
                    "details": "Near-perfect entropy may indicate XOR encryption.",
                })
        return anomalies

    def _classify_streams(
        self, stream_entropy: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        counts: Dict[str, int] = collections.Counter()
        for s in stream_entropy:
            counts[s["classification"]] += 1
        return dict(counts)

    @staticmethod
    def _classify_entropy(ent: float) -> str:
        if ent >= ENCRYPTED_THRESHOLD:
            return "encrypted"
        if ent >= COMPRESSED_THRESHOLD:
            return "compressed"
        if ent >= PLAINTEXT_THRESHOLD:
            return "structured"
        return "plaintext"
