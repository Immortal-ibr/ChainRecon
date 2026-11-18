"""Payload entropy observations; entropy alone cannot identify encryption."""

from __future__ import annotations

import collections
import math
from typing import Any, Dict, Iterable, List, Optional, Tuple

from chainrecon.utils.logging_config import get_logger

logger = get_logger("entropy")

# Entropy thresholds (bits per byte, 0-8)
HIGH_ENTROPY_THRESHOLD = 7.2
ELEVATED_ENTROPY_THRESHOLD = 6.0
LOW_ENTROPY_THRESHOLD = 4.5


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
        high_entropy_count = sum(1 for p in per_packet if p["entropy"] >= HIGH_ENTROPY_THRESHOLD)
        low_entropy_count = sum(1 for p in per_packet if p["entropy"] < LOW_ENTROPY_THRESHOLD)

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
                "high_entropy_payload_count": high_entropy_count,
                "elevated_entropy_payload_count": sum(
                    1 for p in per_packet
                    if ELEVATED_ENTROPY_THRESHOLD <= p["entropy"] < HIGH_ENTROPY_THRESHOLD
                ),
                "low_entropy_payload_count": low_entropy_count,
                "anomaly_count": len(anomalies),
                "avg_entropy": (
                    round(sum(p["entropy"] for p in per_packet) / len(per_packet), 4)
                    if per_packet else 0.0
                ),
            },
            "risk_indicators": [],
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
        # Entropy is a distribution statistic, not a protocol or crypto detector.
        return []

    def _classify_streams(
        self, stream_entropy: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        counts: Dict[str, int] = collections.Counter()
        for s in stream_entropy:
            counts[s["classification"]] += 1
        return dict(counts)

    @staticmethod
    def _classify_entropy(ent: float) -> str:
        if ent >= HIGH_ENTROPY_THRESHOLD:
            return "high_entropy"
        if ent >= ELEVATED_ENTROPY_THRESHOLD:
            return "elevated_entropy"
        if ent >= LOW_ENTROPY_THRESHOLD:
            return "moderate_entropy"
        return "low_entropy"
