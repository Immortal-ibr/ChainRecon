"""Tests for enhanced PCAP analysis modules (Phase 2.2)."""

import collections
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from analysis.mqtt_analyzer import MQTTAnalyzer
from analysis.pcap_stats import PcapStatsAnalyzer
from analysis.traffic import TrafficAnalyzer
from analysis.webrtc_analyzer import WebRTCAnalyzer


# ── Helper: build fake packets ───────────────────────────────────────


class FakePacket:
    """Packet mock that supports the ``in`` operator for layer checks."""

    def __init__(self, layers=None, **attrs):
        self._layers = set(layers or [])
        for k, v in attrs.items():
            setattr(self, k, v)

    def __contains__(self, name):
        return name in self._layers


def _make_packet(src="192.168.1.10", dst="54.239.28.85", sport="12345",
                 dport="443", proto="TCP", length=100, layers=None, **extra):
    """Return a FakePacket that mimics a pyshark packet."""
    ip = SimpleNamespace(src=src, dst=dst)
    tcp = SimpleNamespace(srcport=sport, dstport=dport)
    pkt = FakePacket(
        layers=layers or [],
        ip=ip, tcp=tcp, udp=None,
        highest_layer=proto, length=length,
    )
    for attr, val in extra.items():
        setattr(pkt, attr, val)
    return pkt


# ===========================================================================
# TrafficAnalyzer entropy helpers
# ===========================================================================


class ShannonEntropyTests(unittest.TestCase):
    def test_zero_entropy_for_uniform(self):
        data = bytes([0xAA] * 100)
        ent = TrafficAnalyzer.shannon_entropy(data)
        self.assertAlmostEqual(ent, 0.0)

    def test_max_entropy_for_random(self):
        # All 256 byte values equally → 8.0 bits/byte
        data = bytes(range(256))
        ent = TrafficAnalyzer.shannon_entropy(data)
        self.assertAlmostEqual(ent, 8.0, places=2)

    def test_empty_data(self):
        self.assertEqual(TrafficAnalyzer.shannon_entropy(b""), 0.0)


class EncryptedPayloadDetectionTests(unittest.TestCase):
    def test_high_entropy_flagged(self):
        analyzer = TrafficAnalyzer(capture_factory=MagicMock())
        # Build a packet with high-entropy DATA layer (256 bytes → ~8 bits/byte)
        random_hex = os.urandom(256).hex()
        data_layer = SimpleNamespace(data_data=random_hex)
        ip_layer = SimpleNamespace(src="192.168.1.10", dst="54.239.28.85")
        pkt = SimpleNamespace(
            ip=ip_layer, tcp=None, udp=None, data=data_layer,
            highest_layer="DATA", length=256,
        )
        results = analyzer.detect_encrypted_payloads([pkt], threshold=6.0)
        self.assertGreater(len(results), 0)
        self.assertGreater(results[0]["entropy"], 6.0)

    def test_low_entropy_not_flagged(self):
        analyzer = TrafficAnalyzer(capture_factory=MagicMock())
        low_hex = (b"\x00" * 64).hex()
        data_layer = SimpleNamespace(data_data=low_hex)
        ip_layer = SimpleNamespace(src="192.168.1.10", dst="54.239.28.85")
        pkt = SimpleNamespace(
            ip=ip_layer, tcp=None, udp=None, data=data_layer,
            highest_layer="DATA", length=64,
        )
        results = analyzer.detect_encrypted_payloads([pkt])
        self.assertEqual(results, [])


class PlaintextCredentialTests(unittest.TestCase):
    def test_detects_password(self):
        analyzer = TrafficAnalyzer(capture_factory=MagicMock())
        payload = b"GET /login?password=secret123 HTTP/1.1\r\n"
        data_layer = SimpleNamespace(data_data=payload.hex())
        pkt = FakePacket(layers=["HTTP"], ip=SimpleNamespace(src="192.168.1.10", dst="54.239.28.85"),
                         tcp=None, udp=None, data=data_layer, highest_layer="HTTP", length=80)
        results = analyzer.detect_plaintext_credentials([pkt])
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["type"], "password")

    def test_clean_payload(self):
        analyzer = TrafficAnalyzer(capture_factory=MagicMock())
        payload = b"just some normal data without credentials"
        data_layer = SimpleNamespace(data_data=payload.hex())
        pkt = FakePacket(layers=["DATA"], ip=SimpleNamespace(src="192.168.1.10", dst="54.239.28.85"),
                         tcp=None, udp=None, data=data_layer, highest_layer="DATA", length=80)
        results = analyzer.detect_plaintext_credentials([pkt])
        self.assertEqual(results, [])


# ===========================================================================
# PcapStatsAnalyzer
# ===========================================================================


class PcapStatsAnalyzerTests(unittest.TestCase):
    def _make_packets(self, n=5):
        return [_make_packet(proto=("TCP" if i % 2 == 0 else "UDP"), length=100 + i) for i in range(n)]

    def test_analyze_returns_structure(self):
        analyzer = PcapStatsAnalyzer()
        result = analyzer.analyze(self._make_packets())
        self.assertIn("metadata", result)
        self.assertIn("findings", result)
        self.assertIn("summary", result)
        self.assertEqual(result["metadata"]["packet_count"], 5)

    def test_protocol_distribution(self):
        analyzer = PcapStatsAnalyzer()
        dist = analyzer._protocol_distribution(self._make_packets())
        self.assertIn("TCP", dist)
        self.assertIn("UDP", dist)

    def test_top_talkers(self):
        analyzer = PcapStatsAnalyzer()
        talkers = analyzer._top_talkers(self._make_packets())
        self.assertGreater(len(talkers), 0)
        self.assertIn("ip", talkers[0])

    def test_cloud_identification(self):
        self.assertEqual(PcapStatsAnalyzer._identify_cloud("54.239.28.85"), "AWS")
        self.assertEqual(PcapStatsAnalyzer._identify_cloud("104.16.1.1"), "Cloudflare")
        self.assertIsNone(PcapStatsAnalyzer._identify_cloud("192.168.1.1"))


# ===========================================================================
# WebRTCAnalyzer
# ===========================================================================


class WebRTCAnalyzerTests(unittest.TestCase):
    def test_empty_packets(self):
        analyzer = WebRTCAnalyzer()
        result = analyzer.analyze([])
        self.assertEqual(result["summary"]["stun_count"], 0)
        self.assertEqual(result["summary"]["dtls_count"], 0)

    def test_detects_stun_layer(self):
        pkt = _make_packet(proto="STUN", layers=["STUN"])
        analyzer = WebRTCAnalyzer()
        result = analyzer.analyze([pkt])
        self.assertEqual(result["summary"]["stun_count"], 1)

    def test_detects_stun_magic_cookie(self):
        # Build raw UDP with STUN magic cookie at offset 4
        magic = b"\x00\x01\x00\x08" + bytes.fromhex("2112a442") + b"\x00" * 12
        udp_layer = SimpleNamespace(payload=magic.hex())
        pkt = _make_packet(proto="UDP", udp=udp_layer)
        analyzer = WebRTCAnalyzer()
        result = analyzer.analyze([pkt])
        self.assertGreaterEqual(result["summary"]["stun_count"], 1)

    def test_detects_dtls_layer(self):
        dtls_layer = SimpleNamespace(handshake_type="1")
        pkt = _make_packet(proto="DTLS", layers=["DTLS"], dtls=dtls_layer)
        analyzer = WebRTCAnalyzer()
        result = analyzer.analyze([pkt])
        self.assertEqual(result["summary"]["dtls_count"], 1)

    def test_detects_rtp_heuristic(self):
        # RTP payload: version 2, marker, PT=96
        rtp_payload = b"\x80\x60" + b"\x00" * 10
        udp_layer = SimpleNamespace(payload=rtp_payload.hex())
        pkt = _make_packet(proto="UDP", udp=udp_layer)
        analyzer = WebRTCAnalyzer()
        result = analyzer.analyze([pkt])
        self.assertGreaterEqual(result["summary"]["srtp_count"], 1)

    def test_risk_for_srtp_without_dtls(self):
        rtp_payload = b"\x80\x60" + b"\x00" * 10
        udp_layer = SimpleNamespace(payload=rtp_payload.hex())
        pkt = _make_packet(proto="UDP", layers=["RTP"], udp=udp_layer)
        analyzer = WebRTCAnalyzer()
        result = analyzer.analyze([pkt])
        risks = [r for r in result["risk_indicators"] if "SRTP without DTLS" in r.get("title", "")]
        self.assertGreater(len(risks), 0)


# ===========================================================================
# MQTTAnalyzer
# ===========================================================================


class MQTTAnalyzerTests(unittest.TestCase):
    def _mqtt_pkt(self, topic="home/temp", msg="22.5", port="1883", msgtype="3"):
        mqtt_layer = SimpleNamespace(topic=topic, msg=msg.encode().hex(), qos="1", msgtype=msgtype, username=None)
        tcp = SimpleNamespace(srcport=port, dstport="12345")
        pkt = FakePacket(
            layers=["MQTT"],
            ip=SimpleNamespace(src="192.168.1.50", dst="192.168.1.1"),
            tcp=tcp, udp=None,
            mqtt=mqtt_layer,
            highest_layer="MQTT", length=80,
        )
        return pkt

    def test_analyze_returns_structure(self):
        analyzer = MQTTAnalyzer()
        result = analyzer.analyze([self._mqtt_pkt()])
        self.assertIn("findings", result)
        self.assertIn("topics", result["findings"])
        self.assertIn("payloads", result["findings"])

    def test_extracts_topic(self):
        analyzer = MQTTAnalyzer()
        result = analyzer.analyze([self._mqtt_pkt(topic="device/status")])
        topics = result["findings"]["topics"]
        self.assertGreater(len(topics), 0)
        self.assertEqual(topics[0]["topic"], "device/status")

    def test_extracts_payload(self):
        analyzer = MQTTAnalyzer()
        pkt = self._mqtt_pkt(msg='{"temp":22}')
        result = analyzer.analyze([pkt])
        payloads = result["findings"]["payloads"]
        self.assertGreater(len(payloads), 0)
        self.assertTrue(payloads[0]["is_json"])

    def test_plaintext_mqtt_risk(self):
        analyzer = MQTTAnalyzer()
        result = analyzer.analyze([self._mqtt_pkt(port="1883")])
        risks = [r for r in result["risk_indicators"] if "not encrypted" in r.get("title", "")]
        self.assertGreater(len(risks), 0)

    def test_encrypted_mqtt_no_risk(self):
        pkt = self._mqtt_pkt(port="8883")
        analyzer = MQTTAnalyzer()
        result = analyzer.analyze([pkt])
        risks = [r for r in result["risk_indicators"] if "not encrypted" in r.get("title", "")]
        self.assertEqual(len(risks), 0)

    def test_empty_packets(self):
        analyzer = MQTTAnalyzer()
        result = analyzer.analyze([])
        self.assertEqual(result["summary"]["topic_count"], 0)

    def test_authentication_detected(self):
        mqtt_layer = SimpleNamespace(topic=None, msg=None, qos=None, msgtype="1", username="user1")
        tcp = SimpleNamespace(srcport="1883", dstport="12345")
        pkt = FakePacket(
            layers=["MQTT"],
            ip=SimpleNamespace(src="192.168.1.50", dst="192.168.1.1"),
            tcp=tcp, udp=None,
            mqtt=mqtt_layer,
            highest_layer="MQTT", length=80,
        )
        analyzer = MQTTAnalyzer()
        result = analyzer.analyze([pkt])
        self.assertTrue(result["findings"]["authentication"]["authenticated"])


if __name__ == "__main__":
    unittest.main()
