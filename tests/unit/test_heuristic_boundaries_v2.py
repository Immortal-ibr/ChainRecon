"""Regression tests for evidence that cannot establish a vulnerability alone."""

import struct
from types import SimpleNamespace

from chainrecon.analysis.endpoint_analyzer import EndpointAnalyzer
from chainrecon.analysis.entropy_analyzer import EntropyAnalyzer
from chainrecon.analysis.rtp_analyzer import RTPAnalyzer


def _packet(payload: bytes, *, src: str = "10.0.0.2", dst: str = "52.1.2.3", port: int = 1883, udp: bool = False):
    transport = SimpleNamespace(srcport="45000", dstport=str(port))
    fields = {
        "ip": SimpleNamespace(src=src, dst=dst),
        "length": str(len(payload) + 28),
        "data": SimpleNamespace(data_data=payload.hex()),
    }
    fields["udp" if udp else "tcp"] = transport
    return SimpleNamespace(**fields)


def _rtp(sequence: int, payload: bytes = b"\x65\x00") -> bytes:
    return bytes((0x80, 0x60)) + struct.pack("!HII", sequence, 1000, 1234) + payload


def test_port_and_old_cloud_prefix_are_only_hints():
    result = EndpointAnalyzer().analyze([_packet(b"opaque")])
    external = result["findings"]["external_endpoints"][0]
    assert external["ip"] == "52.1.2.3"
    assert external["ports"] == [1883]
    assert external["service_hints"] == ["MQTT"]
    assert external["services"] == []
    assert external["cloud_provider"] is None
    assert result["risk_indicators"] == []


def test_ipv6_and_non_global_addresses_are_classified_without_prefixes():
    ipv6 = _packet(b"x", src="fd00::1", dst="2606:4700:4700::1111")
    non_global = _packet(b"x", src="192.0.2.1", dst="10.0.0.1")
    ipv6.ipv6 = ipv6.ip
    del ipv6.ip
    result = EndpointAnalyzer().analyze([ipv6, non_global])
    assert {e["ip"] for e in result["findings"]["external_endpoints"]} == {"2606:4700:4700::1111"}
    assert result["risk_indicators"] == []


def test_entropy_on_ports_does_not_identify_encryption_or_plaintext():
    low = _packet(b"A" * 32, port=443)
    high = _packet(bytes(range(256)), port=1883)
    result = EntropyAnalyzer().analyze([low, high])
    assert result["summary"]["low_entropy_payload_count"] == 1
    assert result["summary"]["high_entropy_payload_count"] == 1
    assert {p["classification"] for p in result["findings"]["per_packet"]} == {"low_entropy", "high_entropy"}
    assert result["risk_indicators"] == []
    assert result["findings"]["anomalies"] == []


def test_short_and_long_rtp_like_streams_have_unknown_encryption():
    for packet_count in (1, 11):
        packets = [_packet(_rtp(i), port=5004, udp=True) for i in range(packet_count)]
        result = RTPAnalyzer().analyze(packets)
        stream = result["findings"]["rtp_streams"][0]
        assert stream["packet_count"] == packet_count
        assert stream["encryption_status"] == "unknown"
        assert stream["codecs"] == ["Dynamic PT 96 (requires SDP)"]
        assert result["summary"]["unknown_encryption_stream_count"] == 1
        assert result["risk_indicators"] == []


def test_rtp_parser_rejects_rtcp_and_truncated_extension():
    analyzer = RTPAnalyzer()
    rtcp = bytes((0x80, 200)) + b"\x00" * 10
    truncated_extension = bytes((0x90, 0x60)) + b"\x00" * 10
    result = analyzer.analyze([_packet(rtcp, udp=True), _packet(truncated_extension, udp=True)])
    assert result["findings"]["rtp_streams"] == []
    assert result["findings"]["protocol_classification"]["RTCP candidate"] == 1
    assert result["risk_indicators"] == []


def test_rtp_sequence_gap_handles_wrap_without_claiming_network_loss():
    packets = [_packet(_rtp(seq), udp=True) for seq in (65534, 65535, 1)]
    stream = RTPAnalyzer().analyze(packets)["findings"]["rtp_streams"][0]
    assert stream["observed_sequence_gaps"] == 1
    assert "estimated_loss_pct" not in stream
