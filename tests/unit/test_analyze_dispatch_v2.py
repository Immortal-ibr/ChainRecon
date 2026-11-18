"""Specialist dispatch retains capture limits and review-level claims."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from chainrecon.tui.screens.analyze import AnalyzeScreen


def test_packet_specialists_use_bounded_capture_and_conservative_credential_claim(tmp_path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    pcap = tmp_path / "sample.pcap"
    scapy.wrpcap(str(pcap), [
        scapy.Ether() / scapy.IP(src="192.0.2.10", dst="192.0.2.20")
        / scapy.TCP(sport=40001, dport=80) / scapy.Raw(load=b"password=maybe"),
    ])
    for specialist in ("pcap_stats", "webrtc", "mqtt", "endpoint", "credentials", "entropy", "rtp", "certs"):
        result = AnalyzeScreen._dispatch(specialist, str(pcap))
        assert result["metadata"]["capture_truncated"] is False
        assert result["summary"]["result_truncated"] is False
    credentials = AnalyzeScreen._dispatch("credentials", str(pcap))
    assert credentials["summary"]["credential_hits"] == 1
    assert credentials["risk_indicators"][0]["severity"] == "medium"
    assert credentials["risk_indicators"][0]["title"] == "Credential-like plaintext pattern observed"
    assert "maybe" not in str(credentials)


def test_scan_dispatch_requires_xml_and_ssl_dispatch_is_explicit_probe(tmp_path: Path) -> None:
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/></port>'
        '</ports></host></nmaprun>', encoding="utf-8",
    )
    scan = AnalyzeScreen._dispatch("scan", str(xml))
    assert scan["summary"]["open_port_count"] == 1
    with patch("chainrecon.analysis.ssl_analyzer.SSLAnalyzer.probe_certificates", return_value={"summary": {"probed": 4}}) as probe:
        result = AnalyzeScreen._dispatch("ssl", "192.0.2.10")
    assert result["summary"]["probed"] == 4
    probe.assert_called_once_with("192.0.2.10", [443, 8443, 8883, 8080])
    with pytest.raises(ValueError, match="Unknown analyzer"):
        AnalyzeScreen._dispatch("unknown", str(xml))
