"""Large specialist captures must report their bounded coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from chainrecon.analysis.cert_analyzer import CertAnalyzer
from chainrecon.analysis.traffic import PacketBatch, TrafficAnalyzer
from chainrecon.runners.workflow_runner import WorkflowRunner
from chainrecon.tui.screens.analyze import AnalyzeScreen


class _Capture:
    def __init__(self) -> None:
        self.closed = False
        self.packets_read = 0

    def __iter__(self):
        for _ in range(10_001):
            self.packets_read += 1
            yield object()

    def close(self) -> None:
        self.closed = True


def test_legacy_packet_helper_is_bounded_and_reports_truncation() -> None:
    capture = _Capture()
    batch, handle = TrafficAnalyzer(capture_factory=lambda _path: capture)._load_packets("capture.pcap")
    try:
        assert len(batch) == 10_000
        assert batch.truncated is True
        assert capture.packets_read == 10_001
    finally:
        handle.close()
    assert capture.closed


def test_specialist_default_reader_streams_scapy_packets(tmp_path: Path) -> None:
    pytest.importorskip("scapy.all")
    from scapy.all import Ether, IP, UDP, wrpcap

    source = tmp_path / "small.pcap"
    wrpcap(str(source), [Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1000, dport=2000)])
    batch, capture = TrafficAnalyzer()._load_packets(str(source))
    try:
        assert len(batch) == 1
        assert batch.truncated is False
        assert batch[0].ip.src == "192.0.2.1"
    finally:
        capture.close()


def test_specialist_workflow_stops_on_truncated_capture(tmp_path: Path) -> None:
    pipeline = tmp_path / "workflow.yaml"
    pipeline.write_text("steps:\n  - id: pcap\n    type: pcap_analysis\n    analyzer: pcap_stats\n    input: capture.pcap\n  - id: later\n    type: assert\n    condition: 'True'\n", encoding="utf-8")
    batch = PacketBatch()
    batch.truncated = True
    capture = _Capture()
    result = {"metadata": {}, "summary": {}, "findings": {}, "risk_indicators": []}
    with patch("chainrecon.analysis.traffic.TrafficAnalyzer._load_packets", return_value=(batch, capture)), patch("chainrecon.runners.workflow_runner.PcapStatsAnalyzer.analyze", return_value=result):
        report = WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline))
    assert capture.closed
    assert report["summary"]["status"] == "partial"
    assert "later" not in report["findings"]["steps"]
    assert report["findings"]["steps"]["pcap"]["summary"]["result_truncated"] is True


def test_certificate_and_tui_specialist_paths_expose_truncation() -> None:
    batch = PacketBatch()
    batch.truncated = True
    capture = _Capture()
    result = {"metadata": {}, "summary": {}, "findings": {}, "risk_indicators": []}
    with patch("chainrecon.analysis.traffic.TrafficAnalyzer._load_packets", return_value=(batch, capture)), patch.object(CertAnalyzer, "analyze", return_value=result):
        certs = CertAnalyzer().analyze_pcap("capture.pcap")
    assert capture.closed
    assert certs["metadata"]["capture_truncated"] is True
    assert certs["summary"]["result_truncated"] is True

    capture = _Capture()
    with patch("chainrecon.analysis.traffic.TrafficAnalyzer._load_packets", return_value=(batch, capture)), patch("chainrecon.analysis.pcap_stats.PcapStatsAnalyzer.analyze", return_value={"metadata": {}, "summary": {}, "findings": {}, "risk_indicators": []}):
        ui_result = AnalyzeScreen._dispatch("pcap_stats", "capture.pcap")
    assert capture.closed
    assert ui_result["summary"]["result_truncated"] is True
