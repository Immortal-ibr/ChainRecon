"""The live capture screen records a reproducible case when one is active."""

from __future__ import annotations

from pathlib import Path

import pytest

from chainrecon.case_model import Case, file_sha256
from chainrecon.tui.screens.capture import _record_case_capture


def test_capture_is_copied_and_analyzed_in_case(tmp_path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    pcap = tmp_path / "capture.pcap"
    scapy.wrpcap(str(pcap), [scapy.Ether() / scapy.IP(src="192.0.2.10", dst="192.0.2.20") / scapy.TCP(sport=40001, dport=80)])
    case = Case.create(tmp_path / "case", "Capture case")
    digest = file_sha256(pcap)

    run_ids = _record_case_capture([str(pcap)], str(case.root))

    reopened = Case.open(case.root)
    assert len(run_ids) == 1
    assert reopened.manifest["evidence"][0]["sha256"] == digest
    assert next(iter(reopened.iter_runs()))["status"] == "complete"


def test_capture_without_artifact_is_not_reported_complete(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case", "Capture case")
    with pytest.raises(FileNotFoundError, match="Capture output missing"):
        _record_case_capture([str(tmp_path / "missing.pcap")], str(case.root))
    assert Case.open(case.root).manifest["runs"] == []
