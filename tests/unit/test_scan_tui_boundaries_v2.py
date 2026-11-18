"""The scan TUI only publishes findings parsed from Nmap XML evidence."""

from pathlib import Path

import pytest

from chainrecon.case_model import Case, file_sha256
from chainrecon.tui.screens.scan import SCAN_PROFILE_OPTIONS, _build_scan_report_payload, _record_case_scan


def test_scan_report_uses_xml_instead_of_text_output(tmp_path: Path):
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>'
        '</ports></host></nmaprun>', encoding="utf-8",
    )
    text = tmp_path / "scan.txt"
    text.write_text("23/tcp open telnet", encoding="utf-8")
    payload = _build_scan_report_payload({"output_files": [str(text), str(xml)], "target": "192.0.2.10"})
    services = payload["findings"]["hosts"][0]["services"]
    assert {item["port"] for item in services} == {8080}
    assert "fingerprint" not in {value for _, value in SCAN_PROFILE_OPTIONS}


def test_scan_report_fails_without_xml_evidence(tmp_path: Path):
    text = tmp_path / "scan.txt"
    text.write_text("80/tcp open http", encoding="utf-8")
    with pytest.raises(RuntimeError, match="no XML evidence"):
        _build_scan_report_payload({"output_files": [str(text)]})


def test_case_scan_copies_xml_and_links_analysis_to_raw_evidence(tmp_path: Path):
    case = Case.create(tmp_path / "case", "Scan case")
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>'
        '</ports></host></nmaprun>', encoding="utf-8",
    )
    original_hash = file_sha256(xml)
    run_ids = _record_case_scan({"output_files": [str(xml)]}, str(case.root))
    reopened = Case.open(case.root)
    assert len(run_ids) == 1
    assert len(reopened.manifest["evidence"]) == 1
    assert len(reopened.manifest["runs"]) == 1
    evidence = reopened.manifest["evidence"][0]
    assert evidence["sha256"] == original_hash
    assert next(iter(reopened.iter_runs()))["status"] == "complete"


def test_case_scan_refuses_results_without_xml(tmp_path: Path):
    case = Case.create(tmp_path / "case", "Scan case")
    with pytest.raises(ValueError, match="did not provide XML"):
        _record_case_scan({"output_files": []}, str(case.root))
