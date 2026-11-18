"""Case integrity, migration, review, and export security gates."""

from __future__ import annotations

import csv
import json
import shutil
import tomllib
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from openpyxl import load_workbook

from chainrecon.case_model import Case, Finding, Observation, RunRecord, record_legacy_result
from chainrecon.case_analysis import CaseAnalysisService
from chainrecon.case_reporting import export_case_report
from chainrecon.plugins.csv_export import CsvExportPlugin
from chainrecon.plugins.html_report import HtmlReportPlugin
from chainrecon.plugins.xlsx_report import XlsxReportPlugin
from chainrecon.v2_cli import dispatch
from chainrecon.version import VERSION


def _sample_run(evidence_id: str, *, title: str = "Review me") -> RunRecord:
    observation = Observation(f"obs-{uuid.uuid4().hex}", "test.fact", "Synthetic observation", evidence_id, "offset:4", "high")
    finding = Finding(f"finding-{uuid.uuid4().hex}", title, "medium", "candidate", (observation.id,), "Needs review")
    return RunRecord(f"run-{uuid.uuid4().hex}", "fixture", "complete", (evidence_id,), "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", {"fixture": "1"}, {}, (), {"bytes_examined": 4}, (observation,), (finding,))


def test_recorded_version_matches_package_metadata() -> None:
    project = tomllib.loads((Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert VERSION == project["version"]


def test_case_evidence_is_copied_verified_and_portable(tmp_path: Path) -> None:
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"firmware raw evidence")
    case = Case.create(tmp_path / "case", "Portable fixture")
    first = case.add_evidence(source, kind="firmware")
    source.write_bytes(b"mutated source")
    assert case.evidence_path(first.id).read_bytes() == b"firmware raw evidence"
    assert case.add_evidence(case.evidence_path(first.id), kind="firmware") == first
    with pytest.raises(ValueError, match="already imported as firmware"):
        case.add_evidence(case.evidence_path(first.id), kind="other")
    assert len(case.manifest["evidence"]) == 1
    moved = tmp_path / "moved-case"
    shutil.copytree(case.root, moved)
    reopened = Case.open(moved)
    assert reopened.evidence_path(first.id).read_bytes() == b"firmware raw evidence"
    assert str(tmp_path) not in (moved / "case.json").read_text(encoding="utf-8")
    stored = reopened.evidence_path(first.id)
    stored.chmod(0o644)
    stored.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        reopened.evidence_path(first.id)


def test_case_rejects_manifest_path_escape_and_rebuilds_index(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_text("evidence", encoding="utf-8")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source)
    run = _sample_run(ref.id)
    case.add_run(run)
    case.review_finding(run.findings[0].id, "confirmed", note="Reproduced", reviewer="analyst")
    case.review_finding(run.findings[0].id, "rejected", note="False positive", reviewer="reviewer")
    assert len(case.manifest["review_history"]) == 2
    assert case.query("findings")[0]["status"] == "rejected"
    (case.root / "index.sqlite3").unlink()
    rebuilt = Case.open(case.root)
    assert rebuilt.query("findings")[0]["status"] == "rejected"
    manifest = json.loads((case.root / "case.json").read_text(encoding="utf-8"))
    manifest["evidence"][0]["path"] = "../outside"
    (case.root / "case.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid evidence reference"):
        Case.open(case.root).evidence_path(ref.id)


def test_legacy_result_import_preserves_uncertainty(tmp_path: Path) -> None:
    source = tmp_path / "old.json"
    source.write_text(json.dumps({"findings": [{"name": "port 80"}], "risk_indicators": [{"severity": "high", "title": "Reported risk"}]}), encoding="utf-8")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source, kind="legacy_result")
    run = record_legacy_result(case, ref.id, json.loads(source.read_text()), analyzer="v1-import")
    assert run.status == "complete"
    assert run.coverage["source_analysis_reexecuted"] is False
    assert run.findings[0].status == "candidate"
    assert run.observations[0].locator == "findings.items"
    assert run.findings[0].observation_ids == (run.observations[-1].id,)


def test_case_rejects_run_path_escape_and_unlinked_findings(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"raw")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source)
    run = _sample_run(ref.id)
    with pytest.raises(ValueError, match="Invalid run ID"):
        case.add_run(replace(run, id="../outside"))
    assert not (tmp_path / "outside").exists()
    with pytest.raises(ValueError, match="link to observations"):
        case.add_run(replace(run, findings=(replace(run.findings[0], observation_ids=("missing",)),)))
    assert not list((case.root / "runs").glob("*/run.json"))


def test_stale_case_writer_detects_revision_conflict(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"raw")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source)
    run = _sample_run(ref.id)
    case.add_run(run)
    first = Case.open(case.root)
    stale = Case.open(case.root)
    first.review_finding(run.findings[0].id, "confirmed", reviewer="first")
    with pytest.raises(RuntimeError, match="changed on disk"):
        stale.review_finding(run.findings[0].id, "rejected", reviewer="stale")
    assert Case.open(case.root).manifest["reviews"][run.findings[0].id]["status"] == "confirmed"


def test_case_report_has_provenance_and_review_decision(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"1234")
    case = Case.create(tmp_path / "case", "Disclosure fixture")
    ref = case.add_evidence(source)
    run = _sample_run(ref.id)
    case.add_run(run)
    case.review_finding(run.findings[0].id, "confirmed", reviewer="analyst", note="Verified")
    path = export_case_report(case, "json", tmp_path / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))["case"]
    assert data["findings"]["reviewed_findings"][0]["status"] == "confirmed"
    assert data["findings"]["reviewed_findings"][0]["review_note"] == "Verified"
    assert data["findings"]["observations"][0]["locator"] == "offset:4"
    assert data["findings"]["runs"][0]["coverage"]["bytes_examined"] == 4
    assert data["findings"]["review_history"][0]["reviewer"] == "analyst"


def test_case_html_report_shows_review_and_escapes_untrusted_fields(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"1234")
    case = Case.create(tmp_path / "case", "<script>alert(1)</script>")
    ref = case.add_evidence(source)
    run = _sample_run(ref.id, title="<img src=x onerror=alert(1)>")
    case.add_run(run)
    case.review_finding(run.findings[0].id, "confirmed", reviewer="analyst", note="Reproduced at offset 4")
    html = export_case_report(case, "html", tmp_path / "case.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "offset:4" in html
    assert "Reproduced at offset 4" in html
    assert "bytes_examined" in html
    assert "Review history" in html


@pytest.mark.parametrize("payload", ["=1+1", " +SUM(1,1)", "\t@cmd", "-2+3"])
def test_spreadsheet_export_neutralizes_formulas(tmp_path: Path, payload: str) -> None:
    data = {"case": {"metadata": {}, "summary": {}, "findings": {"values": [payload]}, "risk_indicators": []}}
    csv_path = tmp_path / "out.csv"
    CsvExportPlugin().generate(data, str(csv_path))
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert any(str(value).startswith("'") and payload in str(value) for row in rows for value in row.values())
    xlsx_path = tmp_path / "out.xlsx"
    XlsxReportPlugin().generate(data, str(xlsx_path))
    workbook = load_workbook(xlsx_path, read_only=True, data_only=False)
    cells = [cell.value for sheet in workbook for row in sheet for cell in row]
    assert any(isinstance(value, str) and value.startswith("'") and payload in value for value in cells)


def test_html_export_escapes_markup_and_redacts_secrets(tmp_path: Path) -> None:
    data = {"case": {"metadata": {"title": "<svg onload=alert(1)>"}, "summary": {}, "findings": {"password": "hunter2"}, "risk_indicators": [{"severity": "high", "title": "<img src=x onerror=alert(1)>", "details": "token=abc123"}]}}
    path = tmp_path / "out.html"
    HtmlReportPlugin().generate(data, str(path))
    html = path.read_text(encoding="utf-8")
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "hunter2" not in html
    assert "abc123" not in html


def test_new_cli_case_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "case"
    assert dispatch(["case", "init", str(root), "--title", "CLI fixture"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["case"] == str(root)
    source = tmp_path / "uart.log"
    source.write_text("boot", encoding="utf-8")
    assert dispatch(["case", "add", str(root), str(source), "--kind", "uart_log"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "uart_log"
    assert dispatch(["case", "verify", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] == 1


def test_workflow_run_is_recorded_in_case_with_pipeline_evidence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    case = Case.create(tmp_path / "case")
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("name: Case workflow\nsteps:\n  - id: approval\n    type: review\n    prompt: Inspect the capture\n", encoding="utf-8")
    assert dispatch(["workflow", "run", str(pipeline), "--case", str(case.root)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["status"] == "needs_input"
    reopened = Case.open(case.root)
    assert len(reopened.manifest["evidence"]) == 1
    assert reopened.manifest["runs"][0]["status"] == "needs_input"
    assert reopened.query("observations")[0]["kind"] == "workflow.step"


def test_case_scan_uses_xml_content_even_without_file_extension(tmp_path: Path) -> None:
    source = tmp_path / "scan.xml"
    source.write_text('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>', encoding="utf-8")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source, kind="scan_xml")
    run = CaseAnalysisService(case).run(ref.id, "scan")
    assert run.status == "complete"
    result = json.loads((case.root / run.artifacts[0]).read_text(encoding="utf-8"))
    assert result["summary"]["open_port_count"] == 1
    assert result["metadata"]["source"] == ref.path
    assert run.coverage["host_up_count"] == 1
    assert any(item["kind"] == "scan.hosts" and "192.0.2.10" in item["summary"]
               for item in case.get_run(run.id)["observations"])


def test_case_scan_rejects_text_and_traffic_limit_marks_partial(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    text_scan = tmp_path / "scan.txt"
    text_scan.write_text("80/tcp open http\n", encoding="utf-8")
    scan_ref = case.add_evidence(text_scan, kind="scan_xml")
    scan = CaseAnalysisService(case).run(scan_ref.id, "scan")
    assert scan.status == "failed"
    assert any("Nmap XML" in warning for warning in scan.warnings)
    capture = tmp_path / "traffic.pcap"
    capture.write_bytes(b"synthetic capture")
    capture_ref = case.add_evidence(capture, kind="pcap")
    result = {"metadata": {}, "findings": {}, "summary": {"result_truncated": True}, "risk_indicators": []}
    with patch("chainrecon.analysis.traffic.TrafficAnalyzer.analyze_pcap", return_value=result):
        traffic = CaseAnalysisService(case).run(capture_ref.id, "traffic")
    assert traffic.status == "partial"
    assert traffic.coverage["source_processed"] is True
    assert traffic.coverage["result_complete"] is False
    assert any("bound" in warning for warning in traffic.warnings)


def test_case_frida_log_redacts_payload_and_preserves_event_locator(tmp_path: Path) -> None:
    source = tmp_path / "session.log"
    source.write_text("[HOOK] arbitrary-payload\n[HTTP-REQ] request-body\n[STATUS] attached\n", encoding="utf-8")
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source, kind="frida_log")
    run = CaseAnalysisService(case).run(ref.id, "frida_log")
    artifact = (case.root / run.artifacts[0]).read_text(encoding="utf-8")
    assert "arbitrary-payload" not in artifact
    assert "request-body" not in artifact
    assert "CONTENT REDACTED" in artifact
    assert "HTTP-REQ" in artifact
    assert "analysis.json:findings.events[0]" == run.observations[0].locator


def test_streamed_pcap_case_records_ipv6_dns_http_and_mqtt(tmp_path: Path) -> None:
    pytest.importorskip("scapy.all")
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, IPv6, Raw, TCP, UDP, wrpcap

    source = tmp_path / "traffic.pcap"
    topic = b"lab/status"
    mqtt = bytes([0x30, len(topic) + 2 + 2]) + len(topic).to_bytes(2, "big") + topic + b"ok"
    def ethernet():
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    packets = [
        ethernet()/IP(src="192.0.2.10", dst="192.0.2.53")/UDP(sport=53000, dport=53)/DNS(id=1, qr=1, qd=[DNSQR(qname="lab.example.test")], an=[DNSRR(rrname="lab.example.test", type="A", rdata="203.0.113.8")], ancount=1),
        ethernet()/IPv6(src="2001:db8::10", dst="2001:db8::20")/TCP(sport=40000, dport=80)/Raw(load=b"GET /status HTTP/1.1\r\nHost: lab.example.test\r\n\r\n"),
        ethernet()/IP(src="192.0.2.10", dst="192.0.2.20")/TCP(sport=40001, dport=1883)/Raw(load=mqtt),
        ethernet()/IP(src="192.0.2.10", dst="192.0.2.30")/UDP(sport=50000, dport=3478)/Raw(load=b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"123456789012"),
    ]
    wrpcap(str(source), packets)
    case = Case.create(tmp_path / "case")
    ref = case.add_evidence(source, kind="pcap")
    with patch("chainrecon.analysis.traffic.shutil.which", return_value=None):
        run = CaseAnalysisService(case).run(ref.id, "traffic")
    assert run.status == "complete"
    result = json.loads((case.root / run.artifacts[0]).read_text(encoding="utf-8"))
    assert result["metadata"]["packet_count"] == 4
    assert result["summary"]["dns_answer_count"] == 1
    assert result["summary"]["http_request_count"] == 1
    assert result["summary"]["mqtt_event_count"] == 1
    assert result["summary"]["media_event_count"] == 1
    assert result["findings"]["media_events"][0]["protocol"] == "STUN"
    assert result["findings"]["mqtt_events"][0]["topic"] == "lab/status"
    assert any(item["src_ip"] == "2001:db8::10" for item in result["findings"]["conversations"])
    assert not result["risk_indicators"]
