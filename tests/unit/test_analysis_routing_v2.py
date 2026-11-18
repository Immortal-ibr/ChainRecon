"""Evidence classification determines which case analyzers may run."""

import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from chainrecon.analysis_catalog import ANALYZER_KINDS, BY_KIND, IMPORT_OPTIONS, analyzer_for_kind
from chainrecon.case_analysis import CaseAnalysisService, analyze_evidence
from chainrecon.case_model import Case
from chainrecon.firmware_engine import FirmwareEngine
from chainrecon.v2_cli import dispatch


def test_every_import_option_has_one_explicit_analysis_policy() -> None:
    assert len(BY_KIND) == len(set(BY_KIND))
    assert {kind for _, kind in IMPORT_OPTIONS} == set(BY_KIND) - {"legacy_result"}
    for kind, spec in BY_KIND.items():
        assert analyzer_for_kind(kind) == spec.analyzer
        if spec.analyzer is not None:
            assert kind in ANALYZER_KINDS[spec.analyzer]
    assert analyzer_for_kind("uart_log") is None
    assert analyzer_for_kind("frida_summary") is None


def test_mismatched_analyzers_do_not_create_runs(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    source = tmp_path / "scan.xml"
    source.write_text("<nmaprun/>", encoding="utf-8")
    scan = case.add_evidence(source, kind="scan_xml")
    with pytest.raises(ValueError, match="does not accept scan_xml"):
        CaseAnalysisService(case).run(scan.id, "apk")
    with pytest.raises(ValueError, match="does not accept scan_xml"):
        FirmwareEngine().analyze(case, scan.id)
    with pytest.raises(ValueError, match="use scan"):
        analyze_evidence(case, scan.id, analyzer="traffic")
    assert case.manifest["runs"] == []
    assert not (case.root / "runs").exists()


def test_case_cli_auto_selects_scan_and_reports_unsupported_input(tmp_path: Path, capsys) -> None:
    case = Case.create(tmp_path / "case")
    source = tmp_path / "scan.xml"
    source.write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.3"/></host></nmaprun>', encoding="utf-8")
    case.add_evidence(source, kind="scan_xml")
    assert dispatch(["case", "analyze", str(case.root)]) == 0
    assert '"status": "complete"' in capsys.readouterr().out
    assert len(Case.open(case.root).manifest["runs"]) == 1
    with pytest.raises(ValueError, match="No traffic evidence"):
        dispatch(["case", "analyze", str(case.root), "--analyzer", "traffic"])
    assert len(Case.open(case.root).manifest["runs"]) == 1


def test_manual_only_evidence_has_explicit_error(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    source = tmp_path / "serial.txt"
    source.write_text("boot complete", encoding="utf-8")
    uart = case.add_evidence(source, kind="uart_log")
    with pytest.raises(ValueError, match="No built-in analyzer accepts uart_log"):
        analyze_evidence(case, uart.id)
    assert case.manifest["runs"] == []


def test_incomplete_apk_decode_is_partial_and_records_portable_paths(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    apk_file = tmp_path / "application.apk"
    apk_file.write_bytes(b"synthetic APK fixture")
    apk = case.add_evidence(apk_file, kind="apk")
    result = {
        "metadata": {"apk": str(case.evidence_path(apk.id)),
                     "decompiled_dir": str(tmp_path / "outside"),
                     "jadx_error_count": 2, "jadx_exit_code": 1, "manifest_decoded": False},
        "findings": {"permissions": []},
        "summary": {"permission_count": 0, "jadx_error_count": 2},
        "risk_indicators": [],
    }
    with patch("chainrecon.analysis.apk_analyzer.APKAnalyzer.analyze", return_value=result):
        run = analyze_evidence(case, apk.id)
    assert run.status == "partial"
    assert len(run.warnings) == 3
    artifact = json.loads((case.root / run.artifacts[0]).read_text(encoding="utf-8"))
    assert artifact["metadata"]["apk"] == apk.path
    assert artifact["metadata"]["decompiled_dir"].startswith("runs/")
    assert str(tmp_path) not in (case.root / run.artifacts[0]).read_text(encoding="utf-8")


def test_packet_observations_name_seen_endpoints_without_sensitive_uri(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    capture = tmp_path / "traffic.pcap"
    capture.write_bytes(b"synthetic packet fixture")
    ref = case.add_evidence(capture, kind="pcap")
    result = {
        "metadata": {"source": str(case.evidence_path(ref.id)), "packet_count": 4},
        "findings": {
            "dns_queries": [{"query": "example.org"}],
            "http_requests": [{"method": "GET", "host": "camera.example.org", "uri": "/secret-token"}],
            "tls_sni": [{"server_name": "api.example.org"}],
            "external_ips": ["198.51.100.9"],
        },
        "summary": {"dns_query_count": 1, "http_request_count": 1, "tls_sni_count": 1,
                    "result_truncated": False},
        "risk_indicators": [],
    }
    with patch("chainrecon.analysis.traffic.TrafficAnalyzer.analyze_pcap", return_value=result):
        run = analyze_evidence(case, ref.id)
    summaries = {item.summary for item in run.observations}
    assert {"DNS query example.org", "HTTP GET to camera.example.org", "TLS SNI api.example.org",
            "External IP 198.51.100.9"} <= summaries
    assert all("secret-token" not in summary for summary in summaries)
    assert run.coverage["dns_query_count"] == 1
    assert run.coverage["result_truncated"] is False


def test_scan_service_leads_do_not_become_candidate_findings(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    source = tmp_path / "scan.xml"
    source.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.9"/>'
        '<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
        '<port protocol="udp" portid="1900"><state state="open|filtered"/></port></ports>'
        '</host></nmaprun>', encoding="utf-8",
    )
    ref = case.add_evidence(source, kind="scan_xml")
    run = analyze_evidence(case, ref.id)
    assert run.status == "complete"
    assert run.findings == ()
    summaries = {item.summary for item in run.observations}
    assert "telnet on port 23" in summaries
    assert "udp on port 1900" in summaries
    assert run.coverage["scanned_port_count"] == 2


def test_non_nmap_xml_is_not_a_complete_empty_scan(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    source = tmp_path / "other.xml"
    source.write_text("<other><!-- <nmaprun --></other>", encoding="utf-8")
    ref = case.add_evidence(source, kind="scan_xml")
    run = analyze_evidence(case, ref.id)
    assert run.status == "failed"
    assert any("Expected Nmap XML root" in warning for warning in run.warnings)
    assert run.coverage["result_complete"] is False


def test_complete_apk_metadata_keeps_component_and_permission_names(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    source = tmp_path / "app.apk"
    source.write_bytes(b"synthetic APK fixture")
    ref = case.add_evidence(source, kind="apk")
    result = {
        "metadata": {"manifest_decoded": True, "jadx_exit_code": 0, "jadx_error_count": 0},
        "findings": {
            "components": [{"type": "activity", "name": "com.example.Main"}],
            "permissions": [{"permission": "android.permission.INTERNET"}],
        },
        "summary": {"permission_count": 1, "jadx_error_count": 0},
        "risk_indicators": [],
    }
    with patch("chainrecon.analysis.apk_analyzer.APKAnalyzer.analyze", return_value=result):
        run = analyze_evidence(case, ref.id)
    assert run.status == "complete"
    assert {item.summary for item in run.observations} == {
        "activity com.example.Main", "Permission android.permission.INTERNET",
    }


def test_workflow_adapter_preserves_step_sources_and_unverified_leads(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("name: fixture", encoding="utf-8")
    pipeline_ref = case.add_evidence(pipeline, kind="other")
    scan = tmp_path / "scan.xml"
    scan.write_text("<nmaprun/>", encoding="utf-8")
    scan_ref = case.add_evidence(scan, kind="scan_xml")
    result = {
        "metadata": {"pipeline_sha256": "fixture"},
        "summary": {"status": "completed_with_errors", "step_count": 2, "completed_step_count": 1,
                    "failed_step_count": 1},
        "findings": {"steps": {
            "scan": {"type": "scan", "status": "complete", "evidence_id": scan_ref.id,
                     "risk_indicators": ["not a finding", {"severity": "UNKNOWN", "title": "Verify service"}]},
            "review": {"type": "review", "status": "failed", "error": "researcher input needed",
                       "result": {"risk_indicators": [{"severity": "low", "title": "Review note"}]}},
        }},
    }
    run = CaseAnalysisService(case).record_workflow(
        f"run-{uuid.uuid4().hex}", (pipeline_ref.id,), result, started_at="2026-11-18T00:00:00Z",
    )
    assert run.status == "partial"
    assert set(run.input_ids) == {pipeline_ref.id, scan_ref.id}
    assert {item.evidence_id for item in run.observations} == {pipeline_ref.id, scan_ref.id}
    assert {item.title for item in run.findings} == {"Verify service", "Review note"}
    assert {item.severity for item in run.findings} == {"info", "low"}
    assert run.warnings == ("researcher input needed",)
