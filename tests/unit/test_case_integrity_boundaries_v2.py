"""Reject corrupted case records and keep imported analyzer claims reviewable."""

import json
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from chainrecon.case_analysis import CaseAnalysisService
from chainrecon.case_model import Case, Finding, Observation, RunRecord, record_legacy_result


def _run(evidence_id: str) -> RunRecord:
    observation = Observation(f"obs-{uuid.uuid4().hex}", "test", "fact", evidence_id, "offset:0")
    finding = Finding(f"finding-{uuid.uuid4().hex}", "review", "low", observation_ids=(observation.id,))
    return RunRecord(
        f"run-{uuid.uuid4().hex}", "fixture", "complete", (evidence_id,), "start", "end",
        observations=(observation,), findings=(finding,),
    )


def _case(tmp_path: Path, *, kind: str = "other") -> tuple[Case, str]:
    source = tmp_path / "source.bin"
    source.write_bytes(b"evidence")
    case = Case.create(tmp_path / "case")
    return case, case.add_evidence(source, kind=kind).id


def test_case_open_rejects_incompatible_and_malformed_manifests(tmp_path: Path):
    case, _ = _case(tmp_path)
    path = case.root / "case.json"
    original = json.loads(path.read_text(encoding="utf-8"))
    for changes, message in (
        ({"schema_version": 99}, "Unsupported case schema"),
        ({"evidence": {}}, "invalid evidence or run records"),
        ({"runs": {}}, "invalid evidence or run records"),
    ):
        path.write_text(json.dumps({**original, **changes}), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            Case.open(case.root)
    path.write_text(json.dumps(original), encoding="utf-8")


def test_case_open_retries_brief_manifest_sharing_violation(tmp_path: Path, monkeypatch):
    case, _ = _case(tmp_path)
    manifest_path = case.root / "case.json"
    read_text = Path.read_text
    attempts = 0

    def intermittent_read(path: Path, *args, **kwargs) -> str:
        nonlocal attempts
        if path == manifest_path:
            attempts += 1
            if attempts < 3:
                raise PermissionError("manifest briefly locked")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", intermittent_read)
    with patch("chainrecon.case_model.time.sleep") as pause:
        assert Case.open(case.root).manifest["case_id"] == case.manifest["case_id"]
    assert attempts == 3
    assert pause.call_count == 2

    with patch.object(Path, "read_text", side_effect=PermissionError("manifest remains locked")):
        with patch("chainrecon.case_model.time.sleep") as pause:
            with pytest.raises(PermissionError, match="remains locked"):
                Case.open(case.root)
            assert pause.call_count == 3


def test_case_rejects_invalid_evidence_kinds_and_nonfiles(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    with pytest.raises(ValueError, match="Unsupported evidence kind"):
        case.add_evidence(tmp_path / "source.bin", kind="shell_command")
    with pytest.raises(ValueError, match="regular file"):
        case.add_evidence(tmp_path, kind="other")
    with pytest.raises(KeyError, match="Unknown evidence"):
        case.evidence("ev-missing")
    manifest = case.manifest["evidence"][0]
    original = manifest["sha256"]
    manifest["sha256"] = "bad"
    with pytest.raises(ValueError, match="Invalid evidence reference"):
        case.evidence_path(evidence_id)
    manifest["sha256"] = original


def test_run_reference_checks_prevent_unlinked_or_duplicate_records(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    run = _run(evidence_id)
    bad_observation = replace(run.observations[0], evidence_id="ev-outside")
    bad_finding = replace(run.findings[0], observation_ids=())
    for broken, message in (
        (replace(run, input_ids=()), "reference input evidence"),
        (replace(run, input_ids=("ev-unknown",)), "Unknown evidence"),
        (replace(run, observations=(run.observations[0], run.observations[0])), "Duplicate observation IDs"),
        (replace(run, observations=(bad_observation,)), "outside run inputs"),
        (replace(run, findings=(run.findings[0], run.findings[0])), "Duplicate finding IDs"),
        (replace(run, findings=(bad_finding,)), "link to observations"),
    ):
        with pytest.raises((ValueError, KeyError), match=message):
            case.add_run(broken)
    assert not case.manifest["runs"]
    case.add_run(run)
    with pytest.raises(ValueError, match="already exists"):
        case.add_run(run)
    with pytest.raises(KeyError, match="Unknown run"):
        case.get_run("run-" + "0" * 32)
    case.manifest["runs"][0]["path"] = "../outside.json"
    with pytest.raises(ValueError, match="Invalid run reference"):
        case.get_run(run.id)


def test_review_and_index_queries_reject_invalid_requests(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    run = _run(evidence_id)
    case.add_run(run)
    with pytest.raises(ValueError, match="Invalid finding status"):
        case.review_finding(run.findings[0].id, "autoconfirmed")
    with pytest.raises(KeyError, match="Unknown finding"):
        case.review_finding("missing", "confirmed")
    with pytest.raises(ValueError, match="Unsupported query table"):
        case.query("evidence; DROP TABLE findings")
    for limit in (-1, 0, 10_001, True):
        with pytest.raises(ValueError, match="Query limit"):
            case.query("evidence", limit=limit)
    assert len(case.query("evidence", limit=1)) == 1


def test_legacy_import_downgrades_malformed_risk_labels(tmp_path: Path):
    case, evidence_id = _case(tmp_path)
    run = record_legacy_result(case, evidence_id, {
        "findings": "old summary", "risk_indicators": ["not a finding", {"severity": "CERTAIN", "title": "Claim"}],
    }, analyzer="v1-import")
    assert run.findings[0].status == "candidate"
    assert run.findings[0].severity == "info"
    assert run.observations[0].kind == "legacy.value"
    assert len(run.findings) == 1


def test_apk_adapter_links_every_candidate_to_raw_evidence(tmp_path: Path):
    case, evidence_id = _case(tmp_path, kind="apk")
    payload = {
        "findings": {"items": [{"title": "Keyword match"}, {"name": "label"}, "unstructured"], "count": 2, "empty": 0},
        "risk_indicators": ["bad shape", {"severity": "CERTAIN", "title": "Review this"}],
        "summary": {},
    }
    with patch("chainrecon.analysis.apk_analyzer.APKAnalyzer.analyze", return_value=payload):
        run = CaseAnalysisService(case).run(evidence_id, "apk")
    assert run.status == "complete"
    assert {item.summary for item in run.observations} >= {"Keyword match", "label", "items item 3", "count observed"}
    assert len(run.findings) == 1
    assert run.findings[0].severity == "info"
    assert run.findings[0].observation_ids[0] in {item.id for item in run.observations}
    assert all(item.evidence_id == evidence_id for item in run.observations)
    with pytest.raises(ValueError, match="Unsupported case analyzer"):
        CaseAnalysisService(case).run(evidence_id, "exec")


def test_frida_log_limit_records_partial_coverage(tmp_path: Path):
    case, _ = _case(tmp_path)
    source = tmp_path / "large-frida.log"
    source.write_text("[EVENT] ready\n" * 3, encoding="utf-8")
    evidence_id = case.add_evidence(source, kind="frida_log").id
    with patch("chainrecon.case_analysis._MAX_FRIDA_LOG_LINES", 2):
        run = CaseAnalysisService(case).run(evidence_id, "frida_log")
    assert run.status == "partial"
    assert run.coverage["result_complete"] is False
    assert any("2 lines" in warning for warning in run.warnings)
    assert len(run.observations) == 2
