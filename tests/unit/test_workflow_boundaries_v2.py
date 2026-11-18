"""Workflow parsing, input, resume, and failure boundaries."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chainrecon.runners.workflow_runner import WorkflowRunner, _extract_open_ports, _safe_condition


def _pipeline(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize("condition,expected", [
    ("count > 2 and count >= 3 and count < 4 and count <= 3", True),
    ("count != 3 or count not in [2, 3]", False),
    ("count in [2, 3] and 'lab' in label", True),
    ("count > 'text'", False),
    ("missing not in 5", True),
    ("not False and (True, False) != (False, True)", True),
])
def test_condition_language_handles_data_only_comparisons(condition: str, expected: bool):
    assert _safe_condition(condition, {"count": 3, "label": "lab camera"}) is expected


@pytest.mark.parametrize("condition,message", [
    ("x ==", "syntax"),
    ("x" * 1001, "too long"),
    (" or ".join(["False"] * 85), "too complex"),
    ("b'bytes'", "literal"),
    ("_secret == 1", "Private names"),
    ("step._hidden == 1", "Private attributes"),
])
def test_condition_language_rejects_invalid_or_excessive_expressions(condition: str, message: str):
    with pytest.raises(ValueError, match=message):
        _safe_condition(condition, {})


def test_typed_inputs_reject_lossy_or_nonfinite_numbers():
    runner = WorkflowRunner()
    specs = {"tries": {"type": "integer"}, "ratio": {"type": "number"}, "enabled": {"type": "boolean"}}
    assert runner._typed_inputs(specs, {"tries": "-2", "ratio": "1.5", "enabled": "true"}) == {"tries": -2, "ratio": 1.5, "enabled": True}
    for bad in (1.9, True, "1.9", "1e3", []):
        with pytest.raises(ValueError, match="Invalid workflow input tries"):
            runner._typed_inputs(specs, {"tries": bad})
    for bad in (True, "nan", "inf", "-inf", "not-a-number"):
        with pytest.raises(ValueError, match="Invalid workflow input ratio"):
            runner._typed_inputs(specs, {"ratio": bad})
    for bad in (1, "yes"):
        with pytest.raises(ValueError, match="Invalid workflow input enabled"):
            runner._typed_inputs(specs, {"enabled": bad})


def test_typed_input_schema_rejects_undeclared_or_unsafe_inputs():
    runner = WorkflowRunner()
    with pytest.raises(ValueError, match="does not declare"):
        runner._typed_inputs(None, {"host": "lab"})
    with pytest.raises(ValueError, match="must be a mapping"):
        runner._typed_inputs([], {})
    with pytest.raises(ValueError, match="Undeclared"):
        runner._typed_inputs({}, {"host": "lab"})
    with pytest.raises(ValueError, match="safe names"):
        runner._typed_inputs({"x/y": {"type": "string"}}, {})
    with pytest.raises(ValueError, match="Unsupported workflow input type"):
        runner._typed_inputs({"host": {"type": "python"}}, {})
    with pytest.raises(ValueError, match="Invalid workflow input host"):
        runner._typed_inputs({"host": {"type": "string"}}, {"host": 7})


@pytest.mark.parametrize("content,message", [
    ("- not-a-mapping\n", "YAML mapping"),
    ("steps: {}\n", "must be a list"),
    ("steps:\n  - text\n", "must be a mapping"),
    ("steps:\n  - id: first\n", "missing a type"),
    ("steps:\n  - id: first\n    type: execute_python\n", "unsupported type"),
    ("steps:\n  - id: first\n    type: assert\n    when: steps.later.status == 'completed'\n  - id: later\n    type: review\n", "before they execute"),
    ("steps:\n  - id: first\n    type: assert\n    when: steps.missing.status == 'completed'\n", "unknown step"),
])
def test_pipeline_preflight_rejects_invalid_definitions_without_artifacts(tmp_path: Path, content: str, message: str):
    pipeline = _pipeline(tmp_path, content)
    with pytest.raises(ValueError, match=message):
        WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline))
    assert not (tmp_path / "runs").exists()


def test_resume_rejects_corrupt_document_and_dry_run(tmp_path: Path):
    pipeline = _pipeline(tmp_path, "steps:\n  - id: review\n    type: review\n")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    paused = runner.run(str(pipeline))
    path = Path(paused["metadata"]["summary_file"])
    with pytest.raises(ValueError, match="dry run"):
        runner.run(str(pipeline), resume_file=str(path), dry_run=True)
    original = path.read_text(encoding="utf-8")
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="workflow report"):
        runner.run(str(pipeline), resume_file=str(path))
    saved = json.loads(original)
    saved["findings"]["steps"]["review"] = {"status": "made-up"}
    path.write_text(json.dumps(saved), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid step records"):
        runner.run(str(pipeline), resume_file=str(path))


@pytest.mark.parametrize("critical,step_status,expected", [
    (True, "failed", "failed"),
    (False, "failed", "completed_with_errors"),
    (True, "partial", "partial"),
    (False, "partial", "partial"),
    (True, "needs_input", "needs_input"),
])
def test_step_status_propagates_and_critical_steps_stop(tmp_path: Path, critical: bool, step_status: str, expected: str):
    pipeline = _pipeline(tmp_path, f"steps:\n  - id: first\n    type: assert\n    critical: {str(critical).lower()}\n    condition: 'True'\n  - id: after\n    type: assert\n    condition: 'True'\n")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    original = runner._execute_step
    def execute(step_id, *args):
        if step_id == "first":
            return {"type": "assert", "status": step_status, "result": {"summary": {"fixture": True}}}
        return original(step_id, *args)
    with patch.object(runner, "_execute_step", side_effect=execute):
        result = runner.run(str(pipeline))
    assert result["summary"]["status"] == expected
    should_continue = step_status != "needs_input" and (not critical or step_status not in {"failed", "partial"})
    assert ("after" in result["findings"]["steps"]) is should_continue


def test_open_port_extraction_ignores_closed_and_malformed_entries():
    result = {"findings": {"hosts": [
        "not-a-host",
        {"services": [{"port": 80, "state": "open"}, {"port": "bad"}, {"port": 23, "state": "closed"}], "ports": [{"port": "443"}, "not-a-port"]},
    ]}}
    assert _extract_open_ports(result) == [80, 443]


def test_missing_step_inputs_fail_before_external_tools_run(tmp_path: Path):
    runner = WorkflowRunner()
    for call, message in (
        (lambda: runner._step_scan("s", {}, tmp_path), "requires a target"),
        (lambda: runner._step_tls_scan("s", {}, tmp_path), "requires a target"),
        (lambda: runner._step_pcap("s", {}, tmp_path), "requires a pcap"),
        (lambda: runner._step_frida("s", {}, tmp_path), "requires a target"),
        (lambda: runner._step_frida("s", {"target": "lab.app"}, tmp_path), "requires a script"),
        (lambda: runner._step_firmware("s", {}, tmp_path, {}), "requires an evidence_id"),
        (lambda: runner._step_firmware("s", {"evidence_id": "ev-test"}, tmp_path, {}), "requires a case-backed"),
        (lambda: runner._step_firmware("s", {"rules": "unsafe"}, tmp_path, {}), "rules are not supported"),
        (lambda: runner._step_community("s", {}, tmp_path), "requires a plugin"),
        (lambda: runner._step_assert("s", {}, {}, {}), "requires a condition"),
        (lambda: runner._step_assert("s", {"condition": "False", "message": "failed verification"}, {}, {}), "failed verification"),
    ):
        with pytest.raises((ValueError, AssertionError), match=message):
            call()


def test_tls_scan_uses_observed_probe_results_without_live_network(tmp_path: Path):
    runner = WorkflowRunner()
    with patch("chainrecon.runners.workflow_runner.SSLAnalyzer") as analyzer_type:
        analyzer = analyzer_type.return_value
        analyzer.probe_certificates.return_value = {"findings": {"certificates": [{"port": 443}]}, "summary": {"certificate_count": 1, "reachable_ports": 1}}
        analyzer.analyze_ciphers.return_value = {"findings": {"cipher_analysis": []}, "summary": {"weak_cipher_count": 0}}
        analyzer.assess_tls_security.return_value = {"findings": {"security_findings": []}, "summary": {"risk_rating": "low"}, "risk_indicators": []}
        step = runner._step_tls_scan("tls", {"target": "lab.example.test", "ports": [443]}, tmp_path)
    assert step["status"] == "completed"
    assert step["result"]["summary"]["certificate_count"] == 1
    assert step["result"]["risk_indicators"] == []


def test_pcap_step_marks_truncation_and_rejects_unknown_analyzer(tmp_path: Path):
    runner = WorkflowRunner()
    result = {"metadata": {}, "summary": {"result_truncated": True}, "findings": {}, "risk_indicators": []}
    with patch("chainrecon.runners.workflow_runner.TrafficAnalyzer.analyze_pcap", return_value=result):
        partial = runner._step_pcap("traffic", {"pcap": "capture.pcap"}, tmp_path)
    assert partial["status"] == "partial"
    assert partial["result"]["summary"]["result_truncated"] is True
    with patch("chainrecon.runners.workflow_runner.CertAnalyzer.analyze_pcap", return_value={"summary": {}, "findings": {}}):
        cert = runner._step_pcap("cert", {"input": "capture.pcap", "analyzer": "cert"}, tmp_path)
    assert cert["status"] == "completed"
    closed = {"value": False}
    capture = SimpleNamespace(close=lambda: closed.__setitem__("value", True))
    with patch("chainrecon.runners.workflow_runner.TrafficAnalyzer._load_packets", return_value=([], capture)):
        with pytest.raises(ValueError, match="Unsupported pcap analyzer"):
            runner._step_pcap("wrong", {"pcap": "capture.pcap", "analyzer": "execute"}, tmp_path)
    assert closed["value"] is True


def test_frida_step_marks_failed_and_truncated_sessions(tmp_path: Path):
    runner = WorkflowRunner()
    with patch("chainrecon.runners.workflow_runner.FridaRunner") as runner_type:
        instrument = runner_type.return_value
        instrument.run_script.return_value = {"returncode": 1, "stdout": "[ERROR] attach failed"}
        failed = runner._step_frida("runtime", {"target": "lab.app", "script": "http_trace"}, tmp_path)
        assert failed["status"] == "failed"
        instrument.render_script.return_value = tmp_path / "rendered.js"
        instrument.spawn_and_run.return_value = {"returncode": 0, "stdout": "[STATUS] ready\n" * 10_001}
        partial = runner._step_frida("runtime", {"target": "lab.app", "script": "http_trace", "parameters": {"tag": "lab"}, "spawn": True}, tmp_path)
    assert partial["status"] == "partial"
    assert partial["result"]["summary"]["events_recorded"] == 10_000
    assert partial["result"]["summary"]["events_truncated"] == 1


def test_template_paths_resolve_only_data_fields():
    runner = WorkflowRunner()
    context = {"target": "lab", "steps": {"scan": {"summary": {"ports": [80]}}}}
    assert runner._render_value({"values": ["{{target}}", "${steps.scan.summary.ports}"]}, context) == {"values": ["lab", "[80]"]}
    assert runner._render_value("{{steps.missing}}", context) == ""
    assert runner._resolve_path({"target": "lab"}, "target.nested") is None
    with pytest.raises(ValueError, match="Invalid workflow template path"):
        runner._render_value("{{steps.__class__}}", context)
