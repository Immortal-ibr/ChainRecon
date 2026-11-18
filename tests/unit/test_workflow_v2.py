"""Declarative workflow validation, review, resume, and trust boundaries."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from chainrecon.case_model import Case
from chainrecon.runners.workflow_runner import WorkflowRunner, _safe_condition


@pytest.mark.parametrize("condition", [
    "__import__('os').system('echo unsafe')",
    "steps.__class__.__mro__",
    "[item for item in [1, 2]]",
    "(1).__class__",
    "steps['scan'].status == 'completed'",
    "False and __import__('os').system('echo unsafe')",
    "True or steps.__class__",
    "False and [item for item in [1, 2]]",
])
def test_hostile_conditions_are_rejected(condition: str) -> None:
    with pytest.raises(ValueError):
        _safe_condition(condition, {"steps": {"scan": {"status": "completed"}}})


def test_conditions_only_read_declared_data() -> None:
    values = {"steps": {"scan": {"status": "completed", "summary": {"open_ports": [80, 443]}}}}
    assert _safe_condition("steps.scan.status == 'completed' and 443 in steps.scan.summary.open_ports", values)
    assert not _safe_condition("steps.scan.summary.missing and 80 in steps.scan.summary.missing", values)
    assert _safe_condition("not (steps.scan.status == 'failed')", values)


def test_dry_run_creates_no_artifacts_and_validates_typed_inputs(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("""
name: Typed fixture
inputs:
  endpoint:
    type: string
    required: true
  retries:
    type: integer
    default: 2
  enabled:
    type: boolean
    default: false
steps:
  - id: inspect
    type: assert
    condition: "retries >= 2 and enabled == True"
    when: "enabled == True"
""", encoding="utf-8")
    with patch("chainrecon.runners.workflow_runner.get_output_dir", side_effect=AssertionError("dry run accessed user config")):
        result = WorkflowRunner(output_root=tmp_path / "outputs").run(str(pipeline), dry_run=True, inputs={"endpoint": "lab.local", "enabled": "true"})
    assert result["summary"]["planned_step_count"] == 1
    assert result["metadata"]["output_dir"] is None
    assert not (tmp_path / "outputs").exists()
    with pytest.raises(ValueError, match="Required workflow input"):
        WorkflowRunner(output_root=tmp_path / "outputs").run(str(pipeline), dry_run=True)
    with pytest.raises(ValueError, match="Invalid workflow input"):
        WorkflowRunner(output_root=tmp_path / "outputs").run(str(pipeline), dry_run=True, inputs={"endpoint": "lab.local", "enabled": "maybe"})


def test_review_step_pauses_and_resumes_only_with_matching_pipeline(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("""
name: Review fixture
steps:
  - id: approve
    type: review
    prompt: Confirm evidence scope
  - id: verified
    type: assert
    condition: "steps.approve.status == 'completed'"
""", encoding="utf-8")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    paused = runner.run(str(pipeline))
    assert paused["summary"]["status"] == "needs_input"
    assert "verified" not in paused["findings"]["steps"]
    summary_file = Path(paused["metadata"]["summary_file"])
    assert summary_file.is_file()
    resumed = runner.run(str(pipeline), resume_file=str(summary_file), approved_steps=["approve"])
    assert resumed["summary"]["status"] == "completed"
    assert resumed["findings"]["steps"]["verified"]["status"] == "completed"
    pipeline.write_text(pipeline.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="different pipeline revision"):
        runner.run(str(pipeline), resume_file=str(summary_file))


def test_plugin_requires_explicit_trust(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("token", encoding="utf-8")
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text(f"name: plugin fixture\nsteps:\n  - id: strings\n    type: community\n    plugin: example_string_scan\n    input: {json.dumps(str(sample))}\n", encoding="utf-8")
    result = WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline))
    assert result["summary"]["status"] == "failed"
    assert "requires trusted: true" in result["findings"]["steps"]["strings"]["error"]


def test_duplicate_step_id_rejected_before_artifacts(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("steps:\n  - id: one\n    type: review\n  - id: one\n    type: review\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate workflow step ID"):
        WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline))
    assert not (tmp_path / "runs").exists()


def test_invalid_step_id_and_skipped_hostile_condition_fail_preflight(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("steps:\n  - id: a/b\n    type: review\n", encoding="utf-8")
    with pytest.raises(ValueError, match="step ID"):
        WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline), dry_run=True)
    pipeline.write_text("steps:\n  - id: safe\n    type: review\n    when: \"False and __import__('os').system('x')\"\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported workflow condition"):
        WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline), dry_run=True)
    assert not (tmp_path / "runs").exists()


def test_interrupted_workflow_checkpoints_and_resumes_completed_steps(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("steps:\n  - id: first\n    type: assert\n    condition: 'True'\n  - id: second\n    type: assert\n    condition: 'True'\n", encoding="utf-8")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    execute = runner._execute_step

    def interrupted(step_id, *args):
        if step_id == "second":
            raise KeyboardInterrupt()
        return execute(step_id, *args)

    with patch.object(runner, "_execute_step", side_effect=interrupted):
        with pytest.raises(KeyboardInterrupt):
            runner.run(str(pipeline))
    summaries = list((tmp_path / "runs").glob("**/*workflow_summary.json"))
    assert len(summaries) == 1
    saved = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert saved["summary"]["status"] == "interrupted"
    assert saved["findings"]["steps"]["first"]["status"] == "completed"
    assert saved["findings"]["steps"]["second"]["status"] == "interrupted"

    executed: list[str] = []
    def resumed_step(step_id, *args):
        executed.append(step_id)
        return execute(step_id, *args)

    with patch.object(runner, "_execute_step", side_effect=resumed_step):
        resumed = runner.run(str(pipeline), resume_file=str(summaries[0]))
    assert executed == ["second"]
    assert resumed["summary"]["status"] == "completed"
    assert resumed["metadata"]["summary_file"] == str(summaries[0].resolve())


def test_resume_rejects_inconsistent_artifact_directory(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("steps:\n  - id: review\n    type: review\n", encoding="utf-8")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    paused = runner.run(str(pipeline))
    summary = Path(paused["metadata"]["summary_file"])
    data = json.loads(summary.read_text(encoding="utf-8"))
    data["metadata"]["output_dir"] = str(tmp_path / "other")
    summary.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="inconsistent artifact paths"):
        runner.run(str(pipeline), resume_file=str(summary))
    assert not (tmp_path / "other").exists()


def test_resume_rejects_changed_context_and_forged_step_records(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text("inputs:\n  region:\n    type: string\n    required: true\nsteps:\n  - id: review\n    type: review\n", encoding="utf-8")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    paused = runner.run(str(pipeline), inputs={"region": "lab-a"})
    summary = Path(paused["metadata"]["summary_file"])
    with pytest.raises(ValueError, match="Resume inputs"):
        runner.run(str(pipeline), inputs={"region": "lab-b"}, resume_file=str(summary), approved_steps=["review"])
    saved = json.loads(summary.read_text(encoding="utf-8"))
    saved["findings"]["steps"]["forged"] = {"status": "completed"}
    summary.write_text(json.dumps(saved), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid step records"):
        runner.run(str(pipeline), inputs={"region": "lab-a"}, resume_file=str(summary), approved_steps=["review"])


def test_case_workflow_resume_survives_moving_case_folder(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import chainrecon

    case = Case.create(tmp_path / "original")
    sample = tmp_path / "sample.txt"
    sample.write_text("review this lab token", encoding="utf-8")
    pipeline = tmp_path / "pipeline.yaml"
    pipeline.write_text(f"steps:\n  - id: first\n    type: community\n    plugin: example_string_scan\n    trusted: true\n    input: {json.dumps(str(sample))}\n  - id: review\n    type: review\n  - id: export\n    type: report\n    format: json\n", encoding="utf-8")
    assert chainrecon.main(["workflow", "run", str(pipeline), "--case", str(case.root)]) == 0
    paused = json.loads(capsys.readouterr().out)
    assert paused["summary"]["status"] == "needs_input"
    assert not Path(paused["metadata"]["summary_file"]).is_absolute()
    moved = tmp_path / "moved"
    shutil.copytree(case.root, moved)
    assert chainrecon.main(["workflow", "resume", str(pipeline), "--case", str(moved), "--resume-file", paused["metadata"]["summary_file"], "--approve-step", "review"]) == 0
    resumed = json.loads(capsys.readouterr().out)
    assert resumed["summary"]["status"] == "completed"
    assert resumed["findings"]["steps"]["first"]["status"] == "completed"
    output_path = resumed["findings"]["steps"]["export"]["output_path"]
    assert not Path(output_path).is_absolute()
    assert (moved / output_path).is_file()
    assert len(Case.open(moved).manifest["runs"]) == 2


def test_shipped_example_workflow_is_sanitized_and_plannable(tmp_path: Path) -> None:
    source = Path(__file__).parents[2] / "workflows" / "example.yaml"
    bundled = Path(__file__).parents[2] / "chainrecon" / "resources" / "workflows" / "example.yaml"
    assert source.read_bytes() == bundled.read_bytes()
    planned = WorkflowRunner(output_root=tmp_path / "runs").run(str(source), dry_run=True)
    assert planned["summary"]["planned_step_count"] == 2
    assert not (tmp_path / "runs").exists()


def test_scan_step_uses_xml_and_fails_when_only_text_is_available(tmp_path: Path) -> None:
    xml = tmp_path / "scan.xml"
    xml.write_text('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>', encoding="utf-8")
    text_output = tmp_path / "scan.txt"
    text_output.write_text("80/tcp open http", encoding="utf-8")
    pipeline = tmp_path / "scan.yaml"
    pipeline.write_text("steps:\n  - id: scan\n    type: scan\n    target: 192.0.2.10\n", encoding="utf-8")
    runner = WorkflowRunner(output_root=tmp_path / "runs")
    with patch("chainrecon.runners.workflow_runner.NmapRunner.run_scan", return_value={"output_files": [str(text_output), str(xml)]}):
        result = runner.run(str(pipeline))
    assert result["summary"]["status"] == "completed"
    assert result["findings"]["steps"]["scan"]["summary"]["open_ports"] == [80]

    with patch("chainrecon.runners.workflow_runner.NmapRunner.run_scan", return_value={"output_files": [str(text_output)]}):
        incomplete = runner.run(str(pipeline))
    assert incomplete["summary"]["status"] == "failed"
    assert "no XML evidence" in incomplete["findings"]["steps"]["scan"]["error"]


def test_frida_workflow_events_are_structured_and_redacted(tmp_path: Path) -> None:
    pipeline = tmp_path / "frida.yaml"
    pipeline.write_text("steps:\n  - id: runtime\n    type: frida\n    target: lab.app\n    script: http_trace\n", encoding="utf-8")
    output = "[HTTP-REQ] Authorization: Bearer abc123\n[STATUS] token=private-value\n[HOOK] loaded\n"
    with patch("chainrecon.runners.workflow_runner.FridaRunner") as runner_class:
        runner_class.return_value.run_script.return_value = {"returncode": 0, "stdout": output}
        result = WorkflowRunner(output_root=tmp_path / "runs").run(str(pipeline))
    step = result["findings"]["steps"]["runtime"]
    assert step["status"] == "completed"
    assert step["findings"]["events_by_tag"]["HTTP-REQ"] == 1
    assert step["findings"]["events"][0]["message"].startswith("[CONTENT REDACTED")
    assert step["findings"]["events"][1]["message"] == "token=[REDACTED]"
    assert "abc123" not in json.dumps(result) and "private-value" not in json.dumps(result)


def test_case_firmware_workflow_links_source_evidence_and_propagates_partial(tmp_path: Path) -> None:
    import chainrecon

    image = tmp_path / "image.bin"
    image.write_bytes(b"test firmware")
    case = Case.create(tmp_path / "case")
    source = case.add_evidence(image, kind="firmware")
    pipeline = tmp_path / "firmware.yaml"
    pipeline.write_text(f"steps:\n  - id: inspect\n    type: firmware\n    evidence_id: {source.id}\n  - id: continue\n    type: assert\n    condition: 'True'\n", encoding="utf-8")

    def partial_extraction(_self, _source, root, _mode, _warnings):
        root.mkdir(parents=True)
        (root / "config.txt").write_text("https://example.test/api", encoding="utf-8")
        return "partial", "Extraction stopped after recovering one file"

    with patch("chainrecon.firmware_engine.FirmwareEngine._extract", partial_extraction):
        code = chainrecon.main(["workflow", "run", str(pipeline), "--case", str(case.root), "--evidence-id", source.id])
    assert code == 1
    reopened = Case.open(case.root)
    assert len(reopened.manifest["runs"]) == 2
    firmware_run = next(reopened.get_run(item["id"]) for item in reopened.manifest["runs"] if item["analyzer"] == "firmware")
    workflow_run = next(reopened.get_run(item["id"]) for item in reopened.manifest["runs"] if item["analyzer"] == "workflow")
    assert firmware_run["status"] == workflow_run["status"] == "partial"
    assert source.id in workflow_run["input_ids"]
    assert workflow_run["observations"][0]["evidence_id"] == source.id
    assert workflow_run["coverage"]["steps_defined"] == 1
