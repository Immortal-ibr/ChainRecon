"""A configured case removes repeated CLI paths and internal ID typing."""

import json
from pathlib import Path

from chainrecon.case_model import Case
from chainrecon.utils.config import get_case_directory, reset_config
from chainrecon.v2_cli import _optional_case_positionals, dispatch


def test_configured_case_and_unique_evidence_are_selected(tmp_path: Path, monkeypatch, capsys) -> None:
    case = Case.create(tmp_path / "case", "Configured case")
    scan = tmp_path / "scan.xml"
    scan.write_text('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>', encoding="utf-8")
    case.add_evidence(scan, kind="scan_xml")
    config = tmp_path / "chainrecon.yaml"
    config.write_text(f"case:\n  directory: '{case.root.as_posix()}'\nfirmware:\n  mode: container\n", encoding="utf-8")
    monkeypatch.setenv("CHAINRECON_CONFIG_FILE", str(config))
    reset_config()
    assert get_case_directory() == case.root
    assert dispatch(["case", "list", "evidence"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1
    notes = tmp_path / "notes.txt"
    notes.write_text("lab notes", encoding="utf-8")
    assert dispatch(["case", "add", str(notes), "--kind", "other"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "notes.txt"
    assert dispatch(["case", "analyze", "--analyzer", "scan"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "complete"
    assert len(Case.open(case.root).manifest["runs"]) == 1
    pipeline = tmp_path / "workflow.yaml"
    pipeline.write_text("steps:\n  - id: check\n    type: assert\n    condition: 'True'\n", encoding="utf-8")
    assert dispatch(["workflow", "run", str(pipeline)]) == 0
    capsys.readouterr()
    assert len(Case.open(case.root).manifest["runs"]) == 2
    output = tmp_path / "report.html"
    assert dispatch(["report", "export", "--output", str(output)]) == 0
    assert output.is_file()
    assert _optional_case_positionals("run-old", "run-new", None) == (None, ("run-old", "run-new"))
    reset_config()
