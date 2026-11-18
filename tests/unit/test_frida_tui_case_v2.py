"""Frida UI session artifacts are retained as hashed case evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from chainrecon.case_model import Case, file_sha256
from chainrecon.tui.screens.frida import _record_case_frida_session


def test_frida_session_log_and_summary_are_imported(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case", "Frida case")
    log = tmp_path / "session.log"
    log.write_text("[HOOK] arbitrary-sensitive-payload\n[STATUS] attached\n", encoding="utf-8")
    summary = tmp_path / "session.json"
    summary.write_text('{"status":"completed","script":"crypto_monitor"}', encoding="utf-8")
    digest = file_sha256(log)

    run_id = _record_case_frida_session({"log_path": str(log), "summary_path": str(summary)}, str(case.root))

    reopened = Case.open(case.root)
    assert len(reopened.manifest["evidence"]) == 2
    assert any(item["sha256"] == digest for item in reopened.manifest["evidence"])
    run = next(iter(reopened.iter_runs()))
    assert run["id"] == run_id
    assert run["status"] == "complete"
    artifact = (case.root / run["artifacts"][0]).read_text(encoding="utf-8")
    assert "arbitrary-sensitive-payload" not in artifact


def test_frida_session_without_log_cannot_be_complete(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case", "Frida case")
    with pytest.raises(FileNotFoundError, match="session log missing"):
        _record_case_frida_session({"log_path": str(tmp_path / "missing.log")}, str(case.root))
    assert Case.open(case.root).manifest["runs"] == []
