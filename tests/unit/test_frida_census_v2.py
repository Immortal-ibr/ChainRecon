"""Managed Frida census completion and failure records with mocked processes."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from chainrecon.runners.frida_runner import FridaRunner
from tests.unit.test_frida_privacy_v2 import _session


def test_census_watcher_records_process_result_and_redacts_output(tmp_path: Path) -> None:
    class FinishedProcess:
        def __init__(self, command, **kwargs):
            self.command = command
            self.stdout = StringIO("[CLASS] total=5\n[HOOK] arbitrary-payload\n")
            self.stderr = StringIO("")
            self.stdin = StringIO()
            self.returncode = 0

        def poll(self):
            return self.returncode

    session = _session(tmp_path)
    session.script_key = "device_class_census"
    session.target = "camera"
    runner = FridaRunner(validate_device=False)
    completed = []
    with (
        patch.object(runner, "list_processes_structured", return_value=[{"identifier": "com.example.camera", "name": "Camera"}]),
        patch.object(runner, "is_target_running", return_value=True),
        patch("chainrecon.runners.frida_runner.subprocess.Popen", side_effect=FinishedProcess),
    ):
        runner._watch_device_class_census_session(session, None, completed.append)
    assert session.summary_written.is_set()
    assert session.status_reason == "completed"
    assert completed[0]["process_results"][0]["class_count"] == 5
    assert completed[0]["process_results"][0]["status"] == "completed"
    assert "arbitrary-payload" not in session.log_path.read_text(encoding="utf-8")
    assert "arbitrary-payload" not in session.summary_path.read_text(encoding="utf-8")


def test_census_watcher_marks_process_launch_failure(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.script_key = "device_class_census"
    session.target = "camera"
    runner = FridaRunner(validate_device=False)
    with (
        patch.object(runner, "list_processes_structured", return_value=[{"identifier": "com.example.camera", "name": "Camera"}]),
        patch.object(runner, "is_target_running", return_value=False),
        patch("chainrecon.runners.frida_runner.subprocess.Popen", side_effect=OSError("token=private-value")),
    ):
        runner._watch_device_class_census_session(session, None, None)
    summary = json.loads(session.summary_path.read_text(encoding="utf-8"))
    assert summary["status_reason"] == "partial_failure"
    assert summary["process_results"][0]["status"] == "failed"
    assert "private-value" not in session.summary_path.read_text(encoding="utf-8")
    assert "private-value" not in session.log_path.read_text(encoding="utf-8")
