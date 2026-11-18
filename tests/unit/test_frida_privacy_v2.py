"""Frida session logs must use the same privacy policy as structured events."""

from __future__ import annotations

import json
import time
from io import StringIO
from pathlib import Path

from chainrecon.frida_events import parse_event_line
from chainrecon.runners.frida_runner import FridaRunner
from chainrecon.runners.frida_session import FridaSession


def _session(root: Path) -> FridaSession:
    return FridaSession(
        session_id="test-session",
        serial="emulator-5554",
        target="com.example.app",
        attach_target="com.example.app",
        attach_flag="-N",
        script_key="crypto_monitor",
        parameters={"api_key": "private-parameter"},
        command=["frida", "-N", "com.example.app"],
        process=None,
        log_path=root / "session.log",
        summary_path=root / "session.json",
        rendered_script_path=root / "script.js",
        start_time=time.time(),
        mode="attach",
        target_running_before=True,
        launch_performed=False,
        frida_server_started=False,
        frida_server_path=None,
    )


def test_untagged_and_hook_output_is_private_by_default() -> None:
    assert "raw-payload" not in parse_event_line("[HOOK] raw-payload")["message"]
    assert "raw-payload" not in parse_event_line("raw-payload")["message"]
    assert parse_event_line("[HOOK] raw-payload", reveal_sensitive=True)["message"] == "raw-payload"
    assert parse_event_line("[STATUS] token=secret")["message"] == "token=[REDACTED]"


def test_cli_and_census_streams_persist_only_redacted_events(tmp_path: Path) -> None:
    session = _session(tmp_path)
    runner = FridaRunner(validate_device=False)
    shown: list[str] = []
    runner._stream_pipe(session, StringIO("[HOOK] arbitrary-secret\n[STATUS] ready\n"), "stdout", shown.append)
    captured: list[str] = []
    runner._stream_census_pipe(session, StringIO("[CRYPTO] key-data\n"), "stderr", shown.append, captured)
    assert session.output_line_count == 2
    assert session.error_line_count == 1
    assert session.events_by_tag == {"HOOK": 1, "STATUS": 1, "CRYPTO": 1}
    assert all("arbitrary-secret" not in line and "key-data" not in line for line in shown)
    assert all("key-data" not in line for line in captured)
    assert "arbitrary-secret" not in session.log_path.read_text(encoding="utf-8")
    events = session.log_path.with_suffix(".events.jsonl").read_text(encoding="utf-8")
    assert "arbitrary-secret" not in events and "key-data" not in events
    assert len(events.splitlines()) == 3


def test_api_event_count_and_summary_parameter_redaction(tmp_path: Path) -> None:
    session = _session(tmp_path)
    runner = FridaRunner(validate_device=False)
    runner._handle_api_message(session, {"type": "send", "payload": {"line": "[HOOK] raw-payload"}}, None, None)
    assert session.events_by_tag == {"HOOK": 1}
    session.status_reason = "failed: token=private-status"
    summary = runner._write_session_summary(session, exit_code=1)
    saved = json.loads(session.summary_path.read_text(encoding="utf-8"))
    assert saved["parameters"]["api_key"] == "[REDACTED]"
    assert "private-status" not in json.dumps(summary)
    assert "raw-payload" not in session.log_path.read_text(encoding="utf-8")
