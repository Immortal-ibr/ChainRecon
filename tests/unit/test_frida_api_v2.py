"""Offline Frida API lifecycle fixtures, including attach and detach."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chainrecon.runners.frida_runner import FridaRunner
from tests.unit.test_frida_privacy_v2 import _session


def test_api_script_attach_load_event_and_unload(tmp_path: Path) -> None:
    class FakeScript:
        def __init__(self):
            self.handlers = {}
            self.loaded = False
            self.unloaded = False

        def on(self, name, handler):
            self.handlers[name] = handler

        def load(self):
            self.loaded = True

        def unload(self):
            self.unloaded = True

    class FakeAttached:
        def __init__(self, script):
            self.script = script
            self.handlers = {}
            self.detached = False

        def on(self, name, handler):
            self.handlers[name] = handler

        def create_script(self, source):
            assert "send(" in source
            return self.script

        def detach(self):
            self.detached = True

    script = FakeScript()
    attached = FakeAttached(script)
    attempts = []

    def attach(target):
        attempts.append(target)
        if target == "com.example.app":
            raise RuntimeError("attach by name unavailable")
        return attached

    device = SimpleNamespace(attach=attach)
    session = _session(tmp_path)
    session.rendered_script_path.write_text("send('[HOOK] secret-data')", encoding="utf-8")
    runner = FridaRunner(validate_device=False)
    with patch.object(runner, "_import_frida", return_value=SimpleNamespace(get_device=lambda *a, **k: device)):
        with patch.object(runner, "_pidof", return_value=42):
            runner._load_api_script(session, None)
    assert attempts == [42]  # package identifiers resolve to a PID first
    assert script.loaded is True
    script.handlers["message"]({"type": "send", "payload": {"line": "[HOOK] secret-data"}})
    assert session.events_by_tag["HOOK"] == 1
    assert "secret-data" not in session.log_path.read_text(encoding="utf-8")
    runner._unload_api_session(session)
    assert script.unloaded is True and attached.detached is True


def test_api_watcher_records_user_stop(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.stop_requested = True
    session.stop_event.set()
    runner = FridaRunner(validate_device=False)
    callbacks = []
    with patch.object(runner, "is_target_running", return_value=True):
        runner._watch_api_session(session, callbacks.append)
    assert session.summary_written.is_set()
    assert callbacks[0]["status"] == "stopped_by_user"
    assert json.loads(session.summary_path.read_text(encoding="utf-8"))["exit_code"] == 0


def test_api_watcher_records_target_death(tmp_path: Path) -> None:
    session = _session(tmp_path)
    runner = FridaRunner(validate_device=False)
    with (
        patch.object(session.stop_event, "wait", return_value=False),
        patch.object(runner, "is_target_running", return_value=False),
    ):
        runner._watch_api_session(session, None)
    summary = json.loads(session.summary_path.read_text(encoding="utf-8"))
    assert summary["status_reason"] == "target_died"
    assert summary["status"] == "unexpected_exit"
