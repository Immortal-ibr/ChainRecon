"""Mocked Android process checks must not mistake errors for running targets."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from chainrecon.runners.frida_runner import FridaDeviceError, FridaRunner


def completed(stdout: str = "", stderr: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["adb"], code, stdout, stderr)


def test_frida_server_status_ignores_stderr_and_grep_process() -> None:
    executor = Mock(side_effect=[completed("", "pidof: not found", 127), completed("grep frida-server\n")])
    runner = FridaRunner(executor=executor, validate_device=False)
    assert not runner.is_frida_server_running(serial="emulator-5554")
    executor.side_effect = [completed("1234\n")]
    assert runner.is_frida_server_running(serial="emulator-5554")


def test_existing_server_does_not_request_root() -> None:
    runner = FridaRunner(validate_device=False)
    with patch.object(runner, "is_frida_server_running", return_value=True), patch.object(
        runner, "_prepare_frida_server_privilege", side_effect=AssertionError("unneeded root request")
    ):
        status = runner.start_frida_server_if_needed(serial="emulator-5554")
    assert status["running"] and not status["started"]
    assert status["privilege"]["status"] == "not_needed"


def test_server_start_records_resolution_and_verifies_process(tmp_path: Path) -> None:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"fixture")
    runner = FridaRunner(validate_device=False)
    with (
        patch.object(runner, "is_frida_server_running", side_effect=[False, True]),
        patch.object(runner, "_prepare_frida_server_privilege", return_value={"status": "root"}),
        patch.object(runner, "_resolve_frida_server_path", return_value=(binary, {"architecture": "x86_64"})),
        patch.object(runner, "push_frida_server") as push,
        patch.object(runner, "start_frida_server") as start,
    ):
        state = runner.start_frida_server_if_needed(serial="emulator-5554", frida_server_path=str(binary))
    assert state["running"] and state["started"]
    assert state["resolution"]["architecture"] == "x86_64"
    push.assert_called_once_with(str(binary), serial="emulator-5554")
    start.assert_called_once_with(serial="emulator-5554")


def test_server_start_missing_matching_binary_gives_guidance() -> None:
    runner = FridaRunner(validate_device=False)
    with (
        patch.object(runner, "is_frida_server_running", return_value=False),
        patch.object(runner, "_prepare_frida_server_privilege", return_value={}),
        patch.object(runner, "_resolve_frida_server_path", return_value=(None, {"reason": "wrong ABI"})),
    ):
        with pytest.raises(FridaDeviceError, match="no matching frida-server binary") as raised:
            runner.start_frida_server_if_needed(serial="emulator-5554")
    assert raised.value.state["frida_server_resolution"]["reason"] == "wrong ABI"


def test_target_status_requires_successful_pidof_or_process_match() -> None:
    runner = FridaRunner(executor=Mock(return_value=completed("1234", "", 1)), validate_device=False)
    with patch.object(runner, "list_processes_structured", return_value=[]):
        assert not runner.is_target_running("com.example.app", serial="emulator-5554")
    runner._executor = Mock(return_value=completed("1234\n"))
    assert runner.is_target_running("com.example.app", serial="emulator-5554")
    with patch.object(runner, "list_processes_structured", return_value=[{"name": "Camera", "identifier": "com.example.app"}]):
        assert runner.is_target_running("Camera", serial="emulator-5554")


def test_resolve_target_attaches_or_spawns_only_installed_package() -> None:
    runner = FridaRunner(validate_device=False)
    with patch.object(runner, "_package_installed", return_value=True), patch.object(
        runner, "is_target_running", side_effect=[False, True]
    ), patch.object(runner, "launch_target_if_needed", return_value={"launched": True, "details": "started"}):
        target = runner.resolve_attach_target("com.example.app", serial="emulator-5554")
    assert target["mode"] == "attach" and target["attach_flag"] == "-N"
    assert target["launch_performed"]

    with patch.object(runner, "_package_installed", return_value=True), patch.object(
        runner, "is_target_running", side_effect=[False, False]
    ), patch.object(runner, "launch_target_if_needed", return_value={"launched": False, "details": "not running"}):
        target = runner.resolve_attach_target("com.example.app", serial="emulator-5554")
    assert target["mode"] == "spawn" and target["attach_flag"] == "-f"

    with patch.object(runner, "_package_installed", return_value=False), patch.object(
        runner, "is_target_running", return_value=False
    ):
        with pytest.raises(FridaDeviceError, match="could not be launched"):
            runner.resolve_attach_target("UnknownProcess", serial="emulator-5554")


def test_launch_target_checks_installation_before_shell_commands() -> None:
    runner = FridaRunner(executor=Mock(), validate_device=False)
    with patch.object(runner, "is_target_running", return_value=False), patch.object(
        runner, "_package_installed", return_value=False
    ):
        with pytest.raises(FridaDeviceError, match="not installed"):
            runner.launch_target_if_needed("com.example.app", serial="emulator-5554")
    runner._executor.assert_not_called()


def test_launch_target_waits_for_observed_process() -> None:
    executor = Mock(side_effect=[completed("Starting: Intent"), completed("Events injected: 1")])
    runner = FridaRunner(executor=executor, validate_device=False)
    with (
        patch.object(runner, "is_target_running", side_effect=[False, True]),
        patch.object(runner, "_package_installed", return_value=True),
        patch.object(runner, "_resolve_launcher_activity", return_value="com.example.app/.Main"),
    ):
        result = runner.launch_target_if_needed("com.example.app", serial="emulator-5554")
    assert result["launched"]
    assert "Starting: Intent" in result["details"]
    assert executor.call_count == 2


def test_device_state_requires_unambiguous_online_serial() -> None:
    adb_output = "List of devices attached\nemulator-5554\tdevice\nemulator-5556\tdevice\n"
    runner = FridaRunner(executor=Mock(return_value=completed(adb_output)))
    with patch("chainrecon.runners.frida_runner.check_tool", return_value="adb"), patch.object(
        runner, "_configured_serial", return_value=None
    ):
        state = runner.get_device_state()
    assert state["state"] == "ambiguous" and not state["online"]
    with patch("chainrecon.runners.frida_runner.check_tool", return_value="adb"), patch.object(
        runner, "_configured_serial", return_value="emulator-5554"
    ):
        state = runner.get_device_state()
    assert state["online"] and state["serial"] == "emulator-5554"


def test_device_state_distinguishes_missing_and_offline_serial() -> None:
    runner = FridaRunner(executor=Mock(return_value=completed("List of devices attached\nemulator-5554\toffline\n")))
    with patch("chainrecon.runners.frida_runner.check_tool", return_value="adb"), patch.object(
        runner, "_configured_serial", return_value="emulator-5556"
    ):
        missing = runner.get_device_state()
    assert missing["state"] == "missing"
    with patch("chainrecon.runners.frida_runner.check_tool", return_value="adb"), patch.object(
        runner, "_configured_serial", return_value="emulator-5554"
    ):
        offline = runner.get_device_state()
    assert offline["state"] == "offline" and not offline["online"]
