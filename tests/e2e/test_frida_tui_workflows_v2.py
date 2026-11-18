"""Exercise Frida TUI lifecycle with a mocked Android/Frida backend."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input


async def _until(predicate) -> None:
    for _ in range(150):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Frida TUI worker did not finish")


def test_frida_tui_starts_and_stops_managed_session(tmp_path: Path) -> None:
    log_path = tmp_path / "session.log"
    log_path.write_text("[HOOK] arbitrary-secret\n[STATUS] ready\n", encoding="utf-8")
    summary_path = tmp_path / "session.json"
    summary_path.write_text('{"status":"stopped_by_user"}', encoding="utf-8")
    started = {
        "session_id": "session-1",
        "mode": "attach",
        "attach_target": "com.example.app",
        "log_path": str(log_path),
        "summary_path": str(summary_path),
        "frida_server_started": False,
        "launch_performed": False,
    }
    stopped = {
        **started,
        "serial": "emulator-5554",
        "target": "com.example.app",
        "script": "list_classes",
        "status": "stopped_by_user",
        "status_reason": "stopped_by_user",
        "exit_code": 0,
        "stopped_by_user": True,
    }

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.frida.FridaScreen.on_mount", return_value=None),
            patch("chainrecon.tui.screens.frida.save_frida_config"),
            patch("chainrecon.tui.screens.frida.get_output_dir", return_value=tmp_path),
        ):
            app = ChainReconApp()
            async with app.run_test(size=(110, 36)) as pilot:
                await pilot.pause()
                app.push_screen("frida")
                await pilot.pause()
                screen = app.screen
                screen._refresh_script_inputs()
                await pilot.pause()
                screen.query_one("#target", Input).value = "com.example.app"
                log = screen.query_one("#frida-log", LogViewer)
                with (
                    patch.object(screen._runner, "start_session", return_value=started) as start,
                    patch.object(screen._runner, "stop_session", return_value=stopped) as stop,
                ):
                    screen._start_managed_session(log)
                    await _until(lambda: screen._current_session is not None)
                    start.assert_called_once()
                    screen._stop_managed_session(log)
                    await _until(lambda: screen._last_exit_summary is not None)
                    stop.assert_called_once()
                    await _until(lambda: "Frida session finished" in log._plain_text())
                    assert screen._current_session is None
                    assert "arbitrary-secret" not in str(screen._last_exit_summary)
                    assert any(tmp_path.glob("*_frida_*.json"))

    asyncio.run(exercise())


def test_frida_tui_setup_records_selected_device(tmp_path: Path) -> None:
    setup = {
        "serial": "emulator-5554",
        "selection": "serial:emulator-5554",
        "actions": ["Verified frida-ps connectivity."],
        "frida_ps": "PID Name",
        "apk_installation": {"requested": False},
    }

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.frida.FridaScreen.on_mount", return_value=None),
            patch("chainrecon.tui.screens.frida.save_frida_config"),
            patch("chainrecon.tui.screens.frida.get_output_dir", return_value=tmp_path),
        ):
            app = ChainReconApp()
            async with app.run_test(size=(110, 36)) as pilot:
                await pilot.pause()
                app.push_screen("frida")
                await pilot.pause()
                screen = app.screen
                log = screen.query_one("#frida-log", LogViewer)
                with (
                    patch.object(screen._runner, "setup_device", return_value=setup) as invoke,
                    patch.object(screen, "_refresh_inventory_after_action"),
                ):
                    screen._setup_selected_device(log)
                    await _until(lambda: screen._selected_serial == "emulator-5554")
                    await _until(lambda: "Managed setup complete" in log._plain_text())
                    invoke.assert_called_once()

    asyncio.run(exercise())
