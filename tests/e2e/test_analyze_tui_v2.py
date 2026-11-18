"""Standalone analysis TUI saves a result and exposes coverage limits."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from textual.widgets import Button, Select

from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.tui.widgets.path_input import PathInput


def test_analysis_screen_saves_partial_result_and_warns(tmp_path: Path) -> None:
    result = {
        "metadata": {"source": "sample.pcap"},
        "findings": {"token": "hidden-value"},
        "summary": {"result_truncated": True},
        "risk_indicators": [],
    }

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.analyze.AnalyzeScreen._dispatch", return_value=result),
            patch("chainrecon.tui.screens.analyze.AnalyzeScreen._run_custom_inline") as run_script,
            patch("chainrecon.utils.config.get_output_dir", return_value=tmp_path),
        ):
            app = ChainReconApp()
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("analyze")
                await pilot.pause()
                assert isinstance(app.screen.query_one("#filepath"), PathInput)
                assert isinstance(app.screen.query_one("#custom-path"), PathInput)
                app.screen.query_one("#filepath", Input).value = str(tmp_path / "sample.pcap")
                app.screen.query_one("#custom-path", Input).value = str(tmp_path / "old-script.py")
                log = app.screen.query_one("#analyze-log", LogViewer)
                app.screen.query_one("#btn-analyze", Button).press()
                for _ in range(150):
                    if "Packet analysis reached" in log._plain_text() and "Done. Saved" in log._plain_text():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("Analyze TUI worker did not finish")
                assert "hidden-value" not in log._plain_text()
                run_script.assert_not_called()

    asyncio.run(exercise())
    saved = list(tmp_path.glob("*_analysis_traffic.json"))
    assert len(saved) == 1
    assert json.loads(saved[0].read_text(encoding="utf-8"))["summary"]["result_truncated"] is True


def test_packet_custom_script_runs_only_when_selected(tmp_path: Path) -> None:
    async def exercise() -> None:
        with patch("chainrecon.tui.screens.analyze.AnalyzeScreen._run_custom_inline") as run_script:
            app = ChainReconApp()
            async with app.run_test(size=(80, 24)) as pilot:
                app.push_screen("analyze")
                await pilot.pause()
                app.screen.query_one("#analyzer", Select).value = "custom"
                await pilot.pause()
                app.screen.query_one("#custom-path", Input).value = str(tmp_path / "check.py")
                app.screen.query_one("#btn-analyze", Button).press()
                await pilot.pause()
                run_script.assert_called_once()

    asyncio.run(exercise())
