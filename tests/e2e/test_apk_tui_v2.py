"""APK TUI persists mocked analyzer output and a readable artifact index."""

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


def test_apk_screen_persists_analysis_and_index(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"fixture")

    def analyze(path, output_dir=None, progress_cb=None):
        assert path == str(apk)
        Path(output_dir).mkdir(parents=True)
        if progress_cb:
            progress_cb("progress: done")
        return {"metadata": {"source": path}, "findings": {"permissions": ["INTERNET"], "token": "sensitive-value"}, "summary": {"jadx_error_count": 0}, "risk_indicators": []}

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.apk.APKAnalyzer.analyze", side_effect=analyze) as invoke,
            patch("chainrecon.tui.screens.apk.APKScreen._run_custom_inline") as run_script,
            patch("chainrecon.utils.config.get_output_dir", return_value=tmp_path),
        ):
            app = ChainReconApp()
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("apk")
                await pilot.pause()
                assert isinstance(app.screen.query_one("#apk-path"), PathInput)
                assert isinstance(app.screen.query_one("#custom-path"), PathInput)
                app.screen.query_one("#apk-path", Input).value = str(apk)
                app.screen.query_one("#custom-path", Input).value = str(tmp_path / "old-script.py")
                log = app.screen.query_one("#apk-log", LogViewer)
                app.screen.query_one("#btn-analyze", Button).press()
                for _ in range(150):
                    if (tmp_path / "artifact_index.json").is_file() and "Done." in log._plain_text():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("APK TUI worker did not finish")
                invoke.assert_called_once()
                run_script.assert_not_called()
                assert "sensitive-value" not in log._plain_text()

    asyncio.run(exercise())
    index = json.loads((tmp_path / "artifact_index.json").read_text(encoding="utf-8"))
    assert index["artifacts"][0]["section"] == "apk"
    assert any(tmp_path.glob("*_apk_analysis_sample.json"))


def test_apk_custom_script_runs_after_builtin_analysis_when_selected(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"fixture")

    def analyze(path, output_dir=None, progress_cb=None):
        Path(output_dir).mkdir(parents=True)
        return {"metadata": {"source": path}, "findings": {}, "summary": {"jadx_error_count": 0}, "risk_indicators": []}

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.apk.APKAnalyzer.analyze", side_effect=analyze),
            patch("chainrecon.tui.screens.apk.APKScreen._run_custom_inline") as run_script,
            patch("chainrecon.utils.config.get_output_dir", return_value=tmp_path),
        ):
            app = ChainReconApp()
            async with app.run_test(size=(80, 24)) as pilot:
                app.push_screen("apk")
                await pilot.pause()
                app.screen.query_one("#apk-path", Input).value = str(apk)
                app.screen.query_one("#mode", Select).value = "custom"
                app.screen.query_one("#custom-path", Input).value = str(tmp_path / "check.py")
                app.screen.query_one("#btn-analyze", Button).press()
                for _ in range(150):
                    if run_script.called:
                        break
                    await asyncio.sleep(0.02)
                run_script.assert_called_once()

    asyncio.run(exercise())
