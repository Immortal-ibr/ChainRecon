"""A custom script exit status is evidence to review, not a vulnerability."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from textual.widgets import Button

from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input


def test_custom_script_tui_redacts_output_and_keeps_path_argument(tmp_path: Path) -> None:
    script = tmp_path / "my check.py"
    script.write_text("print('fixture')\n", encoding="utf-8")

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.custom_script.get_output_dir", return_value=tmp_path),
            patch(
                "chainrecon.tui.screens.custom_script.subprocess.run",
                return_value=subprocess.CompletedProcess([], 7, "token=SECRET_VALUE\n", "password=ALSO_SECRET\n"),
            ) as execute,
        ):
            app = ChainReconApp()
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("custom_script")
                await pilot.pause()
                screen = app.screen
                screen.query_one("#script-path", Input).value = str(script)
                screen.query_one("#script-args", Input).value = "--target 192.0.2.10"
                screen.query_one("#description", Input).value = "Local probe"
                screen.query_one("#btn-run", Button).press()
                log = screen.query_one("#script-log", LogViewer)
                for _ in range(500):
                    if "Results saved" in log._plain_text():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError(log._plain_text())
                assert execute.call_args.args[0] == ["python", str(script), "--target", "192.0.2.10"]
                assert "SECRET_VALUE" not in log._plain_text()

    asyncio.run(exercise())
    artifact = json.loads(next(tmp_path.glob("*custom_local_probe*.json")).read_text(encoding="utf-8"))
    assert artifact["summary"]["exit_code"] == 7
    assert artifact["risk_indicators"][0]["severity"] == "info"
    assert "SECRET_VALUE" not in json.dumps(artifact)
    assert "ALSO_SECRET" not in json.dumps(artifact)
