"""Exercise offline workflow planning and report export through the TUI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from textual.widgets import Button, Select

from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input


def test_workflow_tui_dry_run_creates_no_case_artifacts(tmp_path: Path) -> None:
    pipeline = tmp_path / "plan.yaml"
    pipeline.write_text("name: Offline plan\nsteps:\n  - id: review\n    type: review\n    prompt: Inspect evidence\n", encoding="utf-8")

    async def exercise() -> None:
        with patch("chainrecon.runners.workflow_runner.get_output_dir", side_effect=AssertionError("dry run accessed output")):
            app = ChainReconApp()
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("workflow")
                await pilot.pause()
                app.screen.query_one("#pipeline-path", Input).value = str(pipeline)
                app.screen.query_one("#run-workflow", Button).press()
                log = app.screen.query_one("#workflow-log", LogViewer)
                for _ in range(750):
                    if "Workflow plan complete" in log._plain_text() and "review" in log._plain_text():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError(log._plain_text())
                assert "review" in log._plain_text()

    asyncio.run(exercise())
    assert list(tmp_path.iterdir()) == [pipeline]


def test_reports_tui_exports_selected_session_and_saved_files(tmp_path: Path) -> None:
    source_dir = tmp_path / "saved"
    source_dir.mkdir()
    (source_dir / "scan.json").write_text(
        json.dumps({"metadata": {"section": "scan"}, "summary": {"host_count": 1}, "findings": {"hosts": [{"ip": "192.0.2.10"}]}, "risk_indicators": []}),
        encoding="utf-8",
    )
    session_report = tmp_path / "session.json"
    saved_report = tmp_path / "saved.html"

    async def exercise() -> None:
        with patch("chainrecon.utils.config.get_output_dir", return_value=source_dir):
            app = ChainReconApp()
            app._report_gen.add_results(
                "traffic", {"metadata": {"section": "traffic"}, "findings": {"dns_queries": []}, "summary": {"packet_count": 1}, "risk_indicators": []}
            )
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("reports")
                await pilot.pause()
                screen = app.screen
                screen.query_one("#output-path", Input).value = str(session_report)
                screen.query_one("#format", Select).value = "json"
                screen.query_one("#btn-gen", Button).press()
                for _ in range(750):
                    if session_report.is_file():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("Session report not saved")
                assert json.loads(session_report.read_text(encoding="utf-8"))["traffic"] is not None
                screen.query_one("#source-mode", Select).value = "all_output"
                screen.query_one("#format", Select).value = "html"
                screen.query_one("#output-path", Input).value = str(saved_report)
                screen.query_one("#btn-gen", Button).press()
                log = screen.query_one("#reports-log", LogViewer)
                for _ in range(750):
                    if saved_report.is_file() and "result file(s) included" in log._plain_text():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("Saved-file report not saved")

    asyncio.run(exercise())
    html = saved_report.read_text(encoding="utf-8")
    assert "192.0.2.10" in html
