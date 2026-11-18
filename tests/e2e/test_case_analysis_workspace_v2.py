"""The analysis workspace handles supported and manual-only evidence honestly."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from textual.widgets import Button, Collapsible, Select, Static

from chainrecon.case_model import Case, RunRecord
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.screens.case_analysis import CaseAnalysisScreen
from chainrecon.tui.screens.dashboard import DashboardScreen


async def _until(predicate) -> None:
    for _ in range(150):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Analysis workspace did not reach the expected state")


def test_analysis_workspace_routes_types_and_shows_run_history(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case", "Analysis fixture")
    scan_file = tmp_path / "scan.xml"
    scan_file.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.13" addrtype="ipv4"/></host></nmaprun>',
        encoding="utf-8",
    )
    scan = case.add_evidence(scan_file, kind="scan_xml")
    frida_file = tmp_path / "events.log"
    frida_file.write_text('{"tag":"network","message":"connected"}\n', encoding="utf-8")
    frida = case.add_evidence(frida_file, kind="frida_log")
    firmware_file = tmp_path / "image.bin"
    firmware_file.write_bytes(b"opaque test image")
    firmware = case.add_evidence(firmware_file, kind="firmware")
    uart_file = tmp_path / "serial.log"
    uart_file.write_text("boot complete", encoding="utf-8")
    uart = case.add_evidence(uart_file, kind="uart_log")
    workflow_id = f"run-{uuid.uuid4().hex}"
    case.add_run(RunRecord(
        workflow_id, "workflow", "complete", (scan.id,),
        "2026-11-18T00:00:00+00:00", "2026-11-18T00:00:01+00:00",
    ))

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.push_screen("case_analysis")
            await pilot.pause()
            assert isinstance(app.screen, CaseAnalysisScreen)
            analysis = app.screen
            await _until(lambda: analysis.query_one("#analysis-evidence", Select).value == uart.id)
            run_button_region = analysis.query_one("#analysis-run", Button).region
            assert run_button_region.y + run_button_region.height <= app.size.height - 1
            evidence = analysis.query_one("#analysis-evidence", Select)
            assert analysis.query_one("#analysis-run", Button).disabled
            assert "manual review only" in str(analysis.query_one("#analysis-evidence-detail", Static).render())
            assert not analysis.query_one("#analysis-firmware-options", Collapsible).display

            evidence.value = scan.id
            await pilot.pause()
            assert not analysis.query_one("#analysis-run", Button).disabled
            assert not analysis.query_one("#analysis-firmware-options", Collapsible).display
            assert analysis.query_one("#analysis-run-select", Select).value == workflow_id
            analysis.query_one("#analysis-run", Button).press()
            await _until(lambda: len(Case.open(case.root).manifest["runs"]) == 2)
            await _until(lambda: not analysis._busy)
            await pilot.pause()
            run = Case.open(case.root).manifest["runs"][1]
            assert run["analyzer"] == "scan"
            assert analysis.query_one("#analysis-run-select", Select).value == run["id"]
            assert "Status: complete" in str(analysis.query_one("#analysis-run-detail", Static).render())

            evidence.value = frida.id
            await pilot.pause()
            assert not analysis.query_one("#analysis-run", Button).disabled
            assert analysis.query_one("#analysis-run-select", Select).value == Select.NULL
            evidence.value = firmware.id
            await pilot.pause()
            assert analysis.query_one("#analysis-firmware-options", Collapsible).display
            assert analysis.query_one("#analysis-firmware-options", Collapsible).collapsed

    asyncio.run(exercise())


def test_dashboard_analysis_opens_case_chooser_when_none_configured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CHAINRECON_CONFIG_FILE", raising=False)
    from chainrecon.utils import config

    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path / "config")
    monkeypatch.setenv("CHAINRECON_DATA_HOME", str(tmp_path / "data"))
    config.reset_config()

    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            app.screen.query_one("#home-firmware", Button).press()
            await pilot.pause()
            assert isinstance(app.screen, CaseAnalysisScreen)
            assert app.screen._view == "firmware"
            await _until(lambda: app.focused is app.screen.query_one("#analysis-choose-case", Button))
            assert app.focused is app.screen.query_one("#analysis-choose-case", Button)
            assert app.screen.query_one("#analysis-run", Button).disabled

    asyncio.run(exercise())
    config.reset_config()
