"""Run a mocked live scan through the case-bound TUI without network traffic."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

from textual.widgets import Button, Select

from chainrecon.case_model import Case
from chainrecon.runners.nmap_runner import NmapInterfaceMismatchError
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input


async def _until(predicate) -> None:
    for _ in range(750):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Scan TUI did not finish")


def test_scan_screen_persists_xml_and_analysis_in_open_case(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case", "Live scan case")
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.0.2.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
        '</ports></host></nmaprun>', encoding="utf-8",
    )
    output = tmp_path / "artifacts"
    output.mkdir()

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.scan.list_scan_interfaces", return_value=[]),
            patch("chainrecon.tui.screens.scan.get_output_dir", return_value=output),
            patch("chainrecon.tui.screens.scan.NmapRunner") as runner_type,
        ):
            runner_type.return_value.run_scan.return_value = {
                "target": "192.0.2.10",
                "profile": "quick",
                "backend": "nmap",
                "output_files": [str(xml)],
                "commands": [],
            }
            app = ChainReconApp(case_path=str(case.root))
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("scan")
                await pilot.pause()
                app.screen.query_one("#target", Input).value = "192.0.2.10"
                app.screen.query_one("#profile", Select).value = "quick"
                app.screen.query_one("#btn-scan", Button).press()
                log = app.screen.query_one("#scan-log", LogViewer)
                await _until(lambda: len(Case.open(case.root).manifest["runs"]) == 1 and "Scan complete" in log._plain_text())
                runner_type.return_value.run_scan.assert_called_once()

    asyncio.run(exercise())
    reopened = Case.open(case.root)
    assert len(reopened.manifest["evidence"]) == 1
    assert next(iter(reopened.iter_runs()))["analyzer"] == "scan"


def test_scan_screen_reports_route_mismatch_without_case_findings(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case", "Mismatch case")
    output = tmp_path / "artifacts"
    output.mkdir()

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.scan.list_scan_interfaces", return_value=[]),
            patch("chainrecon.tui.screens.scan.get_output_dir", return_value=output),
            patch("chainrecon.tui.screens.scan.NmapRunner") as runner_type,
        ):
            runner_type.return_value.run_scan.side_effect = NmapInterfaceMismatchError(
                "Selected interface cannot reach target",
                {"recommended_interface": {"label": "Lab Ethernet"}},
            )
            app = ChainReconApp(case_path=str(case.root))
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("scan")
                await pilot.pause()
                app.screen.query_one("#target", Input).value = "192.0.2.10"
                app.screen.query_one("#btn-scan", Button).press()
                log = app.screen.query_one("#scan-log", LogViewer)
                await _until(lambda: "Recommended interface: Lab Ethernet" in log._plain_text())

    asyncio.run(exercise())
    assert not Case.open(case.root).manifest["runs"]
    assert not list(output.glob("*.json"))
