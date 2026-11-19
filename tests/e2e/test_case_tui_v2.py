"""Drive the case screen through import, analysis, review, and export."""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, Select

from chainrecon.case_model import Case, file_sha256, record_legacy_result
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.screens.case import CaseScreen
from chainrecon.tui.screens.case_analysis import CaseAnalysisScreen
from chainrecon.tui.screens.dashboard import DashboardScreen
from chainrecon.tui.screens.reports import ReportsScreen
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.utils.config import reset_config


async def _until(predicate) -> None:
    for _ in range(150):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Case TUI job did not finish")


def test_case_screen_import_analyze_review_and_export(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CHAINRECON_ASCII_UI", raising=False)
    case = Case.create(tmp_path / "case", "TUI case")
    legacy = tmp_path / "old.json"
    legacy.write_text('{"risk_indicators":[{"title":"Review candidate","severity":"low"}]}', encoding="utf-8")
    evidence = case.add_evidence(legacy, kind="legacy_result")
    old_run = record_legacy_result(case, evidence.id, {"risk_indicators": [{"title": "Review candidate", "severity": "low"}]}, analyzer="v1-import")
    scan = tmp_path / "scan.xml"
    scan.write_text('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>', encoding="utf-8")
    scan_id = "ev-" + file_sha256(scan)
    report_path = tmp_path / "report.html"

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            assert not app.has_class("ascii-mode")
            screen = app.screen
            assert screen.query_one("#finding-select", Select).value == old_run.findings[0].id
            screen.query_one("#reviewer", Input).value = "TUI reviewer"
            screen.query_one("#review-note", Input).value = "Confirmed in fixture"
            screen.query_one("#case-review", Button).press()
            await _until(lambda: Case.open(case.root).manifest["reviews"].get(old_run.findings[0].id, {}).get("status") == "confirmed")
            await _until(lambda: not screen._busy)

            screen.query_one("#evidence-source", Input).value = str(scan)
            screen.query_one("#evidence-kind", Select).value = "scan_xml"
            screen.query_one("#case-add", Button).press()
            await _until(lambda: len(Case.open(case.root).manifest["evidence"]) == 2)
            await _until(lambda: not screen._busy)

            assert screen.query_one("#evidence-select", Select).value == scan_id
            screen.query_one("#case-open-analysis", Button).press()
            await _until(lambda: isinstance(app.screen, CaseAnalysisScreen))
            await pilot.pause()
            analysis = app.screen
            await _until(lambda: analysis.query_one("#analysis-evidence", Select).value == scan_id)
            assert analysis.query_one("#analysis-evidence", Select).value == scan_id
            assert not analysis.query_one("#analysis-run", Button).disabled
            assert not analysis.query_one("#analysis-firmware-options").display
            analysis.query_one("#analysis-run", Button).press()
            await _until(lambda: len(Case.open(case.root).manifest["runs"]) == 2)
            await _until(lambda: not analysis._busy)
            await pilot.press("escape")
            await _until(lambda: isinstance(app.screen, CaseScreen))

            screen.query_one("#case-open-reports", Button).press()
            await _until(lambda: isinstance(app.screen, ReportsScreen))
            await pilot.pause()
            reports = app.screen
            assert reports.query_one("#source-mode", Select).value == "investigation"
            reports.query_one("#output-path", Input).value = str(report_path)
            reports.query_one("#format", Select).value = "html"
            reports.query_one("#btn-gen", Button).press()
            await _until(report_path.exists)

    asyncio.run(exercise())
    reopened = Case.open(case.root)
    assert reopened.manifest["reviews"][old_run.findings[0].id]["reviewer"] == "TUI reviewer"
    assert any(run["analyzer"] == "scan" for run in reopened.iter_runs())
    html = report_path.read_text(encoding="utf-8")
    assert "Investigation ID" in html
    assert "Review candidate" in html
    assert "TUI reviewer" in html


def test_dashboard_opens_with_configured_case_available(tmp_path: Path, monkeypatch) -> None:
    case = Case.create(tmp_path / "case", "Configured TUI case")
    image = tmp_path / "firmware.img"
    image.write_bytes(b"fixture")
    evidence = case.add_evidence(image, kind="firmware")
    config = tmp_path / "chainrecon.yaml"
    config.write_text(f"case:\n  directory: '{case.root.as_posix()}'\n", encoding="utf-8")
    monkeypatch.setenv("CHAINRECON_CONFIG_FILE", str(config))
    monkeypatch.delenv("CHAINRECON_ASCII_UI", raising=False)
    reset_config()

    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            await pilot.press("i")
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            assert app.screen.query_one("#evidence-select", Select).value == evidence.id
            assert not app.has_class("ascii-mode")

    asyncio.run(exercise())
    reset_config()
