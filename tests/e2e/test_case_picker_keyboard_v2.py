"""Case selection and evidence import work without a mouse."""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Collapsible, DirectoryTree, Select, Static

from chainrecon.case_model import Case
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.screens.case import CaseScreen
from chainrecon.tui.screens.case_analysis import CaseAnalysisScreen
from chainrecon.tui.screens.case_picker import CasePickerScreen, recent_cases
from chainrecon.tui.screens.dashboard import DashboardScreen
from chainrecon.tui.widgets.path_input import PathInput
from chainrecon.utils import config


async def _until(predicate) -> None:
    for _ in range(150):
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("TUI did not reach the expected state")


def _isolate_preferences(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path / "config")
    monkeypatch.setenv("CHAINRECON_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("CHAINRECON_CONFIG_FILE", raising=False)
    config.reset_config()


def test_keyboard_switch_create_and_reopen_recent_case(tmp_path: Path, monkeypatch) -> None:
    _isolate_preferences(monkeypatch, tmp_path)
    first = Case.create(tmp_path / "first", "First case")
    second = Case.create(tmp_path / "second", "Second case")
    created = tmp_path / "new case"

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(first.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            await pilot.press("ctrl+o")
            await _until(lambda: isinstance(app.screen, CasePickerScreen))
            picker = app.screen
            picker.query_one("#folder-path", PathInput).value = str(tmp_path / "missing")
            await pilot.press("ctrl+o")
            status = picker.query_one("#picker-status", Static)
            assert status.tooltip == "No investigation in that folder. Use Create investigation to start one."
            assert status.region.y < picker.query_one("#picker-actions").region.y

            picker.query_one("#folder-path", PathInput).value = str(second.root)
            await pilot.press("ctrl+o")
            await _until(lambda: isinstance(app.screen, CaseScreen) and app._case_path == str(second.root))
            assert second.root in recent_cases()

            await pilot.press("ctrl+o")
            await _until(lambda: isinstance(app.screen, CasePickerScreen))
            app.screen.query_one("#folder-path", PathInput).value = str(created)
            await pilot.press("ctrl+n")
            await _until(lambda: isinstance(app.screen, CaseScreen) and app._case_path == str(created))
            assert Case.open(created).manifest["title"] == "new case"
            assert recent_cases()[0] == created

            await pilot.press("ctrl+o")
            await _until(lambda: isinstance(app.screen, CasePickerScreen))
            await pilot.press("shift+tab")
            assert app.focused is app.screen.query_one("#recent-cases", Select)
            await pilot.press("enter", "down", "down", "enter")
            await pilot.pause()
            assert app.screen.query_one("#folder-path", PathInput).value == str(second.root)
            await pilot.press("escape")
            await _until(lambda: isinstance(app.screen, CaseScreen))
            assert app._case_path == str(created)

    asyncio.run(exercise())
    config.reset_config()


def test_keyboard_import_chooses_type_and_runs_matching_analyzer(tmp_path: Path, monkeypatch) -> None:
    _isolate_preferences(monkeypatch, tmp_path)
    case = Case.create(tmp_path / "case")
    scan = tmp_path / "scan.xml"
    scan.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host></nmaprun>',
        encoding="utf-8",
    )

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, CaseScreen)
            kind = screen.query_one("#evidence-kind", Select)
            assert kind.value == Select.NULL

            source = screen.query_one("#evidence-source", PathInput)
            source.value = ""
            source.focus()
            await pilot.press("a", "o", "r")
            assert source.value == "aor"
            assert isinstance(app.screen, CaseScreen)
            source.value = str(scan)
            await pilot.press("ctrl+tab")
            assert app.focused is kind
            await pilot.press("enter", *("down" for _ in range(6)), "enter")
            assert kind.value == "scan_xml"
            await pilot.press("tab", "enter")
            await _until(lambda: len(Case.open(case.root).manifest["evidence"]) == 1)
            await _until(lambda: not screen._busy)
            await pilot.press("r")
            await _until(lambda: isinstance(app.screen, CaseAnalysisScreen))
            analysis = app.screen
            assert analysis.query_one("#analysis-evidence", Select).value == Case.open(case.root).manifest["evidence"][0]["id"]
            assert not analysis.query_one("#analysis-firmware-options", Collapsible).display
            await pilot.press("r")
            await _until(lambda: len(Case.open(case.root).manifest["runs"]) == 1)
            await _until(lambda: not analysis._busy)
            assert Case.open(case.root).manifest["runs"][0]["analyzer"] == "scan"

    asyncio.run(exercise())
    config.reset_config()


def test_keyboard_directory_browser_selects_folder(tmp_path: Path, monkeypatch) -> None:
    _isolate_preferences(monkeypatch, tmp_path)
    first = Case.create(tmp_path / "alpha")
    second = tmp_path / "beta"
    second.mkdir()

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(first.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+o")
            await _until(lambda: isinstance(app.screen, CasePickerScreen))
            picker = app.screen
            await pilot.press("ctrl+tab")
            browse = picker.query_one("#browse-section", Collapsible)
            assert app.focused is not None and app.focused.parent is browse
            await pilot.press("enter")
            assert not browse.collapsed
            tree = picker.query_one("#folder-tree", DirectoryTree)
            await pilot.press("tab")
            assert app.focused is tree
            await pilot.pause()
            await pilot.press("right", "down", "down", "enter")
            assert picker.query_one("#folder-path", PathInput).value == str(second)

    asyncio.run(exercise())
    config.reset_config()


def test_no_configured_case_can_be_created_from_keyboard(tmp_path: Path, monkeypatch) -> None:
    _isolate_preferences(monkeypatch, tmp_path)
    destination = tmp_path / "first case"

    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            await pilot.press("i")
            await _until(lambda: isinstance(app.screen, CaseScreen))
            assert getattr(app.focused, "id", None) == "case-choose"
            await pilot.press("ctrl+o")
            await _until(lambda: isinstance(app.screen, CasePickerScreen))
            app.screen.query_one("#folder-path", PathInput).value = str(destination)
            await pilot.press("ctrl+n")
            await _until(lambda: isinstance(app.screen, CaseScreen) and destination.joinpath("case.json").is_file())
            assert app._case_path == str(destination)
            assert not app.screen.query_one("#import-section", Collapsible).collapsed

    asyncio.run(exercise())
    config.reset_config()
