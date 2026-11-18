"""Keyboard instructions are visible before a researcher knows the shortcuts."""

from __future__ import annotations

import asyncio
from html import unescape
from pathlib import Path

from textual.widgets import Button, Footer, TextArea

from chainrecon.case_model import Case
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.screens.case import CaseScreen
from chainrecon.tui.screens.case_analysis import CaseAnalysisScreen
from chainrecon.tui.screens.case_picker import CasePickerScreen
from chainrecon.tui.screens.dashboard import DashboardScreen
from chainrecon.tui.screens.help_screen import HelpScreen
from chainrecon.tui.widgets.help_footer import HelpFooter, HelpShortcut
from chainrecon.tui.widgets.path_input import PathInput


async def _rendered_text(app: ChainReconApp, *expected: str) -> str:
    for _ in range(60):
        content = unescape(app.export_screenshot()).replace("\xa0", " ")
        if all(value in content for value in expected):
            return content
        await asyncio.sleep(0.02)
    raise AssertionError(f"Screen did not render {expected}")


def test_footer_keyboard_help_and_f1_work_at_small_terminal_size(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            assert app.screen.query_one(Footer).region.y < app.size.height
            screen_text = await _rendered_text(app, "Complete path", "Next field", "F1", "Help")
            assert "f1" in screen_text.lower() and "Help" in screen_text
            assert "Complete path" in screen_text and "Next field" in screen_text
            assert "tab" in screen_text.lower()
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)
            guide = app.screen.query_one("#help-text", TextArea).text
            assert "Tab moves to the next control" in guide
            assert "Ctrl+Tab moves to the next control" in guide
            assert "Ctrl+O switch folder" in guide
            await pilot.press("escape")
            await pilot.pause()

            assert isinstance(app.screen, CaseScreen)
            app.screen.query_one("#evidence-source", PathInput).focus()
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)
            await pilot.press("escape")
            await pilot.pause()

            assert isinstance(app.screen, CaseScreen)
            app.screen.query_one("#case-open-analysis", Button).press()
            await pilot.pause()
            assert isinstance(app.screen, CaseAnalysisScreen)
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)
            assert "r run analysis" in app.screen.query_one("#help-text", TextArea).text
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()

            assert isinstance(app.screen, DashboardScreen)
            dashboard_text = await _rendered_text(app, "F1", "Help")
            assert "f1" in dashboard_text.lower() and "Help" in dashboard_text
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)

    asyncio.run(exercise())


def test_help_is_pinned_to_bottom_bar_and_clickable_on_main_screens(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(60, 24)) as pilot:
            await pilot.pause()
            for route in (
                "case",
                "case_analysis",
                "reports",
                "scan",
                "capture",
                "analyze",
                "frida",
                "apk",
                "settings",
                "network_setup",
                "custom_script",
                "workflow",
                "plugins",
                "profiles",
            ):
                if route != "case":
                    app.push_screen(route)
                    await pilot.pause()
                footer = app.screen.query_one(HelpFooter)
                for _ in range(60):
                    shortcuts = list(footer.query(HelpShortcut))
                    if shortcuts and shortcuts[0].region.y == app.size.height - 1:
                        break
                    await asyncio.sleep(0.02)
                assert shortcuts, f"Help shortcut did not mount on {route}"
                shortcut = shortcuts[0]
                assert "Help" in str(shortcut.render())
                assert shortcut.region.y == app.size.height - 1
                assert shortcut.region.x + shortcut.region.width == app.size.width
                assert "F1" in await _rendered_text(app, "F1")
                assert len(list(footer.query(HelpShortcut))) == 1
                if route in {"case", "reports", "scan"}:
                    await pilot.click(HelpShortcut)
                    await pilot.pause()
                    assert isinstance(app.screen, HelpScreen)
                    await pilot.press("escape")
                    await pilot.pause()
                if route != "case":
                    app.pop_screen()
                    await pilot.pause()

    asyncio.run(exercise())


def test_home_help_is_visible_at_60_columns() -> None:
    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(60, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            footer = app.screen.query_one(HelpFooter)
            await _rendered_text(app, "F1")
            shortcut = footer.query_one(HelpShortcut)
            assert shortcut.region.x + shortcut.region.width == app.size.width
            await pilot.click(HelpShortcut)
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)

    asyncio.run(exercise())


def test_case_picker_f1_explains_its_shortcuts(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            app.screen.action_choose_case()
            await pilot.pause()
            assert isinstance(app.screen, CasePickerScreen)
            assert "F1" in str(app.screen.query_one("#picker-keys").render())
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)
            text = app.screen.query_one("#help-text", TextArea).text
            assert "Ctrl+O opens" in text
            assert "Ctrl+N creates" in text

    asyncio.run(exercise())


def test_f1_on_a_specialist_screen_includes_navigation_and_tool_help() -> None:
    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app.push_screen("scan")
            await pilot.pause()
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)
            text = app.screen.query_one("#help-text", TextArea).text
            assert "Tab moves to the next control" in text
            assert "Network Scan" in text

    asyncio.run(exercise())
