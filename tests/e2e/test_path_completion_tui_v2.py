"""Path completion works through real TUI key bindings, including spaces."""

import asyncio
import os
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Input

from chainrecon.tui.widgets.path_input import PathInput


class _PathApp(App):
    def compose(self) -> ComposeResult:
        yield PathInput(id="path", directories_only=True)
        yield Input(id="next")


def test_tab_completes_and_cycles_directory_names(tmp_path: Path) -> None:
    (tmp_path / "IoT Goat").mkdir()
    (tmp_path / "IoT Other").mkdir()

    async def exercise() -> None:
        app = _PathApp()
        async with app.run_test(size=(100, 15)) as pilot:
            field = app.query_one("#path", PathInput)
            field.focus()
            field.value = str(tmp_path / "IoT")
            await pilot.press("tab")
            assert field.value == str(tmp_path / "IoT ")
            await pilot.press("tab")
            assert field.value == str(tmp_path / "IoT Goat") + os.sep
            await pilot.press("tab")
            assert field.value == str(tmp_path / "IoT Other") + os.sep

    asyncio.run(exercise())


def test_tab_stays_in_path_field_when_no_match_and_ctrl_tab_moves_on(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _PathApp()
        async with app.run_test(size=(80, 15)) as pilot:
            field = app.query_one("#path", PathInput)
            field.focus()
            field.value = str(tmp_path / "missing-folder")
            await pilot.press("tab")
            assert app.focused is field
            assert field.value == str(tmp_path / "missing-folder")
            await pilot.press("ctrl+tab")
            assert app.focused is app.query_one("#next", Input)
            await pilot.press("shift+tab")
            assert app.focused is field

    asyncio.run(exercise())
