"""A footer with a persistent, clickable keyboard help shortcut."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from textual.app import ComposeResult
from textual.widgets import Footer, Static

if TYPE_CHECKING:
    from chainrecon.tui.app import ChainReconApp


class HelpShortcut(Static):
    """Keep help discoverable even while Textual refreshes screen bindings."""

    ALLOW_SELECT = False

    def __init__(self) -> None:
        super().__init__("[reverse]F1[/reverse] Help", markup=True)

    def on_click(self) -> None:
        self.call_later(cast("ChainReconApp", self.app).action_keyboard_help)


class HelpFooter(Footer):
    """Pin F1 Help at the right edge of each main screen's bottom bar."""

    def __init__(self) -> None:
        super().__init__(show_command_palette=False)

    def compose(self) -> ComposeResult:
        yield from super().compose()
        yield HelpShortcut()
