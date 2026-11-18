"""Full-screen help overlay -- replaces the small collapsible side panel.

Press F1 from any screen to open this. Press Escape / Q / Enter to close.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static, TextArea


KEYBOARD_GUIDE = """Keyboard navigation

Tab moves to the next control; Shift+Tab moves back.
In a path field, Tab completes the path. Ctrl+Tab moves to the next control.
Arrow keys browse menus and folders. Enter chooses or activates.
Esc goes back or cancels. F1 opens keyboard help from any screen.
Single-letter shortcuts work when you are not typing in a field.
Every action also has an on-screen button.
"""


class HelpScreen(ModalScreen):
    """Full-screen modal help viewer.

    Usage (from any screen)::

        def action_toggle_help(self) -> None:
            from chainrecon.tui.screens.help_screen import HelpScreen
            self.app.push_screen(HelpScreen(HELP_TEXT, title="Scan"))
    """

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
        ("enter", "dismiss", "Close"),
    ]

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }

    #help-dialog {
        width: 88%;
        height: 88%;
        border: solid $accent;
        background: $surface;
    }

    #help-title {
        background: $accent;
        color: $text;
        padding: 0 2;
        text-style: bold;
        height: 3;
        content-align: center middle;
    }

    #help-body {
        padding: 1 3;
        height: 1fr;
    }

    #help-text {
        height: 1fr;
        border: none;
    }

    #help-close-bar {
        height: 3;
        align: right middle;
        padding: 0 2;
        background: $boost;
    }
    """

    def __init__(self, help_text: str, title: str = "Help", **kwargs) -> None:
        super().__init__(**kwargs)
        self._help_text = KEYBOARD_GUIDE + ("\n" + help_text if help_text else "")
        self._title = title

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical, Horizontal
        with Vertical(id="help-dialog"):
            yield Static(f"{self._title} -- Help", id="help-title")
            with VerticalScroll(id="help-body"):
                yield TextArea(_plain_help_text(self._help_text), id="help-text", read_only=True)
            with Horizontal(id="help-close-bar"):
                yield Button("Close  [dim]Esc / Q[/]", id="btn-close", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

def _plain_help_text(text: str) -> str:
    import re

    return re.sub(r"\[/?[^\]]*\]", "", text)
