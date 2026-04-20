"""Welcome / OS selection screen — shown on every startup.

The user picks Windows or Linux.  The choice is stored in ``app.os_mode``
and every screen / script that needs to know the platform reads it from
there instead of calling ``platform.system()`` directly.

This lets you deliberately run in Linux mode on Windows (e.g. controlling
a remote box via SSH) or vice-versa.
"""

from __future__ import annotations

import platform

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, Static


_DETECTED = platform.system()  # "Windows" | "Linux" | "Darwin"


class WelcomeScreen(Screen):
    """Startup screen that asks the user which OS mode to use."""

    BINDINGS = [
        ("enter", "continue_action", "Continue"),
    ]

    DEFAULT_CSS = """
    WelcomeScreen {
        align: center middle;
    }
    #welcome-box {
        width: 90%;
        max-width: 100;
        height: auto;
        border: double $accent;
        background: $surface;
        padding: 2 4;
    }
    #welcome-logo {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
        content-align: center middle;
    }
    #welcome-subtitle {
        color: $text-muted;
        margin-bottom: 2;
        content-align: center middle;
    }
    #os-label {
        margin-bottom: 0;
    }
    #os-select {
        margin-bottom: 1;
    }
    #welcome-detected {
        color: $text-muted;
        margin-bottom: 2;
    }
    #btn-continue-container {
        height: auto;
        margin-top: 1;
    }
    #btn-continue {
        width: 20;
    }
    """

    def compose(self) -> ComposeResult:
        detected_label = {"Windows": "Windows", "Linux": "Linux", "Darwin": "Linux"}.get(_DETECTED, _DETECTED)
        with Vertical(id="welcome-box"):
            yield Static(
                "CHAIN RECON\n"
                "IoT Network Security Assessment Tool",
                id="welcome-logo",
            )
            yield Static("v1.0  |  Mobile & IoT Security Framework", id="welcome-subtitle")
            yield Label(
                f"[dim]Detected OS:[/] [bold]{_DETECTED}[/]  "
                "(change below if you want to use a different mode)",
                id="welcome-detected",
            )
            yield Label("Select operating system mode:", id="os-label")
            yield Select(
                [
                    ("Windows", "Windows"),
                    ("Linux", "Linux"),
                ],
                value="Windows" if _DETECTED == "Windows" else "Linux",
                id="os-select",
            )
            with Horizontal(id="btn-continue-container"):
                yield Button("Continue >", id="btn-continue", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-continue":
            self._continue()

    def action_continue_action(self) -> None:
        """Action for Enter key binding."""
        self._continue()

    def _continue(self) -> None:
        """Handle continue action — store OS choice and pop screen."""
        sel = self.query_one("#os-select", Select)
        chosen = sel.value if sel.value != Select.BLANK else (
            "Windows" if _DETECTED == "Windows" else "Linux"
        )
        # Store the OS choice on the app so all screens can read it
        self.app.os_mode = chosen  # type: ignore[attr-defined]
        self.app.pop_screen()
