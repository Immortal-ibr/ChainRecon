"""Dashboard screen -- landing page with tool status and session overview."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, Static

from tui.screens.help_screen import HelpScreen
from utils.platform_info import find_tool

HELP_TEXT = """[bold underline]ChainRecon -- How It Works[/]

ChainRecon is an IoT security assessment framework. It sits between an IoT
device and the internet so you can capture and inspect every packet the
device sends or receives.

[bold]Physical Setup[/]
Your IoT device connects to a dedicated router (not your main one). That
router plugs into your computer via Ethernet. Your computer forwards the
router's traffic out through your WiFi (or another connection) to the
internet. This is standard NAT -- the same thing your home router does,
except now you control the pipe and can see everything.

[bold]What the Tools Do[/]
  - nmap      -- Scans the device for open ports and running services
  - tshark    -- Captures packets (Windows + Linux, comes with Wireshark)
  - adb       -- Connects to Android devices/emulators for Frida injection
  - frida     -- Injects JavaScript into running Android apps at runtime
  - jadx      -- Decompiles APK files to Java source code

[bold]Navigation[/]
  n = Network Setup   s = Scan         c = Capture     a = Analyze
  k = APK             f = Frida        r = Reports     t = Settings
  x = Custom Script   q = Quit         ? = Toggle help

[bold]Tip -- Windows Terminal vs old PowerShell console[/]
Run ChainRecon from Windows Terminal (wt.exe) or cmd.exe for correct
Unicode box-drawing. Admin PowerShell ISE / old conhost.exe can show
garbled characters. Paste paths with Ctrl+Shift+V in Windows Terminal.

[dim]To edit this screen: tui/screens/dashboard.py[/]
"""


class _ToolStatus(Static):
    """Single-line tool availability indicator."""

    def __init__(self, tool_name: str) -> None:
        super().__init__()
        self.tool_name = tool_name

    def on_mount(self) -> None:
        path = find_tool(self.tool_name)
        if path:
            self.update(f"[green]OK[/] {self.tool_name}: {path}")
        else:
            self.update(f"[red]X[/] {self.tool_name}: not found")


_MENU_ITEMS = [
    ("n", "network_setup", "Network Setup  -- configure NAT / routing"),
    ("s", "scan",          "Scan           -- run nmap against target device"),
    ("c", "capture",       "Capture        -- record traffic with tshark"),
    ("a", "analyze",       "Analyze        -- parse pcap / nmap output files"),
    ("k", "apk",           "APK Analysis   -- static analysis of Android .apk"),
    ("f", "frida",         "Frida          -- instrument a running Android app"),
    ("r", "reports",       "Reports        -- generate HTML / JSON / CSV report"),
    ("t", "settings",      "Settings       -- tool paths, config, API keys"),
]


class DashboardScreen(Screen):
    BINDINGS = [
        ("n", "app.push_screen('network_setup')", "Network"),
        ("s", "app.push_screen('scan')", "Scan"),
        ("c", "app.push_screen('capture')", "Capture"),
        ("a", "app.push_screen('analyze')", "Analyze"),
        ("k", "app.push_screen('apk')", "APK"),
        ("f", "app.push_screen('frida')", "Frida"),
        ("r", "app.push_screen('reports')", "Reports"),
        ("t", "app.push_screen('settings')", "Settings"),
        ("x", "app.push_screen('custom_script')", "Custom Script"),
        ("question_mark", "toggle_help", "Help"),
        ("q", "app.quit", "Quit"),
    ]

    DEFAULT_CSS = """
    #dashboard {
        padding: 1 2;
    }
    #dashboard #title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #menu-section {
        margin: 0 0 1 0;
        height: auto;
    }
    #tools-section {
        height: auto;
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        import platform
        yield Header()
        with Vertical(id="dashboard"):
            yield Label("[bold]ChainRecon[/] [dim]IoT Security Assessment Framework[/]", id="title")
            with Vertical(id="menu-section"):
                yield Label("[bold underline]Menu[/]")
                for key, _screen, label in _MENU_ITEMS:
                    yield Label(f"  [bold cyan]{key}[/]  {label}")
            with Vertical(id="tools-section"):
                yield Label("[bold underline]Tool Status[/]")
            # tshark replaces tcpdump on Windows
            tools = ["nmap", "tshark", "adb", "frida", "jadx", "apktool"]
            if platform.system() != "Windows":
                tools.insert(2, "tcpdump")
            with Horizontal():
                with Vertical():
                    for tool in tools:
                        yield _ToolStatus(tool)
            yield Label("")
            yield Label(
                "[dim]Press a key above to navigate  -  [b]?[/b] help  -  [b]q[/b] quit  -  "
                "[b]x[/b] custom script[/]"
            )
        yield Footer()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="ChainRecon -- How It Works"))
