"""Settings screen -- view config and verify tool availability."""

from __future__ import annotations

import platform

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static

from tui.screens.help_screen import HelpScreen
from utils.config import get_config, get_tool_path
from utils.platform_info import find_tool

_IS_WINDOWS = platform.system() == "Windows"

HELP_TEXT = """[bold underline]Settings & Configuration[/]

Shows which external tools are installed and the active configuration.

[bold]Tool Paths[/]
ChainRecon auto-detects tools from your system PATH. If a tool isn't
found automatically, you have three options:
  1. Add its directory to your system PATH
  2. Set its path in config/local.yaml under the tools: section
  3. Use an environment variable (see below)

[bold]Setting Up JADX (APK Decompiler)[/]
  1. Download jadx from: github.com/skylot/jadx/releases
     Get the zip (e.g. jadx-1.5.5.zip), not the .deb package
  2. Unzip to somewhere permanent (e.g. D:\\tools\\jadx-1.5.5)
  3. Add to config/local.yaml -- use SINGLE quotes for Windows paths:

       tools:
         jadx: 'D:\\tools\\jadx-1.5.5\\bin\\jadx.bat'

     Or use forward slashes (also works):
         jadx: D:/tools/jadx-1.5.5/bin/jadx.bat

  4. Or set environment variable: CHAINRECON_JADX_PATH=D:\\tools\\jadx-1.5.5\\bin\\jadx.bat

  [dim]Why single quotes? Double-quoted YAML strings interpret backslashes
  as escape sequences, so "C:\\foo" would be parsed incorrectly.[/dim]

[bold]Setting Up apktool (APK Resource Decoder)[/]
  apktool is a JAR file -- it requires Java to be installed first.
  ChainRecon handles the "java -jar" invocation automatically;
  you just point it at the .jar file.

  1. Download apktool.jar from: apktool.org or github.com/iBotPeaches/Apktool
  2. Add to config/local.yaml:

       tools:
         apktool: 'D:\\tools\\apktool\\apktool.jar'

  3. Or set environment variable: CHAINRECON_APKTOOL_PATH=D:\\tools\\apktool\\apktool.jar

  [dim]Java must be on your PATH. Verify with: java -version[/dim]

[bold]YAML Path Syntax Quick Reference[/]
  Single quotes -- backslash is literal, safest for Windows paths:
    jadx: 'C:\\path\\to\\jadx.bat'
  Unquoted -- also works if no special YAML chars (: { } [ ] , # & | etc):
    jadx: C:\\path\\to\\jadx.bat
  Forward slashes -- always work on Windows too:
    jadx: C:/path/to/jadx.bat

[bold]Config File Cascade[/] (later overrides earlier)
  1. config/default.yaml  Built-in defaults. Don't edit this directly.
  2. config/local.yaml    Your local overrides. Create this file for
                          custom tool paths, API keys, or network values.
  3. config/nooie_profile.yaml  Device-specific profile, loaded via
                          the --config CLI flag.
  4. Environment variables  Highest priority. Always wins.

[bold]Environment Variables[/]
  CHAINRECON_JADX_PATH       Path to jadx.bat
  CHAINRECON_APKTOOL_PATH    Path to apktool.jar
  CHAINRECON_NMAP_PATH       Path to nmap executable
  CHAINRECON_TSHARK_PATH     Path to tshark executable
  CHAINRECON_ADB_PATH        Path to adb executable
  CHAINRECON_FRIDA_PATH      Path to frida-server binary

[bold]What You Can Configure[/]
  Tool paths, API keys (api_keys.shodan), scan profiles,
  IoT port mappings, capture defaults, network interface names,
  Frida settings, and output directory.

[dim]Config files: config/ directory
To edit this screen: tui/screens/settings.py[/]
"""


class SettingsScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("question_mark", "toggle_help", "Help")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="settings"):
            yield Label("[bold]Settings & Tool Verification[/]")
            yield Label("")
            yield Label("[bold underline]External Tools[/]")
            _tools = ["nmap", "tshark", "adb", "frida", "frida-ps", "jadx", "apktool"]
            if not _IS_WINDOWS:
                _tools.insert(2, "tcpdump")  # tcpdump not available on Windows
            for tool in _tools:
                yield _ToolRow(tool)
            yield Label("")
            yield Label("[bold underline]Active Configuration[/]")
            yield _ConfigSummary()
            yield Label("")
            yield Button("Back", id="btn-back")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Settings"))


class _ToolRow(Static):
    def __init__(self, tool: str) -> None:
        super().__init__()
        self._tool = tool

    def on_mount(self) -> None:
        path = find_tool(self._tool)
        if path is None and self._tool == "jadx":
            # Try raw config value even if file not found yet
            cfg_val = get_tool_path("jadx")
            if cfg_val:
                path = cfg_val + "  [dim](from config -- file not found)[/dim]"
        mark = "[green]OK[/]" if path else "[red]X[/]"
        self.update(f"  {mark} {self._tool}: {path or 'not found'}")


class _ConfigSummary(Static):
    def on_mount(self) -> None:
        import json
        try:
            cfg = get_config()
            text = json.dumps(cfg, indent=2, default=str)[:2000]
        except Exception as exc:
            text = f"Error loading config: {exc}"
        # Use Text() to prevent Rich from interpreting JSON brackets as markup
        self.update(Text(text))
