"""Network Setup screen — configure NAT/routing for IoT interception."""

from __future__ import annotations

import platform
import subprocess
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select

from tui.widgets.pasteable_input import PasteableInput as Input

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogViewer
from utils.config import get_network_config, save_network_config
from utils.network import list_interfaces

HELP_TEXT = """[bold underline]Network Setup[/]

Configures your PC as a NAT router so you can intercept all traffic from
an IoT device connected through a dedicated physical router.

[bold]Physical Wiring[/]
  IoT Device  ──wifi──▶  Dedicated Router  ──ethernet──▶  Your PC  ──wifi──▶  Internet

[bold]What This Screen Does[/]
  1. Assigns a static IP to your Ethernet adapter (the one going to the
     router). This makes your PC the gateway for the IoT subnet.
  2. Enables IP forwarding between your Ethernet and Wi-Fi adapters so
     traffic flows from IoT → router → your PC → internet and back.
  3. Creates a NAT rule so outgoing IoT traffic gets masqueraded behind
     your PC's internet IP (just like a home router does).

[bold]Fields[/]
  • Ethernet Interface — The adapter connected to the IoT router.
  • Internet Interface — The adapter with active internet (usually Wi-Fi).
  • Static IP — IP to assign to the Ethernet adapter. Must be in the same
    subnet as the router (e.g. 192.168.123.100 if router is .99).
  • Subnet Prefix — Usually 24 for a /24 (255.255.255.0) network.
  • Target IP — IP of the IoT device (for capture BPF filters).
  • Router IP — IP of the dedicated router.

[bold]Buttons[/]
  • Apply — Runs the setup script (requires admin/root privileges).
  • Save Config — Saves settings to config/local.yaml so they persist
    across sessions and pre-populate the Capture screen.
  • Remove — Tears down the NAT and removes the static IP.

[bold]Platform[/]
  Windows: scripts/network_setup.ps1 (PowerShell, requires Run As Admin)
  Linux:   scripts/network_setup.sh (bash, requires sudo)

[dim]Scripts: scripts/network_setup.ps1, scripts/network_setup.sh
Config: config/local.yaml → network section
To edit this screen: tui/screens/network_setup.py[/]
"""

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"


class NetworkSetupScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "toggle_help", "Help"),
    ]

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _build_iface_options() -> tuple[list[tuple[str, str]], list[str]]:
        """Return (select_options, name_list) from live interface scan."""
        ifaces_raw = list_interfaces() or []
        iface_names = [i["name"] for i in ifaces_raw] if ifaces_raw else ["(none)"]
        opts = [(n, n) for n in iface_names]
        return opts, iface_names

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="network-setup-form"):
            yield Label("[bold]Network Setup — NAT / Routing[/]")
            yield Label(
                "[dim]Interfaces are detected from your OS each time you open this screen.[/]"
            )

            # Detect interfaces live every time this screen is opened
            opts, iface_names = self._build_iface_options()

            saved = get_network_config()
            eth_saved = saved.get("eth_interface") or iface_names[0]
            inet_saved = saved.get("internet_interface") or (iface_names[-1] if len(iface_names) > 1 else iface_names[0])
            if eth_saved not in iface_names:
                eth_saved = iface_names[0]
            if inet_saved not in iface_names:
                inet_saved = iface_names[-1] if len(iface_names) > 1 else iface_names[0]

            yield Label("Ethernet Interface (IoT side):")
            yield Select(opts, value=eth_saved, id="eth-iface")
            yield Label("Internet Interface (Wi-Fi / uplink):")
            yield Select(opts, value=inet_saved, id="inet-iface")
            yield Label("Static IP for Ethernet adapter:")
            yield Input(
                value=saved.get("static_ip", "192.168.123.100/24"),
                placeholder="192.168.123.100/24",
                id="static-ip",
            )
            yield Label("Target IP (IoT device):")
            yield Input(
                value=saved.get("target_ip", ""),
                placeholder="e.g. 192.168.123.50",
                id="target-ip",
            )
            yield Label("Router IP:")
            yield Input(
                value=saved.get("router_ip", ""),
                placeholder="e.g. 192.168.123.99",
                id="router-ip",
            )
            with Horizontal():
                yield Button("Apply", id="btn-apply", variant="primary")
                yield Button("Save Config", id="btn-save", variant="default")
                yield Button("Remove NAT", id="btn-remove", variant="warning")
                yield Button("Back", id="btn-back")
            yield LogViewer(id="net-log")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn-back":
            self.app.pop_screen()
        elif btn == "btn-save":
            self._save_config()
        elif btn == "btn-apply":
            self._run_script(remove=False)
        elif btn == "btn-remove":
            self._run_script(remove=True)

    def _gather_values(self) -> dict:
        eth = self.query_one("#eth-iface", Select).value
        inet = self.query_one("#inet-iface", Select).value
        static_ip = self.query_one("#static-ip", Input).value.strip()
        target_ip = self.query_one("#target-ip", Input).value.strip()
        router_ip = self.query_one("#router-ip", Input).value.strip()
        return {
            "eth_interface": eth if eth != Select.BLANK else None,
            "internet_interface": inet if inet != Select.BLANK else None,
            "static_ip": static_ip,
            "target_ip": target_ip,
            "router_ip": router_ip,
        }

    def _save_config(self) -> None:
        log = self.query_one("#net-log", LogViewer)
        vals = self._gather_values()
        try:
            save_network_config(vals)
            log.append("[green]Config saved to config/local.yaml[/]")
        except Exception as exc:
            log.append(f"[red]Failed to save: {exc}[/]")

    def _run_script(self, *, remove: bool = False) -> None:
        log = self.query_one("#net-log", LogViewer)
        vals = self._gather_values()
        eth = vals["eth_interface"]
        inet = vals["internet_interface"]
        static_raw = vals["static_ip"]

        if not eth or not inet:
            log.append("[red]Please select both interfaces.[/]")
            return

        # Parse static IP and prefix
        if "/" in static_raw:
            ip_part, prefix = static_raw.split("/", 1)
        else:
            ip_part, prefix = static_raw, "24"

        is_win = getattr(self.app, "os_mode", "Windows") == "Windows"
        action = "Removing" if remove else "Applying"
        log.append(f"[bold]{action} network configuration…[/]")

        def _worker() -> None:
            try:
                if is_win:
                    script = str(_SCRIPTS_DIR / "network_setup.ps1")
                    cmd = [
                        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", script,
                        "-EthInterface", eth,
                        "-InternetInterface", inet,
                        "-StaticIP", ip_part,
                        "-SubnetPrefix", prefix,
                    ]
                    if remove:
                        cmd.append("-Remove")
                else:
                    script = str(_SCRIPTS_DIR / "network_setup.sh")
                    cmd = ["sudo", "bash", script]
                    # The Linux script is interactive — pass values via env
                    # For automated use, we'd need to refactor network_setup.sh
                    # For now, just run it and let the user interact in terminal

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                output = result.stdout.strip()
                if output:
                    for line in output.splitlines()[-20:]:
                        self.app.call_from_thread(log.append, line)
                if result.returncode != 0:
                    err = result.stderr.strip()
                    if err:
                        self.app.call_from_thread(log.append, f"[red]{err[:500]}[/]")
                    self.app.call_from_thread(
                        log.append,
                        f"[yellow]Script exited with code {result.returncode}. "
                        "You may need to run as Administrator/root.[/]",
                    )
                else:
                    self.app.call_from_thread(log.append, "[green]Done.[/]")
            except subprocess.TimeoutExpired:
                self.app.call_from_thread(log.append, "[red]Script timed out (30s).[/]")
            except FileNotFoundError:
                self.app.call_from_thread(log.append, "[red]Script not found.[/]")
            except Exception as exc:
                self.app.call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Network Setup"))
