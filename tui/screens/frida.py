"""Frida screen -- managed setup and live instrumentation sessions."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select

from runners.base import ToolNotFoundError
from runners.frida_runner import FRIDA_SCRIPT_GUIDE, FRIDA_SCRIPTS, FridaDeviceError, FridaRunner
from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogActionBar, LogViewer
from tui.widgets.pasteable_input import PasteableInput as Input
from utils.artifacts import artifact_path, safe_token, write_json_artifact
from utils.config import get_frida_config, get_output_dir, save_frida_config

def _build_help_text() -> str:
    sections = [
        "[bold underline]Frida Dynamic Instrumentation[/]",
        "",
        "This screen uses a managed Frida flow:",
        "  1. check host prerequisites",
        "  2. verify the selected device is managed-compatible",
        "  3. make sure frida-server is running",
        "  4. verify or launch the target package/process",
        "  5. attach, spawn, or run process census automatically",
        "  6. stream or summarize hook output and write session artifacts",
        "",
        "[bold]Per-Script Quick Reference[/]",
    ]
    for script_key, metadata in FRIDA_SCRIPTS.items():
        guide = FRIDA_SCRIPT_GUIDE.get(script_key, {})
        params = metadata.get("params", [])
        if params:
            param_bits = []
            for param in params:
                label = str(param.get("label", param["name"]))
                default = str(param.get("default", "")).strip()
                placeholder = str(param.get("placeholder", "")).strip()
                if default:
                    param_bits.append(f"{label} (default: {default})")
                else:
                    param_bits.append(label)
                if placeholder:
                    param_bits[-1] += f"; example: {placeholder}"
            param_text = ", ".join(param_bits)
        else:
            param_text = "none"
        tags = ", ".join(guide.get("expected_tags", [])) or "script-specific status lines"
        sections.extend(
            [
                f"[bold]{metadata['label']}[/]",
                f"  Hooks: {metadata.get('description', '')}",
                f"  When to use: {guide.get('when_to_use', 'Use when this script matches your target behavior.')}",
                f"  Parameters: {param_text}",
                f"  Expected output tags: {tags}",
                f"  Known limitations: {guide.get('limitations', 'Depends on the target app exposing hookable Java APIs.')}",
                "",
            ]
        )
    sections.extend(
        [
            "[bold]Managed Compatibility Policy[/]",
            "  Compatible means compatible with ChainRecon's managed Frida workflow:",
            "  - Google APIs emulator image",
            "  - supported ABI",
            "  - validated API range",
            "  - working adb / emulator tooling",
            "",
            "[bold]Live Output[/]",
            "  While a hook session is running:",
            "  - streamed output is appended to the output box",
            "  - the same stream is written to a session log in the output directory",
            "  - Stop Hook ends the active session and finalizes a JSON summary artifact",
        ]
    )
    return "\n".join(sections)


HELP_TEXT = _build_help_text()


class FridaScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back"), ("question_mark", "toggle_help", "Help")]

    DEFAULT_CSS = """
    #custom-section {
        display: none;
        height: auto;
    }
    #custom-section.visible {
        display: block;
    }
    #param-section {
        height: auto;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._runner = FridaRunner()
        self._selected_serial: str | None = None
        self._device_inventory: dict = {"connected_devices": [], "local_avds": []}
        self._current_session: dict | None = None
        self._last_exit_summary: dict | None = None
        self._param_signature: tuple[str, tuple[str, ...]] | None = None
        self._session_starting = False

    def compose(self) -> ComposeResult:
        frida_cfg = get_frida_config()
        selected_serial = frida_cfg.get("device_serial")
        self._selected_serial = str(selected_serial) if selected_serial else None
        yield Header()
        with VerticalScroll(id="frida-form"):
            yield Label("[bold]Frida Instrumentation[/]")
            yield Label("Selected device:")
            yield Select([("Auto-select online device", "__auto__")], value="__auto__", id="device-select")
            yield Label(
                "[dim]Use List Devices to load connected phones and local AVDs. Selecting a live device saves it for later Frida runs.[/]",
                id="device-note",
            )
            yield Label("APK directory for managed setup [dim](optional)[/]:")
            yield Input(
                placeholder="Folder containing APKs to install during setup",
                value=str(frida_cfg.get("apk_directory") or ""),
                id="apk-directory",
            )
            yield Label("frida-server path or directory [dim](optional)[/]:")
            yield Input(
                placeholder="File or directory containing matching frida-server binary",
                value=str(frida_cfg.get("frida_server_path") or frida_cfg.get("frida_server_directory") or ""),
                id="frida-server-path",
            )
            yield Label("Preferred AVD [dim](optional, used by auto-setup)[/]:")
            yield Input(
                placeholder="e.g. ChainRecon_API35",
                value=str(frida_cfg.get("preferred_avd") or ""),
                id="preferred-avd",
            )
            yield Label("Target process / package:")
            yield Input(placeholder="com.nooie.home", value="com.nooie.home", id="target")
            yield Label("Script:")
            frida_opts = [(v["label"], k) for k, v in FRIDA_SCRIPTS.items()] + [("Custom Frida JS...", "custom")]
            yield Select(frida_opts, value="nooie_mqtt_trace", id="script")
            with Vertical(id="param-section"):
                pass
            with Vertical(id="custom-section"):
                yield Label("[dim]-- Custom Frida JS --[/]")
                yield Label("Script path:")
                yield Input(placeholder=r"C:\scripts\hook.js", id="custom-path")
            with Horizontal():
                yield Button("Run", variant="primary", id="btn-run")
                yield Button("Stop Hook", id="btn-stop")
                yield Button("List Devices", id="btn-devices")
                yield Button("Boot Device", id="btn-boot")
                yield Button("Setup Device", id="btn-setup")
                yield Button("List Processes", id="btn-procs")
                yield Button("Back", id="btn-back")
            yield LogActionBar()
            yield LogViewer(id="frida-log")
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#frida-log", LogViewer)
        self.call_after_refresh(self._refresh_script_inputs)
        threading.Thread(target=self._list_devices, args=(log,), daemon=True).start()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "script":
            section = self.query_one("#custom-section")
            if event.value == "custom":
                section.add_class("visible")
            else:
                section.remove_class("visible")
            self._refresh_script_inputs()
        elif event.select.id == "device-select":
            self._persist_device_selection(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
            return

        log = self.query_one("#frida-log", LogViewer)

        if event.button.id == "btn-devices":
            threading.Thread(target=self._list_devices, args=(log,), daemon=True).start()
        elif event.button.id == "btn-boot":
            self._boot_selected_device(log)
        elif event.button.id == "btn-setup":
            self._setup_selected_device(log)
        elif event.button.id == "btn-procs":
            threading.Thread(target=self._list_procs, args=(log,), daemon=True).start()
        elif event.button.id == "btn-run":
            self._start_managed_session(log)
        elif event.button.id == "btn-stop":
            self._stop_managed_session(log)

    def _refresh_script_inputs(self) -> None:
        container = self.query_one("#param-section", Vertical)
        script_key = self.query_one("#script", Select).value
        metadata = FRIDA_SCRIPTS.get(str(script_key), {})
        params = metadata.get("params", [])
        script_key_text = str(script_key)
        signature = (script_key_text, tuple(str(param["name"]) for param in params))
        if self._param_signature == signature and list(container.children):
            return
        for child in list(container.children):
            child.remove()
        if not script_key or script_key == "custom" or script_key == Select.BLANK:
            self._param_signature = None
            return
        description = metadata.get("description")
        if description:
            container.mount(Label(f"[dim]{description}[/]"))
        if not params:
            container.mount(Label("[dim]Selected script has no extra parameters.[/]"))
            self._param_signature = signature
            return
        container.mount(Label("[bold]Script parameters[/]"))
        for param in params:
            label = str(param.get("label", param["name"]))
            required = " [red]*[/]" if param.get("required") else ""
            container.mount(Label(f"{label}:{required}"))
            container.mount(
                Input(
                    placeholder=str(param.get("placeholder", "")),
                    value=str(param.get("default", "")),
                    id=self._param_widget_id(script_key_text, str(param["name"])),
                )
            )
        self._param_signature = signature

    def _list_devices(self, log: LogViewer) -> None:
        try:
            inventory = self._runner.list_device_inventory()
            self._device_inventory = inventory
            self._safe_call_from_thread(self._apply_device_inventory, inventory)
            if inventory.get("install_guidance"):
                for line in inventory["install_guidance"]:
                    self._safe_call_from_thread(log.append, f"[yellow]{line}[/]")
            self._safe_call_from_thread(log.append, self._inventory_summary(inventory))
        except Exception as exc:
            self._safe_call_from_thread(log.append, f"[red]{exc}[/]")

    def _list_procs(self, log: LogViewer) -> None:
        try:
            processes = self._runner.list_processes_structured()
            if not processes:
                self._safe_call_from_thread(log.append, "[dim]No running processes reported by frida-ps.[/]")
                return
            lines = ["[bold]frida-ps processes[/]"]
            for proc in processes[:80]:
                identity = proc.get("identifier") or proc.get("name") or ""
                lines.append(f"  - {proc.get('pid', '')}  {proc.get('name', '')}  {identity}")
            self._safe_call_from_thread(log.append, "\n".join(lines))
        except Exception as exc:
            self._safe_call_from_thread(log.append, f"[red]{exc}[/]")

    def _start_managed_session(self, log: LogViewer) -> None:
        self._persist_setup_config()
        if self._session_starting or self._current_session is not None:
            log.append("[yellow]A Frida hook session is already starting or running. Stop it first.[/]")
            return

        target = self.query_one("#target", Input).value.strip().strip('"\'')
        script_key = self.query_one("#script", Select).value
        custom_path = self.query_one("#custom-path", Input).value.strip().strip('"\'')
        frida_server_path = self.query_one("#frida-server-path", Input).value.strip().strip('"\'')

        if not target:
            log.append("[red]Enter a target process/package name.[/]")
            return
        if script_key == "custom" and not custom_path:
            log.append("[red]Set a custom Frida JS path before running.[/]")
            return

        try:
            parameters = self._collect_script_parameters()
        except FridaDeviceError as exc:
            log.append(f"[red]{exc}[/]")
            return
        self._session_starting = True
        log.append("[bold]Starting managed Frida session...[/]")

        def _worker() -> None:
            try:
                result = self._runner.start_session(
                    target=target,
                    script_key=str(script_key),
                    parameters=parameters,
                    custom_script_path=custom_path or None,
                    frida_server_path=frida_server_path or None,
                    output_dir=get_output_dir(),
                    on_output=lambda line: self._safe_call_from_thread(log.append, line),
                    on_exit=lambda summary: self._safe_call_from_thread(self._handle_session_exit, summary, log),
                )
                if self._last_exit_summary and self._last_exit_summary.get("session_id") == result.get("session_id"):
                    self._current_session = None
                    self._session_starting = False
                    self._safe_call_from_thread(log.set_last_output_path, self._last_exit_summary.get("summary_path") or result["summary_path"])
                    return
                self._current_session = result
                self._session_starting = False
                self._safe_call_from_thread(log.set_last_output_path, result["log_path"])
                self._safe_call_from_thread(
                    log.append,
                    "\n".join(
                        [
                            f"[green]Frida session started for {target}.[/]",
                            f"[dim]Mode: {result['mode']} | attach target: {result['attach_target']}[/]",
                            f"[dim]Log: {result['log_path']}[/]",
                            f"[dim]Summary: {result['summary_path']}[/]",
                            f"[dim]frida-server started during run: {result['frida_server_started']}[/]",
                            f"[dim]Target launched during run: {result['launch_performed']}[/]",
                        ]
                    ),
                )
            except FridaDeviceError as exc:
                self._session_starting = False
                guidance = (exc.state or {}).get("install_guidance", [])
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")
                for step in guidance:
                    self._safe_call_from_thread(log.append, f"[yellow]{step}[/]")
            except ToolNotFoundError as exc:
                self._session_starting = False
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")
            except Exception as exc:
                self._session_starting = False
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _stop_managed_session(self, log: LogViewer) -> None:
        if self._current_session is None:
            log.append("[yellow]No active Frida hook session is running.[/]")
            return
        log.append("[bold]Stopping active Frida session...[/]")

        def _worker() -> None:
            try:
                summary = self._runner.stop_session()
                if summary is not None:
                    self._safe_call_from_thread(self._handle_session_exit, summary, log)
                else:
                    self._current_session = None
                    self._safe_call_from_thread(log.append, "[yellow]No active Frida hook session is running.[/]")
            except Exception as exc:
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _handle_session_exit(self, summary: dict, log: LogViewer) -> None:
        self._last_exit_summary = summary
        self._session_starting = False
        if self._current_session and self._current_session.get("session_id") != summary.get("session_id"):
            return
        self._current_session = None
        report_payload = {
            "metadata": {
                "section": "frida",
                "serial": summary.get("serial"),
                "target": summary.get("target"),
                "script": summary.get("script"),
                "log_path": summary.get("log_path"),
                "summary_path": str(summary.get("summary_path") or ""),
                "artifacts": [
                    {"type": "frida_log", "path": summary.get("log_path")},
                    {"type": "frida_summary", "path": summary.get("summary_path")},
                ],
            },
            "findings": {
                "session": summary,
                "events_by_tag": summary.get("events_by_tag", {}),
                "hook_events": _extract_frida_log_events(summary.get("log_path"), prefixes=("[HOOK]", "[STATUS]")),
                "error_events": _extract_frida_log_events(summary.get("log_path"), prefixes=("[ERROR]", "[WARN]", "[stderr]")),
            },
            "summary": {
                "status": summary.get("status"),
                "status_reason": summary.get("status_reason"),
                "exit_code": summary.get("exit_code"),
                "stdout_lines": summary.get("stdout_lines"),
                "stderr_lines": summary.get("stderr_lines"),
                "reattach_count": summary.get("reattach_count", 0),
                "dropped_event_count": summary.get("dropped_event_count", 0),
                "target_alive_at_exit": summary.get("target_alive_at_exit"),
            },
            "risk_indicators": _frida_risk_indicators(summary),
        }
        report_path = self._record_frida_report(report_payload)
        if summary.get("summary_path"):
            log.set_last_output_path(summary["summary_path"])
        lines = [
            f"[green]Frida session finished: {summary.get('status')}[/]",
            f"[dim]Exit code: {summary.get('exit_code')} | stopped by user: {summary.get('stopped_by_user')}[/]",
            f"[dim]Log: {summary.get('log_path')}[/]",
            f"[dim]Summary: {summary.get('summary_path')}[/]",
        ]
        if report_path:
            lines.append(f"[dim]Report artifact: {report_path}[/]")
        log.append("\n".join(lines))

    def _boot_selected_device(self, log: LogViewer) -> None:
        self._persist_setup_config()
        selection = self.query_one("#device-select", Select).value
        if selection in (None, Select.BLANK, "__auto__"):
            log.append("[yellow]Select a local AVD first, then press Boot Device.[/]")
            return

        def _worker() -> None:
            try:
                result = self._runner.boot_device(str(selection))
                self._safe_call_from_thread(log.append, f"[green]{result['message']}[/]")
                self._safe_call_from_thread(self._refresh_inventory_after_action, log)
            except ToolNotFoundError as exc:
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")
                self._safe_call_from_thread(log.append, f"[yellow]{self._runner.install_steps('emulator')}[/]")
            except FridaDeviceError as exc:
                self._safe_call_from_thread(log.append, f"[yellow]{exc}[/]")
            except Exception as exc:
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def _setup_selected_device(self, log: LogViewer) -> None:
        self._persist_setup_config()
        selection = self.query_one("#device-select", Select).value
        apk_directory = self.query_one("#apk-directory", Input).value.strip().strip('"\'')
        frida_server_path = self.query_one("#frida-server-path", Input).value.strip().strip('"\'')
        preferred_avd = self.query_one("#preferred-avd", Input).value.strip().strip('"\'')
        target_id = None if selection in (None, Select.BLANK, "__auto__") else str(selection)
        log.append("[bold]Preparing selected device for managed Frida setup...[/]")

        def _worker() -> None:
            try:
                result = self._runner.setup_device(
                    target_id=target_id,
                    apk_directory=apk_directory or None,
                    frida_server_path=frida_server_path or None,
                    preferred_avd=preferred_avd or None,
                )
                self._safe_call_from_thread(save_frida_config, {"device_serial": result["serial"]})
                self._selected_serial = result["serial"]
                report_payload = {
                    "metadata": {
                        "section": "frida",
                        "serial": result["serial"],
                        "selection": result.get("selection"),
                        "frida_server": result.get("frida_server"),
                    },
                    "findings": {
                        "setup_actions": result.get("actions", []),
                        "apk_installation": result.get("apk_installation", {}),
                        "frida_ps": result.get("frida_ps", ""),
                    },
                    "summary": {
                        "apk_verified": bool((result.get("apk_installation") or {}).get("verified", True)),
                        "installed_package_count": int((result.get("apk_installation") or {}).get("installed_count", 0)),
                    },
                    "risk_indicators": [],
                }
                report_path = self._record_frida_report(report_payload)
                for action in result.get("actions", []):
                    self._safe_call_from_thread(log.append, f"[dim]{action}[/]")
                self._safe_call_from_thread(log.append, f"[green]Managed setup complete for {result['serial']}.[/]")
                if report_path:
                    self._safe_call_from_thread(log.append, f"[dim]Result saved: {report_path}[/]")
                apk_installation = result.get("apk_installation") or {}
                if apk_installation.get("requested"):
                    self._safe_call_from_thread(
                        log.append,
                        f"[dim]APK deployment verified: {apk_installation.get('verified')} | "
                        f"packages: {', '.join(apk_installation.get('installed_packages', [])) or 'none'}[/]",
                    )
                    if apk_installation.get("details"):
                        self._safe_call_from_thread(log.append, f"[dim]{apk_installation['details']}[/]")
                resolution = result.get("frida_server_resolution") or {}
                if resolution.get("selected"):
                    self._safe_call_from_thread(log.append, f"[dim]Resolved frida-server: {resolution['selected']}[/]")
                if result.get("frida_ps"):
                    self._safe_call_from_thread(log.append, (result["frida_ps"][:3000]))
                self._safe_call_from_thread(self._refresh_inventory_after_action, log)
            except FridaDeviceError as exc:
                guidance = (exc.state or {}).get("install_guidance", [])
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")
                apk_installation = (exc.state or {}).get("apk_installation", {})
                if apk_installation:
                    self._safe_call_from_thread(log.append, f"[yellow]{json.dumps(apk_installation, indent=2)[:1500]}[/]")
                resolution = (exc.state or {}).get("frida_server_resolution", {})
                if resolution:
                    self._safe_call_from_thread(log.append, f"[yellow]{json.dumps(resolution, indent=2)[:1500]}[/]")
                for step in guidance:
                    self._safe_call_from_thread(log.append, f"[yellow]{step}[/]")
            except ToolNotFoundError as exc:
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")
            except Exception as exc:
                self._safe_call_from_thread(log.append, f"[red]{exc}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Frida Instrumentation"))

    def _apply_device_inventory(self, inventory: dict) -> None:
        select = self.query_one("#device-select", Select)
        options = [("Auto-select online device", "__auto__")]
        selected_value = "__auto__"
        for device in inventory.get("connected_devices", []):
            label = f"{device['serial']}  [{device['state']}]"
            options.append((label, device["id"]))
            if device["serial"] == self._selected_serial:
                selected_value = device["id"]
        for avd in inventory.get("local_avds", []):
            status = "booted" if avd.get("booted") else "stopped"
            options.append((f"{avd['avd_name']}  [AVD {status}]", avd["id"]))
        select.set_options(options)
        select.value = selected_value

    def _persist_device_selection(self, value) -> None:
        if value in (None, Select.BLANK):
            return
        if value == "__auto__":
            save_frida_config({"device_serial": None})
            self._selected_serial = None
            self.query_one("#device-note", Label).update(
                "[dim]Auto-select mode enabled. ChainRecon will use the single online adb device when possible.[/]"
            )
            return
        if not str(value).startswith("serial:"):
            self.query_one("#device-note", Label).update(
                "[dim]Boot target selected. Boot it first; once it appears in adb devices, select the live serial to pin Frida to it.[/]"
            )
            return
        serial = str(value).split(":", 1)[1]
        save_frida_config({"device_serial": serial})
        self._selected_serial = serial
        self.query_one("#device-note", Label).update(
            f"[dim]Pinned Frida to adb device {serial}. Future runs will use -D {serial}.[/]"
        )

    def _inventory_summary(self, inventory: dict) -> str:
        lines = []
        connected = inventory.get("connected_devices", [])
        avds = inventory.get("local_avds", [])
        if connected:
            lines.append("[bold]Connected devices[/]")
            for device in connected:
                status = "compatible" if device.get("frida_compatible") else "not compatible"
                lines.append(
                    f"  - {device['serial']} [{device['state']}] -- {status}: {device.get('frida_note', '')}"
                )
        else:
            lines.append("[dim]No adb devices are connected.[/]")
        if avds:
            lines.append("[bold]Local emulators[/]")
            for avd in avds:
                state = "booted" if avd.get("booted") else "stopped"
                lines.append(
                    f"  - {avd['avd_name']} [{state}] -- {'compatible' if avd.get('frida_compatible') else 'not compatible'}: "
                    f"{avd.get('frida_note', '')}"
                )
        return "\n".join(lines)

    def _refresh_inventory_after_action(self, log: LogViewer) -> None:
        threading.Thread(target=self._list_devices, args=(log,), daemon=True).start()

    def _persist_setup_config(self) -> None:
        frida_server_value = self.query_one("#frida-server-path", Input).value.strip().strip('"\'')
        payload = {
            "apk_directory": self.query_one("#apk-directory", Input).value.strip().strip('"\'') or None,
            "preferred_avd": self.query_one("#preferred-avd", Input).value.strip().strip('"\'') or None,
        }
        if frida_server_value:
            server_path = Path(frida_server_value).expanduser()
            if server_path.is_dir():
                payload["frida_server_directory"] = str(server_path)
                payload["frida_server_path"] = None
            else:
                payload["frida_server_path"] = str(server_path)
                payload["frida_server_directory"] = None
        save_frida_config(payload)

    def _collect_script_parameters(self) -> dict:
        params = {}
        script_key = self.query_one("#script", Select).value
        for param in FRIDA_SCRIPTS.get(str(script_key), {}).get("params", []):
            widget = self.query_one(f"#{self._param_widget_id(str(script_key), str(param['name']))}", Input)
            value = widget.value.strip()
            if param.get("required") and not value:
                raise FridaDeviceError(f"Script parameter '{param['label']}' is required.")
            params[param["name"]] = value
        return params

    @staticmethod
    def _param_widget_id(script_key: str, param_name: str) -> str:
        return f"param-{safe_token(script_key)}-{safe_token(param_name)}"

    def _record_frida_report(self, payload: dict) -> str | None:
        report_path = None
        try:
            outdir = get_output_dir()
            serial = str((payload.get("metadata") or {}).get("serial") or (payload.get("metadata") or {}).get("target") or "session")
            report_path = str(artifact_path(outdir, f"frida_{serial}", ".json").resolve())
            write_json_artifact(report_path, payload)
            payload.setdefault("metadata", {})["source_file"] = report_path
            payload["metadata"]["source_filename"] = Path(report_path).name
        except Exception:
            report_path = None
        if not hasattr(self.app, "_report_gen"):
            from analysis.report_generator import ReportGenerator

            self.app._report_gen = ReportGenerator()
        self.app._report_gen.add_results("frida", payload, mode="append")
        return report_path

    def _safe_call_from_thread(self, callback, *args) -> None:
        try:
            self.app.call_from_thread(callback, *args)
        except Exception:
            return


def _extract_frida_log_events(path: str | None, *, prefixes: tuple[str, ...], limit: int = 50) -> list[str]:
    if not path:
        return []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    matched = []
    for line in lines:
        stripped = line.strip()
        normalized = stripped
        if normalized.startswith("[stdout] "):
            normalized = normalized[len("[stdout] "):]
        if any(normalized.startswith(prefix) or stripped.startswith(prefix) for prefix in prefixes):
            matched.append(stripped)
    return matched[-limit:]


def _frida_risk_indicators(summary: dict) -> list[dict]:
    if summary.get("stopped_by_user"):
        return []
    status = str(summary.get("status") or "")
    reason = str(summary.get("status_reason") or "")
    if status in {"unexpected_exit", "failed"} or "failed" in reason or "target_died" in reason:
        return [{
            "severity": "medium",
            "title": "Frida session ended unexpectedly",
            "details": reason or status,
        }]
    return []
