"""Community Plugins screen -- discover, validate, and run community analyzers."""

from __future__ import annotations

import threading

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, Static

from tui.screens.help_screen import HelpScreen
from tui.widgets.log_viewer import LogActionBar, LogViewer
from tui.widgets.pasteable_input import PasteableInput as Input

HELP_TEXT = """[bold underline]Community Plugins[/]

Community plugins extend ChainRecon with custom analysis steps contributed
by users.  Each plugin is a folder under community_plugins/ containing a
plugin.yaml manifest and a Python module.

[bold]Plugin manifest schema[/]
  name        -- unique identifier (snake_case)
  version     -- semantic version string (1.0.0)
  type        -- "analyzer"
  entrypoint  -- "module.py:ClassName"
  inputs      -- list of parameter names the plugin expects
  outputs     -- list of output field names the plugin produces
  description -- one-line description shown in this screen

[bold]Python callable contract[/]
  Your class must implement:
    def analyze(self, input_path=None, output_dir=None, **kwargs) -> dict

  Return a normalized report dict with keys:
    metadata   -- analyzer name, version, input path
    findings   -- plugin-specific findings dict
    summary    -- counts or key metrics
    risk_indicators -- list of {severity, title, details}

[bold]Adding a new plugin[/]
  1. Create community_plugins/my_plugin/plugin.yaml with all required fields
  2. Create community_plugins/my_plugin/plugin.py with your class
  3. Run: chainrecon.py  (it will auto-discover the plugin on next load)
  4. Open this screen -- your plugin appears in the selector

[bold]Running a plugin[/]
  Select the plugin, enter an input path (file or directory the plugin reads),
  and press Run Plugin.  Output is shown in the log and added to the session
  report under the "community" section.

[bold]Validation status[/]
  OK      -- manifest is valid and entrypoint loads successfully
  INVALID -- a required field is missing or malformed (field shown in log)
  ERROR   -- manifest valid but Python module/class failed to import

[dim]To edit this screen: tui/screens/community_plugins.py[/]
"""


class CommunityPluginsScreen(Screen):
    HELP_TEXT = HELP_TEXT
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "toggle_help", "Help"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            with Vertical(id="plugins-form"):
                yield Label("[bold]Community Plugins[/]", id="title")
                yield Label("Available Plugins")
                yield Select([], id="plugin-select", allow_blank=True)
                yield Static("", id="plugin-description")
                yield Label("Input Path")
                yield Input(placeholder="/path/to/file or directory", id="plugin-input")
                yield Label("Output Directory (optional)")
                yield Input(placeholder="leave empty for session output dir", id="plugin-output-dir")
                with Horizontal():
                    yield Button("Run Plugin", id="run-plugin", variant="primary")
                    yield Button("Validate All", id="validate-plugins")
                    yield Button("Back", id="back-btn")
                yield LogActionBar()
                yield LogViewer(id="plugins-log")
        yield Footer()

    def on_mount(self) -> None:
        self._running = False
        self._descriptors: list = []
        self._refresh_plugins()

    def _refresh_plugins(self) -> None:
        log = self.query_one(LogViewer)
        try:
            from utils.community_plugins import discover_community_plugins
            self._descriptors = discover_community_plugins()
        except Exception as exc:
            log.append(f"[yellow]Plugin discovery error:[/] {exc}")
            self._descriptors = []

        if self._descriptors:
            options = [(f"{d['name']} v{d.get('version', '?')} -- {d.get('description', '')[:50]}", d["name"]) for d in self._descriptors]
            self.query_one("#plugin-select", Select).set_options(options)
        else:
            log.append("[dim]No community plugins found in community_plugins/.[/]")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "plugin-select":
            return
        desc_widget = self.query_one("#plugin-description", Static)
        if event.value in (Select.BLANK, None):
            desc_widget.update("")
            return
        descriptor = next((d for d in self._descriptors if d["name"] == event.value), None)
        if descriptor:
            lines = [
                f"[bold]{descriptor.get('name')}[/] v{descriptor.get('version', '?')}",
                f"Type: {descriptor.get('type', '?')}  Entrypoint: {descriptor.get('entrypoint', '?')}",
                f"Inputs: {', '.join(descriptor.get('inputs', []))}",
                f"Outputs: {', '.join(descriptor.get('outputs', []))}",
                f"[dim]{descriptor.get('description', '')}[/]",
            ]
            desc_widget.update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "validate-plugins":
            self._validate_all()
        elif event.button.id == "run-plugin":
            self._start_run()

    def _validate_all(self) -> None:
        log = self.query_one(LogViewer)
        log.clear_log()
        log.append("[cyan]Validating all community plugins...[/]")
        try:
            from utils.community_plugins import discover_community_plugins
            descriptors = discover_community_plugins()
            if not descriptors:
                log.append("[dim]No plugins found.[/]")
                return
            for d in descriptors:
                name = d.get("name", "?")
                missing = [f for f in ("name", "version", "type", "entrypoint", "inputs", "outputs", "description") if not d.get(f)]
                if missing:
                    log.append(f"[red]INVALID[/] {name} -- missing fields: {', '.join(missing)}")
                    continue
                try:
                    from utils.community_plugins import load_community_plugin
                    load_community_plugin(name)
                    log.append(f"[green]OK     [/] {name} v{d.get('version', '?')}")
                except Exception as exc:
                    log.append(f"[yellow]ERROR  [/] {name} -- {exc}")
        except Exception as exc:
            log.append(f"[red]Validation error:[/] {exc}")

    def _start_run(self) -> None:
        if self._running:
            return
        plugin_name = self.query_one("#plugin-select", Select).value
        if plugin_name in (Select.BLANK, None):
            self.query_one(LogViewer).append("[red]Select a plugin first.[/]")
            return
        input_path = self.query_one("#plugin-input", Input).value.strip()
        if not input_path:
            self.query_one(LogViewer).append("[red]Input path is required.[/]")
            return
        output_dir = self.query_one("#plugin-output-dir", Input).value.strip() or None

        log = self.query_one(LogViewer)
        log.clear_log()
        log.append(f"[cyan]Running plugin:[/] {plugin_name}")

        self._running = True
        threading.Thread(target=self._run_plugin, args=(str(plugin_name), input_path, output_dir), daemon=True).start()

    def _run_plugin(self, plugin_name: str, input_path: str, output_dir) -> None:
        log = self.query_one(LogViewer)
        try:
            from utils.community_plugins import load_community_plugin
            from utils.config import get_output_dir as _get_out
            plugin = load_community_plugin(plugin_name)
            kwargs = {"input_path": input_path}
            if output_dir:
                kwargs["output_dir"] = output_dir
            result = plugin.analyze(**kwargs)
            summary = result.get("summary", {})
            log.append(f"[green]Plugin completed.[/]")
            for k, v in summary.items():
                log.append(f"  {k}: {v}")
            risk = result.get("risk_indicators", [])
            for ri in risk:
                sev = ri.get("severity", "info").upper()
                sev_color = "red" if sev == "HIGH" else ("yellow" if sev == "MEDIUM" else "cyan")
                log.append(f"  [{sev_color}][{sev}][/] {ri.get('title', '')}")
            if hasattr(self, "app") and hasattr(self.app, "_report_gen"):
                self.app._report_gen.add_results("community", result, mode="append")
        except Exception as exc:
            log.append(f"[red]Plugin error:[/] {exc}")
        finally:
            self._running = False

    def action_toggle_help(self) -> None:
        self.app.push_screen(HelpScreen(HELP_TEXT, title="Community Plugins"))
