"""Tests for the TUI application structure and screen composition."""

import tempfile
import unittest
from unittest.mock import patch
import asyncio

from tui.app import ChainReconApp
from tui.screens.dashboard import DashboardScreen
from tui.screens.scan import ScanScreen
from tui.screens.capture import CaptureScreen
from tui.screens.analyze import AnalyzeScreen
from tui.screens.frida import FridaScreen
from tui.screens.apk import APKScreen
from tui.screens.reports import ReportsScreen
from tui.screens.settings import SettingsScreen
from tui.screens.scan import SCAN_PROFILE_OPTIONS
from tui.screens.scan import _displayable_output_files
from tui.screens.scan import _interface_options
from tui.screens.dashboard import _format_tool_status
from tui.widgets.findings_table import FindingsTable
from tui.widgets.log_viewer import LogViewer, _wrap_display_text
from tui.widgets.pasteable_input import PasteableInput
from tui.screens.reports import _has_report_data, _report_output_path
from textual.widgets import Select
from runners.frida_runner import FRIDA_SCRIPTS


class AppRegistrationTests(unittest.TestCase):
    """Verify the app registers all expected screens."""

    def test_all_screens_registered(self):
        expected = {
            "dashboard",
            "scan",
            "capture",
            "analyze",
            "frida",
            "apk",
            "reports",
            "settings",
            "network_setup",
            "custom_script",
            "workflow",
            "firmware",
            "plugins",
            "profiles",
        }
        self.assertEqual(set(ChainReconApp.SCREENS.keys()), expected)

    def test_screen_classes(self):
        mapping = {
            "dashboard": DashboardScreen,
            "scan": ScanScreen,
            "capture": CaptureScreen,
            "analyze": AnalyzeScreen,
            "frida": FridaScreen,
            "apk": APKScreen,
            "reports": ReportsScreen,
            "settings": SettingsScreen,
        }
        for key, cls in mapping.items():
            self.assertIs(ChainReconApp.SCREENS[key], cls)


class WidgetImportTests(unittest.TestCase):
    def test_findings_table_importable(self):
        self.assertTrue(hasattr(FindingsTable, "load"))

    def test_log_viewer_importable(self):
        self.assertTrue(hasattr(LogViewer, "append"))

    def test_pasteable_input_normalizes_quotes_and_newlines(self):
        text = PasteableInput.normalize_paste_text('"C:\\Users\\me\\capture.pcap"\r\n')
        self.assertEqual(text, "C:\\Users\\me\\capture.pcap")

    def test_pasteable_input_normalizes_file_url(self):
        text = PasteableInput.normalize_paste_text("file:///C:/Users/me/capture.pcap")
        self.assertTrue(text.endswith("C:\\Users\\me\\capture.pcap") or text.endswith("/C:/Users/me/capture.pcap"))

    def test_log_viewer_bounds_retained_lines(self):
        log = LogViewer(max_retained_lines=2)
        log.append("one")
        log.append("two")
        log.append("three")
        plain = log._plain_text()
        self.assertIn("older line", plain)
        self.assertNotIn("one\n", plain)
        self.assertIn("two", plain)
        self.assertIn("three", plain)

    def test_wrap_display_text_breaks_long_paths(self):
        wrapped = _wrap_display_text("Result saved: C:\\Users\\me\\some\\very\\long\\path\\to\\an\\artifact\\that\\should\\wrap\\output.json", width=40)
        self.assertIn("\n", wrapped)

    def test_pasteable_input_sets_tooltip_for_long_paths(self):
        widget = PasteableInput()
        widget.watch_value("C:\\Users\\me\\some\\very\\long\\path\\artifact.json")
        self.assertIn("artifact.json", widget.tooltip)

    def test_dashboard_tool_status_wraps_long_paths(self):
        formatted = _format_tool_status("adb", "C:\\Users\\me\\very\\long\\path\\to\\platform-tools\\adb.exe", width=20)
        self.assertIn("\n", formatted)


class ReportsHelperTests(unittest.TestCase):
    def test_report_output_path_replaces_suffix(self):
        path = _report_output_path("report.txt", ".html")
        self.assertTrue(path.endswith("report.html"))

    def test_report_output_path_expands_directory_to_dated_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            path = _report_output_path(td, ".html", stem="report_current")
        self.assertRegex(path, r"\d{8}_\d{6}_report_current\.html$")

    def test_has_report_data_ignores_empty_defaults(self):
        self.assertFalse(_has_report_data({"traffic": None, "ssl": None, "scan": None}))
        self.assertTrue(_has_report_data({"traffic": {"summary": {}}}))


class ScanInterfaceOptionTests(unittest.TestCase):
    def test_interface_options_include_auto_and_selected_interface(self):
        with patch("tui.screens.scan.list_scan_interfaces", return_value=[{"name": "Ethernet", "description": "UP", "runtime_id": "eth0"}]):
            options, selected = _interface_options("Ethernet")
        self.assertEqual(options[0][1], "__auto__")
        self.assertEqual(selected, "Ethernet")


class TuiRequirementTests(unittest.TestCase):
    def test_apk_path_input_keeps_cursor_at_end_for_long_value(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                app.push_screen("apk")
                await pilot.pause()
                field = app.screen.query_one("#apk-path", PasteableInput)
                long_path = r"C:\Users\tarok\OneDrive - purdue.edu\Desktop\Engineering\VeryLongDirectoryName\AnotherLongDirectory\nooie_base_apk.apk"
                field.value = long_path
                field.focus()
                await pilot.pause()
                self.assertEqual(field.cursor_position, len(long_path))
                self.assertIn("nooie_base_apk.apk", field.tooltip)

        asyncio.run(_run())

    def test_frida_inventory_populates_selector_and_summary_note(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                with patch("tui.screens.frida.FridaScreen.on_mount", return_value=None):
                    app.push_screen("frida")
                    await pilot.pause()
                    screen = app.screen
                    inventory = {
                        "connected_devices": [
                            {
                                "serial": "emulator-5554",
                                "state": "device",
                                "id": "serial:emulator-5554",
                                "avd_name": "ChainRecon_API35",
                                "frida_compatible": True,
                                "frida_note": "Compatible for managed setup.",
                            }
                        ],
                        "local_avds": [],
                    }
                    screen._selected_serial = "emulator-5554"
                    screen._apply_device_inventory(inventory)
                    await pilot.pause()
                    select = screen.query_one("#device-select", Select)
                    values = [option[1] for option in select._options]
                    self.assertIn("serial:emulator-5554", values)

        asyncio.run(_run())

    def test_frida_screen_shows_parameter_input_for_selected_script(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                with patch("tui.screens.frida.FridaScreen.on_mount", return_value=None):
                    app.push_screen("frida")
                    await pilot.pause()
                    screen = app.screen
                    screen._refresh_script_inputs()
                    await pilot.pause()
                    widget = screen.query_one("#param-nooie_mqtt_trace-class_filter", PasteableInput)
                    self.assertIsNotNone(widget)

        asyncio.run(_run())

    def test_frida_screen_populates_visible_defaults_for_filter_scripts(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                with patch("tui.screens.frida.FridaScreen.on_mount", return_value=None):
                    app.push_screen("frida")
                    await pilot.pause()
                    screen = app.screen
                    select = screen.query_one("#script", Select)
                    select.value = "network_traffic_monitor"
                    screen._refresh_script_inputs()
                    await pilot.pause()
                    widget = screen.query_one("#param-network_traffic_monitor-host_filter", PasteableInput)
                    self.assertEqual(widget.value, "*")

        asyncio.run(_run())

    def test_frida_parameter_inputs_change_cleanly_between_scripts(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                with patch("tui.screens.frida.FridaScreen.on_mount", return_value=None):
                    app.push_screen("frida")
                    await pilot.pause()
                    screen = app.screen
                    select = screen.query_one("#script", Select)
                    select.value = "hook_method"
                    screen._refresh_script_inputs()
                    await pilot.pause()
                    self.assertIsNotNone(screen.query_one("#param-hook_method-class_name", PasteableInput))
                    select.value = "list_classes"
                    screen._refresh_script_inputs()
                    await pilot.pause()
                    self.assertIsNotNone(screen.query_one("#param-list_classes-class_filter", PasteableInput))

        asyncio.run(_run())

    def test_registered_frida_script_required_params_are_visible(self):
        for key, meta in FRIDA_SCRIPTS.items():
            with self.subTest(script=key):
                for param in meta.get("params", []):
                    self.assertIn("name", param)
                    self.assertIn("label", param)
                    self.assertIn("required", param)

    def test_reports_screen_includes_xlsx_format(self):
        async def _run() -> None:
            app = ChainReconApp()
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                app.push_screen("reports")
                await pilot.pause()
                select = app.screen.query_one("#format", Select)
                prompts = [prompt for prompt, _ in select._options]
                self.assertIn("XLSX (multi-sheet workbook)", prompts)

        asyncio.run(_run())

    def test_scan_output_filter_only_keeps_text_files(self):
        filtered = _displayable_output_files(["scan.txt", "scan.xml", "notes.TXT", "report.json"])
        self.assertEqual(filtered, ["scan.txt", "notes.TXT"])

    def test_analysis_screen_only_exposes_pcap_analyzers(self):
        async def _run() -> None:
            app = ChainReconApp()
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                app.push_screen("analyze")
                await pilot.pause()
                select = app.screen.query_one("#analyzer", Select)
                values = [value for _, value in select._options]
                self.assertNotIn("ssl", values)
                self.assertNotIn("scan", values)

        asyncio.run(_run())

    def test_scan_screen_hides_tcp_connect_profile(self):
        values = [value for _, value in SCAN_PROFILE_OPTIONS]
        self.assertNotIn("tcp_connect", values)
        self.assertIn("arp", values)

    def test_frida_report_recorder_appends_sessions(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            with tempfile.TemporaryDirectory() as td, \
                 patch("tui.screens.frida.FridaScreen.on_mount", return_value=None), \
                 patch("tui.screens.frida.get_output_dir", return_value=td):
                async with app.run_test(size=(100, 28)) as pilot:
                    await pilot.pause()
                    app.push_screen("frida")
                    await pilot.pause()
                    screen = app.screen
                    screen._record_frida_report({
                        "metadata": {"section": "frida", "serial": "emulator-5554", "target": "app.one", "script": "list_classes"},
                        "findings": {"events_by_tag": {"HOOK": 1}, "hook_events": ["[HOOK] one"]},
                        "summary": {"status": "completed"},
                        "risk_indicators": [],
                    })
                    screen._record_frida_report({
                        "metadata": {"section": "frida", "serial": "emulator-5554", "target": "app.two", "script": "hook_all_methods"},
                        "findings": {"events_by_tag": {"HOOK": 2}, "hook_events": ["[HOOK] two"]},
                        "summary": {"status": "stopped_by_user"},
                        "risk_indicators": [],
                    })
                    sessions = app._report_gen.get_data()["frida"]["sessions"]
                    self.assertEqual(len(sessions), 2)
                    self.assertEqual({session["target"] for session in sessions}, {"app.one", "app.two"})

        asyncio.run(_run())

    def test_all_module_screens_open_in_narrow_ascii_mode(self):
        async def _run() -> None:
            app = ChainReconApp()
            app.add_class("ascii-mode")
            async with app.run_test(size=(100, 28)) as pilot:
                await pilot.pause()
                for name in ["scan", "capture", "analyze", "frida", "apk", "reports", "settings", "network_setup", "custom_script"]:
                    app.push_screen(name)
                    await pilot.pause()
                    app.pop_screen()
                    await pilot.pause()

        asyncio.run(_run())


class AnalyzeDispatchTests(unittest.TestCase):
    def test_unknown_analyzer_raises(self):
        with self.assertRaises(ValueError):
            AnalyzeScreen._dispatch("nonexistent", "file.pcap")


class ApkArtifactTests(unittest.TestCase):
    def test_verify_artifact_exists_returns_created_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "result.json"
            target.write_text("{}", encoding="utf-8")
            resolved = APKScreen._verify_artifact_exists(target, retries=1, delay=0)
        self.assertTrue(str(resolved).endswith("result.json"))

    def test_write_json_artifact_is_immediately_readable(self):
        import tempfile
        from pathlib import Path
        from utils.artifacts import write_json_artifact

        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "apk_result.json"
            written = write_json_artifact(target, {"metadata": {"section": "apk"}})
            self.assertTrue(written.exists())
            self.assertIn('"section": "apk"', written.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
