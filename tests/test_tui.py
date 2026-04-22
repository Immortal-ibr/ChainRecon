"""Tests for the TUI application structure and screen composition."""

import unittest

from tui.app import ChainReconApp
from tui.screens.dashboard import DashboardScreen
from tui.screens.scan import ScanScreen
from tui.screens.capture import CaptureScreen
from tui.screens.analyze import AnalyzeScreen
from tui.screens.frida import FridaScreen
from tui.screens.apk import APKScreen
from tui.screens.reports import ReportsScreen
from tui.screens.settings import SettingsScreen
from tui.widgets.findings_table import FindingsTable
from tui.widgets.log_viewer import LogViewer
from tui.widgets.pasteable_input import PasteableInput
from tui.screens.reports import _has_report_data, _report_output_path


class AppRegistrationTests(unittest.TestCase):
    """Verify the app registers all expected screens."""

    def test_all_screens_registered(self):
        expected = {"dashboard", "scan", "capture", "analyze", "frida", "apk", "reports", "settings", "network_setup", "custom_script"}
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


class ReportsHelperTests(unittest.TestCase):
    def test_report_output_path_replaces_suffix(self):
        path = _report_output_path("report.txt", ".html")
        self.assertTrue(path.endswith("report.html"))

    def test_has_report_data_ignores_empty_defaults(self):
        self.assertFalse(_has_report_data({"traffic": None, "ssl": None, "scan": None}))
        self.assertTrue(_has_report_data({"traffic": {"summary": {}}}))


class AnalyzeDispatchTests(unittest.TestCase):
    def test_unknown_analyzer_raises(self):
        with self.assertRaises(ValueError):
            AnalyzeScreen._dispatch("nonexistent", "file.pcap")


if __name__ == "__main__":
    unittest.main()
