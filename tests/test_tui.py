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


class AnalyzeDispatchTests(unittest.TestCase):
    def test_unknown_analyzer_raises(self):
        with self.assertRaises(ValueError):
            AnalyzeScreen._dispatch("nonexistent", "file.pcap")


if __name__ == "__main__":
    unittest.main()
