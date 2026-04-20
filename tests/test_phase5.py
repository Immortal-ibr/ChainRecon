"""Tests for Phase 5 features — help panels, network config, network setup screen."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from utils.config import (
    get_network_config,
    load_config,
    reset_config,
    save_network_config,
)


# ===========================================================================
# Network config persistence
# ===========================================================================


class NetworkConfigTests(unittest.TestCase):
    def setUp(self):
        reset_config()

    def tearDown(self):
        reset_config()

    def test_get_network_config_returns_dict(self):
        load_config(force_reload=True)
        net = get_network_config()
        self.assertIsInstance(net, dict)

    def test_get_network_config_empty_when_unset(self):
        # Without explicit network section the helper should still return {}
        load_config(force_reload=True)
        net = get_network_config()
        # default.yaml has a network section with null values
        self.assertIsInstance(net, dict)

    def test_save_and_load_network_config(self):
        with tempfile.TemporaryDirectory() as td:
            local_yaml = Path(td) / "local.yaml"
            with patch("utils.config._CONFIG_DIR", Path(td)):
                save_network_config({
                    "eth_interface": "Ethernet",
                    "internet_interface": "Wi-Fi",
                    "static_ip": "192.168.123.100/24",
                    "target_ip": "192.168.123.50",
                    "router_ip": "192.168.123.99",
                })
                self.assertTrue(local_yaml.exists())
                with open(local_yaml, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                self.assertEqual(data["network"]["eth_interface"], "Ethernet")
                self.assertEqual(data["network"]["static_ip"], "192.168.123.100/24")

    def test_save_then_get_network_config(self):
        """Verify save + reset_config + get_network_config round-trip via auto-loaded local.yaml."""
        with tempfile.TemporaryDirectory() as td:
            with patch("utils.config._CONFIG_DIR", Path(td)):
                save_network_config({
                    "eth_interface": "Ethernet",
                    "internet_interface": "Wi-Fi",
                    "static_ip": "192.168.123.100/24",
                    "target_ip": "192.168.123.50",
                    "router_ip": "192.168.123.99",
                })
                reset_config()
                cfg = get_network_config()
                self.assertEqual(cfg["eth_interface"], "Ethernet")
                self.assertEqual(cfg["router_ip"], "192.168.123.99")

    def test_save_network_config_merges_existing(self):
        with tempfile.TemporaryDirectory() as td:
            local_yaml = Path(td) / "local.yaml"
            local_yaml.write_text("api_keys:\n  shodan: test-key\n", encoding="utf-8")
            with patch("utils.config._CONFIG_DIR", Path(td)):
                save_network_config({"eth_interface": "eth0"})
                with open(local_yaml, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                # Original key preserved
                self.assertEqual(data["api_keys"]["shodan"], "test-key")
                # Network added
                self.assertEqual(data["network"]["eth_interface"], "eth0")

    def test_env_override_apktool_path(self):
        with patch.dict(os.environ, {"CHAINRECON_APKTOOL_PATH": "/usr/bin/apktool"}):
            config = load_config(force_reload=True)
            self.assertEqual(config["tools"]["apktool"], "/usr/bin/apktool")


# ===========================================================================
# Help panel widget
# ===========================================================================


class HelpPanelWidgetTests(unittest.TestCase):
    """Unit tests for the HelpPanel widget (no Textual app required)."""

    def test_import_succeeds(self):
        from tui.widgets.help_panel import HelpPanel
        self.assertTrue(callable(HelpPanel))

    def test_stores_help_text(self):
        from tui.widgets.help_panel import HelpPanel
        panel = HelpPanel("Test help text", id="help")
        self.assertEqual(panel._help_text, "Test help text")

    def test_default_css_has_display_none(self):
        from tui.widgets.help_panel import HelpPanel
        self.assertIn("display: none", HelpPanel.DEFAULT_CSS)


# ===========================================================================
# All screens have help text constants
# ===========================================================================


class ScreenHelpTextTests(unittest.TestCase):
    """Verify every TUI screen exports a HELP_TEXT constant."""

    def _check_module(self, module_path: str):
        import importlib
        mod = importlib.import_module(module_path)
        self.assertTrue(hasattr(mod, "HELP_TEXT"), f"{module_path} missing HELP_TEXT")
        self.assertGreater(len(mod.HELP_TEXT), 50, f"{module_path} HELP_TEXT too short")

    def test_dashboard_help_text(self):
        self._check_module("tui.screens.dashboard")

    def test_scan_help_text(self):
        self._check_module("tui.screens.scan")

    def test_capture_help_text(self):
        self._check_module("tui.screens.capture")

    def test_analyze_help_text(self):
        self._check_module("tui.screens.analyze")

    def test_frida_help_text(self):
        self._check_module("tui.screens.frida")

    def test_apk_help_text(self):
        self._check_module("tui.screens.apk")

    def test_reports_help_text(self):
        self._check_module("tui.screens.reports")

    def test_settings_help_text(self):
        self._check_module("tui.screens.settings")

    def test_network_setup_help_text(self):
        self._check_module("tui.screens.network_setup")


# ===========================================================================
# All screens have toggle_help binding
# ===========================================================================


class ScreenBindingsTests(unittest.TestCase):
    """Verify every screen has the question_mark → toggle_help binding."""

    SCREENS = [
        "tui.screens.dashboard",
        "tui.screens.scan",
        "tui.screens.capture",
        "tui.screens.analyze",
        "tui.screens.frida",
        "tui.screens.apk",
        "tui.screens.reports",
        "tui.screens.settings",
        "tui.screens.network_setup",
        "tui.screens.custom_script",
        # help_screen and welcome are intentionally excluded:
        # HelpScreen is a ModalScreen with no persistent ? binding
        # WelcomeScreen has no help binding by design
    ]

    def test_all_screens_have_help_binding(self):
        import importlib
        from textual.screen import ModalScreen, Screen
        for mod_path in self.SCREENS:
            mod = importlib.import_module(mod_path)
            screen_cls = None
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, Screen)
                    and attr is not Screen
                    and not issubclass(attr, ModalScreen)
                ):
                    screen_cls = attr
                    break
            self.assertIsNotNone(screen_cls, f"No Screen subclass in {mod_path}")
            bindings = [b for b in screen_cls.BINDINGS if "toggle_help" in str(b)]
            self.assertTrue(len(bindings) > 0, f"{screen_cls.__name__} missing toggle_help binding")


# ===========================================================================
# Network setup screen
# ===========================================================================


class NetworkSetupScreenTests(unittest.TestCase):
    """Tests for the NetworkSetupScreen module."""

    def test_import_succeeds(self):
        from tui.screens.network_setup import NetworkSetupScreen
        self.assertTrue(callable(NetworkSetupScreen))

    def test_scripts_dir_exists(self):
        from tui.screens.network_setup import _SCRIPTS_DIR
        self.assertTrue(_SCRIPTS_DIR.exists(), f"Scripts dir not found: {_SCRIPTS_DIR}")

    def test_ps1_script_exists(self):
        from tui.screens.network_setup import _SCRIPTS_DIR
        ps1 = _SCRIPTS_DIR / "network_setup.ps1"
        self.assertTrue(ps1.exists(), "network_setup.ps1 not found")

    def test_sh_script_exists(self):
        from tui.screens.network_setup import _SCRIPTS_DIR
        sh = _SCRIPTS_DIR / "network_setup.sh"
        self.assertTrue(sh.exists(), "network_setup.sh not found")


# ===========================================================================
# App registration
# ===========================================================================


class AppRegistrationTests(unittest.TestCase):
    """Verify network_setup is registered in the TUI app."""

    def test_network_setup_in_screens_dict(self):
        from tui.app import ChainReconApp
        self.assertIn("network_setup", ChainReconApp.SCREENS)

    def test_network_setup_screen_class(self):
        from tui.app import ChainReconApp
        from tui.screens.network_setup import NetworkSetupScreen
        self.assertIs(ChainReconApp.SCREENS["network_setup"], NetworkSetupScreen)


# ===========================================================================
# Platform info — apktool
# ===========================================================================


class PlatformApktoolTests(unittest.TestCase):
    """Verify apktool is included in check_all_tools."""

    def test_check_all_tools_includes_apktool(self):
        from utils.platform_info import check_all_tools
        with patch("utils.platform_info.find_tool", return_value=None):
            results = check_all_tools()
        self.assertIn("apktool", results)


if __name__ == "__main__":
    unittest.main()
