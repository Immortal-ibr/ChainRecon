"""Tests for the Frida runner module."""

import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from runners.base import ToolNotFoundError
from runners.frida_runner import FRIDA_SCRIPTS, FridaRunner, _SCRIPTS_DIR


# ===========================================================================
# Prerequisites check
# ===========================================================================


class PrerequisiteTests(unittest.TestCase):
    @patch("runners.frida_runner.check_tool")
    def test_all_found(self, mock_check):
        mock_check.return_value = "/usr/bin/tool"
        runner = FridaRunner()
        status = runner.check_prerequisites()
        for t in ("adb", "frida", "frida-ps"):
            self.assertTrue(status[t]["found"])
            self.assertIsNotNone(status[t]["path"])

    @patch("runners.frida_runner.check_tool")
    def test_some_missing(self, mock_check):
        def side(name):
            if name == "frida":
                raise ToolNotFoundError("frida not found")
            return f"/usr/bin/{name}"
        mock_check.side_effect = side
        runner = FridaRunner()
        status = runner.check_prerequisites()
        self.assertTrue(status["adb"]["found"])
        self.assertFalse(status["frida"]["found"])
        self.assertTrue(status["frida-ps"]["found"])


# ===========================================================================
# Device / process helpers
# ===========================================================================


class DeviceHelperTests(unittest.TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.runner = FridaRunner(executor=self.executor)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_list_devices(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, "List of devices attached\nemulator-5554\tdevice\n", ""
        )
        result = self.runner.list_devices()
        self.assertIn("emulator-5554", result)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida-ps")
    def test_list_processes(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, " PID  Name\n----  ----\n1234  com.example.app\n", ""
        )
        result = self.runner.list_processes()
        self.assertIn("com.example.app", result)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_push_frida_server(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        dest = self.runner.push_frida_server("/tmp/frida-server")
        self.assertEqual(dest, "/data/local/tmp/frida-server")
        self.assertEqual(self.executor.call_count, 2)  # push + chmod

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_start_frida_server(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.runner.start_frida_server()
        cmd = self.executor.call_args[0][0]
        self.assertIn("/data/local/tmp/frida-server", cmd)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_forward_port(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.runner.forward_port(27042)
        cmd = self.executor.call_args[0][0]
        self.assertIn("tcp:27042", cmd)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_forward_custom_port(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.runner.forward_port(9999)
        cmd = self.executor.call_args[0][0]
        self.assertIn("tcp:9999", cmd)


# ===========================================================================
# Script management
# ===========================================================================


class ScriptManagementTests(unittest.TestCase):
    def test_list_scripts_returns_all(self):
        runner = FridaRunner()
        scripts = runner.list_scripts()
        self.assertEqual(len(scripts), len(FRIDA_SCRIPTS))

    def test_each_script_has_required_keys(self):
        runner = FridaRunner()
        for s in runner.list_scripts():
            self.assertIn("key", s)
            self.assertIn("label", s)
            self.assertIn("description", s)

    def test_get_script_path_valid(self):
        runner = FridaRunner()
        for key in FRIDA_SCRIPTS:
            path = runner.get_script_path(key)
            self.assertTrue(path.exists(), f"Script file missing: {path}")
            self.assertTrue(path.name.endswith(".js"))

    def test_get_script_path_invalid(self):
        runner = FridaRunner()
        with self.assertRaises(ValueError):
            runner.get_script_path("nonexistent_script")

    def test_script_files_exist_on_disk(self):
        """Verify all registered scripts have a corresponding .js file."""
        for key, meta in FRIDA_SCRIPTS.items():
            path = _SCRIPTS_DIR / meta["file"]
            self.assertTrue(path.exists(), f"Missing: {path}")
            content = path.read_text(encoding="utf-8")
            self.assertIn("Java.perform", content)

    def test_new_scripts_registered(self):
        """Verify the four new Phase-2.3 scripts are in the registry."""
        expected = {
            "shared_preferences_dump",
            "database_dump",
            "http_intercept",
            "certificate_pinning_detect",
        }
        self.assertTrue(expected.issubset(FRIDA_SCRIPTS.keys()))

    def test_total_script_count(self):
        """10 scripts total: 6 original + 4 new."""
        self.assertEqual(len(FRIDA_SCRIPTS), 10)


# ===========================================================================
# Script execution
# ===========================================================================


class RunScriptTests(unittest.TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, "[*] Hooked method\n[+] Call logged\n", ""
        )
        self.runner = FridaRunner(executor=self.executor)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_builtin_script(self, _):
        result = self.runner.run_script("com.example.app", "ssl_pinning_bypass")
        self.assertEqual(result["process"], "com.example.app")
        self.assertEqual(result["script"], "ssl_pinning_bypass")
        self.assertIn("Hooked method", result["stdout"])
        cmd = self.executor.call_args[0][0]
        self.assertEqual(cmd[0], "frida")
        self.assertIn("-U", cmd)
        self.assertIn("-n", cmd)
        self.assertIn("com.example.app", cmd)
        self.assertIn("-l", cmd)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_custom_script(self, _):
        result = self.runner.run_script(
            "com.example.app", "", custom_script_path="/tmp/my_hook.js"
        )
        self.assertEqual(result["script"], "/tmp/my_hook.js")
        cmd = self.executor.call_args[0][0]
        self.assertIn("/tmp/my_hook.js", cmd)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_spawn_and_run(self, _):
        result = self.runner.spawn_and_run("com.example.app", "crypto_monitor")
        self.assertEqual(result["package"], "com.example.app")
        cmd = self.executor.call_args[0][0]
        self.assertIn("-f", cmd)
        self.assertIn("com.example.app", cmd)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_spawn_custom_script(self, _):
        result = self.runner.spawn_and_run(
            "com.example.app", "", custom_script_path="/tmp/hook.js"
        )
        cmd = self.executor.call_args[0][0]
        self.assertIn("-f", cmd)
        self.assertIn("/tmp/hook.js", cmd)

    @patch("runners.frida_runner.check_tool", side_effect=ToolNotFoundError("frida not found"))
    def test_run_script_tool_missing(self, _):
        with self.assertRaises(ToolNotFoundError):
            self.runner.run_script("com.example.app", "ssl_pinning_bypass")

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_script_stderr(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 1, "", "Error: process not found"
        )
        result = self.runner.run_script("com.example.app", "list_classes")
        self.assertIn("Error: process not found", result["stderr"])
        self.assertEqual(result["returncode"], 1)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_script_includes_no_pause(self, _):
        self.runner.run_script("com.example.app", "network_traffic_monitor")
        cmd = self.executor.call_args[0][0]
        self.assertIn("--no-pause", cmd)


if __name__ == "__main__":
    unittest.main()
