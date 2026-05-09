"""Tests for the Frida runner module."""

import json
import os
import subprocess
import threading
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from chainrecon.runners.base import ToolNotFoundError
from chainrecon.runners.frida_runner import FRIDA_SCRIPTS, FridaDeviceError, FridaRunner, _SCRIPTS_DIR, _script_filename_from_label


# ===========================================================================
# Prerequisites check
# ===========================================================================


class PrerequisiteTests(unittest.TestCase):
    @patch("chainrecon.runners.frida_runner.check_tool")
    def test_all_found(self, mock_check):
        mock_check.return_value = "/usr/bin/tool"
        runner = FridaRunner()
        status = runner.check_prerequisites()
        for t in ("adb", "frida", "frida-ps"):
            self.assertTrue(status[t]["found"])
            self.assertIsNotNone(status[t]["path"])

    @patch("chainrecon.runners.frida_runner.check_tool")
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
        self.runner = FridaRunner(executor=self.executor, validate_device=False)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_list_devices(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, "List of devices attached\nemulator-5554\tdevice\n", ""
        )
        result = self.runner.list_devices()
        self.assertIn("emulator-5554", result)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida-ps")
    def test_list_processes(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, " PID  Name\n----  ----\n1234  com.example.app\n", ""
        )
        result = self.runner.list_processes()
        self.assertIn("com.example.app", result)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_push_frida_server(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        dest = self.runner.push_frida_server("/tmp/frida-server")
        self.assertEqual(dest, "/data/local/tmp/frida-server")
        self.assertEqual(self.executor.call_count, 2)  # push + chmod

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_start_frida_server(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.runner.start_frida_server()
        cmd = self.executor.call_args[0][0]
        self.assertIn("/data/local/tmp/frida-server", " ".join(str(part) for part in cmd))

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_forward_port(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.runner.forward_port(27042)
        cmd = self.executor.call_args[0][0]
        self.assertIn("tcp:27042", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/adb")
    def test_forward_custom_port(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.runner.forward_port(9999)
        cmd = self.executor.call_args[0][0]
        self.assertIn("tcp:9999", cmd)


class DeviceValidationTests(unittest.TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.runner = FridaRunner(executor=self.executor)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_get_device_state_online(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, "List of devices attached\nemulator-5554\tdevice\n", ""
        )
        state = self.runner.get_device_state()
        self.assertTrue(state["online"])
        self.assertEqual(state["serial"], "emulator-5554")

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_no_device_raises_for_process_list(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "List of devices attached\n\n", "")
        with patch.object(self.runner, "_configured_serial", return_value=None):
            with self.assertRaises(FridaDeviceError) as ctx:
                self.runner.list_processes()
        self.assertEqual(ctx.exception.state["state"], "no_device")

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_offline_device_raises(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, "List of devices attached\nemulator-5554\toffline\n", ""
        )
        with self.assertRaises(FridaDeviceError) as ctx:
            self.runner.ensure_online_device()
        self.assertEqual(ctx.exception.state["state"], "offline")

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_online_device_allows_process_list(self, _):
        def execute(cmd, timeout=None):
            if cmd[:2] == ["adb", "devices"]:
                return subprocess.CompletedProcess(
                    cmd, 0, "List of devices attached\nemulator-5554\tdevice\n", ""
                )
            return subprocess.CompletedProcess(cmd, 0, " PID Name\n123 com.example.app\n", "")

        self.executor.side_effect = execute
        with patch.object(self.runner, "_configured_serial", return_value=None):
            out = self.runner.list_processes()
        self.assertIn("com.example.app", out)
        self.assertEqual(self.executor.call_args[0][0][:3], ["frida-ps", "-D", "emulator-5554"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_inventory_marks_unauthorized_device_not_compatible(self, _):
        def execute(cmd, timeout=None):
            if cmd[:2] == ["adb", "devices"]:
                return subprocess.CompletedProcess(
                    cmd, 0, "List of devices attached\nABC123\tunauthorized\n", ""
                )
            return subprocess.CompletedProcess(cmd, 0, "", "")

        self.executor.side_effect = execute
        inventory = self.runner.list_device_inventory()
        self.assertEqual(len(inventory["connected_devices"]), 1)
        self.assertFalse(inventory["connected_devices"][0]["frida_compatible"])
        self.assertIn("authorization", inventory["connected_devices"][0]["frida_note"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_inventory_uses_ro_boot_qemu_avd_name_fallback(self, _):
        def execute(cmd, timeout=None):
            if cmd[:2] == ["adb", "devices"]:
                return subprocess.CompletedProcess(
                    cmd, 0, "List of devices attached\nemulator-5554\tdevice\n", ""
                )
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.product.cpu.abi":
                return subprocess.CompletedProcess(cmd, 0, "x86_64\n", "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.kernel.qemu.avd_name":
                return subprocess.CompletedProcess(cmd, 0, "\n", "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.boot.qemu.avd_name":
                return subprocess.CompletedProcess(cmd, 0, "ChainRecon_API35\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        self.executor.side_effect = execute
        with patch.object(self.runner, "_list_avds", return_value=["ChainRecon_API35"]), \
             patch.object(self.runner, "_read_avd_config", return_value={
                 "tag.id": "google_apis",
                 "abi.type": "x86_64",
             }):
            inventory = self.runner.list_device_inventory()
        self.assertTrue(inventory["connected_devices"][0]["frida_compatible"])
        self.assertEqual(inventory["connected_devices"][0]["avd_name"], "ChainRecon_API35")
        self.assertEqual(inventory["local_avds"], [])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_inventory_marks_play_store_avd_not_compatible(self, _):
        with patch.object(self.runner, "_list_avds", return_value=["PlayStore_AVD"]), \
             patch.object(self.runner, "_read_avd_config", return_value={
                 "PlayStore.enabled": "true",
                 "tag.display": "google_apis_playstore",
                 "abi.type": "x86_64",
             }):
            self.executor.return_value = subprocess.CompletedProcess([], 0, "List of devices attached\n\n", "")
            inventory = self.runner.list_device_inventory()
        self.assertEqual(len(inventory["local_avds"]), 1)
        self.assertFalse(inventory["local_avds"][0]["frida_compatible"])
        self.assertIn("Play Store", inventory["local_avds"][0]["frida_note"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_inventory_marks_api_36_avd_not_compatible(self, _):
        with patch.object(self.runner, "_list_avds", return_value=["ChainRecon_API36"]), \
             patch.object(self.runner, "_read_avd_config", return_value={
                 "tag.id": "google_apis",
                 "abi.type": "x86_64",
                 "image.sysdir.1": "system-images;android-36;google_apis;x86_64",
             }):
            self.executor.return_value = subprocess.CompletedProcess([], 0, "List of devices attached\n\n", "")
            inventory = self.runner.list_device_inventory()
        self.assertFalse(inventory["local_avds"][0]["frida_compatible"])
        self.assertIn("API 36", inventory["local_avds"][0]["frida_note"])

    @patch("chainrecon.runners.frida_runner.check_tool")
    def test_boot_device_requires_emulator_tool(self, mock_check):
        def side(name):
            if name == "emulator":
                raise ToolNotFoundError("missing emulator")
            return "/usr/bin/tool"

        mock_check.side_effect = side
        with self.assertRaises(ToolNotFoundError):
            self.runner.boot_device("avd:ChainRecon_API35")

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_boot_device_reuses_running_avd(self, _):
        with patch.object(self.runner, "_list_avds", return_value=["ChainRecon_API35"]), \
             patch.object(self.runner, "_find_connected_avd_serial", return_value="emulator-5554"):
            result = self.runner.boot_device("avd:ChainRecon_API35")
        self.assertFalse(result["booted"])
        self.assertEqual(result["serial"], "emulator-5554")
        self.assertIn("already running", result["message"])


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

    def test_all_js_scripts_are_registered(self):
        """Every injectable JS script in runners/frida_scripts is exposed."""
        registered = {meta["file"] for meta in FRIDA_SCRIPTS.values()}
        js_files = {path.name for path in _SCRIPTS_DIR.glob("*.js")}
        self.assertEqual(js_files, registered)

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
        """All bundled JavaScript scripts are registered."""
        self.assertEqual(len(FRIDA_SCRIPTS), len(list(_SCRIPTS_DIR.glob("*.js"))))

    def test_script_labels_reflect_app_scoped_class_tools(self):
        self.assertEqual(FRIDA_SCRIPTS["list_classes"]["label"], "List App Loaded Classes")
        self.assertEqual(FRIDA_SCRIPTS["hook_all_methods"]["label"], "Hook Selected Class Methods")

    def test_script_file_names_match_display_labels(self):
        for meta in FRIDA_SCRIPTS.values():
            self.assertEqual(meta["file"], _script_filename_from_label(meta["label"]))

    def test_filter_scripts_have_visible_default_values(self):
        self.assertEqual(FRIDA_SCRIPTS["network_traffic_monitor"]["params"][0]["default"], "*")
        self.assertEqual(FRIDA_SCRIPTS["hook_all_methods"]["params"][1]["default"], "50")
        self.assertEqual(FRIDA_SCRIPTS["crypto_monitor"]["params"][0]["default"], "*")


# ===========================================================================
# Script execution
# ===========================================================================


class RunScriptTests(unittest.TestCase):
    def setUp(self):
        self.executor = MagicMock()
        self.executor.return_value = subprocess.CompletedProcess(
            [], 0, "[*] Hooked method\n[+] Call logged\n", ""
        )
        self.runner = FridaRunner(executor=self.executor, validate_device=False)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_builtin_script(self, _):
        with patch.object(self.runner, "_configured_serial", return_value=None):
            result = self.runner.run_script("Settings", "ssl_pinning_bypass")
        self.assertEqual(result["process"], "Settings")
        self.assertEqual(result["script"], "ssl_pinning_bypass")
        self.assertIn("Hooked method", result["stdout"])
        cmd = self.executor.call_args[0][0]
        self.assertEqual(cmd[0], "frida")
        self.assertIn("-U", cmd)
        self.assertIn("-n", cmd)
        self.assertIn("Settings", cmd)
        self.assertIn("-l", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_package_identifier_uses_identifier_attach(self, _):
        self.runner.run_script("com.example.app", "ssl_pinning_bypass")
        cmd = self.executor.call_args[0][0]
        self.assertIn("-N", cmd)
        self.assertNotIn("-n", cmd)
        self.assertIn("com.example.app", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_device_class_census_iterates_matching_processes(self, _):
        self.runner.list_processes_structured = MagicMock(return_value=[
            {"pid": "1", "name": "Nooie", "identifier": "com.nooie.home"},
            {"pid": "2", "name": "NooiePlugin", "identifier": "com.nooie.plugin"},
            {"pid": "3", "name": "Other", "identifier": "com.other.app"},
        ])
        self.executor.side_effect = [
            subprocess.CompletedProcess([], 0, "[CLASS] total=4\n", ""),
            subprocess.CompletedProcess([], 0, "[CLASS] total=7\n", ""),
        ]
        result = self.runner.run_script("nooie", "device_class_census")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("[PROCESS] com.nooie.home", result["stdout"])
        self.assertIn("[PROCESS] com.nooie.plugin", result["stdout"])
        first_cmd = self.executor.call_args_list[0][0][0]
        second_cmd = self.executor.call_args_list[1][0][0]
        self.assertIn("com.nooie.home", first_cmd)
        self.assertIn("com.nooie.plugin", second_cmd)

    def test_normalize_hook_all_methods_class_names_accepts_semicolons(self):
        normalized = self.runner._normalize_script_parameters(
            "hook_all_methods",
            {"class_names": "com.example.One; com.example.Two\ncom.example.Three"},
        )
        self.assertEqual(
            normalized["class_names"],
            ["com.example.One", "com.example.Two", "com.example.Three"],
        )

    def test_normalize_list_classes_filter_accepts_multiple_delimiters(self):
        normalized = self.runner._normalize_script_parameters(
            "list_classes",
            {"class_filter": "com.nooie, com.thingclips; webrtc"},
        )
        self.assertEqual(normalized["class_filter"], ["com.nooie", "com.thingclips", "webrtc"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_setup_device_uses_directory_binary_match_and_installs_apks(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            apk_dir = temp_path / "apks"
            apk_dir.mkdir()
            (apk_dir / "demo.apk").write_text("apk", encoding="utf-8")
            frida_dir = temp_path / "frida"
            frida_dir.mkdir()
            (frida_dir / "frida-server-16.4.9-android-x86_64").write_text("bin", encoding="utf-8")
            (frida_dir / "frida-server-17.8.2-android-x86_64").write_text("bin", encoding="utf-8")

            def execute(cmd, timeout=None):
                if cmd[:2] == ["adb", "devices"]:
                    return subprocess.CompletedProcess(cmd, 0, "List of devices attached\nemulator-5554\tdevice\n", "")
                if cmd[:6] == ["adb", "-s", "emulator-5554", "shell", "pm", "list"]:
                    if not hasattr(execute, "seen_packages"):
                        execute.seen_packages = 0
                    execute.seen_packages += 1
                    output = "package:com.android.settings\n"
                    if execute.seen_packages > 1:
                        output += "package:com.example.demo\n"
                    return subprocess.CompletedProcess(cmd, 0, output, "")
                if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.product.cpu.abi":
                    return subprocess.CompletedProcess(cmd, 0, "x86_64\n", "")
                if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.kernel.qemu.avd_name":
                    return subprocess.CompletedProcess(cmd, 0, "\n", "")
                if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.boot.qemu.avd_name":
                    return subprocess.CompletedProcess(cmd, 0, "ChainRecon_API35\n", "")
                if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "sys.boot_completed":
                    return subprocess.CompletedProcess(cmd, 0, "1\n", "")
                if cmd[:2] == ["frida", "--version"]:
                    return subprocess.CompletedProcess(cmd, 0, "17.8.2\n", "")
                if cmd[:2] == ["frida-ps", "-D"]:
                    return subprocess.CompletedProcess(cmd, 0, " PID  Name\n1234  Settings\n", "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            self.executor.side_effect = execute
            result = self.runner.setup_device(
                target_id="serial:emulator-5554",
                apk_directory=str(apk_dir),
                frida_server_path=str(frida_dir),
            )
        self.assertEqual(result["serial"], "emulator-5554")
        self.assertEqual(len(result["installed_apks"]), 1)
        self.assertTrue(result["apk_installation"]["verified"])
        self.assertIn("com.example.demo", result["apk_installation"]["installed_packages"])
        self.assertIn("Validated frida-ps connectivity.", result["actions"])
        self.assertIn("17.8.2", result["frida_server"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_install_apks_uses_install_multiple_and_requires_verification(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            apk_dir = Path(td)
            (apk_dir / "base.apk").write_text("apk", encoding="utf-8")
            (apk_dir / "split_config_en.apk").write_text("apk", encoding="utf-8")

            def execute(cmd, timeout=None):
                if cmd[:6] == ["adb", "-s", "emulator-5554", "shell", "pm", "list"]:
                    if not hasattr(execute, "seen_packages"):
                        execute.seen_packages = 0
                    execute.seen_packages += 1
                    output = "package:com.android.settings\n"
                    if execute.seen_packages > 1:
                        output += "package:com.example.splitdemo\n"
                    return subprocess.CompletedProcess(cmd, 0, output, "")
                if "install-multiple" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, "Success\n", "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            self.executor.side_effect = execute
            result = self.runner.install_apks(str(apk_dir), serial="emulator-5554")
        self.assertTrue(result["verified"])
        self.assertIn("install-multiple", result["command"])
        self.assertIn("com.example.splitdemo", result["installed_packages"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_setup_device_reuses_booted_avd_without_launching(self, _):
        def execute(cmd, timeout=None):
            if cmd[:2] == ["adb", "devices"]:
                return subprocess.CompletedProcess(cmd, 0, "List of devices attached\nemulator-5554\tdevice\n", "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.product.cpu.abi":
                return subprocess.CompletedProcess(cmd, 0, "x86_64\n", "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.kernel.qemu.avd_name":
                return subprocess.CompletedProcess(cmd, 0, "\n", "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.boot.qemu.avd_name":
                return subprocess.CompletedProcess(cmd, 0, "ChainRecon_API35\n", "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "sys.boot_completed":
                return subprocess.CompletedProcess(cmd, 0, "1\n", "")
            if cmd[:2] == ["frida", "--version"]:
                return subprocess.CompletedProcess(cmd, 0, "17.8.2\n", "")
            if cmd[:2] == ["frida-ps", "-D"]:
                return subprocess.CompletedProcess(cmd, 0, " PID  Name\n1234  Settings\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        self.executor.side_effect = execute
        with patch.object(self.runner, "_list_avds", return_value=["ChainRecon_API35"]), \
             patch.object(self.runner, "_read_avd_config", return_value={
                 "tag.id": "google_apis",
                 "abi.type": "x86_64",
             }), \
             patch.object(self.runner, "_resolve_frida_server_path", return_value=(Path("/tmp/frida-server"), {"selected": "/tmp/frida-server"})), \
             patch.object(self.runner, "boot_device") as boot_device:
            result = self.runner.setup_device(target_id="avd:ChainRecon_API35")
        boot_device.assert_not_called()
        self.assertEqual(result["serial"], "emulator-5554")
        self.assertIn("already running", " ".join(result["actions"]))

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_wait_for_avd_registration_succeeds_after_delay(self, _):
        responses = [
            "List of devices attached\n\n",
            "List of devices attached\nemulator-5554\toffline\n",
            "List of devices attached\nemulator-5554\tdevice\n",
        ]

        def execute(cmd, timeout=None):
            if cmd[:2] == ["adb", "devices"]:
                return subprocess.CompletedProcess(cmd, 0, responses.pop(0), "")
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] in {"ro.kernel.qemu.avd_name", "ro.boot.qemu.avd_name"}:
                return subprocess.CompletedProcess(cmd, 0, "ChainRecon_API35\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        self.executor.side_effect = execute
        with patch("chainrecon.runners.frida_runner.time.sleep", return_value=None):
            serial = self.runner._wait_for_avd_serial_registration(adb_timeout=5, avd_name="ChainRecon_API35")
        self.assertEqual(serial, "emulator-5554")

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_wait_for_boot_complete_succeeds_after_delay(self, _):
        responses = ["0\n", "0\n", "1\n"]

        def execute(cmd, timeout=None):
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "sys.boot_completed":
                return subprocess.CompletedProcess(cmd, 0, responses.pop(0), "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        self.executor.side_effect = execute
        with patch("chainrecon.runners.frida_runner.time.sleep", return_value=None):
            self.runner._wait_for_boot_complete("emulator-5554", timeout=5)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_wait_for_avd_registration_timeout_is_distinct(self, _):
        self.executor.return_value = subprocess.CompletedProcess([], 0, "List of devices attached\n\n", "")
        with patch("chainrecon.runners.frida_runner.time.sleep", return_value=None):
            with self.assertRaises(FridaDeviceError) as ctx:
                self.runner._wait_for_avd_serial_registration(adb_timeout=1, avd_name="ChainRecon_API35")
        self.assertIn("register in adb devices", str(ctx.exception))

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_wait_for_boot_complete_timeout_is_distinct(self, _):
        def execute(cmd, timeout=None):
            if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "sys.boot_completed":
                return subprocess.CompletedProcess(cmd, 0, "0\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        self.executor.side_effect = execute
        with patch("chainrecon.runners.frida_runner.time.sleep", return_value=None):
            with self.assertRaises(FridaDeviceError) as ctx:
                self.runner._wait_for_boot_complete("emulator-5554", timeout=1)
        self.assertIn("boot to complete", str(ctx.exception))

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_resolve_frida_server_path_prefers_exact_version_and_abi(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            (temp_path / "frida-server-16.4.9-android-x86_64").write_text("old", encoding="utf-8")
            (temp_path / "frida-server-17.8.2-android-arm64").write_text("wrongabi", encoding="utf-8")
            exact = temp_path / "frida-server-17.8.2-android-x86_64"
            exact.write_text("exact", encoding="utf-8")

            def execute(cmd, timeout=None):
                if cmd[:2] == ["frida", "--version"]:
                    return subprocess.CompletedProcess(cmd, 0, "17.8.2\n", "")
                if cmd[:4] == ["adb", "-s", "emulator-5554", "shell"] and cmd[-1] == "ro.product.cpu.abi":
                    return subprocess.CompletedProcess(cmd, 0, "x86_64\n", "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            self.executor.side_effect = execute
            selected, resolution = self.runner._resolve_frida_server_path(str(temp_path), serial="emulator-5554")
        self.assertEqual(selected, exact.resolve())
        self.assertEqual(resolution["selected"], str(exact.resolve()))

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_render_script_materializes_parameters(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            rendered = self.runner.render_script(
                "hook_method",
                {"class_name": "com.nooie.home.Device", "method_name": "connect"},
                td,
            )
            content = rendered.read_text(encoding="utf-8")
            self.assertNotEqual(rendered.parent.resolve(), Path(td).resolve())
        self.assertIn("CHAINRECON_CONFIG", content)
        self.assertIn('"class_name": "com.nooie.home.Device"', content)
        self.assertIn('"method_name": "connect"', content)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_resolve_attach_target_auto_launches_installed_package(self, _):
        with patch.object(self.runner, "_package_installed", return_value=True), \
             patch.object(self.runner, "is_target_running", side_effect=[False, True]), \
             patch.object(self.runner, "launch_target_if_needed", return_value={"launched": True, "details": "ok"}):
            result = self.runner.resolve_attach_target("com.nooie.home", serial="emulator-5554")
        self.assertEqual(result["mode"], "attach")
        self.assertTrue(result["launch_performed"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_start_session_streams_output_and_writes_summary(self, _):
        import tempfile

        class FakeProcess:
            def __init__(self, cmd, **_kwargs):
                self.cmd = cmd
                self.stdout = StringIO("[HOOK] hello\n")
                self.stderr = StringIO("")
                self.stdin = StringIO()
                self._stopped = threading.Event()
                self.returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self._stopped.wait(timeout)
                if self.returncode is None:
                    self.returncode = 0
                return self.returncode

            def terminate(self):
                self.returncode = 0
                self._stopped.set()

            def kill(self):
                self.returncode = 1
                self._stopped.set()

        with tempfile.TemporaryDirectory() as td, \
             patch.object(self.runner, "is_target_running", return_value=True), \
             patch.object(self.runner, "_python_frida_available", return_value=False), \
             patch.object(self.runner, "ensure_online_device", return_value={"serial": "emulator-5554", "online": True}), \
             patch.object(self.runner, "list_device_inventory", return_value={"connected_devices": [{"serial": "emulator-5554", "frida_compatible": True}], "local_avds": []}), \
             patch.object(self.runner, "start_frida_server_if_needed", return_value={"running": True, "started": False, "frida_server": "/tmp/frida-server"}), \
             patch.object(self.runner, "resolve_attach_target", return_value={"mode": "attach", "attach_flag": "-N", "attach_target": "com.nooie.home", "target_running_before": True, "launch_performed": False}), \
             patch("chainrecon.runners.frida_runner.subprocess.Popen", side_effect=FakeProcess) as mock_popen:
            streamed = []
            result = self.runner.start_session(
                target="com.nooie.home",
                script_key="list_classes",
                parameters={"class_filter": "com.nooie"},
                output_dir=td,
                on_output=streamed.append,
            )
            summary = self.runner.stop_session(timeout=2)
            self.assertIsNotNone(summary)
            self.assertTrue(Path(result["log_path"]).exists())
            self.assertTrue(Path(result["summary_path"]).exists())
            self.assertTrue(any("hello" in line for line in streamed))
            cmd = mock_popen.call_args[0][0]
            self.assertNotIn("--auto-perform", cmd)
            self.assertIn("--stdio", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_one_shot_script_clean_exit_is_completed(self, _):
        import tempfile

        class FakeProcess:
            def __init__(self, _cmd, **_kwargs):
                self.stdout = StringIO("[STATUS] class enumeration complete\n")
                self.stderr = StringIO("")
                self.stdin = StringIO()
                self.returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def kill(self):
                self.returncode = 1

        with tempfile.TemporaryDirectory() as td, \
             patch.object(self.runner, "_python_frida_available", return_value=False), \
             patch.object(self.runner, "ensure_online_device", return_value={"serial": "emulator-5554", "online": True}), \
             patch.object(self.runner, "list_device_inventory", return_value={"connected_devices": [{"serial": "emulator-5554", "frida_compatible": True}], "local_avds": []}), \
             patch.object(self.runner, "start_frida_server_if_needed", return_value={"running": True, "started": False}), \
             patch.object(self.runner, "resolve_attach_target", return_value={"mode": "attach", "attach_flag": "-N", "attach_target": "com.nooie.home", "target_running_before": True, "launch_performed": False}), \
             patch.object(self.runner, "is_target_running", return_value=True), \
             patch("chainrecon.runners.frida_runner.subprocess.Popen", side_effect=FakeProcess):
            self.runner.start_session(target="com.nooie.home", script_key="list_classes", output_dir=td)
            active = self.runner.active_session()
            self.assertIsNotNone(active)
            if self.runner._active_session and self.runner._active_session.watcher_thread:
                self.runner._active_session.watcher_thread.join(timeout=2)
            summary = json.loads(Path(active["summary_path"]).read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "completed")
        self.assertFalse(summary["expected_long_running"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_stop_session_returns_none_when_idle(self, _):
        self.assertIsNone(self.runner.stop_session())

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_start_session_uses_managed_cli_backend_for_long_running_scripts(self, _):
        import tempfile

        class FakeProcess:
            def __init__(self):
                self.stdout = tempfile.SpooledTemporaryFile(mode="w+t")
                self.stdout.write("[STATUS] cli ready\n")
                self.stdout.seek(0)
                self.stderr = tempfile.SpooledTemporaryFile(mode="w+t")
                self.stdin = tempfile.SpooledTemporaryFile(mode="w+t")
                self.returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = 0
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def kill(self):
                self.returncode = 1

        with tempfile.TemporaryDirectory() as td, \
             patch.object(self.runner, "is_target_running", return_value=True), \
             patch.object(self.runner, "ensure_online_device", return_value={"serial": "emulator-5554", "online": True}), \
             patch.object(self.runner, "list_device_inventory", return_value={"connected_devices": [{"serial": "emulator-5554", "frida_compatible": True}], "local_avds": []}), \
             patch.object(self.runner, "start_frida_server_if_needed", return_value={"running": True, "started": False, "frida_server": "/tmp/frida-server"}), \
             patch.object(self.runner, "resolve_attach_target", return_value={"mode": "attach", "attach_flag": "-N", "attach_target": "com.nooie.home", "target_running_before": True, "launch_performed": False}), \
             patch("chainrecon.runners.frida_runner.subprocess.Popen", return_value=FakeProcess()):
            result = self.runner.start_session(
                target="com.nooie.home",
                script_key="network_traffic_monitor",
                output_dir=td,
            )
            active = self.runner.active_session()
            self.assertIsNotNone(active)
            self.assertEqual(self.runner._active_session.session_backend, "frida_cli_managed")
            self.assertEqual(result["command"][0], "frida")
            self.assertNotIn("--auto-perform", result["command"])
            summary = self.runner.stop_session(timeout=2)
        self.assertEqual(summary["status"], "stopped_by_user")


@unittest.skipUnless(os.environ.get("CHAINRECON_LIVE_FRIDA") == "1", "live Frida validation disabled")
class LiveFridaValidationTests(unittest.TestCase):
    def test_live_chainrecon_api35_setup_and_process_list(self):
        runner = FridaRunner()
        inventory = runner.list_device_inventory()
        self.assertTrue(any(d.get("avd_name") == "ChainRecon_API35" or d.get("serial", "").startswith("emulator-") for d in inventory["connected_devices"] + inventory["local_avds"]))
        result = runner.setup_device(
            target_id="avd:ChainRecon_API35",
            apk_directory=None,
            frida_server_path=str(Path("third_party") / "frida"),
            preferred_avd="ChainRecon_API35",
        )
        self.assertEqual(result["serial"].startswith("emulator-"), True)
        self.assertIn("Validated frida-ps connectivity.", result["actions"])

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_custom_script(self, _):
        result = self.runner.run_script(
            "com.example.app", "", custom_script_path="/tmp/my_hook.js"
        )
        self.assertEqual(result["script"], "/tmp/my_hook.js")
        cmd = self.executor.call_args[0][0]
        self.assertIn("/tmp/my_hook.js", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_spawn_and_run(self, _):
        result = self.runner.spawn_and_run("com.example.app", "crypto_monitor")
        self.assertEqual(result["package"], "com.example.app")
        cmd = self.executor.call_args[0][0]
        self.assertIn("-f", cmd)
        self.assertIn("com.example.app", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_spawn_custom_script(self, _):
        result = self.runner.spawn_and_run(
            "com.example.app", "", custom_script_path="/tmp/hook.js"
        )
        cmd = self.executor.call_args[0][0]
        self.assertIn("-f", cmd)
        self.assertIn("/tmp/hook.js", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", side_effect=ToolNotFoundError("frida not found"))
    def test_run_script_tool_missing(self, _):
        with self.assertRaises(ToolNotFoundError):
            self.runner.run_script("com.example.app", "ssl_pinning_bypass")

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_script_stderr(self, _):
        self.executor.return_value = subprocess.CompletedProcess(
            [], 1, "", "Error: process not found"
        )
        result = self.runner.run_script("com.example.app", "list_classes")
        self.assertIn("Error: process not found", result["stderr"])
        self.assertEqual(result["returncode"], 1)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_run_script_uses_current_frida_noninteractive_flags(self, _):
        self.runner.run_script("com.example.app", "network_traffic_monitor")
        cmd = self.executor.call_args[0][0]
        self.assertIn("-q", cmd)
        self.assertIn("-t", cmd)
        self.assertIn("120", cmd)
        self.assertIn("--exit-on-error", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_every_builtin_script_builds_attach_command(self, _):
        for key, meta in FRIDA_SCRIPTS.items():
            with self.subTest(script=key):
                self.executor.reset_mock()
                result = self.runner.run_script("com.example.app", key)
                self.assertEqual(result["script"], key)
                cmd = self.executor.call_args[0][0]
                self.assertEqual(cmd[:4], ["frida", "-U", "-N", "com.example.app"])
                self.assertIn(str(_SCRIPTS_DIR / meta["file"]), cmd)
                self.assertIn("-q", cmd)
                self.assertIn("-t", cmd)
                self.assertIn("120", cmd)
                self.assertIn("--exit-on-error", cmd)

    @patch("chainrecon.runners.frida_runner.check_tool", return_value="/usr/bin/frida")
    def test_every_builtin_script_builds_spawn_command(self, _):
        for key, meta in FRIDA_SCRIPTS.items():
            with self.subTest(script=key):
                self.executor.reset_mock()
                result = self.runner.spawn_and_run("com.example.app", key)
                self.assertEqual(result["script"], key)
                cmd = self.executor.call_args[0][0]
                self.assertEqual(cmd[:4], ["frida", "-U", "-f", "com.example.app"])
                self.assertIn(str(_SCRIPTS_DIR / meta["file"]), cmd)
                self.assertIn("-q", cmd)
                self.assertIn("-t", cmd)
                self.assertIn("120", cmd)
                self.assertIn("--exit-on-error", cmd)


if __name__ == "__main__":
    unittest.main()
