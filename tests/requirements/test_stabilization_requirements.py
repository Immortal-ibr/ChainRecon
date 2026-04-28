import tempfile
import unittest
import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

from analysis.report_generator import ReportGenerator, normalize_report_data
from analysis.scanner import ScannerAnalyzer
from runners.nmap_runner import NmapInterfaceMismatchError, NmapRunner
from utils.artifacts import update_artifact_index, write_json_artifact
from utils.frida_utils import _extract_frida_log_events


class ScanRequirementTests(unittest.TestCase):
    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_wrong_interface_blocks_misleading_scan_by_default(self, _):
        def preflight(_target, selected_interface=None):
            return {
                "interface_mismatch": True,
                "selected_interface": {"label": selected_interface},
                "route_interface": {"label": "eth0"},
            }

        with self.assertRaises(NmapInterfaceMismatchError):
            NmapRunner(preflight_func=preflight).run_scan("192.168.123.99", "quick", interface="eth4")

    def test_udp_open_filtered_is_reported_as_ambiguous_not_open(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write(
                "Nmap scan report for 192.168.123.99\n"
                "Host is up.\n\n"
                "PORT     STATE         SERVICE\n"
                "1900/udp open|filtered upnp\n"
            )
            path = handle.name
        result = ScannerAnalyzer().parse_nmap_output(path)
        self.assertEqual(result["summary"]["open_port_count"], 0)
        self.assertEqual(result["summary"]["ambiguous_udp_count"], 1)
        self.assertTrue(any(item["title"] == "Ambiguous UDP scan result" for item in result["risk_indicators"]))


class FridaReportRequirementTests(unittest.TestCase):
    def test_frida_report_extracts_events_not_only_links(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as handle:
            handle.write("[stdout] [HOOK] java.net.Socket.connect\n[stderr] [WARN] retrying\n")
            path = handle.name
        hooks = _extract_frida_log_events(path, prefixes=("[HOOK]",))
        errors = _extract_frida_log_events(path, prefixes=("[WARN]", "[stderr]"))
        self.assertEqual(hooks, ["[stdout] [HOOK] java.net.Socket.connect"])
        self.assertTrue(errors)


class ApkArtifactRequirementTests(unittest.TestCase):
    def test_artifact_index_is_immediately_readable(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "apk.json"
            write_json_artifact(out, {"metadata": {"section": "apk"}})
            index = update_artifact_index(td, {"section": "apk", "type": "apk_analysis", "path": str(out)})
            self.assertTrue(index.exists())
            payload = json.loads(index.read_text(encoding="utf-8"))
            self.assertEqual(payload["artifacts"][0]["path"], str(out))


class ReportRequirementTests(unittest.TestCase):
    def test_report_normalization_adds_artifacts_shape(self):
        gen = ReportGenerator()
        gen.add_results("frida", {
            "metadata": {"source_file": "session.json"},
            "summary": {"status": "stopped_by_user"},
            "findings": {"events_by_tag": {"HOOK": 1}},
        })
        data = normalize_report_data(gen.get_data())
        self.assertIn("artifacts", data["frida"])
        self.assertEqual(data["frida"]["metadata"]["section"], "frida")
        self.assertEqual(data["frida"]["artifacts"][0]["path"], "session.json")


class FridaLifecycleRequirementTests(unittest.TestCase):
    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_managed_frida_command_omits_auto_perform(self, _):
        from runners.frida_runner import FridaRunner

        cmd = FridaRunner._build_managed_command(
            serial="emulator-5554",
            attach_flag="-N",
            attach_target="com.nooie.home",
            rendered_script_path=Path("session.js"),
        )
        self.assertNotIn("--auto-perform", cmd)

    @patch("runners.frida_runner.check_tool", return_value="/usr/bin/tool")
    def test_frida_long_session_stays_active_until_stop(self, _):
        from runners.frida_runner import FridaRunner

        class FakeProcess:
            def __init__(self, _cmd, **_kwargs):
                self.stdout = tempfile.SpooledTemporaryFile(mode="w+t")
                self.stdout.write("[STATUS] ready\n")
                self.stdout.seek(0)
                self.stderr = tempfile.SpooledTemporaryFile(mode="w+t")
                self.stdin = tempfile.SpooledTemporaryFile(mode="w+t")
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

        runner = FridaRunner()
        with tempfile.TemporaryDirectory() as td, \
             patch.object(runner, "_python_frida_available", return_value=False), \
             patch.object(runner, "is_target_running", return_value=True), \
             patch.object(runner, "ensure_online_device", return_value={"serial": "emulator-5554", "online": True}), \
             patch.object(runner, "list_device_inventory", return_value={"connected_devices": [{"serial": "emulator-5554", "frida_compatible": True}], "local_avds": []}), \
             patch.object(runner, "start_frida_server_if_needed", return_value={"running": True, "started": False}), \
             patch.object(runner, "resolve_attach_target", return_value={"mode": "attach", "attach_flag": "-N", "attach_target": "com.nooie.home", "target_running_before": True, "launch_performed": False}), \
             patch("runners.frida_runner.subprocess.Popen", side_effect=FakeProcess):
            runner.start_session(target="com.nooie.home", script_key="network_traffic_monitor", output_dir=td)
            self.assertIsNotNone(runner.active_session())
            summary = runner.stop_session(timeout=2)
        self.assertEqual(summary["status"], "stopped_by_user")


if __name__ == "__main__":
    unittest.main()
