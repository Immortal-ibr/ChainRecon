"""Tests for the runners package (base utilities, NmapRunner, CaptureRunner)."""

import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from runners.base import (
    ToolNotFoundError,
    check_tool,
    is_linux,
    is_windows,
    make_output_dir,
    run_subprocess,
)
from runners.capture_runner import CAPTURE_MODES, CaptureRunner
from runners.nmap_runner import SCAN_PROFILES, NmapInterfaceMismatchError, NmapRunner, powershell_command


# ===========================================================================
# runners.base utilities
# ===========================================================================


class CheckToolTests(unittest.TestCase):
    @patch("utils.platform_info.shutil.which", return_value="/usr/bin/nmap")
    def test_returns_path_when_found(self, mock_which):
        self.assertEqual(check_tool("nmap"), "/usr/bin/nmap")

    @patch("utils.platform_info.shutil.which", return_value=None)
    @patch("utils.platform_info.os.path.isfile", return_value=False)
    @patch("utils.platform_info.os.path.isdir", return_value=False)
    def test_raises_when_not_found(self, mock_isdir, mock_isfile, mock_which):
        with self.assertRaises(ToolNotFoundError) as ctx:
            check_tool("nmap")
        self.assertIn("nmap", str(ctx.exception))


class MakeOutputDirTests(unittest.TestCase):
    def test_creates_timestamped_directory(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            result = make_output_dir(td)
            self.assertTrue(result.exists())
            self.assertTrue(result.is_dir())
            self.assertRegex(result.name, r"^\d{8}_\d{6}_iot_recon$")

    def test_returns_path_object(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            result = make_output_dir(td)
            self.assertIsInstance(result, Path)


class RunSubprocessTests(unittest.TestCase):
    @patch("runners.base.subprocess.run")
    def test_passes_defaults(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        run_subprocess(["echo", "hi"], timeout=5)
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertEqual(kwargs["timeout"], 5)

    @patch("runners.base.subprocess.run")
    def test_allows_overriding_defaults(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
        run_subprocess(["echo"], capture_output=False, text=False)
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs["capture_output"])
        self.assertFalse(kwargs["text"])


class PlatformTests(unittest.TestCase):
    @patch("runners.base.platform.system", return_value="Linux")
    def test_is_linux_true(self, _):
        self.assertTrue(is_linux())

    @patch("runners.base.platform.system", return_value="Windows")
    def test_is_linux_false(self, _):
        self.assertFalse(is_linux())

    @patch("runners.base.platform.system", return_value="Windows")
    def test_is_windows_true(self, _):
        self.assertTrue(is_windows())

    @patch("runners.base.platform.system", return_value="Darwin")
    def test_is_windows_false(self, _):
        self.assertFalse(is_windows())


# ===========================================================================
# NmapRunner
# ===========================================================================


class NmapRunnerListProfilesTests(unittest.TestCase):
    def test_returns_all_profiles(self):
        runner = NmapRunner()
        profiles = runner.list_profiles()
        self.assertEqual(len(profiles), len(SCAN_PROFILES))

    def test_each_profile_has_required_keys(self):
        runner = NmapRunner()
        for p in runner.list_profiles():
            self.assertIn("key", p)
            self.assertIn("label", p)
            self.assertIn("description", p)


class NmapRunnerScanTests(unittest.TestCase):
    def setUp(self):
        self.executor = MagicMock()

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_arp_scan_builds_host_discovery_command(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            result = runner.run_scan("192.168.1.0/24", "arp", td)
            cmd = self.executor.call_args[0][0]
            self.assertIn("-sn", cmd)
            self.assertIn("-PR", cmd)
            self.assertEqual(result["profile"], "arp")

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_quick_scan_builds_correct_command(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            result = runner.run_scan("10.0.0.1", "quick", td)
            self.executor.assert_called_once()
            cmd = self.executor.call_args[0][0]
            self.assertEqual(cmd[0], "/usr/bin/nmap")
            self.assertIn("-Pn", cmd)
            self.assertIn("-sV", cmd)
            self.assertIn("10.0.0.1", cmd)
            self.assertIn("-oN", cmd)
            self.assertEqual(result["profile"], "quick")
            self.assertEqual(result["target"], "10.0.0.1")
            self.assertEqual(len(result["output_files"]), 2)  # .txt + .xml

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_iot_scan_runs_two_commands(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            result = runner.run_scan("10.0.0.1", "iot", td)
            self.assertEqual(self.executor.call_count, 2)
            self.assertEqual(len(result["output_files"]), 4)
            # TCP first, UDP second
            tcp_cmd = self.executor.call_args_list[0][0][0]
            udp_cmd = self.executor.call_args_list[1][0][0]
            self.assertIn("-sV", tcp_cmd)
            self.assertIn("-sU", udp_cmd)
            self.assertIn("-oX", tcp_cmd)
            self.assertIn("-oX", udp_cmd)

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_vuln_scan_includes_script_flag(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            runner.run_scan("10.0.0.1", "vuln", td)
            cmd = self.executor.call_args[0][0]
            self.assertIn("--script", cmd)
            self.assertIn("vuln", cmd)

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_invalid_profile_raises_value_error(self, _):
        runner = NmapRunner(executor=self.executor)
        with self.assertRaises(ValueError) as ctx:
            runner.run_scan("10.0.0.1", "nonexistent")
        self.assertIn("nonexistent", str(ctx.exception))

    @patch("runners.nmap_runner.check_tool", side_effect=ToolNotFoundError("nmap not found"))
    def test_tool_not_found_propagates(self, _):
        runner = NmapRunner(executor=self.executor)
        with self.assertRaises(ToolNotFoundError):
            runner.run_scan("10.0.0.1", "quick")
        self.executor.assert_not_called()

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_creates_output_dir_when_none_given(self, _):
        import tempfile

        runner = NmapRunner(executor=self.executor)
        with patch("runners.nmap_runner.make_output_dir") as mock_dir:
            mock_dir.return_value = Path(tempfile.mkdtemp())
            result = runner.run_scan("10.0.0.1", "quick")
            mock_dir.assert_called_once()

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_full_scan_uses_all_ports(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            runner.run_scan("10.0.0.1", "full", td)
            cmd = self.executor.call_args[0][0]
            self.assertIn("-p-", cmd)
            self.assertIn("-A", cmd)

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_gentle_scan_uses_slow_timing(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            runner.run_scan("10.0.0.1", "gentle", td)
            cmd = self.executor.call_args[0][0]
            self.assertIn("-T2", cmd)
            self.assertIn("-sT", cmd)

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_explicit_interface_adds_e_flag(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            runner.run_scan("10.0.0.1", "quick", td, interface="eth4")
            cmd = self.executor.call_args[0][0]
            self.assertEqual(cmd[:3], ["/usr/bin/nmap", "-e", "eth4"])

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    @patch("utils.config.get_scan_config", return_value={"interface_name": "Wi-Fi"})
    @patch("utils.network.resolve_scan_interface", return_value={"runtime_id": "eth4"})
    def test_configured_interface_is_resolved_before_scan(self, *_):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            runner.run_scan("10.0.0.1", "quick", td)
            cmd = self.executor.call_args[0][0]
            self.assertEqual(cmd[:3], ["/usr/bin/nmap", "-e", "eth4"])

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    @patch("utils.config.get_scan_config", return_value={"interface_name": "Wi-Fi"})
    @patch("utils.network.resolve_scan_interface", return_value=None)
    def test_unresolved_configured_interface_falls_back_without_e_flag(self, *_):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = NmapRunner(executor=self.executor)
            runner.run_scan("10.0.0.1", "quick", td)
            cmd = self.executor.call_args[0][0]
            self.assertNotIn("-e", cmd)

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_real_executor_blocks_interface_mismatch(self, _):
        def mismatch_preflight(target, selected_interface=None):
            return {
                "target": target,
                "interface_mismatch": True,
                "selected_interface": {"label": selected_interface or "eth4"},
                "route_interface": {"label": "eth0"},
            }

        runner = NmapRunner(preflight_func=mismatch_preflight)
        with self.assertRaises(NmapInterfaceMismatchError):
            runner.run_scan("192.168.123.99", "quick", interface="eth4")

    @patch("runners.nmap_runner.check_tool", return_value="/usr/bin/nmap")
    def test_allow_interface_mismatch_runs_anyway(self, _):
        import tempfile

        def mismatch_preflight(target, selected_interface=None):
            return {"target": target, "interface_mismatch": True}

        with tempfile.TemporaryDirectory() as td:
            with patch("runners.nmap_runner.run_subprocess", self.executor):
                runner = NmapRunner(preflight_func=mismatch_preflight)
                result = runner.run_scan("192.168.123.99", "quick", td, interface="eth4", allow_interface_mismatch=True)
        self.assertEqual(result["preflight"]["interface_mismatch"], True)
        self.executor.assert_called_once()

    def test_powershell_command_quotes_executable_path(self):
        cmd = powershell_command([r"C:\Program Files (x86)\Nmap\nmap.EXE", "-e", "eth0", "192.168.1.1"])
        self.assertTrue(cmd.startswith("& 'C:\\Program Files (x86)\\Nmap\\nmap.EXE'"))
        self.assertIn("-e eth0", cmd)


# ===========================================================================
# CaptureRunner
# ===========================================================================


class CaptureRunnerListModesTests(unittest.TestCase):
    def test_returns_all_modes(self):
        runner = CaptureRunner()
        modes = runner.list_modes()
        self.assertEqual(len(modes), len(CAPTURE_MODES))

    def test_each_mode_has_required_keys(self):
        runner = CaptureRunner()
        for m in runner.list_modes():
            self.assertIn("key", m)
            self.assertIn("label", m)
            self.assertIn("description", m)


class CaptureRunnerCaptureTests(unittest.TestCase):
    def setUp(self):
        self.executor = MagicMock()

    @patch("runners.capture_runner.is_windows", return_value=False)
    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_basic_capture_builds_tcpdump_command(self, _ct, _win):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            result = runner.run_capture("eth0", "basic", duration=30, output_dir=td)
            self.executor.assert_called_once()
            cmd = self.executor.call_args[0][0]
            # check_tool is mocked to return the same path for any tool name;
            # tshark is tried first so the resolved path is the mocked value
            self.assertEqual(cmd[0], "/usr/sbin/tcpdump")
            self.assertIn("-i", cmd)
            self.assertIn("eth0", cmd)
            self.assertEqual(result["mode"], "basic")
            self.assertEqual(len(result["pcap_files"]), 1)

    @patch("runners.capture_runner.check_tool", return_value="/usr/bin/tshark")
    def test_live_capture_uses_tshark(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            result = runner.run_capture("eth0", "live", duration=10, output_dir=td)
            cmd = self.executor.call_args[0][0]
            self.assertEqual(cmd[0], "/usr/bin/tshark")
            self.assertIn("-a", cmd)
            self.assertEqual(result["mode"], "live")

    @patch("runners.capture_runner.is_windows", return_value=False)
    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_bpf_filter_added_with_target_ip(self, _ct, _win):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            runner.run_capture("eth0", "basic", target_ip="10.0.0.5", output_dir=td)
            cmd = self.executor.call_args[0][0]
            # tshark uses -f <filter>, so BPF is in the arg after -f
            self.assertIn("-f", cmd)
            bpf = cmd[cmd.index("-f") + 1]
            self.assertIn("host", bpf)
            self.assertIn("10.0.0.5", bpf)

    @patch("runners.capture_runner.is_windows", return_value=False)
    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_no_bpf_filter_without_target_ip(self, _ct, _win):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            runner.run_capture("eth0", "basic", output_dir=td)
            cmd = self.executor.call_args[0][0]
            self.assertNotIn("host", cmd)

    def test_tshark_fallback_to_tcpdump(self):
        """When tshark is not found but tcpdump is, capture falls back to tcpdump."""
        import tempfile

        def mock_check(name):
            if name == "tshark":
                raise ToolNotFoundError("tshark not found")
            return "/usr/sbin/tcpdump"

        with tempfile.TemporaryDirectory() as td:
            with patch("runners.capture_runner.is_windows", return_value=False):
                with patch("runners.capture_runner.check_tool", side_effect=mock_check):
                    runner = CaptureRunner(executor=self.executor)
                    result = runner.run_capture("eth0", "live", output_dir=td)
                    cmd = self.executor.call_args[0][0]
                    self.assertEqual(cmd[0], "/usr/sbin/tcpdump")

    def test_neither_tool_found_raises(self):
        """When neither tshark nor tcpdump is found, error propagates."""
        with patch("runners.capture_runner.is_windows", return_value=False):
            with patch("runners.capture_runner.check_tool", side_effect=ToolNotFoundError("not found")):
                runner = CaptureRunner(executor=self.executor)
                with self.assertRaises(ToolNotFoundError):
                    runner.run_capture("eth0", "basic")

    def test_windows_prefers_tshark_for_tcpdump_modes(self):
        """On Windows, all modes use tshark with its full resolved path."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            with patch("runners.capture_runner.is_windows", return_value=True):
                with patch("runners.capture_runner.check_tool", return_value="C:\\Wireshark\\tshark.exe"):
                    runner = CaptureRunner(executor=self.executor)
                    result = runner.run_capture("eth0", "basic", output_dir=td)
                    cmd = self.executor.call_args[0][0]
                    self.assertEqual(cmd[0], "C:\\Wireshark\\tshark.exe")

    def test_invalid_mode_raises_value_error(self):
        runner = CaptureRunner(executor=self.executor)
        with self.assertRaises(ValueError) as ctx:
            runner.run_capture("eth0", "nonexistent")
        self.assertIn("nonexistent", str(ctx.exception))

    @patch("runners.capture_runner.is_windows", return_value=False)
    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_dns_mode_produces_pcap(self, _ct, _win):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            result = runner.run_capture("eth0", "dns", output_dir=td)
            self.assertEqual(result["mode"], "dns")
            self.assertTrue(result["pcap_files"][0].endswith(".pcap"))

    @patch("runners.capture_runner.is_windows", return_value=False)
    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_duration_passed_to_tcpdump(self, _ct, _win):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            runner.run_capture("eth0", "full", duration=120, output_dir=td)
            cmd = self.executor.call_args[0][0]
            # tshark is now preferred: uses -a duration:N format
            self.assertIn("-a", cmd)
            a_idx = cmd.index("-a")
            self.assertEqual(cmd[a_idx + 1], "duration:120")

    @patch("runners.capture_runner.check_tool", return_value="/usr/bin/tshark")
    def test_tshark_duration_flag(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            runner.run_capture("eth0", "live", duration=45, output_dir=td)
            cmd = self.executor.call_args[0][0]
            self.assertIn("duration:45", cmd)

    @patch("runners.capture_runner.check_tool", return_value="/usr/bin/tshark")
    def test_tshark_bpf_uses_f_flag(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            runner.run_capture("eth0", "live", target_ip="10.0.0.1", output_dir=td)
            cmd = self.executor.call_args[0][0]
            self.assertIn("-f", cmd)
            idx = cmd.index("-f")
            self.assertEqual(cmd[idx + 1], "host 10.0.0.1")

    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_creates_output_dir_when_none_given(self, _):
        runner = CaptureRunner(executor=self.executor)
        with patch("runners.capture_runner.make_output_dir") as mock_dir:
            import tempfile

            mock_dir.return_value = Path(tempfile.mkdtemp())
            result = runner.run_capture("eth0", "basic")
            mock_dir.assert_called_once()

    @patch("runners.capture_runner.check_tool", return_value="/usr/sbin/tcpdump")
    def test_timeout_includes_buffer(self, _):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            runner = CaptureRunner(executor=self.executor)
            runner.run_capture("eth0", "basic", duration=60, output_dir=td)
            _, kwargs = self.executor.call_args
            self.assertEqual(kwargs["timeout"], 90)


if __name__ == "__main__":
    unittest.main()
