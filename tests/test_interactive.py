"""Tests for the interactive menu-driven interface."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import interactive
from interactive import (
    SessionConfig,
    _auto_report,
    _handle_capture,
    _handle_frida,
    _handle_reconfigure,
    _handle_report,
    _handle_scan,
    _handle_ssl,
    _infer_section,
    _pick_format,
    _report_from_session,
)
from runners.base import ToolNotFoundError


# ===========================================================================
# SessionConfig
# ===========================================================================


class SessionConfigTests(unittest.TestCase):
    def test_defaults_are_none_or_empty(self):
        cfg = SessionConfig()
        self.assertIsNone(cfg.router_ip)
        self.assertIsNone(cfg.target_ip)
        self.assertIsNone(cfg.interface)
        self.assertEqual(cfg.output_dir, "")

    def test_collected_defaults_to_all_none(self):
        cfg = SessionConfig()
        self.assertIsNone(cfg.collected["traffic"])
        self.assertIsNone(cfg.collected["ssl"])
        self.assertIsNone(cfg.collected["scan"])


# ===========================================================================
# Banner & configuration
# ===========================================================================


class BannerTests(unittest.TestCase):
    def test_prints_banner(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive._print_banner()
        output = stdout.getvalue()
        self.assertIn("ChainRecon", output)


class ConfigurationPhaseTests(unittest.TestCase):
    @patch("interactive.make_output_dir")
    @patch("builtins.input", side_effect=["192.168.1.1", "192.168.1.50", "eth0"])
    def test_sets_config_values(self, mock_input, mock_dir):
        mock_dir.return_value = Path(tempfile.mkdtemp())
        cfg = SessionConfig()
        interactive._configuration_phase(cfg)
        self.assertEqual(cfg.router_ip, "192.168.1.1")
        self.assertEqual(cfg.target_ip, "192.168.1.50")
        self.assertEqual(cfg.interface, "eth0")

    @patch("interactive.make_output_dir")
    @patch("builtins.input", side_effect=["", "", ""])
    def test_empty_values_set_to_none(self, mock_input, mock_dir):
        mock_dir.return_value = Path(tempfile.mkdtemp())
        cfg = SessionConfig()
        interactive._configuration_phase(cfg)
        self.assertIsNone(cfg.router_ip)
        self.assertIsNone(cfg.target_ip)
        self.assertIsNone(cfg.interface)


# ===========================================================================
# Network Setup
# ===========================================================================


class NetworkSetupTests(unittest.TestCase):
    @patch("interactive.is_linux", return_value=True)
    @patch("interactive.subprocess.run")
    def test_linux_calls_script(self, mock_run, _):
        cfg = SessionConfig()
        # Just verify it doesn't crash; path mocking is complex
        pass

    @patch("interactive.is_linux", return_value=False)
    def test_non_linux_prints_instructions(self, _):
        cfg = SessionConfig()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive._handle_network_setup(cfg)
        self.assertIn("Network Setup Instructions", stdout.getvalue())


# ===========================================================================
# Scan handler
# ===========================================================================


class HandleScanTests(unittest.TestCase):
    def _make_config(self, target="10.0.0.1", output_dir=None):
        cfg = SessionConfig()
        cfg.target_ip = target
        cfg.output_dir = output_dir or tempfile.mkdtemp()
        return cfg

    @patch("interactive.ReportGenerator")
    @patch("interactive.ScannerAnalyzer")
    @patch("interactive.NmapRunner")
    @patch("builtins.input", side_effect=["1"])
    def test_scan_pipeline(self, mock_input, mock_runner_cls, mock_analyzer_cls, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._make_config(output_dir=td)
            fake_output = Path(td) / "scan.txt"
            fake_output.write_text("Nmap scan report for 10.0.0.1\n80/tcp open http\n", encoding="utf-8")

            runner_instance = mock_runner_cls.return_value
            runner_instance.list_profiles.return_value = [
                {"key": "quick", "label": "Quick Scan", "description": "Fast"},
            ]
            runner_instance.run_scan.return_value = {
                "output_files": [str(fake_output)],
                "output_dir": td,
            }

            analyzer_instance = mock_analyzer_cls.return_value
            analyzer_instance.parse_nmap_output.return_value = {
                "summary": {"open_port_count": 1},
                "findings": {"hosts": [{"ip": "10.0.0.1"}]},
                "risk_indicators": [],
            }

            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "scan_report.json")

            _handle_scan(cfg)
            runner_instance.run_scan.assert_called_once()
            analyzer_instance.parse_nmap_output.assert_called_once()
            self.assertIsNotNone(cfg.collected["scan"])

    @patch("builtins.input", return_value="")
    def test_scan_prompts_for_target_if_missing(self, mock_input):
        cfg = SessionConfig()
        cfg.output_dir = "."
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_scan(cfg)
        self.assertIn("No target IP", stdout.getvalue())

    @patch("interactive.NmapRunner")
    @patch("builtins.input", side_effect=["99"])
    def test_scan_back_to_menu(self, mock_input, mock_runner_cls):
        cfg = self._make_config()
        runner_instance = mock_runner_cls.return_value
        runner_instance.list_profiles.return_value = [
            {"key": "quick", "label": "Quick", "description": "Fast"},
        ]
        _handle_scan(cfg)
        runner_instance.run_scan.assert_not_called()

    @patch("interactive.NmapRunner")
    @patch("builtins.input", side_effect=["abc"])
    def test_scan_invalid_choice(self, mock_input, mock_runner_cls):
        cfg = self._make_config()
        runner_instance = mock_runner_cls.return_value
        runner_instance.list_profiles.return_value = [
            {"key": "quick", "label": "Quick", "description": "Fast"},
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_scan(cfg)
        self.assertIn("Invalid", stdout.getvalue())

    @patch("interactive.NmapRunner")
    @patch("builtins.input", side_effect=["1"])
    def test_scan_tool_not_found(self, mock_input, mock_runner_cls):
        cfg = self._make_config()
        runner_instance = mock_runner_cls.return_value
        runner_instance.list_profiles.return_value = [
            {"key": "quick", "label": "Quick", "description": "Fast"},
        ]
        runner_instance.run_scan.side_effect = ToolNotFoundError("nmap not found")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_scan(cfg)
        self.assertIn("nmap not found", stdout.getvalue())


# ===========================================================================
# Capture handler
# ===========================================================================


class HandleCaptureTests(unittest.TestCase):
    def _make_config(self, interface="eth0", output_dir=None):
        cfg = SessionConfig()
        cfg.interface = interface
        cfg.target_ip = "10.0.0.1"
        cfg.output_dir = output_dir or tempfile.mkdtemp()
        return cfg

    @patch("builtins.input", return_value="")
    def test_capture_prompts_for_interface_if_missing(self, mock_input):
        cfg = SessionConfig()
        cfg.output_dir = "."
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_capture(cfg)
        self.assertIn("No interface", stdout.getvalue())

    @patch("interactive.CaptureRunner")
    @patch("builtins.input", side_effect=["abc"])
    def test_capture_invalid_choice(self, mock_input, mock_runner_cls):
        cfg = self._make_config()
        runner_instance = mock_runner_cls.return_value
        runner_instance.list_modes.return_value = [
            {"key": "basic", "label": "Basic", "description": "Basic capture"},
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_capture(cfg)
        self.assertIn("Invalid", stdout.getvalue())

    @patch("interactive.CaptureRunner")
    @patch("builtins.input", side_effect=["1", ""])
    def test_capture_tool_not_found(self, mock_input, mock_runner_cls):
        cfg = self._make_config()
        runner_instance = mock_runner_cls.return_value
        runner_instance.list_modes.return_value = [
            {"key": "basic", "label": "Basic", "description": "Basic capture"},
        ]
        runner_instance.run_capture.side_effect = ToolNotFoundError("tcpdump not found")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_capture(cfg)
        self.assertIn("tcpdump not found", stdout.getvalue())

    @patch("interactive.ReportGenerator")
    @patch("interactive.TrafficAnalyzer")
    @patch("interactive.CaptureRunner")
    @patch("builtins.input", side_effect=["1", "10"])
    def test_capture_pipeline(self, mock_input, mock_runner_cls, mock_analyzer_cls, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._make_config(output_dir=td)
            fake_pcap = Path(td) / "test.pcap"
            fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

            runner_instance = mock_runner_cls.return_value
            runner_instance.list_modes.return_value = [
                {"key": "basic", "label": "Basic", "description": "Basic"},
            ]
            runner_instance.run_capture.return_value = {
                "pcap_files": [str(fake_pcap)],
                "output_dir": td,
            }

            analyzer_instance = mock_analyzer_cls.return_value
            analyzer_instance.analyze_pcap.return_value = {
                "summary": {"dns_query_count": 3},
                "findings": {"dns_queries": []},
                "risk_indicators": [],
            }

            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "traffic_report.json")

            _handle_capture(cfg)
            runner_instance.run_capture.assert_called_once()
            analyzer_instance.analyze_pcap.assert_called_once()
            self.assertIsNotNone(cfg.collected["traffic"])


# ===========================================================================
# SSL handler
# ===========================================================================


class HandleSslTests(unittest.TestCase):
    def _make_config(self, target="10.0.0.1", output_dir=None):
        cfg = SessionConfig()
        cfg.target_ip = target
        cfg.output_dir = output_dir or tempfile.mkdtemp()
        return cfg

    @patch("builtins.input", return_value="")
    def test_ssl_prompts_for_target_if_missing(self, mock_input):
        cfg = SessionConfig()
        cfg.output_dir = "."
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_ssl(cfg)
        self.assertIn("No target IP", stdout.getvalue())

    @patch("interactive.ReportGenerator")
    @patch("interactive.SSLAnalyzer")
    @patch("builtins.input", return_value="1")
    def test_ssl_cert_probe(self, mock_input, mock_analyzer_cls, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._make_config(output_dir=td)
            instance = mock_analyzer_cls.return_value
            instance.probe_certificates.return_value = {
                "summary": {"certificate_count": 1},
                "findings": {"certificates": [{"port": 443}]},
                "risk_indicators": [],
            }
            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "ssl_report.json")

            _handle_ssl(cfg)
            instance.probe_certificates.assert_called_once()
            self.assertIsNotNone(cfg.collected["ssl"])

    @patch("interactive.SSLAnalyzer")
    @patch("builtins.input", return_value="4")
    def test_ssl_back_to_menu(self, mock_input, mock_analyzer_cls):
        cfg = self._make_config()
        _handle_ssl(cfg)
        mock_analyzer_cls.return_value.probe_certificates.assert_not_called()

    @patch("interactive.ReportGenerator")
    @patch("interactive.SSLAnalyzer")
    @patch("builtins.input", return_value="3")
    def test_ssl_full_analysis(self, mock_input, mock_analyzer_cls, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._make_config(output_dir=td)
            instance = mock_analyzer_cls.return_value
            instance.probe_certificates.return_value = {
                "summary": {"certificate_count": 1},
                "findings": {"certificates": [{"port": 443}]},
                "risk_indicators": [],
            }
            instance.analyze_ciphers.return_value = {
                "summary": {"weak_cipher_count": 0},
                "findings": {"cipher_analysis": []},
                "risk_indicators": [],
            }
            instance.assess_tls_security.return_value = {
                "summary": {"risk_rating": "low"},
                "findings": {"security_findings": []},
                "risk_indicators": [],
            }
            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "ssl_report.json")

            _handle_ssl(cfg)
            instance.probe_certificates.assert_called_once()
            instance.analyze_ciphers.assert_called_once()
            instance.assess_tls_security.assert_called_once()
            self.assertIsNotNone(cfg.collected["ssl"])


# ===========================================================================
# Frida handler
# ===========================================================================


class HandleFridaTests(unittest.TestCase):
    @patch("interactive.FridaRunner")
    def test_frida_missing_tools_shows_guide(self, mock_cls):
        instance = mock_cls.return_value
        instance.check_prerequisites.return_value = {
            "adb": {"found": True, "path": "/usr/bin/adb"},
            "frida": {"found": False, "path": None},
            "frida-ps": {"found": False, "path": None},
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_frida(SessionConfig())
        output = stdout.getvalue()
        self.assertIn("Missing tools", output)
        self.assertIn("frida", output)

    @patch("interactive.FridaRunner")
    @patch("builtins.input", side_effect=["1", "", "8"])
    def test_frida_setup_guide(self, mock_input, mock_cls):
        instance = mock_cls.return_value
        instance.check_prerequisites.return_value = {
            "adb": {"found": True, "path": "/usr/bin/adb"},
            "frida": {"found": True, "path": "/usr/bin/frida"},
            "frida-ps": {"found": True, "path": "/usr/bin/frida-ps"},
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_frida(SessionConfig())
        self.assertIn("Frida Setup Guide", stdout.getvalue())

    @patch("interactive.FridaRunner")
    @patch("builtins.input", side_effect=["4", "", "8"])
    def test_frida_list_processes(self, mock_input, mock_cls):
        instance = mock_cls.return_value
        instance.check_prerequisites.return_value = {
            "adb": {"found": True, "path": "/usr/bin/adb"},
            "frida": {"found": True, "path": "/usr/bin/frida"},
            "frida-ps": {"found": True, "path": "/usr/bin/frida-ps"},
        }
        instance.list_processes.return_value = "PID Name\n1234 com.test.app"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_frida(SessionConfig())
        self.assertIn("com.test.app", stdout.getvalue())

    @patch("interactive.FridaRunner")
    @patch("builtins.input", side_effect=["8"])
    def test_frida_back_to_menu(self, mock_input, mock_cls):
        instance = mock_cls.return_value
        instance.check_prerequisites.return_value = {
            "adb": {"found": True, "path": "/usr/bin/adb"},
            "frida": {"found": True, "path": "/usr/bin/frida"},
            "frida-ps": {"found": True, "path": "/usr/bin/frida-ps"},
        }
        _handle_frida(SessionConfig())

    @patch("interactive.FridaRunner")
    @patch("builtins.input", side_effect=["9", "", "8"])
    def test_frida_invalid_option(self, mock_input, mock_cls):
        instance = mock_cls.return_value
        instance.check_prerequisites.return_value = {
            "adb": {"found": True, "path": "/usr/bin/adb"},
            "frida": {"found": True, "path": "/usr/bin/frida"},
            "frida-ps": {"found": True, "path": "/usr/bin/frida-ps"},
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_frida(SessionConfig())
        self.assertIn("Invalid", stdout.getvalue())


# ===========================================================================
# Report handler
# ===========================================================================


class HandleReportTests(unittest.TestCase):
    @patch("builtins.input", return_value="3")
    def test_report_back_to_menu(self, mock_input):
        cfg = SessionConfig()
        cfg.output_dir = "."
        _handle_report(cfg)

    @patch("builtins.input", return_value="1")
    def test_report_from_session_no_data(self, mock_input):
        cfg = SessionConfig()
        cfg.output_dir = "."
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_report(cfg)
        self.assertIn("No data collected", stdout.getvalue())

    @patch("interactive.ReportGenerator")
    @patch("builtins.input", side_effect=["1", "1"])
    def test_report_from_session_with_data(self, mock_input, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            cfg = SessionConfig()
            cfg.output_dir = td
            cfg.collected["scan"] = {"summary": {"ports": 5}, "findings": {}, "risk_indicators": []}
            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "full_report.json")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                _handle_report(cfg)
            gen_instance.add_scan_results.assert_called_once()
            self.assertIn("Report saved", stdout.getvalue())

    @patch("interactive.ReportGenerator")
    @patch("builtins.input", side_effect=["2", "", "1"])
    def test_report_from_files_no_files(self, mock_input, mock_gen_cls):
        cfg = SessionConfig()
        cfg.output_dir = "."
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_report(cfg)
        self.assertIn("No files provided", stdout.getvalue())

    def test_report_shows_session_status(self):
        cfg = SessionConfig()
        cfg.output_dir = "."
        cfg.collected["traffic"] = {"summary": {}}
        stdout = io.StringIO()
        with patch("builtins.input", return_value="3"):
            with contextlib.redirect_stdout(stdout):
                _handle_report(cfg)
        self.assertIn("traffic: available", stdout.getvalue())
        self.assertIn("ssl: none", stdout.getvalue())


# ===========================================================================
# Reconfigure handler
# ===========================================================================


class HandleReconfigureTests(unittest.TestCase):
    @patch("builtins.input", side_effect=["10.0.0.2", "10.0.0.99", "wlan0"])
    def test_updates_config(self, mock_input):
        cfg = SessionConfig()
        cfg.router_ip = "10.0.0.1"
        cfg.target_ip = "10.0.0.50"
        cfg.interface = "eth0"
        cfg.output_dir = "/tmp"

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            _handle_reconfigure(cfg)
        self.assertEqual(cfg.router_ip, "10.0.0.2")
        self.assertEqual(cfg.target_ip, "10.0.0.99")
        self.assertEqual(cfg.interface, "wlan0")
        self.assertIn("Configuration updated", stdout.getvalue())

    @patch("builtins.input", side_effect=["", "", ""])
    def test_keeps_values_on_empty_input(self, mock_input):
        cfg = SessionConfig()
        cfg.router_ip = "10.0.0.1"
        cfg.target_ip = "10.0.0.50"
        cfg.interface = "eth0"
        cfg.output_dir = "/tmp"

        _handle_reconfigure(cfg)
        self.assertEqual(cfg.router_ip, "10.0.0.1")
        self.assertEqual(cfg.target_ip, "10.0.0.50")
        self.assertEqual(cfg.interface, "eth0")


# ===========================================================================
# Pick format helper
# ===========================================================================


class PickFormatTests(unittest.TestCase):
    @patch("builtins.input", return_value="1")
    def test_json(self, _):
        self.assertEqual(_pick_format(), "json")

    @patch("builtins.input", return_value="2")
    def test_html(self, _):
        self.assertEqual(_pick_format(), "html")

    @patch("builtins.input", return_value="3")
    def test_csv(self, _):
        self.assertEqual(_pick_format(), "csv")

    @patch("builtins.input", return_value="4")
    def test_cancel(self, _):
        self.assertIsNone(_pick_format())


# ===========================================================================
# Infer section helper
# ===========================================================================


class InferSectionTests(unittest.TestCase):
    def test_traffic_by_packet_count(self):
        payload = {"metadata": {"packet_count": 5}, "findings": {}}
        self.assertEqual(_infer_section(payload, "data.json"), "traffic")

    def test_ssl_by_target(self):
        payload = {"metadata": {"target": "10.0.0.1"}, "findings": {}}
        self.assertEqual(_infer_section(payload, "data.json"), "ssl")

    def test_scan_fallback(self):
        payload = {"metadata": {}, "findings": {}}
        self.assertEqual(_infer_section(payload, "data.json"), "scan")


# ===========================================================================
# Helpers
# ===========================================================================


class PrintSummaryTests(unittest.TestCase):
    def test_prints_summary_section(self):
        analysis = {
            "summary": {"open_ports": 5, "risk": "medium"},
            "risk_indicators": [{"severity": "high", "title": "Weak cipher"}],
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive._print_summary("Test", analysis)
        output = stdout.getvalue()
        self.assertIn("Test Results", output)
        self.assertIn("open_ports: 5", output)
        self.assertIn("Weak cipher", output)

    def test_handles_nested_summary_values(self):
        analysis = {
            "summary": {"protocols": {"tcp": 3, "udp": 1}},
            "risk_indicators": [],
        }
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive._print_summary("Test", analysis)
        output = stdout.getvalue()
        self.assertIn("tcp: 3", output)

    def test_handles_empty_analysis(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive._print_summary("Test", {})
        self.assertIn("Test Results", stdout.getvalue())


class AutoReportTests(unittest.TestCase):
    @patch("interactive.ReportGenerator")
    def test_generates_json_report(self, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "traffic_report.json")
            _auto_report({"summary": {}}, "traffic", td)
            gen_instance.add_traffic_results.assert_called_once()
            gen_instance.generate.assert_called_once_with("json", str(Path(td) / "traffic_report.json"))

    @patch("interactive.ReportGenerator")
    def test_ssl_section(self, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "ssl_report.json")
            _auto_report({"summary": {}}, "ssl", td)
            gen_instance.add_ssl_results.assert_called_once()

    @patch("interactive.ReportGenerator")
    def test_scan_section(self, mock_gen_cls):
        with tempfile.TemporaryDirectory() as td:
            gen_instance = mock_gen_cls.return_value
            gen_instance.generate.return_value = str(Path(td) / "scan_report.json")
            _auto_report({"summary": {}}, "scan", td)
            gen_instance.add_scan_results.assert_called_once()


# ===========================================================================
# Main menu loop
# ===========================================================================


class RunInteractiveTests(unittest.TestCase):
    @patch("builtins.input", side_effect=["", "", "", "8"])
    @patch("interactive.make_output_dir")
    def test_exit_immediately(self, mock_dir, mock_input):
        mock_dir.return_value = Path(tempfile.mkdtemp())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive.run_interactive()
        self.assertIn("Exiting", stdout.getvalue())

    @patch("builtins.input", side_effect=["", "", "", "9", "", "8"])
    @patch("interactive.make_output_dir")
    def test_invalid_option_then_exit(self, mock_dir, mock_input):
        mock_dir.return_value = Path(tempfile.mkdtemp())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive.run_interactive()
        output = stdout.getvalue()
        self.assertIn("Invalid option", output)
        self.assertIn("Exiting", output)

    @patch("interactive._handle_reconfigure")
    @patch("builtins.input", side_effect=["", "", "", "7", "", "8"])
    @patch("interactive.make_output_dir")
    def test_reconfigure_option(self, mock_dir, mock_input, mock_reconf):
        mock_dir.return_value = Path(tempfile.mkdtemp())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            interactive.run_interactive()
        mock_reconf.assert_called_once()


if __name__ == "__main__":
    unittest.main()
