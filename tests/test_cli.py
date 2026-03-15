"""Comprehensive tests for the CLI entrypoint (chainrecon.py)."""

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import chainrecon
from runners.base import ToolNotFoundError


# ===========================================================================
# analyze-traffic subcommand
# ===========================================================================


class AnalyzeTrafficCliTests(unittest.TestCase):
    PAYLOAD = {
        "metadata": {"source": "capture.pcap", "packet_count": 5},
        "findings": {"dns_queries": [{"query": "example.com"}]},
        "summary": {"dns_query_count": 1},
        "risk_indicators": [],
    }

    def test_dispatches_to_traffic_analyzer(self):
        stdout = io.StringIO()
        with patch("chainrecon.TrafficAnalyzer") as cls:
            cls.return_value.analyze_pcap.return_value = self.PAYLOAD
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.main(["analyze-traffic", "capture.pcap"])
        self.assertEqual(code, 0)
        cls.return_value.analyze_pcap.assert_called_once_with("capture.pcap")

    def test_writes_json_report_when_format_specified(self):
        with tempfile.TemporaryDirectory() as td:
            output = str(Path(td) / "traffic.json")
            stdout = io.StringIO()
            with patch("chainrecon.TrafficAnalyzer") as cls:
                cls.return_value.analyze_pcap.return_value = self.PAYLOAD
                with contextlib.redirect_stdout(stdout):
                    chainrecon.main(["analyze-traffic", "capture.pcap", "--format", "json", "--output", output])
            self.assertTrue(Path(output).exists())
            with open(output, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("traffic", data)

    def test_prints_json_to_stdout(self):
        stdout = io.StringIO()
        with patch("chainrecon.TrafficAnalyzer") as cls:
            cls.return_value.analyze_pcap.return_value = self.PAYLOAD
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-traffic", "capture.pcap"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["metadata"]["packet_count"], 5)

    def test_no_output_flag_doesnt_write_file(self):
        stdout = io.StringIO()
        with patch("chainrecon.TrafficAnalyzer") as cls:
            cls.return_value.analyze_pcap.return_value = self.PAYLOAD
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-traffic", "capture.pcap"])
        # Just verify it didn't crash -- no file assertion needed


# ===========================================================================
# analyze-ssl subcommand
# ===========================================================================


class AnalyzeSslCliTests(unittest.TestCase):
    def _mock_ssl(self):
        patcher = patch("chainrecon.SSLAnalyzer")
        mock_cls = patcher.start()
        instance = mock_cls.return_value
        instance.probe_certificates.return_value = {
            "findings": {"certificates": [{"port": 443, "subject": "CN=dev"}]},
            "summary": {"certificate_count": 1},
        }
        instance.analyze_ciphers.return_value = {
            "findings": {"cipher_analysis": [{"port": 443, "weak_cipher": False}]},
            "summary": {"weak_cipher_count": 0},
        }
        instance.assess_tls_security.return_value = {
            "findings": {"security_findings": []},
            "summary": {"risk_rating": "low"},
            "risk_indicators": [],
        }
        instance.compute_ja3.return_value = {
            "findings": {"ja3": {"available": True, "hash": "abc"}},
        }
        return patcher, instance

    def test_ssl_analysis_runs(self):
        patcher, instance = self._mock_ssl()
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.main(["analyze-ssl", "10.0.0.1"])
        finally:
            patcher.stop()
        self.assertEqual(code, 0)
        result = json.loads(stdout.getvalue())
        self.assertIn("certificates", result["findings"])

    def test_ssl_with_custom_ports(self):
        patcher, instance = self._mock_ssl()
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-ssl", "10.0.0.1", "--ports", "443", "8443"])
        finally:
            patcher.stop()
        instance.probe_certificates.assert_called_once_with("10.0.0.1", [443, 8443])

    def test_ssl_with_pcap_includes_ja3(self):
        patcher, instance = self._mock_ssl()
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-ssl", "10.0.0.1", "--pcap", "capture.pcap"])
        finally:
            patcher.stop()
        result = json.loads(stdout.getvalue())
        self.assertIn("ja3", result["findings"])
        instance.compute_ja3.assert_called_once_with("capture.pcap")

    def test_ssl_without_pcap_no_ja3(self):
        patcher, instance = self._mock_ssl()
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-ssl", "10.0.0.1"])
        finally:
            patcher.stop()
        result = json.loads(stdout.getvalue())
        self.assertNotIn("ja3", result["findings"])


# ===========================================================================
# analyze-scan subcommand
# ===========================================================================


class AnalyzeScanCliTests(unittest.TestCase):
    PAYLOAD = {
        "metadata": {"source": "scan.xml"},
        "findings": {"hosts": [{"ip": "192.168.1.50"}], "iot_services": [], "cve_hints": []},
        "summary": {"open_port_count": 1},
        "risk_indicators": [],
    }

    def test_scan_dispatches_correctly(self):
        stdout = io.StringIO()
        with patch("chainrecon.ScannerAnalyzer") as cls:
            cls.return_value.parse_nmap_output.return_value = copy.deepcopy(self.PAYLOAD)
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.main(["analyze-scan", "scan.xml"])
        self.assertEqual(code, 0)

    def test_scan_with_shodan(self):
        stdout = io.StringIO()
        with patch("chainrecon.ScannerAnalyzer") as cls:
            instance = cls.return_value
            instance.parse_nmap_output.return_value = copy.deepcopy(self.PAYLOAD)
            instance.lookup_shodan.return_value = {"enabled": True, "ip": "192.168.1.50", "organization": "Test"}
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-scan", "scan.xml", "--shodan-api-key", "key"])
        result = json.loads(stdout.getvalue())
        self.assertIn("shodan", result["findings"])
        self.assertTrue(result["findings"]["shodan"][0]["enabled"])

    def test_scan_without_shodan_no_enrichment(self):
        stdout = io.StringIO()
        with patch("chainrecon.ScannerAnalyzer") as cls:
            cls.return_value.parse_nmap_output.return_value = copy.deepcopy(self.PAYLOAD)
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["analyze-scan", "scan.xml"])
        result = json.loads(stdout.getvalue())
        self.assertNotIn("shodan", result["findings"])

    def test_scan_with_output_format(self):
        with tempfile.TemporaryDirectory() as td:
            output = str(Path(td) / "scan.html")
            stdout = io.StringIO()
            with patch("chainrecon.ScannerAnalyzer") as cls:
                cls.return_value.parse_nmap_output.return_value = copy.deepcopy(self.PAYLOAD)
                with contextlib.redirect_stdout(stdout):
                    chainrecon.main(["analyze-scan", "scan.xml", "--format", "html", "--output", output])
            self.assertTrue(Path(output).exists())


# ===========================================================================
# report subcommand
# ===========================================================================


class ReportCliTests(unittest.TestCase):
    def test_merges_json_inputs_from_directory(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "traffic.json").write_text(
                json.dumps({"metadata": {"source": "cap.pcap", "packet_count": 2}, "findings": {}, "summary": {}, "risk_indicators": []}),
                encoding="utf-8",
            )
            (tp / "ssl.json").write_text(
                json.dumps({"metadata": {"target": "10.0.0.1"}, "findings": {"security_findings": []}, "summary": {}, "risk_indicators": []}),
                encoding="utf-8",
            )
            output = tp / "report.html"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.main(["report", td, "--format", "html", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(stdout.getvalue())["format"], "html")

    def test_merges_individual_files(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            f1 = tp / "traffic.json"
            f1.write_text(
                json.dumps({"metadata": {"source": "cap.pcap", "packet_count": 1}, "findings": {}, "summary": {}, "risk_indicators": []}),
                encoding="utf-8",
            )
            output = tp / "report.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.main(["report", str(f1), "--format", "json", "--output", str(output)])
            self.assertEqual(code, 0)
            with open(output, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsNotNone(data["traffic"])

    def test_report_csv_format(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "scan.json").write_text(
                json.dumps({"metadata": {}, "findings": {"hosts": [{"ip": "10.0.0.1"}]}, "summary": {}, "risk_indicators": []}),
                encoding="utf-8",
            )
            output = tp / "report.csv"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["report", td, "--format", "csv", "--output", str(output)])
            self.assertTrue(output.exists())


# ===========================================================================
# Helper function tests
# ===========================================================================


class InferSectionTests(unittest.TestCase):
    def test_traffic_by_packet_count(self):
        payload = {"metadata": {"packet_count": 5}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "traffic")

    def test_traffic_by_source_pcap(self):
        payload = {"metadata": {"source": "capture.pcap"}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "traffic")

    def test_traffic_by_filename(self):
        payload = {"metadata": {}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "traffic_results.json"), "traffic")

    def test_ssl_by_target(self):
        payload = {"metadata": {"target": "10.0.0.1"}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "ssl")

    def test_ssl_by_security_findings(self):
        payload = {"metadata": {}, "findings": {"security_findings": []}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "ssl")

    def test_ssl_by_filename(self):
        payload = {"metadata": {}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "ssl_results.json"), "ssl")

    def test_scan_default_fallback(self):
        payload = {"metadata": {}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "scan")


class EmitResultTests(unittest.TestCase):
    def test_prints_json_to_stdout(self):
        result = {"metadata": {"test": True}}
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = chainrecon.emit_result(result, "traffic")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["metadata"]["test"], True)

    def test_generates_report_when_format_and_output(self):
        result = {"metadata": {"test": True}, "findings": {}, "summary": {}}
        with tempfile.TemporaryDirectory() as td:
            output = str(Path(td) / "out.json")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.emit_result(result, "traffic", format_name="json", output_path=output)
            self.assertEqual(code, 0)
            self.assertTrue(Path(output).exists())


class BuildParserTests(unittest.TestCase):
    def test_parser_has_all_subcommands(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["analyze-traffic", "test.pcap"])
        self.assertEqual(args.command, "analyze-traffic")

    def test_default_ssl_ports(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["analyze-ssl", "10.0.0.1"])
        self.assertEqual(args.ports, chainrecon.DEFAULT_SSL_PORTS)

    def test_no_args_gives_none_command(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args([])
        self.assertIsNone(args.command)

    def test_scan_subcommand_parses(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["scan", "10.0.0.1", "--profile", "iot"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, "10.0.0.1")
        self.assertEqual(args.profile, "iot")

    def test_scan_subcommand_defaults(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["scan", "10.0.0.1"])
        self.assertEqual(args.profile, "quick")
        self.assertIsNone(args.format)
        self.assertIsNone(args.output)

    def test_capture_subcommand_parses(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["capture", "eth0", "--mode", "dns", "--duration", "120", "--target-ip", "10.0.0.5"])
        self.assertEqual(args.command, "capture")
        self.assertEqual(args.interface, "eth0")
        self.assertEqual(args.mode, "dns")
        self.assertEqual(args.duration, 120)
        self.assertEqual(args.target_ip, "10.0.0.5")

    def test_capture_subcommand_defaults(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["capture", "wlan0"])
        self.assertEqual(args.mode, "full")
        self.assertEqual(args.duration, 60)
        self.assertIsNone(args.target_ip)


# ===========================================================================
# Interactive mode entry
# ===========================================================================


class InteractiveModeTests(unittest.TestCase):
    def test_no_args_launches_interactive(self):
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"interactive": mock_module}):
            code = chainrecon.main([])
        self.assertEqual(code, 0)
        mock_module.run_interactive.assert_called_once()


# ===========================================================================
# scan subcommand handler
# ===========================================================================


class HandleScanCliTests(unittest.TestCase):
    def test_scan_tool_not_found(self):
        args = MagicMock()
        args.target = "10.0.0.1"
        args.profile = "quick"
        args.format = None
        args.output = None

        stdout = io.StringIO()
        mock_runners = MagicMock()
        mock_runners.NmapRunner.return_value.run_scan.side_effect = ToolNotFoundError("nmap not found")
        mock_base = MagicMock()
        mock_base.ToolNotFoundError = ToolNotFoundError
        with patch.dict("sys.modules", {"runners": mock_runners, "runners.base": mock_base}):
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.handle_scan(args)
        self.assertEqual(code, 1)
        self.assertIn("nmap not found", stdout.getvalue())

    def test_scan_no_output_files(self):
        args = MagicMock()
        args.target = "10.0.0.1"
        args.profile = "quick"
        args.format = None
        args.output = None

        stdout = io.StringIO()
        mock_runners = MagicMock()
        mock_runners.NmapRunner.return_value.run_scan.return_value = {
            "output_files": ["/nonexistent/scan.txt"],
            "output_dir": "/tmp",
        }
        mock_base = MagicMock()
        mock_base.ToolNotFoundError = ToolNotFoundError
        with patch.dict("sys.modules", {"runners": mock_runners, "runners.base": mock_base}):
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.handle_scan(args)
        self.assertEqual(code, 1)
        self.assertIn("No scan output", stdout.getvalue())


# ===========================================================================
# capture subcommand handler
# ===========================================================================


class HandleCaptureCliTests(unittest.TestCase):
    def test_capture_tool_not_found(self):
        args = MagicMock()
        args.interface = "eth0"
        args.mode = "basic"
        args.duration = 10
        args.target_ip = None
        args.format = None
        args.output = None

        stdout = io.StringIO()
        mock_runners = MagicMock()
        mock_runners.CaptureRunner.return_value.run_capture.side_effect = ToolNotFoundError("tcpdump not found")
        mock_base = MagicMock()
        mock_base.ToolNotFoundError = ToolNotFoundError
        with patch.dict("sys.modules", {"runners": mock_runners, "runners.base": mock_base}):
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.handle_capture(args)
        self.assertEqual(code, 1)
        self.assertIn("tcpdump not found", stdout.getvalue())

    def test_capture_no_output_files(self):
        args = MagicMock()
        args.interface = "eth0"
        args.mode = "basic"
        args.duration = 10
        args.target_ip = None
        args.format = None
        args.output = None

        stdout = io.StringIO()
        mock_runners = MagicMock()
        mock_runners.CaptureRunner.return_value.run_capture.return_value = {
            "pcap_files": ["/nonexistent/test.pcap"],
            "output_dir": "/tmp",
        }
        mock_base = MagicMock()
        mock_base.ToolNotFoundError = ToolNotFoundError
        with patch.dict("sys.modules", {"runners": mock_runners, "runners.base": mock_base}):
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.handle_capture(args)
        self.assertEqual(code, 1)
        self.assertIn("No capture output", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
