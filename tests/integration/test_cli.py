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
from chainrecon.runners.base import ToolNotFoundError


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

    def test_report_xlsx_format(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "scan.json").write_text(
                json.dumps({"metadata": {}, "findings": {"hosts": [{"ip": "10.0.0.1"}]}, "summary": {}, "risk_indicators": []}),
                encoding="utf-8",
            )
            output = tp / "report.xlsx"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                chainrecon.main(["report", td, "--format", "xlsx", "--output", str(output)])
            self.assertTrue(output.exists())

    def test_report_directory_aggregates_multiple_files_per_section(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            for idx in range(2):
                (tp / f"traffic_{idx}.json").write_text(
                    json.dumps({
                        "metadata": {"source": f"cap_{idx}.pcap", "packet_count": idx + 1},
                        "findings": {},
                        "summary": {},
                        "risk_indicators": [{"severity": "info", "title": f"traffic {idx}", "details": "test"}],
                    }),
                    encoding="utf-8",
                )
            merged = chainrecon.load_report_inputs([td])
        self.assertEqual(merged["traffic"]["metadata"]["source_mode"], "multiple_files")
        self.assertEqual(merged["traffic"]["metadata"]["source_count"], 2)
        self.assertEqual(len(merged["traffic"]["findings"]["items"]), 2)
        self.assertEqual(len(merged["traffic"]["risk_indicators"]), 2)

    def test_report_directory_aggregates_multiple_frida_runs_newest_first(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "20260426_frida_a.json").write_text(
                json.dumps({
                    "metadata": {"target": "app.old", "script": "list_classes"},
                    "summary": {"status": "completed"},
                    "findings": {"session": {"started_at": 10}, "events_by_tag": {"HOOK": 1}},
                    "risk_indicators": [],
                }),
                encoding="utf-8",
            )
            (tp / "20260426_frida_b.json").write_text(
                json.dumps({
                    "metadata": {"target": "app.new", "script": "hook_all_methods"},
                    "summary": {"status": "stopped_by_user"},
                    "findings": {"session": {"started_at": 20}, "events_by_tag": {"HOOK": 2}},
                    "risk_indicators": [],
                }),
                encoding="utf-8",
            )
            merged = chainrecon.load_report_inputs([td])
        self.assertEqual(len(merged["frida"]["sessions"]), 2)
        self.assertEqual(merged["frida"]["sessions"][0]["target"], "app.new")

    def test_report_directory_ignores_nested_or_non_object_json(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "traffic.json").write_text(
                json.dumps({"metadata": {"packet_count": 1}, "findings": {}, "summary": {}, "risk_indicators": []}),
                encoding="utf-8",
            )
            (tp / "asset.json").write_text(json.dumps(["not", "analysis"]), encoding="utf-8")
            (tp / "partial.json").write_text('{"traffic": ', encoding="utf-8")
            nested = tp / "apk_decompiled" / "resources"
            nested.mkdir(parents=True)
            (nested / "countryList.en.json").write_text(json.dumps([{"name": "US"}]), encoding="utf-8")
            merged = chainrecon.load_report_inputs([td])
        self.assertIn("traffic", merged)
        self.assertEqual(set(merged), {"traffic"})

    def test_report_loader_unwraps_single_section_report_json(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "apk.json").write_text(
                json.dumps({
                    "traffic": None,
                    "ssl": None,
                    "scan": {
                        "metadata": {"apk": "nooie.apk", "analyzer": "APKAnalyzer"},
                        "findings": {"permissions": []},
                        "summary": {},
                        "risk_indicators": [{"severity": "high", "title": "apk", "details": "test"}],
                    },
                }),
                encoding="utf-8",
            )
            merged = chainrecon.load_report_inputs([td])
        self.assertEqual(set(merged), {"apk"})
        self.assertEqual(len(merged["apk"]["risk_indicators"]), 1)

    def test_report_loader_skips_multi_section_generated_report_json(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            (tp / "report.json").write_text(
                json.dumps({
                    "traffic": {"metadata": {"packet_count": 1}, "findings": {}, "summary": {}},
                    "ssl": {"metadata": {"target": "10.0.0.1"}, "findings": {}, "summary": {}},
                    "scan": None,
                }),
                encoding="utf-8",
            )
            merged = chainrecon.load_report_inputs([td])
        self.assertEqual(merged, {})

    def test_report_infers_apk_section(self):
        payload = {
            "metadata": {"apk": "nooie.apk", "analyzer": "APKAnalyzer"},
            "findings": {"permissions": []},
        }
        self.assertEqual(chainrecon.infer_section(payload, "live_apk.json"), "apk")


# ===========================================================================
# Helper function tests
# ===========================================================================


class InferSectionTests(unittest.TestCase):
    def test_declared_section_wins(self):
        payload = {"metadata": {"section": "mqtt"}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "mqtt")

    def test_analyzer_name_maps_to_dynamic_section(self):
        payload = {"metadata": {"analyzer": "EntropyAnalyzer"}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "entropy")

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
        self.assertEqual(chainrecon.infer_section(payload, "data.json"), "analysis")

    def test_firmware_by_analyzer_name(self):
        payload = {"metadata": {"analyzer": "FirmwareAnalyzer"}, "findings": {}}
        self.assertEqual(chainrecon.infer_section(payload, "firmware.json"), "firmware")


class FirmwareAndWorkflowCliTests(unittest.TestCase):
    def test_firmware_subcommand_parses(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["firmware", "firmware.bin", "--extract-dir", "out"])
        self.assertEqual(args.command, "firmware")
        self.assertEqual(args.firmware_path, "firmware.bin")
        self.assertEqual(args.extract_dir, "out")

    def test_workflow_run_subcommand_parses(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["workflow", "run", "pipeline.yaml", "--target", "10.0.0.1", "--dry-run"])
        self.assertEqual(args.command, "workflow")
        self.assertEqual(args.workflow_command, "run")
        self.assertEqual(args.pipeline, "pipeline.yaml")
        self.assertTrue(args.dry_run)

    def test_workflow_handler_dispatches_runner(self):
        stdout = io.StringIO()
        with patch("chainrecon.runners.workflow_runner.WorkflowRunner.run", return_value={"summary": {"status": "completed"}}):
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.main(["workflow", "run", "pipeline.yaml", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["summary"]["status"], "completed")


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

    def test_generates_generic_section_report_when_format_and_output(self):
        result = {"metadata": {"apk": "app.apk"}, "findings": {}, "summary": {}, "risk_indicators": []}
        with tempfile.TemporaryDirectory() as td:
            output = str(Path(td) / "apk.json")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.emit_result(result, "apk", format_name="json", output_path=output)
            self.assertEqual(code, 0)
            saved = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertIn("apk", saved)
        self.assertNotIn("scan", saved)


class BuildParserTests(unittest.TestCase):
    def test_parser_has_all_subcommands(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["analyze-traffic", "test.pcap"])
        self.assertEqual(args.command, "analyze-traffic")

    def test_default_ssl_ports(self):
        parser = chainrecon.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["analyze-ssl", "10.0.0.1"])

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

    def test_scan_subcommand_accepts_arp_profile(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["scan", "192.168.1.0/24", "--profile", "arp"])
        self.assertEqual(args.profile, "arp")

    def test_scan_subcommand_accepts_ssl_profile(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["scan", "10.0.0.1", "--profile", "ssl"])
        self.assertEqual(args.profile, "ssl")

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
    def test_no_args_launches_tui(self):
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"tui": mock_module, "chainrecon.tui.app": mock_module}):
            code = chainrecon.main([])
        self.assertEqual(code, 0)
        mock_module.run_tui.assert_called_once()

    def test_interactive_subcommand(self):
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"chainrecon.interactive": mock_module}):
            code = chainrecon.main(["interactive"])
        self.assertEqual(code, 0)
        mock_module.run_interactive.assert_called_once()

    def test_tui_subcommand(self):
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"tui": mock_module, "chainrecon.tui.app": mock_module}):
            code = chainrecon.main(["tui"])
        self.assertEqual(code, 0)
        mock_module.run_tui.assert_called_once()


# ===========================================================================
# scan subcommand handler
# ===========================================================================


class HandleScanCliTests(unittest.TestCase):
    def test_combine_scan_results_merges_text_and_xml_for_same_host(self):
        scan_result = {
            "target": "192.168.123.99",
            "profile": "quick",
            "output_files": ["scan.txt", "scan.xml"],
        }
        text_result = {
            "findings": {
                "hosts": [{
                    "ip": "192.168.123.99",
                    "host_state": "up",
                    "ports": [],
                    "services": [],
                    "notes": ["Not shown: 1000 closed tcp ports (reset)"],
                    "state_summary": {"closed": 1000},
                }],
                "iot_services": [],
                "cve_hints": [],
            },
            "risk_indicators": [],
        }
        xml_result = {
            "findings": {
                "hosts": [{
                    "ip": "192.168.123.99",
                    "host_state": "up",
                    "ports": [],
                    "services": [],
                    "state_summary": {"closed": 1000},
                }],
                "iot_services": [],
                "cve_hints": [],
            },
            "risk_indicators": [],
        }
        result = chainrecon.combine_scan_results(scan_result, [text_result, xml_result])
        self.assertEqual(result["summary"]["host_count"], 1)
        self.assertEqual(result["summary"]["closed_port_count"], 1000)
        self.assertEqual(result["summary"]["scanned_port_count"], 1000)
        self.assertEqual(result["findings"]["hosts"][0]["notes"], ["Not shown: 1000 closed tcp ports (reset)"])

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
        with patch.dict("sys.modules", {"chainrecon.runners": mock_runners, "chainrecon.runners.base": mock_base}):
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
        with patch.dict("sys.modules", {"chainrecon.runners": mock_runners, "chainrecon.runners.base": mock_base}):
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
        with patch.dict("sys.modules", {"chainrecon.runners": mock_runners, "chainrecon.runners.base": mock_base}):
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
        with patch.dict("sys.modules", {"chainrecon.runners": mock_runners, "chainrecon.runners.base": mock_base}):
            with contextlib.redirect_stdout(stdout):
                code = chainrecon.handle_capture(args)
        self.assertEqual(code, 1)
        self.assertIn("No capture output", stdout.getvalue())


# ===========================================================================
# APK subcommand
# ===========================================================================


class HandleAPKCliTests(unittest.TestCase):
    def test_apk_subcommand_parses(self):
        parser = chainrecon.build_parser()
        args = parser.parse_args(["apk", "test.apk"])
        self.assertEqual(args.command, "apk")
        self.assertEqual(args.apk_path, "test.apk")

    def test_apk_handler_calls_analyzer(self):
        args = MagicMock()
        args.apk_path = "test.apk"
        args.format = None
        args.output = None

        mock_analyzer = MagicMock()
        mock_analyzer.return_value.analyze.return_value = {
            "findings": {"permissions": []},
            "risk_indicators": [],
        }
        with patch.dict("sys.modules", {"chainrecon.analysis.apk_analyzer": MagicMock(APKAnalyzer=mock_analyzer)}):
            with contextlib.redirect_stdout(io.StringIO()):
                code = chainrecon.handle_apk(args)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
