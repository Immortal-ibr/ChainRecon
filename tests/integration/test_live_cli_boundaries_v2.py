"""Compatibility live CLI must use structured evidence and report failures."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import chainrecon
from chainrecon.runners.base import ToolNotFoundError
from chainrecon.runners.nmap_runner import NmapInterfaceMismatchError


def test_live_scan_uses_xml_and_ignores_text(tmp_path: Path, capsys) -> None:
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host></nmaprun>',
        encoding="utf-8",
    )
    text = tmp_path / "scan.txt"
    text.write_text("Nmap scan report for 203.0.113.9\n80/tcp open http\n", encoding="utf-8")
    with patch("chainrecon.runners.NmapRunner") as runner_type:
        runner_type.return_value.run_scan.return_value = {
            "target": "192.0.2.10", "profile": "quick", "output_files": [str(text), str(xml)]
        }
        assert chainrecon.main(["scan", "192.0.2.10"]) == 0
    output = capsys.readouterr().out
    assert output.startswith("{"), repr(output)
    result = json.loads(output)
    assert result["summary"]["host_count"] == 1
    assert result["findings"]["hosts"][0]["ip"] == "192.0.2.10"
    assert "203.0.113.9" not in json.dumps(result)


def test_live_scan_reports_missing_xml_and_route_mismatch(tmp_path: Path, capsys) -> None:
    text = tmp_path / "scan.txt"
    text.write_text("Nmap scan report for 192.0.2.10\n", encoding="utf-8")
    with patch("chainrecon.runners.NmapRunner") as runner_type:
        runner_type.return_value.run_scan.return_value = {
            "target": "192.0.2.10", "profile": "quick", "output_files": [str(text)]
        }
        assert chainrecon.main(["scan", "192.0.2.10"]) == 1
        assert "No scan output" in capsys.readouterr().out
        runner_type.return_value.run_scan.side_effect = NmapInterfaceMismatchError("wrong route", {})
        assert chainrecon.main(["scan", "192.0.2.10", "--interface", "test0"]) == 2
        assert "wrong route" in capsys.readouterr().out


def test_live_capture_reports_missing_tool_and_empty_result(capsys) -> None:
    with patch("chainrecon.runners.CaptureRunner") as runner_type:
        runner_type.return_value.run_capture.side_effect = ToolNotFoundError("tshark missing")
        assert chainrecon.main(["capture", "test0"]) == 1
        assert "tshark missing" in capsys.readouterr().out
        runner_type.return_value.run_capture.side_effect = None
        runner_type.return_value.run_capture.return_value = {"pcap_files": []}
        assert chainrecon.main(["capture", "test0"]) == 1
        assert "No capture output" in capsys.readouterr().out


def test_live_capture_analyzes_existing_pcap(tmp_path: Path, capsys) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap fixture")
    payload = {"metadata": {"source": str(pcap)}, "findings": {}, "summary": {"packet_count": 1}, "risk_indicators": []}
    with patch("chainrecon.runners.CaptureRunner") as runner_type, patch("chainrecon.TrafficAnalyzer") as analyzer_type:
        runner_type.return_value.run_capture.return_value = {"pcap_files": [str(pcap)]}
        analyzer_type.return_value.analyze_pcap.return_value = payload
        assert chainrecon.main(["capture", "test0", "--duration", "5"]) == 0
        analyzer_type.return_value.analyze_pcap.assert_called_once_with(str(pcap))
    assert json.loads(capsys.readouterr().out)["summary"]["packet_count"] == 1


def test_network_config_listing_and_save_are_explicit(capsys) -> None:
    with (
        patch("chainrecon.utils.network.list_interfaces", return_value=[{"name": "Lab", "device": "test0"}]),
        patch("chainrecon.utils.config.get_network_config", return_value={"target_ip": "192.0.2.10"}),
        patch("chainrecon.utils.config.save_network_config") as save,
        patch("chainrecon.utils.config.reset_config"),
    ):
        assert chainrecon.main(["network-config", "--list-interfaces"]) == 0
        assert "Lab" in capsys.readouterr().out
        assert chainrecon.main(["network-config", "--target-ip", "192.0.2.10"]) == 0
        assert json.loads(capsys.readouterr().out)["saved"] is True
        assert save.call_args.args[0]["target_ip"] == "192.0.2.10"


def test_network_config_show_and_apply_requires_both_adapters(capsys) -> None:
    with (
        patch("chainrecon.utils.config.get_network_config", return_value={"target_ip": "192.0.2.10"}),
        patch("chainrecon.utils.config.save_network_config"),
        patch("chainrecon.utils.config.reset_config"),
    ):
        assert chainrecon.main(["network-config"]) == 0
        assert json.loads(capsys.readouterr().out)["network_config"]["target_ip"] == "192.0.2.10"
        assert chainrecon.main(["network-config", "--target-ip", "192.0.2.10", "--apply"]) == 1
        assert "--eth and --internet are required" in capsys.readouterr().out


def test_scan_rejects_empty_xml_as_incomplete_result(tmp_path: Path, capsys) -> None:
    xml = tmp_path / "empty.xml"
    xml.touch()
    with patch("chainrecon.runners.NmapRunner") as runner_type:
        runner_type.return_value.run_scan.return_value = {
            "target": "192.0.2.10", "profile": "quick", "output_files": [str(xml)]
        }
        assert chainrecon.main(["scan", "192.0.2.10"]) == 1
    assert "No scan output" in capsys.readouterr().out


def test_explicit_tls_probe_composes_cert_cipher_and_capture_evidence(capsys) -> None:
    with patch("chainrecon.SSLAnalyzer") as analyzer_type:
        analyzer = analyzer_type.return_value
        analyzer.probe_certificates.return_value = {
            "findings": {"certificates": [{"port": 443, "target_resolved": True, "tcp_reachable": True, "tls_reachable": True, "certificate_observed": True}]},
            "summary": {"certificate_count": 1},
        }
        analyzer.analyze_ciphers.return_value = {
            "findings": {"cipher_analysis": [{"port": 443, "cipher": "TLS_AES_128_GCM_SHA256"}]},
            "summary": {"weak_cipher_count": 0},
        }
        analyzer.assess_tls_security.return_value = {
            "findings": {"security_findings": []}, "summary": {"risk_rating": "low"}, "risk_indicators": []
        }
        analyzer.compute_ja3.return_value = {"findings": {"ja3": [{"hash": "known-fixture"}]}}
        assert chainrecon.main(["analyze-ssl", "192.0.2.10", "--ports", "443", "8443", "--pcap", "capture.pcap"]) == 0
        analyzer.probe_certificates.assert_called_once_with("192.0.2.10", [443, 8443])
        analyzer.compute_ja3.assert_called_once_with("capture.pcap")
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["certificate_observed_count"] == 1
    assert payload["findings"]["ja3"][0]["hash"] == "known-fixture"
