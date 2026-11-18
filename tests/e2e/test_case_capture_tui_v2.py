"""Run a mocked capture through the case-bound TUI without a network device."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from textual.widgets import Button

from chainrecon.case_model import Case
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.log_viewer import LogViewer
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input


def test_capture_screen_imports_pcap_into_open_case(tmp_path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    pcap = tmp_path / "capture.pcap"
    scapy.wrpcap(str(pcap), [scapy.Ether() / scapy.IP(src="192.0.2.10", dst="192.0.2.20") / scapy.TCP(sport=40001, dport=80)])
    case = Case.create(tmp_path / "case", "Capture case")

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.capture.list_interfaces", return_value=[{"name": "Test", "device": "test0"}]),
            patch("chainrecon.tui.screens.capture.CaptureRunner") as runner_type,
        ):
            runner_type.return_value.run_capture.return_value = {"pcap_files": [str(pcap)]}
            app = ChainReconApp(case_path=str(case.root))
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("capture")
                await pilot.pause()
                app.screen.query_one("#btn-capture", Button).press()
                log = app.screen.query_one("#capture-log", LogViewer)
                for _ in range(750):
                    if len(Case.open(case.root).manifest["runs"]) == 1 and "Capture complete" in log._plain_text():
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("Capture TUI did not record a case run")
                runner_type.return_value.run_capture.assert_called_once()

    asyncio.run(exercise())
    reopened = Case.open(case.root)
    assert len(reopened.manifest["evidence"]) == 1
    assert next(iter(reopened.iter_runs()))["analyzer"] == "traffic"


def test_capture_custom_script_keeps_pcap_path_with_spaces(tmp_path: Path) -> None:
    pcap = tmp_path / "packet capture.pcap"
    pcap.write_bytes(b"fixture")
    script = tmp_path / "my script.py"
    script.write_text("print('unused')\n", encoding="utf-8")

    async def exercise() -> None:
        with (
            patch("chainrecon.tui.screens.capture.list_interfaces", return_value=[{"name": "Test", "device": "test0"}]),
            patch("chainrecon.tui.screens.capture.CaptureRunner") as runner_type,
            patch("chainrecon.tui.screens.capture.get_network_config", return_value={"target_ip": "192.0.2.10"}),
            patch("chainrecon.utils.config.get_output_dir", return_value=tmp_path),
            patch("chainrecon.tui.screens.capture.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "complete", "")) as execute,
        ):
            runner_type.return_value.run_capture.return_value = {"pcap_files": [str(pcap)]}
            app = ChainReconApp()
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("capture")
                await pilot.pause()
                app.screen.query_one("#custom-path", Input).value = str(script)
                app.screen.query_one("#btn-capture", Button).press()
                for _ in range(500):
                    if list(tmp_path.glob("*custom_capture*.json")):
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("Custom capture script did not finish")
                assert execute.call_args.args[0][-2:] == ["192.0.2.10", str(pcap)]

    asyncio.run(exercise())
    artifact = json.loads(next(tmp_path.glob("*custom_capture*.json")).read_text(encoding="utf-8"))
    assert artifact["args"] == ["192.0.2.10", str(pcap)]
