"""The TUI home stays focused while all specialist paths remain reachable."""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, Collapsible, Select, Static

from chainrecon.case_model import Case
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.screens.analyze import AnalyzeScreen
from chainrecon.tui.screens.apk import APKScreen
from chainrecon.tui.screens.case import CaseScreen
from chainrecon.tui.screens.case_analysis import CaseAnalysisScreen
from chainrecon.tui.screens.case_picker import CasePickerScreen
from chainrecon.tui.screens.dashboard import DashboardScreen
from chainrecon.tui.screens.reports import ReportsScreen
from chainrecon.tui.screens.settings import SettingsScreen
from chainrecon.utils.config import reset_config


async def _until_screen(app: ChainReconApp, screen_type: type) -> None:
    for _ in range(100):
        if isinstance(app.screen, screen_type):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"Did not open {screen_type.__name__}")


def test_home_has_one_investigation_route_and_progressive_tools(tmp_path: Path, monkeypatch) -> None:
    case = Case.create(tmp_path / "case", "Focused investigation")
    image = tmp_path / "image.bin"
    image.write_bytes(b"fixture")
    evidence = case.add_evidence(image, kind="firmware")
    config = tmp_path / "chainrecon.yaml"
    config.write_text(f"case:\n  directory: '{case.root.as_posix()}'\n", encoding="utf-8")
    monkeypatch.setenv("CHAINRECON_CONFIG_FILE", str(config))
    reset_config()

    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            assert "firmware" not in app.SCREENS
            assert "m" not in {binding.key for binding in DashboardScreen.BINDINGS}
            assert app.screen.query_one("#more-tools", Collapsible).collapsed
            reports = app.screen.query_one("#home-reports", Button).region
            assert reports.y + reports.height <= app.size.height - 1
            app.screen.query_one("#home-case", Button).press()
            await pilot.pause()
            assert isinstance(app.screen, CaseScreen)
            for _ in range(100):
                selects = list(app.screen.query("#evidence-select"))
                if selects and selects[0].value == evidence.id:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("Investigation did not show the imported evidence")
            assert app.screen.query_one("#evidence-select", Select).value == evidence.id
            analyze = app.screen.query_one("#case-open-analysis", Button).region
            assert analyze.y + analyze.height <= app.size.height - 1
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            app.screen.query_one("#home-firmware", Button).press()
            await pilot.pause()
            assert isinstance(app.screen, CaseAnalysisScreen)
            assert app.screen._view == "firmware"
            for _ in range(100):
                if app.screen.query_one("#analysis-evidence", Select).value == evidence.id:
                    break
                await asyncio.sleep(0.02)
            assert app.screen.query_one("#analysis-evidence", Select).value == evidence.id
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            app.screen.query_one("#more-tools", Collapsible).collapsed = False
            app.screen.query_one("#home-settings", Button).press()
            await pilot.pause()
            assert isinstance(app.screen, SettingsScreen)

    asyncio.run(exercise())
    reset_config()


def test_case_analysis_follows_evidence_kind(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    image = tmp_path / "image.bin"
    image.write_bytes(b"firmware")
    firmware = case.add_evidence(image, kind="firmware")
    log = tmp_path / "boot.log"
    log.write_text("boot complete", encoding="utf-8")
    uart = case.add_evidence(log, kind="uart_log")

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, CaseScreen)
            screen.query_one("#case-open-analysis", Button).press()
            await pilot.pause()
            analysis = app.screen
            assert isinstance(analysis, CaseAnalysisScreen)
            select = analysis.query_one("#analysis-evidence", Select)
            for _ in range(100):
                if select.value == uart.id:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("Analysis did not select the latest evidence")
            await pilot.pause()
            assert analysis.query_one("#analysis-run", Button).disabled
            assert not analysis.query_one("#analysis-firmware-options", Collapsible).display
            select.value = firmware.id
            for _ in range(100):
                if not analysis.query_one("#analysis-run", Button).disabled:
                    break
                await asyncio.sleep(0.02)
            assert not analysis.query_one("#analysis-run", Button).disabled
            assert analysis.query_one("#analysis-firmware-options", Collapsible).display
            assert analysis.query_one("#analysis-firmware-options", Collapsible).collapsed

    asyncio.run(exercise())


def test_analysis_types_and_reports_are_visible_on_home() -> None:
    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            for button_id in ("home-firmware", "home-packets", "home-android", "home-nmap", "home-frida-log", "home-reports"):
                region = app.screen.query_one(f"#{button_id}", Button).region
                assert region.y + region.height <= app.size.height - 1
            app.screen.query_one("#home-packets", Button).press()
            await _until_screen(app, CaseAnalysisScreen)
            await pilot.pause()
            assert app.screen._view == "packets"
            app.screen.query_one("#analysis-packet-tools", Button).press()
            await _until_screen(app, AnalyzeScreen)
            await pilot.pause()
            assert isinstance(app.screen, AnalyzeScreen)
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            app.screen.query_one("#home-android", Button).press()
            await _until_screen(app, CaseAnalysisScreen)
            await pilot.pause()
            assert app.screen._view == "apk"
            app.screen.query_one("#analysis-apk-tools", Button).press()
            await _until_screen(app, APKScreen)
            await pilot.pause()
            assert isinstance(app.screen, APKScreen)
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            app.screen.query_one("#home-reports", Button).press()
            await _until_screen(app, ReportsScreen)
            await pilot.pause()
            assert isinstance(app.screen, ReportsScreen)
            export_action = app.screen.query_one("#btn-gen", Button).region
            assert export_action.y + export_action.height <= app.size.height - 1

    asyncio.run(exercise())


def test_home_analysis_choices_select_only_matching_imported_files(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "investigation", "Typed analysis")
    sources = (
        ("firmware.img", "firmware", b"opaque firmware", "home-firmware", "firmware"),
        ("traffic.pcap", "pcap", b"pcap fixture", "home-packets", "packets"),
        ("app.apk", "apk", b"apk fixture", "home-android", "apk"),
        ("scan.xml", "scan_xml", b"<nmaprun></nmaprun>", "home-nmap", "scan"),
        ("events.log", "frida_log", b'{"tag":"test","message":"event"}\n', "home-frida-log", "frida"),
    )
    expected: list[tuple[str, str, str]] = []
    for name, kind, content, button, view in sources:
        path = tmp_path / name
        path.write_bytes(content)
        expected.append((button, view, case.add_evidence(path, kind=kind).id))

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(case.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            for button_id, view, evidence_id in expected:
                assert isinstance(app.screen, DashboardScreen)
                app.screen.query_one(f"#{button_id}", Button).press()
                await _until_screen(app, CaseAnalysisScreen)
                await pilot.pause()
                assert app.screen._view == view
                assert app.screen.query_one("#analysis-evidence", Select).value == evidence_id
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(exercise())


def test_missing_analysis_type_guides_import_and_home_switch_changes_report_source(tmp_path: Path) -> None:
    first = Case.create(tmp_path / "first", "First investigation")
    second = Case.create(tmp_path / "second", "Second investigation")
    firmware_path = tmp_path / "firmware.img"
    firmware_path.write_bytes(b"opaque firmware")
    first.add_evidence(firmware_path, kind="firmware")

    async def exercise() -> None:
        app = ChainReconApp(case_path=str(first.root))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            app.screen.query_one("#home-android", Button).press()
            await _until_screen(app, CaseAnalysisScreen)
            await pilot.pause()
            assert app.screen.query_one("#analysis-evidence", Select).value == Select.NULL
            assert app.screen.query_one("#analysis-run", Button).disabled
            assert "No android application packages" in str(app.screen.query_one("#analysis-evidence-detail", Static).render())
            app.screen.query_one("#analysis-manage-evidence", Button).press()
            await _until_screen(app, CaseScreen)
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)

            app.screen.query_one("#home-switch", Button).press()
            await _until_screen(app, CasePickerScreen)
            await pilot.pause()
            app.screen.query_one("#folder-path").value = str(second.root)
            app.screen.action_open_case()
            await _until_screen(app, DashboardScreen)
            await pilot.pause()
            assert app._case_path == str(second.root)
            app.screen.query_one("#home-reports", Button).press()
            await _until_screen(app, ReportsScreen)
            await pilot.pause()
            assert app.screen.query_one("#source-mode", Select).value == "investigation"
            assert "Second investigation" in str(app.screen.query_one("#report-source-detail", Static).render())

    asyncio.run(exercise())


def test_live_actions_fit_a_small_terminal() -> None:
    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            for route, button_id in (
                ("scan", "btn-scan"),
                ("capture", "btn-capture"),
                ("frida", "btn-run"),
            ):
                app.push_screen(route)
                await pilot.pause()
                region = app.screen.query_one(f"#{button_id}", Button).region
                assert region.y + region.height <= app.size.height - 1, route
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(exercise())


def test_settings_summary_does_not_render_secret_values(tmp_path: Path, monkeypatch) -> None:
    secret = "unit-test-secret-should-not-appear"
    config = tmp_path / "private.yaml"
    config.write_text(f"api_keys:\n  shodan: {secret}\n", encoding="utf-8")
    monkeypatch.setenv("CHAINRECON_CONFIG_FILE", str(config))
    reset_config()

    async def exercise() -> None:
        app = ChainReconApp()
        async with app.run_test(size=(80, 24)) as pilot:
            app.push_screen("settings")
            await pilot.pause()
            assert isinstance(app.screen, SettingsScreen)
            assert secret not in app.export_screenshot()

    asyncio.run(exercise())
    reset_config()


def test_tui_entrypoint_preserves_dashboard_for_configured_default(monkeypatch) -> None:
    from chainrecon.tui import app as tui_app

    started: list[str | None] = []

    class FakeApp:
        def __init__(self, case_path: str | None = None) -> None:
            started.append(case_path)

        def run(self) -> None:
            pass

    monkeypatch.setattr(tui_app, "ChainReconApp", FakeApp)
    monkeypatch.setattr(tui_app, "disable_terminal_mouse_reporting", lambda: None)
    monkeypatch.setattr("signal.signal", lambda *_: None)
    monkeypatch.setattr("os.system", lambda _: 0)
    tui_app.run_tui()
    assert started == [None]
