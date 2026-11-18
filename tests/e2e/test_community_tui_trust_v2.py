"""Community plugin validation must not import code; execution requires trust."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from textual.widgets import Button, Checkbox, Select

from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.pasteable_input import PasteableInput as Input
from chainrecon.utils.community_plugins import discover_community_plugins, load_community_plugin


def test_community_plugin_requires_explicit_trust(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "probe"
    plugin_dir.mkdir()
    marker = tmp_path / "executed.txt"
    (plugin_dir / "plugin.yaml").write_text(
        "name: probe\nversion: 1.0.0\ntype: analyzer\nentrypoint: plugin.py:Probe\n"
        "inputs: [input_path]\noutputs: [count]\ndescription: Local trust fixture\n",
        encoding="utf-8",
    )
    (plugin_dir / "plugin.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "class Probe:\n"
        "    def analyze(self, **kwargs):\n"
        "        return {'metadata': {}, 'summary': {'count': 1}, 'findings': {'token': 'do-not-export'}, 'risk_indicators': []}\n",
        encoding="utf-8",
    )
    with pytest.raises(PermissionError):
        load_community_plugin("probe", base_dir=tmp_path)
    assert not marker.exists()

    async def exercise() -> None:
        with patch(
            "chainrecon.utils.community_plugins.discover_community_plugins",
            side_effect=lambda *args, **kwargs: discover_community_plugins(base_dir=tmp_path),
        ), patch("chainrecon.utils.config.get_output_dir", return_value=tmp_path):
            app = ChainReconApp()
            async with app.run_test(size=(110, 34)) as pilot:
                await pilot.pause()
                app.push_screen("plugins")
                await pilot.pause()
                app.screen._refresh_plugins()
                app.screen.query_one("#validate-plugins", Button).press()
                await pilot.pause()
                assert not marker.exists()
                app.screen.query_one("#plugin-select", Select).value = "probe"
                app.screen.query_one("#plugin-input", Input).value = str(tmp_path)
                app.screen.query_one("#plugin-output-dir", Input).value = str(tmp_path)
                app.screen.query_one("#run-plugin", Button).press()
                await pilot.pause()
                assert not marker.exists()
                app.screen.query_one("#plugin-trusted", Checkbox).value = True
                app.screen.query_one("#run-plugin", Button).press()
                for _ in range(300):
                    if marker.exists() and list(tmp_path.glob("*community_probe*.json")):
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("Trusted plugin did not complete")

    asyncio.run(exercise())
    report_path = next(tmp_path.glob("*community_probe*.json"))
    result = json.loads(report_path.read_text(encoding="utf-8"))
    assert result["summary"]["count"] == 1
    assert result["findings"]["token"] == "[REDACTED]"


def test_plugin_entrypoint_cannot_leave_its_directory(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "probe"
    plugin_dir.mkdir()
    (tmp_path / "escaped.py").write_text("class Probe: pass\n", encoding="utf-8")
    (plugin_dir / "plugin.yaml").write_text(
        "name: probe\nversion: 1.0.0\ntype: analyzer\nentrypoint: ../escaped.py:Probe\n"
        "inputs: []\noutputs: []\ndescription: Traversal fixture\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="inside its plugin directory"):
        load_community_plugin("probe", base_dir=tmp_path, trusted=True)
