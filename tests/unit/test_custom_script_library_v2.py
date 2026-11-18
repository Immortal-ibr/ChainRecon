"""Personal script entries stay local and do not multiply on repeated saves."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from chainrecon.utils import custom_scripts


def test_script_library_is_local_and_deduplicates_per_screen(tmp_path: Path) -> None:
    library = tmp_path / "settings" / "custom_scripts.yaml"
    with patch.object(custom_scripts, "_LIBRARY_FILE", library):
        assert custom_scripts.load_library() == []
        custom_scripts.save_to_library("scan", str(tmp_path / "my script.py"), "python")
        custom_scripts.save_to_library("scan", str(tmp_path / "my script.py"), "bash", label="duplicate")
        custom_scripts.save_to_library("capture", str(tmp_path / "my script.py"), "python", label="Capture helper")
        entries = custom_scripts.load_library()
    assert library.is_file()
    assert len(entries) == 2
    assert entries[0]["label"] == "my script"
    assert entries[0]["interp"] == "python"
    assert entries[1]["label"] == "Capture helper"


def test_script_library_returns_empty_for_invalid_or_nonlist_yaml(tmp_path: Path) -> None:
    library = tmp_path / "custom_scripts.yaml"
    with patch.object(custom_scripts, "_LIBRARY_FILE", library):
        library.write_text("not: a list\n", encoding="utf-8")
        assert custom_scripts.load_library() == []
        library.write_text("[unterminated\n", encoding="utf-8")
        assert custom_scripts.load_library() == []
