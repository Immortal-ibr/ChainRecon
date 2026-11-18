"""JADX output draining preserves a real process deadline."""

import io
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from chainrecon.analysis.apk_analyzer import APKAnalyzer


class _FakeProcess:
    def __init__(self, output: str, *, times_out: bool = False) -> None:
        self.stdout = io.StringIO(output)
        self.times_out = times_out
        self.killed = False

    def wait(self, timeout=None) -> int:
        if self.times_out and timeout is not None:
            raise subprocess.TimeoutExpired("jadx", timeout)
        return -9 if self.killed else 0

    def kill(self) -> None:
        self.killed = True


def test_jadx_timeout_kills_stalled_process(tmp_path: Path) -> None:
    fake_exe = tmp_path / "jadx"
    fake_exe.touch()
    process = _FakeProcess("", times_out=True)
    with patch("subprocess.Popen", return_value=process):
        with pytest.raises(RuntimeError, match="600-second analysis limit"):
            APKAnalyzer(jadx_path=str(fake_exe))._decompile("sample.apk", str(tmp_path / "output"))
    assert process.killed


def test_jadx_progress_and_error_count_are_drained(tmp_path: Path) -> None:
    fake_exe = tmp_path / "jadx"
    fake_exe.touch()
    process = _FakeProcess("ERROR in com.example.Bad\nfinished with errors, count: 1\n")
    progress: list[str] = []
    with patch("subprocess.Popen", return_value=process):
        result = APKAnalyzer(jadx_path=str(fake_exe))._decompile(
            "sample.apk", str(tmp_path / "output"), progress_cb=progress.append,
        )
    assert result["jadx_error_count"] == 1
    assert result["jadx_error_classes"] == ["com.example.Bad"]
    assert len(progress) == 2
