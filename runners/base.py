"""Shared utilities for subprocess-based tool runners."""

from __future__ import annotations

import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not installed."""


def check_tool(name: str) -> str:
    """Return the full path to a tool, or raise ToolNotFoundError."""
    path = shutil.which(name)
    if path is None:
        raise ToolNotFoundError(f"'{name}' not found on PATH. Install it before using this feature.")
    return path


def make_output_dir(base: str = ".") -> Path:
    """Create and return a timestamped output directory."""
    dirname = f"iot_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    path = Path(base) / dirname
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_subprocess(cmd: list, timeout: Optional[int] = None, **kwargs) -> subprocess.CompletedProcess:
    """Run a command as a subprocess with standardized defaults."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, timeout=timeout, **kwargs)


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_windows() -> bool:
    return platform.system() == "Windows"
