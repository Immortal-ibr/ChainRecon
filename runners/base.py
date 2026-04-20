"""Shared utilities for subprocess-based tool runners."""

from __future__ import annotations

import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logging_config import get_logger
from utils.platform_info import find_tool as _find_tool

logger = get_logger("runners")


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not installed."""


def check_tool(name: str) -> str:
    """Return the full path to a tool, or raise ToolNotFoundError.

    Uses platform-aware search that checks well-known install directories
    on Windows (Nmap, Wireshark, Android SDK, etc.).
    """
    path = _find_tool(name)
    if path is None:
        logger.warning("Tool '%s' not found on PATH", name)
        raise ToolNotFoundError(f"'{name}' not found on PATH. Install it before using this feature.")
    logger.debug("Tool '%s' resolved to %s", name, path)
    return path


def make_output_dir(base: Optional[str] = None) -> Path:
    """Create and return a timestamped output subdirectory.

    If *base* is None, uses the configured output directory from config.
    Otherwise creates a timestamped subdir under *base*.
    """
    if base is None:
        try:
            from utils.config import get_output_dir
            base_path = get_output_dir()
        except Exception:
            base_path = Path("output")
            base_path.mkdir(exist_ok=True)
    else:
        base_path = Path(base)
        base_path.mkdir(parents=True, exist_ok=True)

    dirname = f"iot_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    path = base_path / dirname
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_subprocess(cmd: list, timeout: Optional[int] = None, **kwargs) -> subprocess.CompletedProcess:
    """Run a command as a subprocess with standardized defaults."""
    logger.debug("Running: %s (timeout=%s)", " ".join(str(c) for c in cmd), timeout)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    # Explicitly set UTF-8 with replacement for undecodable bytes so that
    # tools like jadx (which may emit progress bars with non-ASCII chars)
    # don't raise UnicodeDecodeError on Windows where the default encoding
    # is the system locale (cp1252 / cp850).
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    return subprocess.run(cmd, timeout=timeout, **kwargs)


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_windows() -> bool:
    return platform.system() == "Windows"
