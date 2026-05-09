"""Cross-platform tool detection and path resolution for ChainRecon."""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Dict, List, Optional


def get_os() -> str:
    """Return normalized OS name: 'windows', 'linux', or 'darwin'."""
    return platform.system().lower()


def is_windows() -> bool:
    return get_os() == "windows"


def is_linux() -> bool:
    return get_os() == "linux"


def is_mac() -> bool:
    return get_os() == "darwin"


# -- Tool resolution ------------------------------------------------------

# Common Windows installation paths for security tools
_WINDOWS_SEARCH_PATHS: Dict[str, List[str]] = {
    "nmap": [
        r"C:\Program Files (x86)\Nmap",
        r"C:\Program Files\Nmap",
    ],
    "tshark": [
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark",
    ],
    "tcpdump": [
        r"C:\Program Files\Wireshark",  # WinDump sometimes bundled
    ],
    "adb": [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools"),
        r"C:\Android\platform-tools",
    ],
    "emulator": [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\emulator"),
        r"C:\Android\emulator",
    ],
    "sdkmanager": [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest\bin"),
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\tools\bin"),
    ],
    "avdmanager": [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest\bin"),
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\tools\bin"),
    ],
    "jadx": [
        r"C:\jadx\bin",
        r"C:\Program Files\jadx\bin",
        os.path.expandvars(r"%USERPROFILE%\jadx\bin"),
    ],
    "apktool": [
        r"C:\apktool",
        r"C:\Program Files\apktool",
        os.path.expandvars(r"%USERPROFILE%\apktool"),
    ],
}


def _candidate_binaries(name: str) -> List[str]:
    """Return executable filename candidates for a tool on the current OS."""
    candidates = [name]
    if is_windows():
        suffixes = [".exe", ".bat", ".cmd"]
        for suffix in suffixes:
            if not name.lower().endswith(suffix):
                candidates.append(name + suffix)
    return candidates


def find_tool(name: str, extra_paths: Optional[List[str]] = None) -> Optional[str]:
    """Locate a tool binary, checking config first, then PATH, then well-known dirs.

    Returns the full path or None if not found.
    """
    # 0. Check config file for an explicit user-configured path
    try:
        from chainrecon.utils.config import get_tool_path
        cfg_path = get_tool_path(name)
        if cfg_path:
            p = Path(cfg_path)
            if p.exists():
                return str(p)
    except Exception:
        pass

    # 1. Check PATH
    for candidate in _candidate_binaries(name):
        found = shutil.which(candidate)
        if found:
            return found

    # 3. Check well-known installation directories
    search_dirs = list(extra_paths or [])
    if is_windows():
        search_dirs.extend(_WINDOWS_SEARCH_PATHS.get(name, []))

    for directory in search_dirs:
        directory = os.path.expandvars(directory)
        if not os.path.isdir(directory):
            continue
        for candidate in _candidate_binaries(name):
            full_path = os.path.join(directory, candidate)
            if os.path.isfile(full_path):
                return full_path

    return None


def require_tool(name: str, extra_paths: Optional[List[str]] = None) -> str:
    """Like find_tool but raises if the tool is not found."""
    from chainrecon.runners.base import ToolNotFoundError

    path = find_tool(name, extra_paths)
    if path is None:
        msg = f"'{name}' not found on PATH"
        if is_windows() and name in _WINDOWS_SEARCH_PATHS:
            locations = ", ".join(_WINDOWS_SEARCH_PATHS[name])
            msg += f" or in common locations ({locations})"
        msg += ". Install it before using this feature."
        raise ToolNotFoundError(msg)
    return path


def check_all_tools() -> Dict[str, Dict[str, object]]:
    """Return status of all tools ChainRecon can use."""
    tools = ["nmap", "tshark", "tcpdump", "adb", "frida", "frida-ps", "openssl", "jadx", "apktool"]
    status = {}
    for tool in tools:
        path = find_tool(tool)
        status[tool] = {"found": path is not None, "path": path}
    return status


def get_architecture() -> str:
    """Return the machine architecture (e.g. 'x86_64', 'arm64')."""
    return platform.machine().lower()


def get_python_version() -> str:
    """Return the Python version string."""
    return platform.python_version()
