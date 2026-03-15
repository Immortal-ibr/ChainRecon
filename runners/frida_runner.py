"""Run Frida instrumentation sessions on Android apps via an emulator."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import ToolNotFoundError, check_tool, run_subprocess

# Directory containing built-in Frida JS scripts (shipped with ChainRecon)
_SCRIPTS_DIR = Path(__file__).parent / "frida_scripts"

FRIDA_SCRIPTS: Dict[str, Dict[str, str]] = {
    "list_classes": {
        "label": "List Loaded Classes",
        "description": "Enumerate all loaded Java classes (optionally filtered by package name)",
        "file": "list_classes.js",
    },
    "hook_all_methods": {
        "label": "Hook All Methods of a Class",
        "description": "Hook every method in one or more classes and log calls with arguments",
        "file": "hook_all_methods.js",
    },
    "hook_method": {
        "label": "Hook a Single Method",
        "description": "Hook one specific method and log calls + return values",
        "file": "hook_method.js",
    },
    "ssl_pinning_bypass": {
        "label": "SSL Pinning Bypass",
        "description": "Bypass common SSL/TLS certificate pinning (TrustManager, OkHttp3, WebView)",
        "file": "ssl_pinning_bypass.js",
    },
    "network_traffic_monitor": {
        "label": "Network Traffic Monitor",
        "description": "Monitor HTTP, OkHttp3, and raw Socket connections from the app",
        "file": "network_traffic_monitor.js",
    },
    "crypto_monitor": {
        "label": "Crypto Monitor",
        "description": "Log encryption, decryption, hashing, and HMAC operations with keys/payloads",
        "file": "crypto_monitor.js",
    },
}


class FridaRunner:
    """Manage Frida setup and script execution on an Android emulator."""

    def __init__(self, executor: Optional[Callable] = None):
        self._executor = executor or run_subprocess

    # ── Dependency checks ────────────────────────────────────────────

    def check_prerequisites(self) -> Dict[str, Any]:
        """Check for required tools (adb, frida, frida-ps) and return status."""
        status = {}
        for tool in ("adb", "frida", "frida-ps"):
            try:
                status[tool] = {"found": True, "path": check_tool(tool)}
            except ToolNotFoundError:
                status[tool] = {"found": False, "path": None}
        return status

    # ── Device / process helpers ─────────────────────────────────────

    def list_devices(self) -> str:
        """Return raw output from `adb devices`."""
        check_tool("adb")
        result = self._executor(["adb", "devices"], timeout=10)
        return result.stdout.strip() if result.stdout else ""

    def list_processes(self) -> str:
        """Return running processes on the connected device via frida-ps."""
        check_tool("frida-ps")
        result = self._executor(["frida-ps", "-U"], timeout=15)
        return result.stdout.strip() if result.stdout else ""

    def push_frida_server(self, server_path: str) -> str:
        """Push frida-server binary to the device and make it executable."""
        check_tool("adb")
        dest = "/data/local/tmp/frida-server"
        self._executor(["adb", "push", server_path, dest], timeout=120)
        self._executor(["adb", "shell", "chmod", "+x", dest], timeout=10)
        return dest

    def start_frida_server(self) -> None:
        """Start frida-server on the device in the background."""
        check_tool("adb")
        self._executor(
            ["adb", "shell", "/data/local/tmp/frida-server", "&"],
            timeout=5,
        )

    def forward_port(self, port: int = 27042) -> None:
        """Set up adb port forwarding for Frida communication."""
        check_tool("adb")
        self._executor(
            ["adb", "forward", f"tcp:{port}", f"tcp:{port}"],
            timeout=10,
        )

    # ── Script management ────────────────────────────────────────────

    def list_scripts(self) -> List[Dict[str, str]]:
        """Return metadata for all built-in Frida scripts."""
        return [
            {"key": key, "label": s["label"], "description": s["description"]}
            for key, s in FRIDA_SCRIPTS.items()
        ]

    def get_script_path(self, script_key: str) -> Path:
        """Return the on-disk path for a built-in script."""
        if script_key not in FRIDA_SCRIPTS:
            raise ValueError(f"Unknown script: {script_key}")
        return _SCRIPTS_DIR / FRIDA_SCRIPTS[script_key]["file"]

    def run_script(
        self,
        process_name: str,
        script_key: str,
        custom_script_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Attach Frida to a process and load a JS script.

        Returns dict with stdout/stderr from the frida session.
        The session runs with a 60-second timeout so it doesn't hang forever
        in a non-interactive context (the user can Ctrl-C in interactive mode).
        """
        check_tool("frida")
        if custom_script_path:
            script_path = custom_script_path
        else:
            script_path = str(self.get_script_path(script_key))

        cmd = ["frida", "-U", "-n", process_name, "-l", script_path, "--no-pause"]
        result = self._executor(cmd, timeout=120)

        return {
            "process": process_name,
            "script": script_key or custom_script_path,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "returncode": result.returncode,
        }

    def spawn_and_run(
        self,
        package_name: str,
        script_key: str,
        custom_script_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Spawn the app (cold start) and inject a script immediately."""
        check_tool("frida")
        if custom_script_path:
            script_path = custom_script_path
        else:
            script_path = str(self.get_script_path(script_key))

        cmd = ["frida", "-U", "-f", package_name, "-l", script_path, "--no-pause"]
        result = self._executor(cmd, timeout=120)

        return {
            "package": package_name,
            "script": script_key or custom_script_path,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "returncode": result.returncode,
        }
