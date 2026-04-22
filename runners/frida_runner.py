"""Run Frida instrumentation sessions on Android apps via an emulator."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import ToolNotFoundError, check_tool, run_subprocess
from utils.logging_config import get_logger

logger = get_logger("frida")

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
    "shared_preferences_dump": {
        "label": "SharedPreferences Dump",
        "description": "Hook SharedPreferences to log all get/put operations and dump stored entries",
        "file": "shared_preferences_dump.js",
    },
    "database_dump": {
        "label": "Database Monitor",
        "description": "Hook SQLiteDatabase to log queries, inserts, updates, and raw SQL execution",
        "file": "database_dump.js",
    },
    "http_intercept": {
        "label": "HTTP Intercept",
        "description": "Intercept OkHttp, HttpURLConnection, WebView, and Retrofit HTTP traffic",
        "file": "http_intercept.js",
    },
    "certificate_pinning_detect": {
        "label": "Certificate Pinning Detection",
        "description": "Detect certificate-pinning implementations without bypassing them",
        "file": "certificate_pinning_detect.js",
    },
    "webrtc_frame_buffer": {
        "label": "WebRTC Frame Buffer Dump",
        "description": "Hook WebRTC decoder buffers and dump encoded frame bytes for inspection",
        "file": "framesBufferOld.js",
    },
}


class FridaRunner:
    """Manage Frida setup and script execution on an Android emulator."""

    def __init__(self, executor: Optional[Callable] = None, validate_device: bool = True):
        self._executor = executor or run_subprocess
        self._validate_device = validate_device

    # -- Dependency checks --------------------------------------------

    def check_prerequisites(self) -> Dict[str, Any]:
        """Check for required tools (adb, frida, frida-ps) and return status."""
        status = {}
        for tool in ("adb", "frida", "frida-ps"):
            try:
                status[tool] = {"found": True, "path": check_tool(tool)}
            except ToolNotFoundError:
                status[tool] = {"found": False, "path": None}
        return status

    # -- Device / process helpers -------------------------------------

    def list_devices(self) -> str:
        """Return raw output from `adb devices`."""
        check_tool("adb")
        result = self._executor(["adb", "devices"], timeout=10)
        return result.stdout.strip() if result.stdout else ""

    def list_processes(self) -> str:
        """Return running processes on the connected device via frida-ps."""
        check_tool("frida-ps")
        selector = self._frida_selector()
        self.ensure_online_device()
        result = self._executor(["frida-ps"] + selector, timeout=15)
        return result.stdout.strip() if result.stdout else ""

    def push_frida_server(self, server_path: str) -> str:
        """Push frida-server binary to the device and make it executable."""
        check_tool("adb")
        self.ensure_online_device()
        dest = "/data/local/tmp/frida-server"
        self._executor(["adb", "push", server_path, dest], timeout=120)
        self._executor(["adb", "shell", "chmod", "+x", dest], timeout=10)
        return dest

    def start_frida_server(self) -> None:
        """Start frida-server on the device in the background."""
        check_tool("adb")
        self.ensure_online_device()
        self._executor(
            ["adb", "shell", "/data/local/tmp/frida-server", "&"],
            timeout=5,
        )

    def forward_port(self, port: int = 27042) -> None:
        """Set up adb port forwarding for Frida communication."""
        check_tool("adb")
        self.ensure_online_device()
        self._executor(
            ["adb", "forward", f"tcp:{port}", f"tcp:{port}"],
            timeout=10,
        )

    # -- Script management --------------------------------------------

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
        selector = self._frida_selector()
        self.ensure_online_device()
        if custom_script_path:
            script_path = custom_script_path
        else:
            script_path = str(self.get_script_path(script_key))

        attach_flag = "-N" if "." in process_name else "-n"
        cmd = [
            "frida", *selector, attach_flag, process_name,
            "-l", script_path,
            "-q", "-t", "120", "--exit-on-error",
        ]
        logger.info("Attaching to '%s' with script '%s'", process_name, script_key or custom_script_path)
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
        selector = self._frida_selector()
        self.ensure_online_device()
        if custom_script_path:
            script_path = custom_script_path
        else:
            script_path = str(self.get_script_path(script_key))

        cmd = [
            "frida", *selector, "-f", package_name,
            "-l", script_path,
            "-q", "-t", "120", "--exit-on-error",
        ]
        result = self._executor(cmd, timeout=120)

        return {
            "package": package_name,
            "script": script_key or custom_script_path,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "returncode": result.returncode,
        }

    def get_device_state(self) -> Dict[str, Any]:
        """Return parsed adb device state without using Frida cache/output."""
        check_tool("adb")
        result = self._executor(["adb", "devices"], timeout=10)
        devices = _parse_adb_devices(result.stdout or "")
        configured = self._configured_serial()
        selected = None
        if configured:
            selected = next((device for device in devices if device["serial"] == configured), None)
            if selected is None:
                return {
                    "online": False,
                    "state": "missing",
                    "serial": configured,
                    "devices": devices,
                    "message": f"Configured device '{configured}' was not listed by adb.",
                }
        elif len(devices) == 1:
            selected = devices[0]
        elif len(devices) > 1:
            online = [device for device in devices if device["state"] == "device"]
            if len(online) == 1:
                selected = online[0]
            else:
                return {
                    "online": False,
                    "state": "ambiguous",
                    "devices": devices,
                    "message": "Multiple adb devices are connected. Set frida.device_serial in config/local.yaml.",
                }

        if selected is None:
            return {
                "online": False,
                "state": "no_device",
                "devices": devices,
                "message": "No adb device is connected.",
            }
        if selected["state"] != "device":
            return {
                "online": False,
                "state": selected["state"],
                "serial": selected["serial"],
                "devices": devices,
                "message": f"ADB device {selected['serial']} is {selected['state']}.",
            }
        return {
            "online": True,
            "state": "device",
            "serial": selected["serial"],
            "devices": devices,
            "message": f"ADB device {selected['serial']} is online.",
        }

    def ensure_online_device(self) -> Dict[str, Any]:
        if not self._validate_device:
            return {"online": True, "state": "skipped", "serial": None, "message": "Device validation skipped."}
        state = self.get_device_state()
        if not state.get("online"):
            raise FridaDeviceError(state.get("message", "No online adb device available."), state=state)
        return state

    def _configured_serial(self) -> Optional[str]:
        try:
            from utils.config import get_frida_config

            serial = get_frida_config().get("device_serial")
            return str(serial) if serial else None
        except Exception:
            return None

    def _frida_selector(self) -> List[str]:
        serial = self._configured_serial()
        return ["-D", serial] if serial else ["-U"]


class FridaDeviceError(RuntimeError):
    """Raised when no usable online adb device is available."""

    def __init__(self, message: str, state: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.state = state or {}


def _parse_adb_devices(output: str) -> List[Dict[str, str]]:
    devices: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("list of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1], "detail": " ".join(parts[2:])})
    return devices
