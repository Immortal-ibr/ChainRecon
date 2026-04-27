"""Run and manage Frida instrumentation sessions on Android devices and emulators."""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from runners.base import ToolNotFoundError, check_tool, run_subprocess
from utils.artifacts import artifact_path, safe_token
from utils.logging_config import get_logger

logger = get_logger("frida")

_SCRIPTS_DIR = Path(__file__).parent / "frida_scripts"


def _expected_long_running(script_key: str) -> bool:
    runtime = FRIDA_SCRIPTS.get(script_key, {}).get("runtime", {})
    return bool(runtime.get("expected_long_running", runtime.get("expect_long_running_output", False)))


def _split_parameter_values(value: str) -> list[str]:
    pieces = re.split(r"[\r\n,;]+", value)
    return [piece.strip() for piece in pieces if piece.strip()]


FRIDA_SCRIPTS: Dict[str, Dict[str, Any]] = {
    "list_classes": {
        "label": "List App Loaded Classes",
        "description": "Enumerate loaded Java classes in the attached app process. Filters accept comma, semicolon, or newline-separated terms.",
        "file": "list_classes.js",
        "target_type": "package",
        "params": [
            {
                "name": "class_filter",
                "label": "Class filter",
                "placeholder": "com.nooie; com.thingclips",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": False},
    },
    "device_class_census": {
        "label": "Device-Wide Class Census",
        "description": "Capture a census-style class dump from the currently attached process and explicitly mark the output as process-scoped so it is not mistaken for global device state.",
        "file": "device_class_census.js",
        "target_type": "package",
        "params": [],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": False},
    },
    "hook_all_methods": {
        "label": "Hook Selected Class Methods",
        "description": "Hook every overload for one or more selected classes and stream calls live. Use package/class filters from the class-listing tools first, then paste the exact classes you want.",
        "file": "hook_all_methods.js",
        "target_type": "package",
        "params": [
            {
                "name": "class_names",
                "label": "Class names",
                "placeholder": "One class per line, or comma / semicolon separated",
                "required": True,
            },
            {
                "name": "max_events_per_second",
                "label": "Max events/sec",
                "placeholder": "50",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "hook_method": {
        "label": "Hook Single Method",
        "description": "Hook one method and log arguments and return values.",
        "file": "hook_method.js",
        "target_type": "package",
        "params": [
            {
                "name": "class_name",
                "label": "Class name",
                "placeholder": "com.nooie.home.SomeClass",
                "required": True,
            },
            {
                "name": "method_name",
                "label": "Method name",
                "placeholder": "someMethod",
                "required": True,
            },
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "ssl_pinning_bypass": {
        "label": "SSL Pinning Bypass",
        "description": "Attempt common TrustManager, OkHttp, and WebView pinning bypasses.",
        "file": "ssl_pinning_bypass.js",
        "target_type": "package",
        "params": [],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "http_intercept": {
        "label": "HTTP Trace",
        "description": "Trace Java/Android HTTP requests through URLConnection, HttpURLConnection, WebView, and OkHttp hooks without injecting a new interceptor into the target app.",
        "file": "http_intercept.js",
        "target_type": "package",
        "params": [
            {
                "name": "host_filter",
                "label": "Host filter",
                "placeholder": "api.nooie.com",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "network_traffic_monitor": {
        "label": "Socket and URL Monitor",
        "description": "Trace URLConnection, Socket, and OkHttp traffic with concise event tags. Prefer this for long-running network activity when you need lower-overhead output than the HTTP trace.",
        "file": "network_traffic_monitor.js",
        "target_type": "package",
        "params": [
            {
                "name": "host_filter",
                "label": "Host filter",
                "placeholder": "mqtt, nooie, or leave blank",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "crypto_monitor": {
        "label": "Crypto Monitor",
        "description": "Log selected Cipher, MessageDigest, and MAC operations.",
        "file": "crypto_monitor.js",
        "target_type": "package",
        "params": [],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "shared_preferences_dump": {
        "label": "Shared Preferences Watch",
        "description": "Dump and watch SharedPreferences reads and writes.",
        "file": "shared_preferences_dump.js",
        "target_type": "package",
        "params": [
            {
                "name": "key_filter",
                "label": "Key filter",
                "placeholder": "token, mqtt, user",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "database_dump": {
        "label": "Database Monitor",
        "description": "Trace SQLite queries, inserts, and updates.",
        "file": "database_dump.js",
        "target_type": "package",
        "params": [
            {
                "name": "query_filter",
                "label": "Query filter",
                "placeholder": "device, mqtt, token",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "certificate_pinning_detect": {
        "label": "Certificate Pinning Detection",
        "description": "Detect common pinning implementations without modifying behavior.",
        "file": "certificate_pinning_detect.js",
        "target_type": "package",
        "params": [],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": False},
    },
    "nooie_mqtt_trace": {
        "label": "Nooie MQTT and Token Trace",
        "description": "Watch MQTT token fetches, connects, publishes, and subscription events. Good for correlating login, token refresh, and broker activity in one long-running hook.",
        "file": "nooie_mqtt_trace.js",
        "target_type": "package",
        "params": [
            {
                "name": "class_filter",
                "label": "Class filter",
                "placeholder": "com.thingclips or com.nooie",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "nooie_stream_trace": {
        "label": "Nooie Stream and WebRTC Trace",
        "description": "Trace stream lifecycle and WebRTC-related classes used by Nooie. Use after identifying the app-side stream classes from the class-listing tools.",
        "file": "nooie_stream_trace.js",
        "target_type": "package",
        "params": [
            {
                "name": "class_filter",
                "label": "Class filter",
                "placeholder": "webrtc, player, stream",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "nooie_runtime_config": {
        "label": "Nooie Runtime Config",
        "description": "Dump runtime preferences, token-like values, and selected config accesses so report artifacts preserve the configuration state seen during a session.",
        "file": "nooie_runtime_config.js",
        "target_type": "package",
        "params": [
            {
                "name": "key_filter",
                "label": "Key filter",
                "placeholder": "token, mqtt, stream",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
}


@dataclass
class FridaSession:
    session_id: str
    serial: str
    target: str
    attach_target: str
    attach_flag: str
    script_key: str
    parameters: Dict[str, Any]
    command: List[str]
    process: Optional[subprocess.Popen[str]]
    log_path: Path
    summary_path: Path
    rendered_script_path: Path
    start_time: float
    mode: str
    target_running_before: bool
    launch_performed: bool
    frida_server_started: bool
    frida_server_path: Optional[str]
    api_device: Any = None
    api_session: Any = None
    api_script: Any = None
    session_backend: str = "cli"
    health_checks: Dict[str, Any] = field(default_factory=dict)
    summary_written: threading.Event = field(default_factory=threading.Event)
    stop_event: threading.Event = field(default_factory=threading.Event)
    output_line_count: int = 0
    error_line_count: int = 0
    exit_code: Optional[int] = None
    stop_requested: bool = False
    status_reason: str = ""
    reattach_count: int = 0
    events_by_tag: Dict[str, int] = field(default_factory=dict)
    dropped_event_count: int = 0
    target_alive_at_exit: Optional[bool] = None
    reader_threads: List[threading.Thread] = field(default_factory=list)
    watcher_thread: Optional[threading.Thread] = None


class FridaRunner:
    """Manage Frida setup and long-running instrumentation sessions."""

    def __init__(self, executor: Optional[Callable] = None, validate_device: bool = True):
        self._executor = executor or run_subprocess
        self._validate_device = validate_device
        self._host_frida_version_cache: Optional[str] = None
        self._session_lock = threading.Lock()
        self._active_session: Optional[FridaSession] = None

    # -- Dependency checks --------------------------------------------

    def check_prerequisites(self) -> Dict[str, Any]:
        status = {}
        for tool in ("adb", "frida", "frida-ps", "emulator", "avdmanager", "sdkmanager"):
            try:
                status[tool] = {"found": True, "path": check_tool(tool)}
            except ToolNotFoundError:
                status[tool] = {"found": False, "path": None}
        return status

    # -- Device / process helpers -------------------------------------

    def list_devices(self) -> str:
        check_tool("adb")
        result = self._executor(["adb", "devices"], timeout=10)
        return (result.stdout or "").strip()

    def list_device_inventory(self) -> Dict[str, Any]:
        status = self.check_prerequisites()
        inventory: Dict[str, Any] = {
            "prerequisites": status,
            "connected_devices": [],
            "local_avds": [],
            "install_guidance": [],
        }
        if not status["adb"]["found"]:
            inventory["install_guidance"].append(self.install_steps("adb"))
            return inventory

        adb_output = self.list_devices()
        connected = _parse_adb_devices(adb_output)
        booted_avd_names: set[str] = set()
        for device in connected:
            enriched = dict(device)
            enriched.update(self._describe_connected_device(device))
            if enriched.get("avd_name"):
                booted_avd_names.add(str(enriched["avd_name"]))
            inventory["connected_devices"].append(enriched)

        if status["emulator"]["found"]:
            avds = self._list_avds()
            for avd_name in avds:
                if avd_name in booted_avd_names:
                    continue
                inventory["local_avds"].append(self._describe_local_avd(avd_name, False))
        else:
            inventory["install_guidance"].append(self.install_steps("emulator"))
        if not status["sdkmanager"]["found"]:
            inventory["install_guidance"].append(self.install_steps("sdkmanager"))
        if not status["avdmanager"]["found"]:
            inventory["install_guidance"].append(self.install_steps("avdmanager"))
        if not status["frida"]["found"] or not status["frida-ps"]["found"]:
            inventory["install_guidance"].append(self.install_steps("frida"))
        return inventory

    def list_processes(self) -> str:
        check_tool("frida-ps")
        state = self.ensure_online_device()
        serial = str(state.get("serial"))
        result = self._executor(["frida-ps", "-D", serial], timeout=15)
        return (result.stdout or "").strip()

    def list_processes_structured(self, *, serial: Optional[str] = None) -> List[Dict[str, str]]:
        check_tool("frida-ps")
        serial = serial or str(self.ensure_online_device().get("serial"))
        result = self._executor(["frida-ps", "-D", serial, "-a"], timeout=20)
        return _parse_frida_process_table(result.stdout or "")

    def get_device_state(self) -> Dict[str, Any]:
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

    def is_frida_server_running(self, *, serial: Optional[str] = None) -> bool:
        serial = serial or str(self.ensure_online_device().get("serial"))
        commands = [
            self._adb_cmd(serial, "shell", "pidof", "frida-server"),
            self._adb_cmd(serial, "shell", "sh", "-c", "ps -A | grep frida-server"),
        ]
        for cmd in commands:
            try:
                result = self._executor(cmd, timeout=10)
            except Exception:
                continue
            output = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
            if output:
                return True
        return False

    def start_frida_server_if_needed(
        self,
        *,
        serial: Optional[str] = None,
        frida_server_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        serial = serial or str(self.ensure_online_device().get("serial"))
        privilege = self._prepare_frida_server_privilege(serial)
        if self.is_frida_server_running(serial=serial):
            return {"running": True, "started": False, "frida_server": None, "resolution": {}, "privilege": privilege}

        configured_path = frida_server_path or self._configured_frida_server_path()
        server_binary, resolution = self._resolve_frida_server_path(configured_path, serial=serial)
        if not server_binary:
            raise FridaDeviceError(
                "frida-server is not running and no matching frida-server binary was found.",
                state={
                    "install_guidance": [self.install_steps("frida-server")],
                    "frida_server_resolution": resolution,
                },
            )

        self.push_frida_server(str(server_binary), serial=serial)
        self.start_frida_server(serial=serial)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.is_frida_server_running(serial=serial):
                return {
                    "running": True,
                    "started": True,
                    "frida_server": str(server_binary.resolve()),
                    "resolution": resolution,
                    "privilege": privilege,
                }
            time.sleep(0.5)
        raise FridaDeviceError(
            "frida-server was pushed but did not remain running on the device.",
            state={"frida_server_resolution": resolution},
        )

    def is_target_running(self, target: str, *, serial: Optional[str] = None) -> bool:
        serial = serial or str(self.ensure_online_device().get("serial"))
        if "." in target:
            try:
                result = self._executor(self._adb_cmd(serial, "shell", "pidof", target), timeout=10)
                if (result.stdout or "").strip():
                    return True
            except Exception:
                pass
        for process in self.list_processes_structured(serial=serial):
            if target in {process.get("name"), process.get("identifier")}:
                return True
        return False

    def launch_target_if_needed(self, target: str, *, serial: Optional[str] = None) -> Dict[str, Any]:
        serial = serial or str(self.ensure_online_device().get("serial"))
        if self.is_target_running(target, serial=serial):
            return {"launched": False, "details": f"{target} is already running."}
        if not self._package_installed(serial, target):
            raise FridaDeviceError(
                f"Target package '{target}' is not installed on {serial}.",
                state={"serial": serial, "target": target},
            )
        result = self._executor(self._adb_cmd(serial, "shell", "monkey", "-p", target, "1"), timeout=30)
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.is_target_running(target, serial=serial):
                return {
                    "launched": True,
                    "details": (result.stdout or result.stderr or f"Launched {target} with monkey.").strip(),
                }
            time.sleep(1)
        return {
            "launched": False,
            "details": (result.stdout or result.stderr or f"Launch attempt for {target} did not yield a running process.").strip(),
        }

    def resolve_attach_target(self, target: str, *, serial: Optional[str] = None) -> Dict[str, Any]:
        serial = serial or str(self.ensure_online_device().get("serial"))
        package_installed = "." in target and self._package_installed(serial, target)
        target_running_before = self.is_target_running(target, serial=serial)
        launch_info = {"launched": False, "details": ""}
        if package_installed and not target_running_before:
            launch_info = self.launch_target_if_needed(target, serial=serial)
        if self.is_target_running(target, serial=serial):
            return {
                "mode": "attach",
                "attach_flag": "-N" if "." in target else "-n",
                "attach_target": target,
                "target_running_before": target_running_before,
                "launch_performed": bool(launch_info.get("launched")),
                "launch_details": launch_info.get("details", ""),
                "package_installed": package_installed,
            }
        if package_installed:
            return {
                "mode": "spawn",
                "attach_flag": "-f",
                "attach_target": target,
                "target_running_before": target_running_before,
                "launch_performed": bool(launch_info.get("launched")),
                "launch_details": launch_info.get("details", ""),
                "package_installed": package_installed,
            }
        raise FridaDeviceError(
            f"Target '{target}' is not running and could not be launched automatically.",
            state={"serial": serial, "target": target},
        )

    # -- Setup workflow -----------------------------------------------

    def setup_device(
        self,
        *,
        target_id: Optional[str] = None,
        apk_directory: Optional[str] = None,
        frida_server_path: Optional[str] = None,
        preferred_avd: Optional[str] = None,
        port: int = 27042,
    ) -> Dict[str, Any]:
        status = self.check_prerequisites()
        missing = []
        for tool in ("adb", "frida", "frida-ps"):
            if not status.get(tool, {}).get("found"):
                missing.append(self.install_steps(tool))
        if target_id and str(target_id).startswith("avd:") and not status.get("emulator", {}).get("found"):
            missing.append(self.install_steps("emulator"))
        if missing:
            raise FridaDeviceError("Missing prerequisites for Frida setup.", state={"install_guidance": missing})

        inventory = self.list_device_inventory()
        selection = target_id or self._default_target(inventory, preferred_avd)
        if not selection:
            raise FridaDeviceError(
                "No adb device is online and no bootable AVD was selected.",
                state={"install_guidance": inventory.get("install_guidance", [])},
            )

        actions: List[str] = []
        serial: Optional[str] = None
        if selection.startswith("avd:"):
            avd_name = selection.split(":", 1)[1]
            serial = self._find_connected_avd_serial(avd_name, devices=inventory.get("connected_devices"))
            if serial:
                actions.append(f"Selected AVD {avd_name} is already running as {serial}.")
            else:
                boot = self.boot_device(selection)
                actions.append(boot["message"])
                serial = self._wait_for_avd_serial_registration(adb_timeout=180, avd_name=avd_name)
                actions.append(f"ADB serial registered for AVD {avd_name}: {serial}")
        elif selection.startswith("serial:"):
            serial = selection.split(":", 1)[1]
        else:
            serial = selection

        if not serial:
            raise FridaDeviceError("Could not determine the adb serial for the selected device.")

        serial = self._wait_for_device_online(serial, timeout=180)
        actions.append(f"ADB device {serial} is online.")
        self._wait_for_boot_complete(serial, timeout=180)
        actions.append(f"Android boot completed for {serial}.")

        if serial.startswith("emulator-"):
            try:
                self._executor(["adb", "-s", serial, "root"], timeout=20)
                actions.append("Requested adb root on the emulator.")
            except Exception:
                actions.append("adb root was not available; continuing without it.")

        apk_installation = self.install_apks(apk_directory, serial=serial)
        if apk_installation["requested"]:
            if apk_installation["verified"]:
                actions.append(
                    f"Verified APK deployment for {apk_installation['installed_count']} package(s) from {apk_directory}."
                )
            else:
                raise FridaDeviceError(
                    "APK deployment did not verify successfully during managed setup.",
                    state={"apk_installation": apk_installation},
                )

        server_binary, resolution = self._resolve_frida_server_path(frida_server_path or self._configured_frida_server_path(), serial=serial)
        if not server_binary:
            raise FridaDeviceError(
                "frida-server was not found. Configure frida.frida_server_path or place matching binaries in that directory.",
                state={
                    "install_guidance": [self.install_steps("frida-server")],
                    "frida_server_resolution": resolution,
                },
            )
        self._prepare_frida_server_privilege(serial)
        self.push_frida_server(str(server_binary), serial=serial)
        actions.append(f"Pushed frida-server: {server_binary}")
        self.start_frida_server(serial=serial)
        actions.append("Started frida-server in the background.")
        self.forward_port(port=port, serial=serial)
        actions.append(f"Forwarded tcp:{port} to the device.")
        process_output = self._executor(["frida-ps", "-D", serial], timeout=20)
        actions.append("Validated frida-ps connectivity.")

        return {
            "serial": serial,
            "selection": selection,
            "frida_server": str(server_binary),
            "installed_apks": apk_installation.get("installed_files", []),
            "apk_installation": apk_installation,
            "actions": actions,
            "frida_ps": (process_output.stdout or "").strip(),
            "frida_server_resolution": resolution,
        }

    def boot_device(self, target_id: str) -> Dict[str, Any]:
        if not target_id.startswith("avd:"):
            raise FridaDeviceError("Only local Android emulators can be booted from ChainRecon.")
        emulator_path = check_tool("emulator")
        avd_name = target_id.split(":", 1)[1]
        if avd_name not in self._list_avds():
            raise FridaDeviceError(f"AVD '{avd_name}' was not found on this machine.")
        existing_serial = self._find_connected_avd_serial(avd_name)
        if existing_serial:
            return {
                "booted": False,
                "target_id": target_id,
                "serial": existing_serial,
                "message": f"AVD '{avd_name}' is already running as {existing_serial}.",
            }
        subprocess.Popen(
            [emulator_path, "-avd", avd_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        return {
            "booted": True,
            "target_id": target_id,
            "message": f"Started emulator AVD '{avd_name}'. Wait for it to appear in adb devices.",
        }

    def push_frida_server(self, server_path: str, *, serial: Optional[str] = None) -> str:
        check_tool("adb")
        serial = serial or str(self.ensure_online_device().get("serial"))
        dest = "/data/local/tmp/frida-server"
        self._executor(self._adb_cmd(serial, "push", server_path, dest), timeout=120)
        self._executor(self._adb_cmd(serial, "shell", "chmod", "+x", dest), timeout=10)
        return dest

    def start_frida_server(self, *, serial: Optional[str] = None) -> None:
        check_tool("adb")
        serial = serial or str(self.ensure_online_device().get("serial"))
        self._executor(
            self._adb_cmd(serial, "shell", "sh", "-c", "/data/local/tmp/frida-server >/dev/null 2>&1 &"),
            timeout=5,
        )

    def forward_port(self, port: int = 27042, *, serial: Optional[str] = None) -> None:
        check_tool("adb")
        serial = serial or str(self.ensure_online_device().get("serial"))
        self._executor(self._adb_cmd(serial, "forward", f"tcp:{port}", f"tcp:{port}"), timeout=10)

    # -- Script management --------------------------------------------

    def list_scripts(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": key,
                "label": meta["label"],
                "description": meta["description"],
                "params": meta.get("params", []),
                "runtime": meta.get("runtime", {}),
            }
            for key, meta in FRIDA_SCRIPTS.items()
        ]

    def get_script_path(self, script_key: str) -> Path:
        if script_key not in FRIDA_SCRIPTS:
            raise ValueError(f"Unknown script: {script_key}")
        return _SCRIPTS_DIR / FRIDA_SCRIPTS[script_key]["file"]

    def render_script(self, script_key: str, parameters: Dict[str, Any], output_dir: str | Path) -> Path:
        script_path = self.get_script_path(script_key)
        rendered_path = artifact_path(output_dir, f"frida_script_{safe_token(script_key)}", ".js")
        rendered_payload = self._normalize_script_parameters(script_key, parameters)
        prelude = "const CHAINRECON_CONFIG = Object.freeze(" + json.dumps(rendered_payload, indent=2) + ");\n\n"
        rendered = prelude + script_path.read_text(encoding="utf-8")
        if _expected_long_running(script_key):
            rendered += "\n\nsetInterval(function () {}, 1000);\n"
        rendered_path.write_text(rendered, encoding="utf-8")
        return rendered_path.resolve()

    def start_session(
        self,
        *,
        target: str,
        script_key: str,
        parameters: Optional[Dict[str, Any]] = None,
        output_dir: str | Path,
        frida_server_path: Optional[str] = None,
        custom_script_path: Optional[str] = None,
        on_output: Optional[Callable[[str], None]] = None,
        on_exit: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        check_tool("frida")
        check_tool("frida-ps")
        if not target.strip():
            raise FridaDeviceError("Enter a target package or process before starting a Frida run.")

        with self._session_lock:
            if self._active_session is not None:
                raise FridaDeviceError("A Frida hook session is already running. Stop it before starting another.")

        state = self.ensure_online_device()
        serial = str(state.get("serial"))
        inventory = self.list_device_inventory()
        device = next((item for item in inventory.get("connected_devices", []) if item.get("serial") == serial), None)
        if device and not device.get("frida_compatible"):
            has_server_hint = bool(frida_server_path or self._configured_frida_server_path())
            if not has_server_hint and not self.is_frida_server_running(serial=serial):
                raise FridaDeviceError(device.get("frida_note") or "Selected device is not managed-compatible for Frida.")

        server_status = self.start_frida_server_if_needed(serial=serial, frida_server_path=frida_server_path)
        resolution = self.resolve_attach_target(target, serial=serial)

        if custom_script_path:
            rendered_script_path = Path(custom_script_path).expanduser().resolve()
            if not rendered_script_path.exists():
                raise FridaDeviceError(f"Custom Frida script not found: {rendered_script_path}")
            chosen_script_key = "custom"
        else:
            chosen_script_key = script_key
            rendered_script_path = self.render_script(script_key, parameters or {}, output_dir)

        session_id = safe_token(f"{serial}_{target}_{chosen_script_key}_{int(time.time())}", "frida_session")
        log_path = artifact_path(output_dir, f"frida_session_{session_id}", ".log").resolve()
        summary_path = artifact_path(output_dir, f"frida_session_{session_id}", ".json").resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")

        cmd = self._build_managed_command(
            serial=serial,
            attach_flag=str(resolution["attach_flag"]),
            attach_target=str(resolution["attach_target"]),
            rendered_script_path=rendered_script_path,
        )

        session = FridaSession(
            session_id=session_id,
            serial=serial,
            target=target,
            attach_target=str(resolution["attach_target"]),
            attach_flag=str(resolution["attach_flag"]),
            script_key=chosen_script_key,
            parameters=self._normalize_script_parameters(script_key, parameters or {}),
            command=cmd,
            process=None,
            log_path=log_path,
            summary_path=summary_path,
            rendered_script_path=rendered_script_path,
            start_time=time.time(),
            mode=str(resolution["mode"]),
            target_running_before=bool(resolution.get("target_running_before")),
            launch_performed=bool(resolution.get("launch_performed")),
            frida_server_started=bool(server_status.get("started")),
            frida_server_path=server_status.get("frida_server"),
            session_backend="frida_cli_managed",
            health_checks={
                "device_online": True,
                "frida_server_running": bool(server_status.get("running")),
                "frida_server_started": bool(server_status.get("started")),
                "target_running_before": bool(resolution.get("target_running_before")),
                "target_launch_performed": bool(resolution.get("launch_performed")),
                "attach_target": str(resolution["attach_target"]),
                "java_bridge_mode": "frida_cli_managed",
                "script_loaded": False,
                "expected_long_running": _expected_long_running(chosen_script_key),
            },
        )
        with self._session_lock:
            self._active_session = session

        try:
            self._start_cli_process(session, on_output)
        except Exception as exc:
            session.status_reason = f"attach_failed: {exc}"
            summary = self._write_session_summary(session, exit_code=1)
            session.summary_written.set()
            with self._session_lock:
                if self._active_session is session:
                    self._active_session = None
            if on_exit is not None:
                on_exit(summary)
            raise FridaDeviceError(f"Frida attach/script load failed: {exc}") from exc

        session.watcher_thread = threading.Thread(
            target=self._watch_session,
            args=(session, on_output, on_exit),
            daemon=True,
        )
        session.watcher_thread.start()

        return {
            "session_id": session.session_id,
            "serial": serial,
            "target": target,
            "mode": session.mode,
            "command": cmd,
            "log_path": str(log_path),
            "summary_path": str(summary_path),
            "rendered_script_path": str(rendered_script_path),
            "attach_target": session.attach_target,
            "frida_server_started": session.frida_server_started,
            "frida_server_path": session.frida_server_path,
            "launch_performed": session.launch_performed,
        }

    @staticmethod
    def _build_managed_command(
        *,
        serial: str,
        attach_flag: str,
        attach_target: str,
        rendered_script_path: Path,
    ) -> List[str]:
        return [
            "frida",
            "-D",
            serial,
            attach_flag,
            attach_target,
            "-l",
            str(rendered_script_path),
            "--keepalive-interval",
            "30",
            "--stdio",
            "pipe",
            "-q",
        ]

    def _start_cli_process(
        self,
        session: FridaSession,
        on_output: Optional[Callable[[str], None]],
    ) -> None:
        session.reader_threads = []
        session.process = subprocess.Popen(
            session.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        session.health_checks["script_loaded"] = True
        self._append_session_line(session, "[STATUS] Managed Frida CLI session started", "stdout", on_output)
        for channel, pipe in (("stdout", session.process.stdout), ("stderr", session.process.stderr)):
            thread = threading.Thread(
                target=self._stream_pipe,
                args=(session, pipe, channel, on_output),
                daemon=True,
            )
            session.reader_threads.append(thread)
            thread.start()

    def _load_api_script(self, session: FridaSession, on_output: Optional[Callable[[str], None]]) -> None:
        frida_mod = self._import_frida()
        device = frida_mod.get_device(session.serial, timeout=5)
        attach_target: Any = session.attach_target
        try:
            api_session = device.attach(attach_target)
        except Exception:
            pid = self._pidof(session.serial, session.target) if "." in session.target else None
            if pid is None:
                raise
            attach_target = pid
            api_session = device.attach(attach_target)
        session.health_checks["api_attach_target"] = attach_target

        def _on_detached(reason, crash=None) -> None:
            if not session.stop_requested:
                session.status_reason = f"detached: {reason}"
            if crash:
                self._append_session_line(session, f"Frida detached with crash details: {crash}", "stderr", on_output)
            session.stop_event.set()

        try:
            api_session.on("detached", _on_detached)
        except Exception:
            pass

        script_source = session.rendered_script_path.read_text(encoding="utf-8", errors="replace")
        api_script = api_session.create_script(script_source)

        def _on_message(message, data=None) -> None:
            self._handle_api_message(session, message, data, on_output)

        api_script.on("message", _on_message)
        api_script.load()
        session.api_device = device
        session.api_session = api_session
        session.api_script = api_script
        session.health_checks["script_loaded"] = True
        self._append_session_line(session, "[STATUS] Python Frida API session loaded", "stdout", on_output)

    @staticmethod
    def _import_frida():
        try:
            import frida  # type: ignore
        except ImportError as exc:
            raise FridaDeviceError("Python frida package is not installed. Install with: python -m pip install frida-tools") from exc
        return frida

    def _handle_api_message(
        self,
        session: FridaSession,
        message: Dict[str, Any],
        data: Any,
        on_output: Optional[Callable[[str], None]],
    ) -> None:
        msg_type = str(message.get("type", "message"))
        channel = "stderr" if msg_type == "error" else "stdout"
        if msg_type == "error":
            payload = message.get("stack") or message.get("description") or message
        else:
            payload = message.get("payload", message)
        line = str(payload)
        self._append_session_line(session, line, channel, on_output)
        tag = _event_tag(line)
        if tag:
            session.events_by_tag[tag] = session.events_by_tag.get(tag, 0) + 1
        if isinstance(payload, dict) and "dropped_event_count" in payload:
            try:
                session.dropped_event_count += int(payload["dropped_event_count"])
            except (TypeError, ValueError):
                pass

    def _watch_api_session(self, session: FridaSession, on_exit: Optional[Callable[[Dict[str, Any]], None]]) -> None:
        while not session.stop_event.wait(timeout=1.0):
            if session.stop_requested:
                break
            if not self.is_target_running(session.target, serial=session.serial):
                session.status_reason = "target_died"
                break
        if (
            not session.stop_requested
            and session.stop_event.is_set()
            and session.reattach_count < 1
            and self.is_target_running(session.target, serial=session.serial)
        ):
            session.reattach_count += 1
            session.stop_event.clear()
            self._append_session_line(session, "[STATUS] Frida session detached; attempting one automatic reattach", "stderr", None)
            try:
                self._unload_api_session(session)
                self._load_api_script(session, None)
                return self._watch_api_session(session, on_exit)
            except Exception as exc:
                session.status_reason = f"reattach_failed: {exc}"
        session.target_alive_at_exit = self.is_target_running(session.target, serial=session.serial)
        if session.stop_requested:
            session.status_reason = "stopped_by_user"
        elif not session.status_reason:
            session.status_reason = "unexpected_exit"

        self._unload_api_session(session)
        exit_code = 0 if session.stop_requested else 1
        summary = self._write_session_summary(session, exit_code=exit_code)
        with self._session_lock:
            if self._active_session is session:
                self._active_session = None
        session.summary_written.set()
        if on_exit is not None:
            on_exit(summary)

    @staticmethod
    def _unload_api_session(session: FridaSession) -> None:
        try:
            if session.api_script is not None:
                session.api_script.unload()
        except Exception:
            pass
        try:
            if session.api_session is not None:
                session.api_session.detach()
        except Exception:
            pass

    def stop_session(self, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        with self._session_lock:
            session = self._active_session
        if session is None:
            return None
        session.stop_requested = True
        session.stop_event.set()
        if session.process is None:
            self._unload_api_session(session)
            if not session.summary_written.wait(timeout=timeout):
                return {
                    "session_id": session.session_id,
                    "status": "stopping",
                    "log_path": str(session.log_path),
                    "summary_path": str(session.summary_path),
                }
            return self._load_summary(session.summary_path)
        try:
            if session.process.poll() is None:
                if session.process.stdin is not None:
                    try:
                        session.process.stdin.close()
                    except Exception:
                        pass
                session.process.terminate()
                session.process.wait(timeout=timeout)
        except Exception:
            try:
                session.process.kill()
            except Exception:
                pass
        if not session.summary_written.wait(timeout=timeout):
            return {
                "session_id": session.session_id,
                "status": "stopping",
                "log_path": str(session.log_path),
                "summary_path": str(session.summary_path),
            }
        return self._load_summary(session.summary_path)

    def active_session(self) -> Optional[Dict[str, Any]]:
        with self._session_lock:
            session = self._active_session
        if session is None:
            return None
        return {
            "session_id": session.session_id,
            "serial": session.serial,
            "target": session.target,
            "log_path": str(session.log_path),
            "summary_path": str(session.summary_path),
            "mode": session.mode,
        }

    # -- Legacy one-shot wrappers -------------------------------------

    def run_script(
        self,
        process_name: str,
        script_key: str,
        custom_script_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        check_tool("frida")
        selector = self._frida_selector()
        self.ensure_online_device()
        script_path = custom_script_path or str(self.get_script_path(script_key))
        attach_flag = "-N" if "." in process_name else "-n"
        cmd = ["frida", *selector, attach_flag, process_name, "-l", script_path, "-q", "-t", "120", "--exit-on-error"]
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
        check_tool("frida")
        selector = self._frida_selector()
        self.ensure_online_device()
        script_path = custom_script_path or str(self.get_script_path(script_key))
        cmd = ["frida", *selector, "-f", package_name, "-l", script_path, "-q", "-t", "120", "--exit-on-error"]
        result = self._executor(cmd, timeout=120)
        return {
            "package": package_name,
            "script": script_key or custom_script_path,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "returncode": result.returncode,
        }

    # -- Internal helpers ----------------------------------------------

    def _configured_serial(self) -> Optional[str]:
        try:
            from utils.config import get_frida_config

            serial = get_frida_config().get("device_serial")
            return str(serial) if serial else None
        except Exception:
            return None

    def _configured_frida_server_path(self) -> Optional[str]:
        try:
            from utils.config import get_frida_config

            cfg = get_frida_config()
            return str(cfg.get("frida_server_path") or cfg.get("frida_server_directory") or "").strip() or None
        except Exception:
            return None

    def _frida_selector(self) -> List[str]:
        serial = self._configured_serial()
        return ["-D", serial] if serial else ["-U"]

    def _prepare_frida_server_privilege(self, serial: str) -> Dict[str, Any]:
        """For managed emulators, run adbd as root and restart shell-owned frida-server."""
        result: Dict[str, Any] = {"adb_root_attempted": False, "restarted_shell_server": False}
        if not serial.startswith("emulator-"):
            return result
        try:
            root_result = self._executor(self._adb_cmd(serial, "root"), timeout=15)
            result["adb_root_attempted"] = True
            result["adb_root_output"] = (root_result.stdout or root_result.stderr or "").strip()
            self._wait_for_device_online(serial, timeout=30)
        except Exception as exc:
            result["adb_root_error"] = str(exc)
            return result
        try:
            user = self._frida_server_user(serial)
            result["frida_server_user"] = user
            if user and user != "root":
                self._executor(self._adb_cmd(serial, "shell", "pkill", "-f", "frida-server"), timeout=10)
                result["restarted_shell_server"] = True
                time.sleep(0.5)
        except Exception as exc:
            result["frida_server_user_error"] = str(exc)
        return result

    def _frida_server_user(self, serial: str) -> str:
        result = self._executor(self._adb_cmd(serial, "shell", "ps", "-A"), timeout=10)
        for line in (result.stdout or "").splitlines():
            if "frida-server" not in line:
                continue
            parts = line.split()
            return parts[0] if parts else ""
        return ""

    def _pidof(self, serial: str, package_name: str) -> Optional[int]:
        try:
            result = self._executor(self._adb_cmd(serial, "shell", "pidof", package_name), timeout=10)
        except Exception:
            return None
        first = (result.stdout or "").strip().split()
        if not first:
            return None
        return _safe_int(first[0])

    def install_steps(self, tool: str) -> str:
        if tool == "adb":
            return (
                "Missing adb/platform-tools. Install Android platform-tools via Android Studio SDK Manager "
                "or run: sdkmanager --sdk_root=%LOCALAPPDATA%\\Android\\Sdk \"platform-tools\""
            )
        if tool == "emulator":
            return (
                "Missing Android emulator tools. Install them with Android SDK Manager or run: "
                "sdkmanager --sdk_root=%LOCALAPPDATA%\\Android\\Sdk \"emulator\" "
                "\"system-images;android-35;google_apis;x86_64\""
            )
        if tool == "frida":
            return (
                "Missing Frida host tools. Install them with: python -m pip install frida-tools. "
                "Then download the matching frida-server binary for the device ABI and push it with adb."
            )
        if tool == "sdkmanager":
            return (
                "Missing sdkmanager. Install Android command-line tools and add "
                "%LOCALAPPDATA%\\Android\\Sdk\\cmdline-tools\\latest\\bin to PATH."
            )
        if tool == "avdmanager":
            return (
                "Missing avdmanager. Install Android command-line tools and add "
                "%LOCALAPPDATA%\\Android\\Sdk\\cmdline-tools\\latest\\bin to PATH."
            )
        if tool == "frida-server":
            return (
                "Missing frida-server binary. Download the release that matches the device ABI "
                "(for example android-x86_64 or android-arm64) and set frida.frida_server_path "
                "to that file or to a directory that contains matching frida-server binaries."
            )
        return f"Install the missing tool '{tool}' and retry."

    def _list_avds(self) -> List[str]:
        result = self._executor([check_tool("emulator"), "-list-avds"], timeout=15)
        return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]

    def _describe_connected_device(self, device: Dict[str, str]) -> Dict[str, Any]:
        serial = device["serial"]
        state = device["state"]
        base = {
            "id": f"serial:{serial}",
            "label": serial,
            "avd_name": None,
            "frida_compatible": False,
            "frida_note": "",
            "abi": None,
        }
        if state == "unauthorized":
            base["frida_note"] = "Not compatible yet: adb authorization is still pending on the device."
            return base
        if state != "device":
            base["frida_note"] = f"Not compatible yet: adb reports the device as {state}."
            return base

        abi = self._getprop(serial, "ro.product.cpu.abi")
        avd_name = self._resolve_emulator_avd_name(serial) if serial.startswith("emulator-") else ""
        api_level = self._getprop(serial, "ro.build.version.sdk")
        base["abi"] = abi or None
        base["avd_name"] = avd_name or None
        base["api_level"] = _safe_int(api_level)
        if serial.startswith("emulator-"):
            avd_info = self._describe_local_avd(avd_name or serial, booted=True)
            base["frida_compatible"] = avd_info["frida_compatible"]
            base["frida_note"] = avd_info["frida_note"]
        else:
            base["frida_compatible"] = False
            base["frida_note"] = (
                "Not compatible for managed setup: physical devices require manual Frida server matching and device-specific "
                "permissions/root handling."
            )
        return base

    def _getprop(self, serial: str, prop: str) -> str:
        try:
            result = self._executor(["adb", "-s", serial, "shell", "getprop", prop], timeout=10)
        except Exception:
            return ""
        return (result.stdout or "").strip()

    def _resolve_emulator_avd_name(self, serial: str) -> str:
        for prop in ("ro.kernel.qemu.avd_name", "ro.boot.qemu.avd_name"):
            value = self._getprop(serial, prop)
            if value:
                return value
        try:
            result = self._executor(["adb", "-s", serial, "emu", "avd", "name"], timeout=10)
            value = (result.stdout or "").strip()
            if value and "unknown command" not in value.lower():
                return value
        except Exception:
            pass
        return ""

    def install_apks(self, apk_directory: Optional[str], *, serial: Optional[str] = None) -> Dict[str, Any]:
        if not apk_directory:
            return {
                "requested": False,
                "verified": True,
                "installed_count": 0,
                "installed_files": [],
                "installed_packages": [],
                "launch_performed": False,
                "details": "APK deployment not requested.",
            }
        path = Path(apk_directory).expanduser()
        if not path.exists():
            raise FridaDeviceError(f"APK directory does not exist: {path}")
        if not path.is_dir():
            raise FridaDeviceError(f"APK path is not a directory: {path}")
        apks = sorted(path.glob("*.apk"))
        if not apks:
            return {
                "requested": True,
                "verified": True,
                "installed_count": 0,
                "installed_files": [],
                "installed_packages": [],
                "launch_performed": False,
                "details": "APK directory did not contain any .apk files.",
            }
        serial = serial or str(self.ensure_online_device().get("serial"))
        installed_files = [str(apk.resolve()) for apk in apks]
        before_packages = self._list_installed_packages(serial)
        command = (
            self._adb_cmd(serial, "install", "-r", str(apks[0]))
            if len(apks) == 1
            else self._adb_cmd(serial, "install-multiple", "-r", *[str(apk) for apk in apks])
        )
        result = self._executor(command, timeout=300)
        stdout = (getattr(result, "stdout", "") or "").strip()
        stderr = (getattr(result, "stderr", "") or "").strip()
        after_packages = self._list_installed_packages(serial)
        installed_packages = sorted(after_packages - before_packages)
        verified = getattr(result, "returncode", 1) == 0 and ("Success" in stdout or bool(installed_packages))
        return {
            "requested": True,
            "verified": verified,
            "installed_count": len(installed_packages),
            "installed_files": installed_files,
            "installed_packages": installed_packages,
            "launch_performed": False,
            "details": stdout or stderr or "adb install did not return output.",
            "command": command,
        }

    def _adb_cmd(self, serial: Optional[str], *parts: str) -> List[str]:
        cmd = ["adb"]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(parts)
        return cmd

    def _normalize_script_parameters(self, script_key: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {key: value for key, value in (parameters or {}).items() if value not in (None, "")}
        if "class_names" in normalized and isinstance(normalized["class_names"], str):
            normalized["class_names"] = _split_parameter_values(normalized["class_names"])
        if script_key == "list_classes" and "class_filter" in normalized and isinstance(normalized["class_filter"], str):
            pieces = _split_parameter_values(normalized["class_filter"])
            normalized["class_filter"] = pieces if len(pieces) > 1 else (pieces[0] if pieces else "")
        return normalized

    def _resolve_frida_server_path(self, configured_path: Optional[str], *, serial: str) -> tuple[Optional[Path], Dict[str, Any]]:
        candidates: List[Path] = []
        diagnostics: Dict[str, Any] = {
            "configured_path": configured_path,
            "host_frida_version": self._host_frida_version(),
            "device_abi": None,
            "candidates": [],
            "selected": None,
        }
        if configured_path:
            configured = Path(configured_path).expanduser()
            if configured.is_file():
                resolved = configured.resolve()
                diagnostics["selected"] = str(resolved)
                return resolved, diagnostics
            if configured.is_dir():
                candidates.extend(sorted(configured.glob("*frida-server*")))
        abi = self._getprop(serial, "ro.product.cpu.abi")
        diagnostics["device_abi"] = abi or None
        abi_hint = safe_token((abi or "").replace("-", "_"), "frida")
        version = self._host_frida_version()
        exact_matches: List[Path] = []
        abi_matches: List[Path] = []
        version_matches: List[Path] = []
        diagnostics["candidates"] = [str(candidate.resolve()) for candidate in candidates]
        for candidate in candidates:
            name = candidate.name.lower()
            has_abi = bool(abi_hint and abi_hint in name)
            has_version = bool(version and version.lower() in name)
            if has_abi and has_version:
                exact_matches.append(candidate)
            elif has_abi:
                abi_matches.append(candidate)
            elif has_version:
                version_matches.append(candidate)
        selected = None
        if exact_matches:
            selected = exact_matches[0]
        elif abi_matches:
            selected = abi_matches[0]
        elif version_matches:
            selected = version_matches[0]
        elif candidates:
            selected = candidates[0]
        if selected is None:
            return None, diagnostics
        resolved = selected.resolve()
        diagnostics["selected"] = str(resolved)
        return resolved, diagnostics

    def _default_target(self, inventory: Dict[str, Any], preferred_avd: Optional[str]) -> Optional[str]:
        online = [device for device in inventory.get("connected_devices", []) if device.get("state") == "device"]
        if preferred_avd:
            preferred_serial = self._find_connected_avd_serial(preferred_avd, devices=inventory.get("connected_devices"))
            if preferred_serial:
                return f"serial:{preferred_serial}"
        if len(online) == 1:
            return str(online[0]["id"])
        if preferred_avd:
            for avd in inventory.get("local_avds", []):
                if avd.get("avd_name") == preferred_avd:
                    return str(avd["id"])
        compatible_avds = [avd for avd in inventory.get("local_avds", []) if avd.get("frida_compatible")]
        if len(online) > 1:
            configured = self._configured_serial()
            if configured:
                return f"serial:{configured}"
            return None
        return str(compatible_avds[0]["id"]) if len(compatible_avds) == 1 else None

    def _find_connected_avd_serial(self, avd_name: str, *, devices: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
        candidates = devices if devices is not None else _parse_adb_devices(self.list_devices())
        for device in candidates:
            serial = str(device.get("serial", ""))
            state = str(device.get("state", ""))
            current_avd_name = device.get("avd_name") or (self._resolve_emulator_avd_name(serial) if serial.startswith("emulator-") else "")
            if serial.startswith("emulator-") and current_avd_name == avd_name and state == "device":
                return serial
        return None

    def _wait_for_avd_serial_registration(self, *, adb_timeout: int, avd_name: str) -> str:
        deadline = time.time() + adb_timeout
        while time.time() < deadline:
            for device in _parse_adb_devices(self.list_devices()):
                serial = device["serial"]
                if serial.startswith("emulator-") and self._resolve_emulator_avd_name(serial) == avd_name:
                    return serial
            time.sleep(2)
        raise FridaDeviceError(f"Timed out waiting for AVD '{avd_name}' to register in adb devices.")

    def _wait_for_device_online(self, serial: str, timeout: int) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = self.get_device_state()
            if state.get("online") and state.get("serial") == serial:
                return serial
            devices = state.get("devices", [])
            for device in devices:
                if device.get("serial") == serial and device.get("state") == "device":
                    return serial
            time.sleep(2)
        raise FridaDeviceError(f"Timed out waiting for adb device {serial} to become online.")

    def _wait_for_boot_complete(self, serial: str, timeout: int) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._getprop(serial, "sys.boot_completed") == "1":
                return
            time.sleep(2)
        raise FridaDeviceError(f"Timed out waiting for Android boot to complete on {serial}.")

    def _describe_local_avd(self, avd_name: str, booted: bool) -> Dict[str, Any]:
        config = self._read_avd_config(avd_name)
        play_store = str(config.get("PlayStore.enabled", "")).lower() == "true"
        tag = str(config.get("tag.display", config.get("tag.id", ""))).lower()
        abi = str(config.get("abi.type", "")).lower()
        api_level = _extract_api_level(config, avd_name)
        google_apis = "google_apis" in tag or "google apis" in tag
        compatible = google_apis and not play_store and abi in {"x86_64", "x86", "arm64-v8a"} and api_level is not None and api_level < 36
        if play_store:
            note = "Not compatible for managed Frida: Play Store images usually block the adb-root workflow required for frida-server."
        elif api_level is None:
            note = "Not compatible for managed Frida: could not determine the Android API level for this AVD."
        elif api_level >= 36:
            note = (
                f"Not compatible for managed Frida: Android API {api_level} is beyond the validated Frida-managed range. "
                "Use API 35 or lower unless explicitly validated."
            )
        elif not google_apis:
            note = "Not compatible for managed Frida: use a Google APIs image so adb and emulator tooling behave predictably."
        elif abi not in {"x86_64", "x86", "arm64-v8a"}:
            note = f"Not compatible for managed Frida: unsupported ABI '{abi or 'unknown'}'."
        else:
            note = "Compatible for managed Frida: Google APIs image supports boot, adb, APK install, and frida-server bootstrap."
        return {
            "id": f"avd:{avd_name}",
            "label": avd_name,
            "avd_name": avd_name,
            "booted": booted,
            "frida_compatible": compatible,
            "frida_note": note,
            "abi": abi or None,
            "api_level": api_level,
        }

    def _host_frida_version(self) -> str:
        if self._host_frida_version_cache is not None:
            return self._host_frida_version_cache
        try:
            result = self._executor(["frida", "--version"], timeout=10)
            self._host_frida_version_cache = (result.stdout or "").strip()
        except Exception:
            self._host_frida_version_cache = ""
        return self._host_frida_version_cache

    def _read_avd_config(self, avd_name: str) -> Dict[str, str]:
        config_path = Path.home() / ".android" / "avd" / f"{avd_name}.avd" / "config.ini"
        values: Dict[str, str] = {}
        if not config_path.exists():
            return values
        for line in config_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    def _list_installed_packages(self, serial: str) -> set[str]:
        result = self._executor(self._adb_cmd(serial, "shell", "pm", "list", "packages"), timeout=20)
        packages = set()
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.add(line.split(":", 1)[1].strip())
        return packages

    def _package_installed(self, serial: str, package_name: str) -> bool:
        return package_name in self._list_installed_packages(serial)

    def _stream_pipe(
        self,
        session: FridaSession,
        pipe,
        channel: str,
        on_output: Optional[Callable[[str], None]],
    ) -> None:
        if pipe is None:
            return
        with session.log_path.open("a", encoding="utf-8") as handle:
            for raw_line in iter(pipe.readline, ""):
                line = self._clean_session_line(raw_line.rstrip("\r\n"))
                if not line:
                    continue
                tag = "[stderr]" if channel == "stderr" else "[stdout]"
                formatted = f"{tag} {line}"
                handle.write(formatted + "\n")
                handle.flush()
                if channel == "stderr":
                    session.error_line_count += 1
                else:
                    session.output_line_count += 1
                if on_output is not None:
                    on_output(formatted)
        try:
            pipe.close()
        except Exception:
            pass

    @staticmethod
    def _clean_session_line(line: str) -> str:
        stripped = line.strip()
        banner_markers = (
            stripped == "____"
            or "Frida " in stripped
            or stripped == "| (_| |"
            or stripped.startswith("> _  |")
            or stripped.startswith("/_/ |_|")
            or stripped.startswith(". . . .")
        )
        if banner_markers:
            return ""
        if stripped.startswith("[Android Emulator") and stripped.endswith("]->"):
            return ""
        return line

    def _watch_session(
        self,
        session: FridaSession,
        on_output: Optional[Callable[[str], None]],
        on_exit: Optional[Callable[[Dict[str, Any]], None]],
    ) -> None:
        exit_code = 1
        while True:
            if session.process is None:
                break
            exit_code = session.process.wait()
            for thread in session.reader_threads:
                thread.join(timeout=2)
            session.target_alive_at_exit = self.is_target_running(session.target, serial=session.serial)
            if session.stop_requested:
                session.status_reason = "stopped_by_user"
                exit_code = 0
                break
            if session.target_alive_at_exit and session.reattach_count < 1:
                session.reattach_count += 1
                self._append_session_line(
                    session,
                    "[STATUS] Frida session exited unexpectedly; attempting one automatic reattach",
                    "stderr",
                    on_output,
                )
                try:
                    self._start_cli_process(session, on_output)
                    continue
                except Exception as exc:
                    session.status_reason = f"reattach_failed: {exc}"
                    break
            if not session.target_alive_at_exit:
                session.status_reason = "target_died"
            elif _expected_long_running(session.script_key):
                session.status_reason = "unexpected_exit" if exit_code == 0 else f"unexpected_exit: code={exit_code}"
            elif exit_code == 0:
                session.status_reason = "completed"
            else:
                session.status_reason = f"unexpected_exit: code={exit_code}"
            break
        summary = self._write_session_summary(session, exit_code=exit_code)
        with self._session_lock:
            if self._active_session is session:
                self._active_session = None
        session.summary_written.set()
        if on_exit is not None:
            on_exit(summary)

    def _append_session_line(
        self,
        session: FridaSession,
        line: str,
        channel: str,
        on_output: Optional[Callable[[str], None]],
    ) -> None:
        cleaned = self._clean_session_line(line.rstrip("\r\n"))
        if not cleaned:
            return
        tag = "[stderr]" if channel == "stderr" else "[stdout]"
        formatted = f"{tag} {cleaned}"
        with session.log_path.open("a", encoding="utf-8") as handle:
            handle.write(formatted + "\n")
            handle.flush()
        if channel == "stderr":
            session.error_line_count += 1
        else:
            session.output_line_count += 1
        if on_output is not None:
            on_output(formatted)

    def _write_session_summary(self, session: FridaSession, *, exit_code: int) -> Dict[str, Any]:
        session.exit_code = exit_code
        summary = {
            "session_id": session.session_id,
            "serial": session.serial,
            "target": session.target,
            "attach_target": session.attach_target,
            "attach_flag": session.attach_flag,
            "script": session.script_key,
            "parameters": session.parameters,
            "command": session.command,
            "mode": session.mode,
            "target_running_before": session.target_running_before,
            "launch_performed": session.launch_performed,
            "frida_server_started": session.frida_server_started,
            "frida_server_path": session.frida_server_path,
            "session_backend": session.session_backend,
            "health_checks": session.health_checks,
            "rendered_script_path": str(session.rendered_script_path),
            "log_path": str(session.log_path),
            "summary_path": str(session.summary_path),
            "started_at": session.start_time,
            "ended_at": time.time(),
            "exit_code": exit_code,
            "stopped_by_user": session.stop_requested,
            "stdout_lines": session.output_line_count,
            "stderr_lines": session.error_line_count,
            "status_reason": session.status_reason or ("stopped_by_user" if session.stop_requested else "completed"),
            "reattach_count": session.reattach_count,
            "events_by_tag": dict(sorted(session.events_by_tag.items())),
            "dropped_event_count": session.dropped_event_count,
            "target_alive_at_exit": session.target_alive_at_exit,
            "expected_long_running": _expected_long_running(session.script_key),
            "status": (
                "stopped_by_user"
                if session.stop_requested
                else (
                    "completed"
                    if session.status_reason == "completed"
                    else ("unexpected_exit" if exit_code is not None else "running")
                )
            ),
        }
        session.summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    @staticmethod
    def _load_summary(path: Path) -> Dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))


class FridaDeviceError(RuntimeError):
    """Raised when no usable managed Frida state is available."""

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


def _parse_frida_process_table(output: str) -> List[Dict[str, str]]:
    processes: List[Dict[str, str]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("pid", "name", "----")):
            continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) == 3:
            processes.append({"pid": parts[0], "name": parts[1], "identifier": parts[2]})
        elif len(parts) == 2:
            processes.append({"pid": parts[0], "name": parts[1], "identifier": parts[1]})
        elif len(parts) == 1:
            processes.append({"pid": "", "name": parts[0], "identifier": parts[0]})
    return processes


def _event_tag(line: str) -> str:
    match = re.match(r"\s*\[([A-Za-z0-9_.:-]+)\]", line)
    return match.group(1).upper() if match else ""


def _extract_api_level(config: Dict[str, str], avd_name: str) -> Optional[int]:
    candidates = [config.get("image.sysdir.1", ""), config.get("sdk.api", ""), avd_name]
    for candidate in candidates:
        match = re.search(r"android-(\d+)|api[_-]?(\d+)", str(candidate), re.IGNORECASE)
        if not match:
            continue
        for group in match.groups():
            if group:
                return _safe_int(group)
    return None


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
