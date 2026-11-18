"""Built-in Frida script definitions and parameter normalization."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from chainrecon.utils.artifacts import safe_token


_SCRIPTS_DIR = Path(__file__).parent / "frida_scripts"
_ANSI_CONTROL_RE = re.compile(
    r"(?:\x1b\[[0-?]*[ -/]*[@-~])"
    r"|(?:\x1b\][^\x07]*(?:\x07|\x1b\\))"
    r"|(?:\x1b[@-Z\\-_])"
)


def _runtime_script_dir() -> Path:
    """Return the runtime-only directory for rendered Frida wrappers."""
    path = Path(tempfile.gettempdir()) / "chainrecon" / "frida_scripts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _script_filename_from_label(label: str) -> str:
    token = safe_token(label, "frida_script")
    return f"{token}.js"


def _expected_long_running(script_key: str) -> bool:
    runtime = FRIDA_SCRIPTS.get(script_key, {}).get("runtime", {})
    return bool(runtime.get("expected_long_running", runtime.get("expect_long_running_output", False)))


def _split_parameter_values(value: str) -> list[str]:
    pieces = re.split(r"[\r\n,;]+", value)
    return [piece.strip() for piece in pieces if piece.strip()]


def _normalize_optional_filter_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"*", "any", "all"}:
        return None
    return text


FRIDA_SCRIPTS: Dict[str, Dict[str, Any]] = {
    "list_classes": {
        "label": "List App Loaded Classes",
        "description": "Enumerate loaded Java classes in the attached app process. Filters accept comma, semicolon, or newline-separated terms.",
        "file": _script_filename_from_label("List App Loaded Classes"),
        "target_type": "package",
        "params": [
            {
                "name": "class_filter",
                "label": "Class filter",
                "placeholder": "com.example.camera; org.example.sdk",
                "default": "*",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": False},
    },
    "device_class_census": {
        "label": "Device-Wide Class Census",
        "description": "Iterate matching device processes explicitly and run a census-style class dump for each one so the result is device-scoped rather than a single attached-process snapshot.",
        "file": _script_filename_from_label("Device-Wide Class Census"),
        "target_type": "package",
        "params": [
            {
                "name": "class_filter",
                "label": "Class filter",
                "placeholder": "com.example.camera, mqtt, token",
                "default": "*",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "live_class_monitor": {
        "label": "Live Loaded Class Monitor",
        "description": "Continuously log newly loaded Java classes and Class.forName requests after the hook starts. Use a package/class filter to keep output manageable.",
        "file": _script_filename_from_label("Live Loaded Class Monitor"),
        "target_type": "package",
        "params": [
            {
                "name": "class_filter",
                "label": "Class filter",
                "placeholder": "com.example.camera; org.example.sdk; mqtt",
                "default": "*",
                "required": False,
            },
            {
                "name": "max_events_per_second",
                "label": "Max events/sec",
                "placeholder": "50",
                "default": "50",
                "required": False,
            },
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "hook_all_methods": {
        "label": "Hook Selected Class Methods",
        "description": "Hook every overload for one or more selected classes and stream calls live. Use package/class filters from the class-listing tools first, then paste the exact classes you want.",
        "file": _script_filename_from_label("Hook Selected Class Methods"),
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
                "default": "50",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "hook_method": {
        "label": "Hook Single Method",
        "description": "Hook one method and log arguments and return values.",
        "file": _script_filename_from_label("Hook Single Method"),
        "target_type": "package",
        "params": [
            {
                "name": "class_name",
                "label": "Class name",
                "placeholder": "com.example.camera.SomeClass",
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
        "file": _script_filename_from_label("SSL Pinning Bypass"),
        "target_type": "package",
        "params": [],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "http_intercept": {
        "label": "HTTP Trace",
        "description": "Trace Java/Android HTTP requests through URLConnection, HttpURLConnection, WebView, and OkHttp hooks without injecting a new interceptor into the target app.",
        "file": _script_filename_from_label("HTTP Trace"),
        "target_type": "package",
        "params": [
            {
                "name": "host_filter",
                "label": "Host filter",
                "placeholder": "api.example.invalid",
                "default": "*",
                "required": False,
            },
            {
                "name": "additional_classes",
                "label": "Additional classes",
                "placeholder": "One class per line, or comma / semicolon separated",
                "default": "",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "network_traffic_monitor": {
        "label": "Socket and URL Monitor",
        "description": "Trace URLConnection, Socket, and OkHttp traffic with concise event tags. Prefer this for long-running network activity when you need lower-overhead output than the HTTP trace.",
        "file": _script_filename_from_label("Socket and URL Monitor"),
        "target_type": "package",
        "params": [
            {
                "name": "host_filter",
                "label": "Host filter",
                "placeholder": "mqtt, camera, or leave blank",
                "default": "*",
                "required": False,
            },
            {
                "name": "additional_classes",
                "label": "Additional classes",
                "placeholder": "One class per line, or comma / semicolon separated",
                "default": "",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "crypto_monitor": {
        "label": "Crypto Monitor",
        "description": "Log selected Cipher, MessageDigest, and MAC operations.",
        "file": _script_filename_from_label("Crypto Monitor"),
        "target_type": "package",
        "params": [
            {
                "name": "algorithm_filter",
                "label": "Algorithm filter",
                "placeholder": "AES, HmacSHA256, SHA-256",
                "default": "*",
                "required": False,
            },
            {
                "name": "max_bytes",
                "label": "Hex preview bytes",
                "placeholder": "64",
                "default": "64",
                "required": False,
            },
            {
                "name": "reveal_sensitive",
                "label": "Reveal key and payload bytes (local only)",
                "default": "false",
                "required": False,
            },
            {
                "name": "additional_classes",
                "label": "Additional classes",
                "placeholder": "One class per line, or comma / semicolon separated",
                "default": "",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "shared_preferences_dump": {
        "label": "Shared Preferences Watch",
        "description": "Dump and watch SharedPreferences reads and writes.",
        "file": _script_filename_from_label("Shared Preferences Watch"),
        "target_type": "package",
        "params": [
            {
                "name": "key_filter",
                "label": "Key filter",
                "placeholder": "token, mqtt, user",
                "default": "*",
                "required": False,
            },
            {
                "name": "additional_classes",
                "label": "Additional classes",
                "placeholder": "One class per line, or comma / semicolon separated",
                "default": "",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "database_dump": {
        "label": "Database Monitor",
        "description": "Trace SQLite queries, inserts, and updates.",
        "file": _script_filename_from_label("Database Monitor"),
        "target_type": "package",
        "params": [
            {
                "name": "query_filter",
                "label": "Query filter",
                "placeholder": "device, mqtt, token",
                "default": "*",
                "required": False,
            }
        ],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": True},
    },
    "certificate_pinning_detect": {
        "label": "Certificate Pinning Detection",
        "description": "Detect common pinning implementations without modifying behavior.",
        "file": _script_filename_from_label("Certificate Pinning Detection"),
        "target_type": "package",
        "params": [],
        "runtime": {"launch_if_needed": True, "expect_long_running_output": False},
    },
}

FRIDA_SCRIPT_GUIDE: Dict[str, Dict[str, Any]] = {
    "list_classes": {
        "when_to_use": "Use first when you need app-process class discovery before choosing narrower hooks.",
        "expected_tags": ["[STATUS]", "[CLASS]"],
        "limitations": "Current attached app process only; not device-wide.",
    },
    "device_class_census": {
        "when_to_use": "Use when you want a broader census across matching device processes, not just one app attachment.",
        "expected_tags": ["[PROCESS]", "[STATUS]", "[CLASS]"],
        "limitations": "Runs each matching process sequentially, so large filters take longer and system processes can still be missed if Frida cannot attach.",
    },
    "live_class_monitor": {
        "when_to_use": "Use when you want to watch class loading activity from the moment the hook starts until you stop it.",
        "expected_tags": ["[STATUS]", "[CLASS-SEED]", "[CLASS-LOAD]", "[CLASS-FORNAME]", "[HOOK]", "[WARN]"],
        "limitations": "Safe mode logs class load and Class.forName activity; it does not auto-hook every method on every class.",
    },
    "hook_all_methods": {
        "when_to_use": "Use after class discovery when you need broad call tracing for a short list of exact classes.",
        "expected_tags": ["[HOOK]", "[CALL]", "[RET]", "[WARN]"],
        "limitations": "High-volume classes can flood output; keep class selection tight and use the rate limit.",
    },
    "hook_method": {
        "when_to_use": "Use when you already know the exact class and method you want to inspect.",
        "expected_tags": ["[HOOK]", "[CALL]", "[RET]", "[ERROR]"],
        "limitations": "Only hooks one method definition at a time and depends on the class being loaded.",
    },
    "ssl_pinning_bypass": {
        "when_to_use": "Use before HTTP or socket tracing when the target app enforces certificate pinning.",
        "expected_tags": ["[STATUS]", "[HOOK]", "[WARN]"],
        "limitations": "Common Android pinning patterns only; native or heavily obfuscated flows may still fail.",
    },
    "http_intercept": {
        "when_to_use": "Use for request and response tracing in Java HTTP stacks such as URLConnection, HttpURLConnection, WebView, and OkHttp.",
        "expected_tags": ["[HTTP-BUILD]", "[HTTP-REQ]", "[HTTP-RESP]", "[WEBVIEW]", "[HOOK]", "[WARN]"],
        "limitations": "Java-side traffic only; native sockets and custom transports can bypass these hooks.",
    },
    "network_traffic_monitor": {
        "when_to_use": "Use for lower-overhead long-running monitoring of sockets and URL opens.",
        "expected_tags": ["[SOCKET]", "[URL]", "[HTTP]", "[HOOK]", "[WARN]"],
        "limitations": "Less protocol detail than the HTTP trace and still limited to hookable Java networking APIs.",
    },
    "crypto_monitor": {
        "when_to_use": "Use when you need to confirm when ciphers, digests, or MACs are exercised at runtime.",
        "expected_tags": ["[CRYPTO-INIT]", "[CRYPTO-IN]", "[CRYPTO-OUT]", "[HASH-IN]", "[HASH-OUT]", "[HMAC-IN]", "[HMAC-OUT]", "[HOOK]", "[WARN]"],
        "limitations": "Does not decrypt payloads; it only traces selected crypto API usage.",
    },
    "shared_preferences_dump": {
        "when_to_use": "Use to observe preference reads and writes for tokens, broker settings, or feature flags.",
        "expected_tags": ["[PREF-GET]", "[PREF-PUT]", "[HOOK]", "[WARN]"],
        "limitations": "SharedPreferences only; Room, SQLite, and file-backed settings are outside this script.",
    },
    "database_dump": {
        "when_to_use": "Use to trace SQLite queries and narrow on tables related to devices, auth, or messaging.",
        "expected_tags": ["[DB-QUERY]", "[DB-EXEC]", "[DB-INSERT]", "[DB-UPDATE]", "[HOOK]", "[WARN]"],
        "limitations": "SQLite-focused; custom native storage and encrypted wrappers can reduce visibility.",
    },
    "certificate_pinning_detect": {
        "when_to_use": "Use when you want to detect likely pinning libraries before attempting a bypass.",
        "expected_tags": ["[STATUS]", "[PINNING]", "[WARN]"],
        "limitations": "Detection only; it does not alter behavior or guarantee every pinning path is found.",
    },
}
