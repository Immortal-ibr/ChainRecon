"""Conservative redaction and spreadsheet export safeguards."""

from __future__ import annotations

import re
from typing import Any


_SENSITIVE_KEY = re.compile(r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|(?:^|[_-])tokens?(?:$|[_-])|private[_-]?key|authorization|credential)", re.I)
_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|authorization)\s*([=:])\s*([^\s,;\"']+)")
_FLAG_VALUE = re.compile(
    r"(?i)(--(?:password|passwd|secret|api[_-]?key|(?:access|refresh)[_-]?token|token|authorization)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)"
)
_QUOTED_ASSIGNMENT = re.compile(
    r"(?i)([\"'])(password|passwd|secret|api[_-]?key|token|authorization)\1(\s*:\s*)([\"'])(?:\\.|(?!\4).)*?\4"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_WINDOWS_HOME = re.compile(r"(?i)[A-Z]:[/\\]Users[/\\][^/\\\s]+(?:[/\\][^\s\"'<>]+)*")
_UNIX_HOME = re.compile(r"/(?:home|Users)/[^/\s]+(?:/[^\s\"'<>]+)*")


def redact_text(value: str) -> str:
    value = _PRIVATE_KEY.sub("[PRIVATE KEY REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _FLAG_VALUE.sub(lambda m: f"{m.group(1)}[REDACTED]", value)
    value = _QUOTED_ASSIGNMENT.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}{m.group(4)}[REDACTED]{m.group(4)}",
        value,
    )
    value = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)
    value = _WINDOWS_HOME.sub("[LOCAL_PATH]", value)
    return _UNIX_HOME.sub("[LOCAL_PATH]", value)


def redact_report_data(value: Any, *, key: str = "") -> Any:
    if key and _SENSITIVE_KEY.search(key) and key.lower() not in {"credential_hit_count", "credential_count", "private_key_count", "password_hash_type", "token_count"}:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: redact_report_data(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_report_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_report_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def spreadsheet_cell(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
