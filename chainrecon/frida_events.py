"""Structured, redacted Frida event records."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from chainrecon.utils.redaction import redact_text


_TAG = re.compile(r"^\[([A-Z][A-Z0-9_-]*)\]\s*(.*)$")
_PUBLIC_TAGS = {"STATUS", "WARN", "ERROR", "PROCESS", "CLASS", "DROPPED"}


def parse_event_line(line: str, *, channel: str = "stdout", reveal_sensitive: bool = False) -> dict[str, Any]:
    matched = _TAG.match(line.strip())
    tag = matched.group(1) if matched else "LOG"
    message = matched.group(2) if matched else line.strip()
    if not reveal_sensitive:
        message = redact_text(message)
        if tag not in _PUBLIC_TAGS:
            message = "[CONTENT REDACTED; rerun with explicit reveal_sensitive for local analysis]"
    return {
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "channel": channel,
        "tag": tag,
        "message": message,
    }


def redact_frida_output(output: str, *, reveal_sensitive: bool = False) -> str:
    if reveal_sensitive:
        return output
    lines = []
    for line in output.splitlines(keepends=True):
        event = parse_event_line(line, reveal_sensitive=False)
        prefix = f"[{event['tag']}] " if event["tag"] != "LOG" else ""
        ending = "\n" if line.endswith("\n") else ""
        lines.append(f"{prefix}{event['message']}{ending}")
    return "".join(lines)
