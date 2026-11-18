"""Pure-Python helpers for Frida log parsing (no Textual dependency)."""

from __future__ import annotations

from collections import deque
from pathlib import Path

from chainrecon.frida_events import redact_frida_output


def _extract_frida_log_events(path: str | None, *, prefixes: tuple[str, ...], limit: int = 50) -> list[str]:
    if not path or limit <= 0:
        return []
    matched: deque[str] = deque(maxlen=limit)
    try:
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                channel = ""
                normalized = stripped
                for prefix in ("[stdout] ", "[stderr] "):
                    if normalized.startswith(prefix):
                        channel = prefix
                        normalized = normalized[len(prefix):]
                        break
                if any(normalized.startswith(prefix) or stripped.startswith(prefix) for prefix in prefixes):
                    safe = redact_frida_output(normalized, reveal_sensitive=False).strip()
                    matched.append(channel + safe)
    except OSError:
        return []
    return list(matched)
