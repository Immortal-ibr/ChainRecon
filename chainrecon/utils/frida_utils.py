"""Pure-Python helpers for Frida log parsing (no Textual dependency)."""

from __future__ import annotations

from pathlib import Path


def _extract_frida_log_events(path: str | None, *, prefixes: tuple[str, ...], limit: int = 50) -> list[str]:
    if not path:
        return []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    matched = []
    for line in lines:
        stripped = line.strip()
        normalized = stripped
        if normalized.startswith("[stdout] "):
            normalized = normalized[len("[stdout] "):]
        if any(normalized.startswith(prefix) or stripped.startswith(prefix) for prefix in prefixes):
            matched.append(stripped)
    return matched[-limit:]
