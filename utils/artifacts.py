"""Helpers for ChainRecon artifact naming and local file links."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


def timestamp_parts(now: datetime | None = None) -> tuple[str, str]:
    """Return local date and time parts used in artifact names."""
    current = now or datetime.now()
    return current.strftime("%Y%m%d"), current.strftime("%H%M%S")


def dated_name(stem: str, suffix: str, now: datetime | None = None) -> str:
    """Return a date-first artifact name like 20260423_scan_quick_124059.json."""
    date_part, time_part = timestamp_parts(now)
    return f"{date_part}_{stem}_{time_part}{suffix}"


def artifact_path(directory: str | Path, stem: str, suffix: str, now: datetime | None = None) -> Path:
    """Return a date-first artifact path inside *directory*."""
    return Path(directory) / dated_name(stem, suffix, now=now)


def timestamped_dir(base: str | Path, stem: str = "iot_recon", now: datetime | None = None) -> Path:
    """Return a date-first timestamped directory path inside *base*."""
    return Path(base) / dated_name(stem, "", now=now)


def safe_token(value: str, default: str = "artifact") -> str:
    """Return a filesystem-safe token suitable for filenames."""
    cleaned = "".join(ch.lower() if ch.isalnum() else "_" for ch in value.strip())
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    cleaned = cleaned.strip("_")
    return cleaned or default


def local_file_href(path: str | Path) -> str:
    """Return a file:/// URI for a local path, or an empty string on failure."""
    try:
        return Path(path).expanduser().resolve().as_uri()
    except Exception:
        return ""


def write_json_artifact(path: str | Path, payload: Any, *, sort_keys: bool = False) -> Path:
    """Write JSON through a flushed same-directory temp file, then atomically replace."""
    def _dump(handle) -> None:
        json.dump(payload, handle, indent=2, default=str, sort_keys=sort_keys)
        handle.write("\n")

    return write_text_artifact(path, _dump)


def update_artifact_index(directory: str | Path, record: dict[str, Any], index_name: str = "artifact_index.json") -> Path:
    """Append or replace a record in the output artifact index."""
    outdir = Path(directory).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    index_path = outdir / index_name
    records: list[dict[str, Any]] = []
    if index_path.exists():
        try:
            existing = json.loads(index_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(existing, dict):
                records = [item for item in existing.get("artifacts", []) if isinstance(item, dict)]
        except (OSError, json.JSONDecodeError):
            records = []

    normalized = dict(record)
    normalized.setdefault("updated_at", datetime.now().isoformat(timespec="seconds"))
    path_key = str(normalized.get("path") or normalized.get("source_file") or "")
    records = [
        item for item in records
        if str(item.get("path") or item.get("source_file") or "") != path_key
    ]
    records.append(normalized)
    write_json_artifact(index_path, {"artifacts": records})
    return index_path


def write_text_artifact(path: str | Path, content: str | Any) -> Path:
    """Write text content atomically and flush it so file pickers see it immediately."""
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    def _write_to_handle(handle) -> None:
        if callable(content):
            content(handle)
        else:
            handle.write(str(content))

    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            _write_to_handle(handle)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.replace(tmp_path, target)
        except PermissionError:
            with target.open("w", encoding="utf-8") as handle:
                _write_to_handle(handle)
                handle.flush()
                os.fsync(handle.fileno())
            tmp_path.unlink(missing_ok=True)
        return target
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise
