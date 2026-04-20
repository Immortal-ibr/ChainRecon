"""Custom script library — save and load user-defined scripts across sessions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

_LIBRARY_FILE = Path(__file__).resolve().parent.parent / "config" / "custom_scripts.yaml"


def load_library() -> List[Dict[str, Any]]:
    """Return all saved custom scripts (list of dicts)."""
    if not _LIBRARY_FILE.exists() or yaml is None:
        return []
    try:
        with open(_LIBRARY_FILE, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_to_library(screen: str, script_path: str, interp: str, label: Optional[str] = None) -> None:
    """Persist a script entry to the library.  Silently skips duplicate paths."""
    scripts = load_library()
    # Avoid duplicates by (screen, path)
    for entry in scripts:
        if entry.get("path") == script_path and entry.get("screen") == screen:
            return
    scripts.append({
        "screen": screen,
        "path": script_path,
        "interp": interp,
        "label": label or Path(script_path).stem,
    })
    _LIBRARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if yaml is not None:
        with open(_LIBRARY_FILE, "w", encoding="utf-8") as fh:
            yaml.dump(scripts, fh, allow_unicode=True, default_flow_style=False)
