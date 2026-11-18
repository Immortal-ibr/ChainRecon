"""Pytest collection policy for ChainRecon test categories."""

from __future__ import annotations

import sys
import os
import tempfile
from pathlib import Path

# Tests must never read or modify an analyst's personal case configuration.
_test_config_home = tempfile.TemporaryDirectory(prefix="chainrecon-test-config-")
os.environ["CHAINRECON_CONFIG_HOME"] = _test_config_home.name
os.environ.pop("CHAINRECON_CONFIG_FILE", None)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_collection_modifyitems(items):
    """Apply the project test taxonomy without forcing a disruptive file move."""
    for item in items:
        path = str(item.path).replace("\\", "/")
        name = item.name.lower()
        cls_name = (item.cls.__name__.lower() if item.cls else "")

        if "/e2e/" in path or "live" in cls_name or "run_test" in name or "tui" in path:
            item.add_marker("e2e")
        elif "/requirements/" in path or "requirement" in cls_name or "requirement" in name:
            item.add_marker("requirement")
        elif "/integration/" in path or any(token in cls_name for token in ("full", "dispatch", "output")):
            item.add_marker("integration")
        else:
            item.add_marker("unit")
