"""Validate all built distributions on both PowerShell and Bash runners."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path


def main() -> int:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    prefix = f"{project['name'].replace('-', '_')}-{project['version']}"
    artifacts = sorted(
        path for path in Path("dist").iterdir()
        if path.name == f"{prefix}.tar.gz"
        or (path.name.startswith(f"{prefix}-") and path.suffix == ".whl")
    )
    if len(artifacts) != 2 or not any(path.suffix == ".whl" for path in artifacts) or not any(path.name.endswith(".tar.gz") for path in artifacts):
        raise RuntimeError(f"Expected one wheel and one sdist in dist/, found: {[path.name for path in artifacts]}")
    return subprocess.run([sys.executable, "-m", "twine", "check", *(str(path) for path in artifacts)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
