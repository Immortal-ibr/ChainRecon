"""Build distributions from a clean temporary source copy.

Setuptools reuses ``build/lib`` from previous builds. A deleted source file can
otherwise remain inside a newly built wheel.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


_GENERATED = {
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".venv", "__pycache__", "build", "dist", "venv",
}


def _ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name for name in names
        if name in _GENERATED or name.endswith((".egg-info", ".pyc"))
        or name in {".coverage", "coverage.xml", "coverage.json", "test-results.xml"}
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="dist")
    parser.add_argument("--no-isolation", action="store_true")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = Path(args.outdir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="chainrecon-clean-build-") as directory:
        checkout = Path(directory) / "source"
        shutil.copytree(source, checkout, ignore=_ignore)
        command = [sys.executable, "-m", "build", "--outdir", str(output)]
        if args.no_isolation:
            command.append("--no-isolation")
        return subprocess.run(command, cwd=checkout, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
