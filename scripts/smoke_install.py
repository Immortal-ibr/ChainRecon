"""Check a clean wheel install without importing the repository checkout."""

from __future__ import annotations

import argparse
import glob
import os
import subprocess
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", help="Built wheel or source archive")
    parser.add_argument("--offline", action="store_true", help="Use installed system dependencies without package downloads")
    args = parser.parse_args()
    matches = glob.glob(args.artifact)
    if len(matches) != 1:
        raise ValueError(f"Expected one artifact matching {args.artifact}, found {len(matches)}")
    artifact = Path(matches[0]).resolve(strict=True)
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            members = set(archive.namelist())
    elif artifact.name.endswith(".tar.gz"):
        with tarfile.open(artifact, "r:gz") as archive:
            members = {name.partition("/")[2] for name in archive.getnames()}
    else:
        raise ValueError(f"Expected a wheel or source archive: {artifact}")
    required = {
        "chainrecon/resources/config/default.yaml",
        "chainrecon/resources/config/apk_patterns.yaml",
        "chainrecon/resources/profiles/generic_camera.yaml",
        "chainrecon/resources/scripts/network_setup.sh",
        "chainrecon/resources/scripts/network_setup.ps1",
        "chainrecon/resources/workflows/example.yaml",
        "chainrecon/resources/community_plugins/example_string_scan/plugin.py",
    }
    missing = required - members
    if missing:
        raise RuntimeError(f"Package lacks required built-in assets: {sorted(missing)}")
    if any("nooie" in name.lower() or "local.yaml" in name.lower() or ".coverage" in name.lower() for name in members):
        raise RuntimeError("Package contains private lab or test material")
    with tempfile.TemporaryDirectory(prefix="chainrecon-wheel-smoke-") as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True, system_site_packages=args.offline).create(root / "venv")
        python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        install = [str(python), "-m", "pip", "install"]
        if args.offline:
            install.extend(("--no-index", "--no-deps"))
        subprocess.run([*install, f"{artifact}[tui]"], cwd=root, env=env, check=True)
        subprocess.run([str(python), "-I", "-m", "chainrecon", "--help"], cwd=root, env=env, check=True, capture_output=True)
        command = root / "venv" / ("Scripts/chainrecon.exe" if os.name == "nt" else "bin/chainrecon")
        subprocess.run([str(command), "--help"], cwd=root, env=env, check=True, capture_output=True)
        code = """
import importlib.resources as resources
from importlib.metadata import version
import chainrecon
from chainrecon.tui.app import ChainReconApp
from chainrecon.tui.widgets.help_footer import HelpFooter
from chainrecon.case_model import Case
from chainrecon.analysis_catalog import analyzer_for_kind
from chainrecon.utils.config import get_config
from chainrecon.version import VERSION
import asyncio
print('PACKAGE_PATH=' + chainrecon.__file__, flush=True)
assert version('chainrecon') == VERSION
assert (resources.files('chainrecon') / 'resources/config/default.yaml').is_file()
assert 'case' in ChainReconApp.SCREENS
assert 'case_analysis' in ChainReconApp.SCREENS
assert analyzer_for_kind('scan_xml') == 'scan'
assert analyzer_for_kind('uart_log') is None
assert get_config()
assert chainrecon.main(['case', 'init', './case']) == 0
example = resources.files('chainrecon') / 'resources/workflows/example.yaml'
assert chainrecon.main(['case', 'add', './case', str(example), '--kind', 'other']) == 0
assert len(Case.open('./case').manifest['evidence']) == 1
assert chainrecon.main(['workflow', 'plan', str(example)]) == 0
async def check_tui():
    app = ChainReconApp()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.screen.query_one(HelpFooter)
asyncio.run(check_tui())
"""
        result = subprocess.run([str(python), "-I", "-c", code], cwd=root, env=env, check=True, capture_output=True, text=True)
        package_paths = [line.partition("=")[2] for line in result.stdout.splitlines() if line.startswith("PACKAGE_PATH=")]
        if len(package_paths) != 1:
            raise RuntimeError("Clean install did not report its imported package path")
        installed = Path(package_paths[0]).resolve()
        if Path.cwd().resolve() in installed.parents:
            raise RuntimeError("Smoke imported the repository checkout instead of the package")
        print(f"Clean {artifact.name} import: {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
