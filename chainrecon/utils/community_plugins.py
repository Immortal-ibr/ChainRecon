"""Community analyzer plugin discovery and loading."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from chainrecon.utils.artifacts import safe_token

COMMUNITY_PLUGIN_DIR = Path(__file__).resolve().parents[2] / "community_plugins"
_REQUIRED_MANIFEST_FIELDS = ("name", "version", "type", "entrypoint", "inputs", "outputs", "description")


def _normalize_plugin_manifest(payload: Dict[str, Any], plugin_dir: Path) -> Dict[str, Any]:
    missing = [field for field in _REQUIRED_MANIFEST_FIELDS if field not in payload]
    if missing:
        raise ValueError(f"Community plugin manifest missing required fields: {', '.join(missing)}")
    entrypoint = str(payload.get("entrypoint") or "").strip()
    if ":" not in entrypoint:
        raise ValueError("Community plugin entrypoint must use 'module.py:ClassName' format.")
    python_file, class_name = [part.strip() for part in entrypoint.split(":", 1)]
    if not python_file or not class_name:
        raise ValueError("Community plugin entrypoint must include both a module path and class name.")
    inputs = payload.get("inputs")
    outputs = payload.get("outputs")
    if not isinstance(inputs, list) or not all(isinstance(item, str) for item in inputs):
        raise ValueError("Community plugin manifest 'inputs' must be a list of strings.")
    if not isinstance(outputs, list) or not all(isinstance(item, str) for item in outputs):
        raise ValueError("Community plugin manifest 'outputs' must be a list of strings.")
    descriptor = dict(payload)
    descriptor["python_file"] = python_file
    descriptor["class_name"] = class_name
    descriptor["plugin_dir"] = str(plugin_dir.resolve())
    return descriptor


def discover_community_plugins(base_dir: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    root = Path(base_dir) if base_dir else COMMUNITY_PLUGIN_DIR
    if not root.exists():
        return []
    plugins: List[Dict[str, Any]] = []
    for plugin_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        manifest = plugin_dir / "plugin.yaml"
        if not manifest.exists():
            continue
        try:
            payload = yaml.safe_load(manifest.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(payload, dict):
            continue
        try:
            plugins.append(_normalize_plugin_manifest(payload, plugin_dir))
        except ValueError:
            continue
    return plugins


def load_community_plugin(name: str, base_dir: Optional[str | Path] = None):
    descriptor = get_community_plugin_descriptor(name, base_dir=base_dir)
    if descriptor is None:
        raise ValueError(f"Unknown community plugin: {name}")
    plugin_dir = Path(descriptor["plugin_dir"])
    module_path = plugin_dir / str(descriptor.get("python_file") or "plugin.py")
    if not module_path.exists():
        raise FileNotFoundError(f"Community plugin module not found: {module_path}")
    module_name = f"chainrecon.community.{safe_token(str(descriptor.get('name') or plugin_dir.name))}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load community plugin module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cls = getattr(module, str(descriptor.get("class_name") or "CommunityAnalyzer"))
    plugin = cls()
    setattr(plugin, "descriptor", descriptor)
    return plugin


def get_community_plugin_descriptor(name: str, base_dir: Optional[str | Path] = None) -> Optional[Dict[str, Any]]:
    for descriptor in discover_community_plugins(base_dir=base_dir):
        if str(descriptor.get("name")) == name or Path(str(descriptor.get("plugin_dir"))).name == name:
            return descriptor
    return None
