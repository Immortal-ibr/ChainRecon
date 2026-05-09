"""Configuration management for ChainRecon.

Loads settings with cascading priority:
  defaults -> config/default.yaml -> user YAML (--config) -> env vars
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_DEFAULT_CONFIG = _CONFIG_DIR / "default.yaml"
_DEVICE_PROFILE_DIR = _CONFIG_DIR.parent / "profiles" / "devices"

# Singleton cache
_loaded_config: Optional[Dict[str, Any]] = None


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (mutates base)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(user_config_path: Optional[str] = None, *, force_reload: bool = False) -> Dict[str, Any]:
    """Load the merged configuration dict.

    Parameters
    ----------
    user_config_path:
        Optional path to a user/device-specific YAML that overrides defaults.
    force_reload:
        When True, bypass the singleton cache and reload from disk.
    """
    global _loaded_config
    if _loaded_config is not None and not force_reload and user_config_path is None:
        return _loaded_config

    # 1. Built-in defaults
    config: Dict[str, Any] = {}
    if _DEFAULT_CONFIG.exists():
        with open(_DEFAULT_CONFIG, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    # 1.5. Local overrides (config/local.yaml) -- always applied automatically
    _local_config = _CONFIG_DIR / "local.yaml"
    if _local_config.exists():
        try:
            with open(_local_config, encoding="utf-8") as f:
                local_data = yaml.safe_load(f) or {}
            _deep_merge(config, local_data)
        except yaml.YAMLError as exc:
            import warnings
            warnings.warn(
                f"config/local.yaml has invalid YAML (skipping): {exc}\n"
                "Tip: Use single quotes for Windows paths, e.g.  jadx: 'C:\\path\\to\\jadx.bat'",
                RuntimeWarning,
                stacklevel=3,
            )

    # 2. User / device profile override
    if user_config_path:
        path = Path(user_config_path)
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    user_data = yaml.safe_load(f) or {}
                _deep_merge(config, user_data)
            except yaml.YAMLError as exc:
                import warnings
                warnings.warn(
                    f"{user_config_path} has invalid YAML (skipping): {exc}",
                    RuntimeWarning,
                    stacklevel=3,
                )

    # 3. Environment variable overrides
    _apply_env_overrides(config)

    _loaded_config = config
    return config


def get_config(user_config_path: Optional[str] = None) -> Dict[str, Any]:
    """Return the current configuration (loading if needed)."""
    return load_config(user_config_path)


def reset_config() -> None:
    """Clear the singleton cache (useful for testing)."""
    global _loaded_config
    _loaded_config = None


def get_tool_path(tool_name: str) -> Optional[str]:
    """Return a configured tool path override, or None to auto-detect."""
    cfg = get_config()
    return (cfg.get("tools") or {}).get(tool_name)


def get_api_key(service: str) -> Optional[str]:
    """Return an API key, preferring env vars over config file."""
    env_key = f"CHAINRECON_{service.upper()}_KEY"
    env_val = os.environ.get(env_key)
    if env_val:
        return env_val
    cfg = get_config()
    return (cfg.get("api_keys") or {}).get(service)


def get_iot_ports() -> Dict[int, str]:
    """Return the IoT port->protocol mapping."""
    cfg = get_config()
    raw = cfg.get("iot_ports") or {}
    return {int(k): str(v) for k, v in raw.items()}


def get_ssl_ports() -> list:
    """Return the SSL/TLS ports to probe."""
    cfg = get_config()
    return cfg.get("ssl_ports") or [443, 8443, 8008, 8080, 8883, 1883]


def get_scan_profiles() -> Dict[str, Any]:
    """Return scan profile definitions."""
    cfg = get_config()
    return cfg.get("scan_profiles") or {}


def get_capture_config() -> Dict[str, Any]:
    """Return capture-related settings."""
    cfg = get_config()
    return cfg.get("capture") or {}


def get_frida_config() -> Dict[str, Any]:
    """Return Frida-related settings."""
    cfg = get_config()
    return cfg.get("frida") or {}


def get_scan_config() -> Dict[str, Any]:
    """Return scan-related settings."""
    cfg = get_config()
    return cfg.get("scan") or {}


def get_output_config() -> Dict[str, Any]:
    """Return output-related settings."""
    cfg = get_config()
    return cfg.get("output") or {}


def get_network_config() -> Dict[str, Any]:
    """Return saved network setup values."""
    cfg = get_config()
    return cfg.get("network") or {}


def _validate_device_profile(payload: Dict[str, Any], path: Path) -> Dict[str, Any]:
    required = ("name", "vendor", "model", "ports", "expected_protocols", "scan_defaults", "frida_defaults", "firmware_rules")
    missing = [field for field in required if field not in payload]
    if missing:
        raise ValueError(f"Device profile {path} missing required fields: {', '.join(missing)}")
    if not isinstance(payload.get("ports"), list):
        raise ValueError(f"Device profile {path} field 'ports' must be a list.")
    if not isinstance(payload.get("expected_protocols"), list):
        raise ValueError(f"Device profile {path} field 'expected_protocols' must be a list.")
    for mapping_field in ("scan_defaults", "frida_defaults", "firmware_rules"):
        if not isinstance(payload.get(mapping_field), dict):
            raise ValueError(f"Device profile {path} field '{mapping_field}' must be a mapping.")
    validated = dict(payload)
    validated.setdefault("path", str(path.resolve()))
    return validated


def list_device_profiles() -> list[Dict[str, Any]]:
    profiles = []
    if not _DEVICE_PROFILE_DIR.exists():
        return profiles
    for path in sorted(_DEVICE_PROFILE_DIR.glob("*.yaml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(payload, dict):
            continue
        try:
            payload = _validate_device_profile(payload, path)
        except ValueError:
            continue
        profiles.append(_device_profile_descriptor(payload, path))
    return profiles


def load_device_profile(profile_name_or_path: Optional[str]) -> Dict[str, Any]:
    if not profile_name_or_path:
        return {}
    requested = Path(profile_name_or_path)
    if requested.exists():
        path = requested
    else:
        candidate = _DEVICE_PROFILE_DIR / f"{requested.stem}.yaml"
        if not candidate.exists():
            raise FileNotFoundError(f"Device profile not found: {profile_name_or_path}")
        path = candidate
    payload = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Device profile must be a mapping: {path}")
    return _validate_device_profile(payload, path)


def _device_profile_descriptor(payload: Dict[str, Any], path: Path) -> Dict[str, Any]:
    """Return the stable flattened shape consumed by TUI profile selectors."""
    validated = dict(payload)
    resolved = str(path.resolve())
    validated.setdefault("path", resolved)
    return {
        "stem": path.stem,
        "name": validated.get("name") or path.stem,
        "vendor": validated.get("vendor"),
        "model": validated.get("model"),
        "target": validated.get("target"),
        "ports": validated.get("ports") or [],
        "expected_protocols": validated.get("expected_protocols") or [],
        "scan_defaults": validated.get("scan_defaults") or {},
        "frida_defaults": validated.get("frida_defaults") or {},
        "firmware_rules": validated.get("firmware_rules") or {},
        "path": resolved,
        "profile": validated,
    }


def get_output_dir() -> Path:
    """Return the configured output directory as an absolute Path, creating it if needed."""
    cfg = get_config()
    raw = (cfg.get("output") or {}).get("directory", "output")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        # Resolve relative to the project root (where config/ lives)
        path = (_CONFIG_DIR.parent / path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_network_config(data: Dict[str, Any]) -> None:
    """Persist network setup values to config/local.yaml."""
    local_path = _CONFIG_DIR / "local.yaml"
    existing: Dict[str, Any] = {}
    if local_path.exists():
        with open(local_path, encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}
    existing["network"] = data
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with open(local_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(existing, f, default_flow_style=False)
    # Bust the singleton cache so next get_config() sees the update
    reset_config()


def save_frida_config(data: Dict[str, Any]) -> None:
    """Persist Frida-related values to config/local.yaml."""
    local_path = _CONFIG_DIR / "local.yaml"
    existing: Dict[str, Any] = {}
    if local_path.exists():
        with open(local_path, encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}
    merged = dict(existing.get("frida") or {})
    merged.update(data)
    existing["frida"] = merged
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with open(local_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(existing, f, default_flow_style=False)
    reset_config()


def save_scan_config(data: Dict[str, Any]) -> None:
    """Persist scan-related values to config/local.yaml."""
    local_path = _CONFIG_DIR / "local.yaml"
    existing: Dict[str, Any] = {}
    if local_path.exists():
        with open(local_path, encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}
    merged = dict(existing.get("scan") or {})
    merged.update(data)
    existing["scan"] = merged
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with open(local_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(existing, f, default_flow_style=False)
    reset_config()


def _apply_env_overrides(config: Dict[str, Any]) -> None:
    """Apply environment variable overrides to the config dict."""
    # API keys
    shodan_key = os.environ.get("CHAINRECON_SHODAN_KEY")
    if shodan_key:
        config.setdefault("api_keys", {})["shodan"] = shodan_key

    # Tool paths
    for tool in ("nmap", "tshark", "tcpdump", "adb", "frida", "openssl", "jadx", "apktool"):
        env_val = os.environ.get(f"CHAINRECON_{tool.upper()}_PATH")
        if env_val:
            config.setdefault("tools", {})[tool] = env_val
