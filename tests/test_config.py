"""Tests for the YAML configuration system."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from utils.config import (
    _deep_merge,
    get_api_key,
    get_capture_config,
    get_config,
    get_frida_config,
    get_iot_ports,
    get_output_config,
    get_scan_profiles,
    get_ssl_ports,
    get_tool_path,
    load_config,
    reset_config,
)


class DeepMergeTests(unittest.TestCase):
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        self.assertEqual(result, {"a": 1, "b": 3, "c": 4})

    def test_nested_merge(self):
        base = {"tools": {"nmap": None, "tshark": None}}
        override = {"tools": {"nmap": "/usr/bin/nmap"}}
        result = _deep_merge(base, override)
        self.assertEqual(result["tools"]["nmap"], "/usr/bin/nmap")
        self.assertIsNone(result["tools"]["tshark"])

    def test_override_replaces_non_dict(self):
        base = {"ssl_ports": [443, 8443]}
        override = {"ssl_ports": [443]}
        result = _deep_merge(base, override)
        self.assertEqual(result["ssl_ports"], [443])


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        reset_config()

    def tearDown(self):
        reset_config()

    def test_loads_default_config(self):
        config = load_config(force_reload=True)
        self.assertIn("tools", config)
        self.assertIn("scan_profiles", config)
        self.assertIn("iot_ports", config)
        self.assertIn("ssl_ports", config)

    def test_user_config_overrides_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "override.yaml")
            with open(cfg_path, "w") as f:
                f.write("ssl_ports: [443, 9443]\n")
            config = load_config(cfg_path, force_reload=True)
            self.assertEqual(config["ssl_ports"], [443, 9443])

    def test_singleton_caching(self):
        config1 = load_config(force_reload=True)
        config2 = get_config()
        self.assertIs(config1, config2)

    def test_force_reload_clears_cache(self):
        config1 = load_config(force_reload=True)
        config2 = load_config(force_reload=True)
        self.assertIsNot(config1, config2)

    def test_env_var_overrides_api_key(self):
        with patch.dict(os.environ, {"CHAINRECON_SHODAN_KEY": "test-key-123"}):
            config = load_config(force_reload=True)
            self.assertEqual(config["api_keys"]["shodan"], "test-key-123")

    def test_env_var_overrides_tool_path(self):
        with patch.dict(os.environ, {"CHAINRECON_NMAP_PATH": "/custom/nmap"}):
            config = load_config(force_reload=True)
            self.assertEqual(config["tools"]["nmap"], "/custom/nmap")

    def test_nonexistent_user_config_ignored(self):
        config = load_config("/nonexistent/path.yaml", force_reload=True)
        # Should still have defaults
        self.assertIn("tools", config)


class HelperFunctionTests(unittest.TestCase):
    def setUp(self):
        reset_config()

    def tearDown(self):
        reset_config()

    def test_get_tool_path_returns_none_by_default(self):
        load_config(force_reload=True)
        self.assertIsNone(get_tool_path("nmap"))

    def test_get_api_key_from_env(self):
        with patch.dict(os.environ, {"CHAINRECON_SHODAN_KEY": "env-key"}):
            self.assertEqual(get_api_key("shodan"), "env-key")

    def test_get_iot_ports_returns_dict(self):
        load_config(force_reload=True)
        ports = get_iot_ports()
        self.assertIsInstance(ports, dict)
        self.assertIn(1883, ports)
        self.assertEqual(ports[1883], "MQTT")

    def test_get_ssl_ports_returns_list(self):
        load_config(force_reload=True)
        ports = get_ssl_ports()
        self.assertIsInstance(ports, list)
        self.assertIn(443, ports)

    def test_get_scan_profiles_returns_dict(self):
        load_config(force_reload=True)
        profiles = get_scan_profiles()
        self.assertIn("quick", profiles)
        self.assertIn("iot", profiles)

    def test_get_capture_config(self):
        load_config(force_reload=True)
        cap = get_capture_config()
        self.assertEqual(cap.get("default_duration"), 60)

    def test_get_frida_config(self):
        load_config(force_reload=True)
        frida = get_frida_config()
        self.assertIsNone(frida.get("device_serial"))

    def test_get_output_config(self):
        load_config(force_reload=True)
        out = get_output_config()
        self.assertEqual(out.get("default_format"), "json")


if __name__ == "__main__":
    unittest.main()
