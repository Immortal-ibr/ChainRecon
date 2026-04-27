import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runners.workflow_runner import WorkflowRunner
from utils.community_plugins import discover_community_plugins, load_community_plugin
from utils.config import list_device_profiles, load_device_profile


class DeviceProfileTests(unittest.TestCase):
    def test_builtin_device_profiles_are_listed(self):
        names = {item["name"] for item in list_device_profiles()}
        self.assertIn("Nooie Lab Device", names)

    def test_load_builtin_device_profile_by_name(self):
        profile = load_device_profile("nooie")
        self.assertEqual(profile["name"], "Nooie Lab Device")
        self.assertEqual(profile["target"], "192.168.123.99")
        self.assertIn("vendor", profile)
        self.assertIn("scan_defaults", profile)
        self.assertIn("firmware_rules", profile)


class CommunityPluginTests(unittest.TestCase):
    def test_discovers_example_plugin(self):
        descriptors = discover_community_plugins()
        names = {item["name"] for item in descriptors}
        self.assertIn("example_string_scan", names)
        descriptor = next(item for item in descriptors if item["name"] == "example_string_scan")
        self.assertEqual(descriptor["type"], "analyzer")
        self.assertEqual(descriptor["entrypoint"], "plugin.py:ExampleStringAnalyzer")

    def test_loads_example_plugin_and_analyzes_input(self):
        plugin = load_community_plugin("example_string_scan")
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.txt"
            sample.write_text("token=password\n", encoding="utf-8")
            result = plugin.analyze(input_path=str(sample))
        self.assertEqual(result["summary"]["hit_count"], 2)


class WorkflowRunnerTests(unittest.TestCase):
    def test_dry_run_renders_profile_and_target_overrides(self):
        with tempfile.TemporaryDirectory() as td:
            pipeline = Path(td) / "pipeline.yaml"
            pipeline.write_text(
                """
name: Demo Pipeline
variables:
  profile: quick
steps:
  - id: scan_main
    type: scan
    target: "{{ target }}"
    profile: "{{ profile }}"
  - id: optional_tls
    type: tls_scan
    when: "steps.scan_main.status == 'completed'"
    target: "{{ target }}"
""",
                encoding="utf-8",
            )
            result = WorkflowRunner(output_root=td).run(str(pipeline), target="10.0.0.1", profile="ssl", dry_run=True)
        self.assertEqual(result["summary"]["planned_step_count"], 1)
        self.assertEqual(result["summary"]["skipped_step_count"], 1)
        self.assertEqual(result["findings"]["steps"]["scan_main"]["rendered"]["profile"], "ssl")

    def test_community_step_executes_example_plugin(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.txt"
            sample.write_text("secret token\n", encoding="utf-8")
            pipeline = Path(td) / "pipeline.yaml"
            pipeline.write_text(
                f"""
name: Community Pipeline
steps:
  - id: strings
    type: community
    plugin: example_string_scan
    input: {json.dumps(str(sample))}
""",
                encoding="utf-8",
            )
            result = WorkflowRunner(output_root=td).run(str(pipeline))
        self.assertEqual(result["findings"]["steps"]["strings"]["status"], "completed")
        self.assertEqual(result["findings"]["steps"]["strings"]["result"]["summary"]["hit_count"], 2)

    def test_critical_failure_stops_workflow(self):
        with tempfile.TemporaryDirectory() as td:
            pipeline = Path(td) / "pipeline.yaml"
            pipeline.write_text(
                """
name: Failing Pipeline
steps:
  - id: bad_scan
    type: scan
    target: 10.0.0.1
    profile: quick
    critical: true
  - id: never_runs
    type: community
    plugin: example_string_scan
    input: ignored.txt
""",
                encoding="utf-8",
            )
            with patch("runners.workflow_runner.NmapRunner.run_scan", side_effect=RuntimeError("nmap failed")):
                result = WorkflowRunner(output_root=td).run(str(pipeline))
        self.assertEqual(result["summary"]["status"], "failed")
        self.assertNotIn("never_runs", result["findings"]["steps"])

    def test_when_reference_to_unknown_step_fails_validation(self):
        with tempfile.TemporaryDirectory() as td:
            pipeline = Path(td) / "pipeline.yaml"
            pipeline.write_text(
                """
name: Bad Pipeline
steps:
  - id: conditional
    type: scan
    target: 10.0.0.1
    profile: quick
    when: "steps.missing.status == 'completed'"
""",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                WorkflowRunner(output_root=td).run(str(pipeline), dry_run=True)

    def test_sample_nooie_mqtt_tls_pipeline_is_valid_yaml(self):
        """The bundled sample workflow should parse correctly and have the expected steps."""
        import yaml
        pipeline_path = Path(__file__).resolve().parents[2] / "workflows" / "nooie_mqtt_tls.yaml"
        self.assertTrue(pipeline_path.exists(), "Sample pipeline file missing")
        with open(pipeline_path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        self.assertIn("steps", doc)
        step_ids = [s["id"] for s in doc["steps"]]
        self.assertIn("port_scan", step_ids)
        self.assertIn("mqtt_tls_check", step_ids)
        self.assertIn("final_report", step_ids)
        self.assertEqual(len(step_ids), 4)