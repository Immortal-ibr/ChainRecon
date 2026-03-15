"""Comprehensive tests for the ReportGenerator."""

import json
import tempfile
import unittest

from analysis import ReportGenerator


class ReportGeneratorDataTests(unittest.TestCase):
    """Tests for data aggregation in ReportGenerator."""

    def test_add_traffic_results(self):
        gen = ReportGenerator()
        data = {"findings": {"dns_queries": [{"query": "example.com"}]}}
        gen.add_traffic_results(data)
        self.assertEqual(gen.get_data()["traffic"], data)

    def test_add_ssl_results(self):
        gen = ReportGenerator()
        data = {"findings": {"certificates": []}}
        gen.add_ssl_results(data)
        self.assertEqual(gen.get_data()["ssl"], data)

    def test_add_scan_results(self):
        gen = ReportGenerator()
        data = {"findings": {"hosts": []}}
        gen.add_scan_results(data)
        self.assertEqual(gen.get_data()["scan"], data)

    def test_get_data_returns_deep_copy(self):
        gen = ReportGenerator()
        gen.add_traffic_results({"findings": {"list": [1, 2, 3]}})
        copy1 = gen.get_data()
        copy2 = gen.get_data()
        copy1["traffic"]["findings"]["list"].append(4)
        self.assertEqual(len(copy2["traffic"]["findings"]["list"]), 3)

    def test_initial_state_all_none(self):
        gen = ReportGenerator()
        data = gen.get_data()
        self.assertIsNone(data["traffic"])
        self.assertIsNone(data["ssl"])
        self.assertIsNone(data["scan"])

    def test_overwrite_section(self):
        gen = ReportGenerator()
        gen.add_traffic_results({"first": True})
        gen.add_traffic_results({"second": True})
        self.assertTrue(gen.get_data()["traffic"]["second"])


class ReportGeneratorOutputTests(unittest.TestCase):
    """Tests for report generation via plugins."""

    def _full_generator(self):
        gen = ReportGenerator()
        gen.add_traffic_results({"findings": {"dns_queries": [{"query": "example.com"}]}})
        gen.add_ssl_results({"findings": {"security_findings": [{"title": "Weak cipher"}]}})
        gen.add_scan_results({"findings": {"hosts": [{"ip": "10.0.0.1"}]}})
        return gen

    def test_generate_json(self):
        gen = self._full_generator()
        with tempfile.NamedTemporaryFile("r+", suffix=".json", delete=False, encoding="utf-8") as f:
            path = gen.generate("json", f.name)
            f.seek(0)
            payload = json.load(f)
        self.assertEqual(path, f.name)
        self.assertIn("traffic", payload)
        self.assertIn("ssl", payload)
        self.assertIn("scan", payload)

    def test_generate_html(self):
        gen = self._full_generator()
        with tempfile.NamedTemporaryFile("r+", suffix=".html", delete=False, encoding="utf-8") as f:
            gen.generate("html", f.name)
            f.seek(0)
            content = f.read()
        self.assertIn("ChainRecon", content)
        self.assertIn("example.com", content)

    def test_generate_csv(self):
        gen = self._full_generator()
        with tempfile.NamedTemporaryFile("r+", suffix=".csv", delete=False, encoding="utf-8", newline="") as f:
            gen.generate("csv", f.name)
            f.seek(0)
            content = f.read()
        self.assertIn("section", content)
        self.assertIn("traffic", content)

    def test_unknown_format_raises(self):
        gen = ReportGenerator()
        with self.assertRaises(ValueError):
            gen.generate("xml", "output.xml")

    def test_partial_data_generates_correctly(self):
        """Only traffic added, ssl and scan are None."""
        gen = ReportGenerator()
        gen.add_traffic_results({"findings": {"dns_queries": []}})
        with tempfile.NamedTemporaryFile("r+", suffix=".json", delete=False, encoding="utf-8") as f:
            gen.generate("json", f.name)
            f.seek(0)
            payload = json.load(f)
        self.assertIsNotNone(payload["traffic"])
        self.assertIsNone(payload["ssl"])
        self.assertIsNone(payload["scan"])


if __name__ == "__main__":
    unittest.main()
