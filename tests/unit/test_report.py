"""Comprehensive tests for the ReportGenerator."""

import json
import tempfile
import unittest

from analysis import ReportGenerator
from models.finding import Category, Finding, FindingCollection, Severity


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
        self.assertEqual(data, {})

    def test_overwrite_section(self):
        gen = ReportGenerator()
        gen.add_traffic_results({"first": True})
        gen.add_traffic_results({"second": True})
        self.assertTrue(gen.get_data()["traffic"]["second"])

    def test_dynamic_section_is_retained(self):
        gen = ReportGenerator()
        gen.add_results("mqtt", {"findings": {"topics": ["iot/status"]}})
        self.assertIn("mqtt", gen.get_data())

    def test_append_mode_preserves_multiple_frida_sessions(self):
        gen = ReportGenerator()
        gen.add_results("frida", {
            "metadata": {"target": "app.one", "script": "list_classes", "source_file": "one.json"},
            "summary": {"status": "completed"},
            "findings": {"events_by_tag": {"HOOK": 1}, "hook_events": ["[HOOK] one"]},
        }, mode="append")
        gen.add_results("frida", {
            "metadata": {"target": "app.two", "script": "hook_all_methods", "source_file": "two.json"},
            "summary": {"status": "stopped_by_user"},
            "findings": {"events_by_tag": {"HOOK": 2}, "hook_events": ["[HOOK] two"]},
        }, mode="append")
        data = gen.get_data()["frida"]
        self.assertEqual(len(data["sessions"]), 2)
        self.assertEqual({session["target"] for session in data["sessions"]}, {"app.one", "app.two"})


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
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        path = gen.generate("json", fname)
        with open(fname, encoding="utf-8") as f:
            payload = json.load(f)
        self.assertEqual(path, fname)
        self.assertIn("traffic", payload)
        self.assertIn("ssl", payload)
        self.assertIn("scan", payload)

    def test_generate_html(self):
        gen = self._full_generator()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            fname = f.name
        gen.generate("html", fname)
        with open(fname, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("ChainRecon", content)
        self.assertIn("example.com", content)

    def test_generate_csv(self):
        gen = self._full_generator()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            fname = f.name
        gen.generate("csv", fname)
        with open(fname, encoding="utf-8", newline="") as f:
            content = f.read()
        self.assertIn("section", content)
        self.assertIn("traffic", content)

    def test_unknown_format_raises(self):
        gen = ReportGenerator()
        with self.assertRaises(ValueError):
            gen.generate("xml", "output.xml")

    def test_partial_data_generates_correctly(self):
        """Only traffic added, and untouched sections are omitted."""
        gen = ReportGenerator()
        gen.add_traffic_results({"findings": {"dns_queries": []}})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        gen.generate("json", fname)
        with open(fname, encoding="utf-8") as f:
            payload = json.load(f)
        self.assertIsNotNone(payload["traffic"])
        self.assertNotIn("ssl", payload)
        self.assertNotIn("scan", payload)

    def test_normalize_frida_section_adds_sessions_shape(self):
        gen = ReportGenerator()
        gen.add_results("frida", {
            "metadata": {"target": "com.nooie.home", "script": "network_traffic_monitor", "source_file": "session.json"},
            "summary": {"status": "stopped_by_user"},
            "findings": {"events_by_tag": {"HOOK": 3}, "hook_events": ["[HOOK] socket.connect"]},
        }, mode="append")
        data = gen.generate("json", tempfile.NamedTemporaryFile(suffix=".json", delete=False).name)
        self.assertTrue(data.endswith(".json"))


# ===========================================================================
# Finding model
# ===========================================================================


class FindingModelTests(unittest.TestCase):
    def _make(self, **kw):
        defaults = dict(
            title="Test", description="desc", severity=Severity.HIGH,
            category=Category.NETWORK, source="test",
        )
        defaults.update(kw)
        return Finding(**defaults)

    def test_to_dict_serialises_enums(self):
        f = self._make()
        d = f.to_dict()
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["category"], "network")

    def test_from_dict_roundtrip(self):
        f = self._make(recommendation="fix it")
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        self.assertEqual(f2.title, f.title)
        self.assertEqual(f2.severity, f.severity)
        self.assertEqual(f2.recommendation, "fix it")

    def test_id_auto_generated(self):
        f = self._make()
        self.assertEqual(len(f.id), 12)

    def test_timestamp_auto_generated(self):
        f = self._make()
        self.assertIn("T", f.timestamp)

    def test_severity_ordering(self):
        self.assertTrue(Severity.LOW < Severity.HIGH)
        self.assertFalse(Severity.CRITICAL < Severity.MEDIUM)


class FindingCollectionTests(unittest.TestCase):
    def _sample(self):
        col = FindingCollection()
        col.add(Finding("A", "desc", Severity.HIGH, Category.NETWORK, "nmap"))
        col.add(Finding("B", "desc", Severity.LOW, Category.TLS, "ssl"))
        col.add(Finding("C", "desc", Severity.HIGH, Category.CRYPTO, "apk"))
        return col

    def test_len(self):
        self.assertEqual(len(self._sample()), 3)

    def test_by_severity(self):
        col = self._sample()
        self.assertEqual(len(col.by_severity(Severity.HIGH)), 2)

    def test_by_category(self):
        col = self._sample()
        self.assertEqual(len(col.by_category(Category.TLS)), 1)

    def test_by_source(self):
        col = self._sample()
        self.assertEqual(len(col.by_source("apk")), 1)

    def test_severity_counts(self):
        col = self._sample()
        counts = col.severity_counts
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["low"], 1)

    def test_sorted_by_severity(self):
        col = self._sample()
        ordered = col.sorted_by_severity()
        self.assertEqual(ordered[0].severity, Severity.HIGH)
        self.assertEqual(ordered[-1].severity, Severity.LOW)

    def test_to_list_from_list_roundtrip(self):
        col = self._sample()
        data = col.to_list()
        col2 = FindingCollection.from_list(data)
        self.assertEqual(len(col2), 3)
        self.assertEqual(col2.findings[0].title, "A")

    def test_iter(self):
        col = self._sample()
        titles = [f.title for f in col]
        self.assertEqual(titles, ["A", "B", "C"])


# ===========================================================================
# Report generator with findings
# ===========================================================================


class ReportGeneratorFindingsTests(unittest.TestCase):
    def test_add_results_generic(self):
        gen = ReportGenerator()
        gen.add_results("apk", {"permissions": ["CAMERA"]})
        self.assertIn("apk", gen.get_data())

    def test_add_finding(self):
        gen = ReportGenerator()
        gen.add_finding(Finding("X", "d", Severity.HIGH, Category.NETWORK, "s"))
        self.assertEqual(len(gen.findings), 1)

    def test_add_findings_batch(self):
        gen = ReportGenerator()
        gen.add_findings([
            Finding("X", "d", Severity.HIGH, Category.NETWORK, "s"),
            Finding("Y", "d", Severity.LOW, Category.TLS, "s"),
        ])
        self.assertEqual(len(gen.findings), 2)

    def test_get_data_includes_findings_summary(self):
        gen = ReportGenerator()
        gen.add_finding(Finding("X", "d", Severity.CRITICAL, Category.CRYPTO, "s"))
        data = gen.get_data()
        self.assertEqual(data["findings_summary"]["total"], 1)
        self.assertEqual(data["findings_summary"]["by_severity"]["critical"], 1)
        self.assertEqual(len(data["findings"]), 1)

    def test_generate_json_with_findings(self):
        gen = ReportGenerator()
        gen.add_finding(Finding("Weak TLS", "desc", Severity.HIGH, Category.TLS, "ssl"))
        gen.add_traffic_results({"findings": {"dns": []}})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            fname = f.name
        gen.generate("json", fname)
        with open(fname, encoding="utf-8") as f:
            payload = json.load(f)
        self.assertIn("findings", payload)
        self.assertEqual(payload["findings"][0]["title"], "Weak TLS")

    def test_generate_html_with_findings(self):
        gen = ReportGenerator()
        gen.add_finding(Finding("Open Port", "desc", Severity.MEDIUM, Category.NETWORK, "nmap"))
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            fname = f.name
        gen.generate("html", fname)
        with open(fname, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Open Port", content)
        self.assertIn("Findings Summary", content)

    def test_no_findings_no_summary(self):
        gen = ReportGenerator()
        data = gen.get_data()
        self.assertNotIn("findings_summary", data)
        self.assertNotIn("findings", data)

    def test_add_findings_empty_iterable(self):
        gen = ReportGenerator()
        gen.add_findings([])
        self.assertEqual(len(gen.findings), 0)

    def test_findings_property_type(self):
        gen = ReportGenerator()
        self.assertIsInstance(gen.findings, FindingCollection)

    def test_add_results_overwrites(self):
        gen = ReportGenerator()
        gen.add_results("apk", {"v": 1})
        gen.add_results("apk", {"v": 2})
        self.assertEqual(gen.get_data()["apk"]["v"], 2)

    def test_generate_csv_with_findings(self):
        gen = ReportGenerator()
        gen.add_finding(Finding("CSV Test", "d", Severity.LOW, Category.NETWORK, "s"))
        gen.add_traffic_results({"findings": {"dns": [{"query": "test.com"}]}})
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            fname = f.name
        gen.generate("csv", fname)
        with open(fname, encoding="utf-8", newline="") as f:
            content = f.read()
        self.assertIn("section", content)


# ===========================================================================
# Finding model edge cases
# ===========================================================================


class FindingEdgeCaseTests(unittest.TestCase):
    def test_from_dict_invalid_severity(self):
        with self.assertRaises(ValueError):
            Finding.from_dict({
                "title": "X", "description": "d", "severity": "unknown",
                "category": "network", "source": "s", "id": "a", "timestamp": "t",
                "recommendation": "", "evidence": "", "references": [], "metadata": {},
            })

    def test_custom_id_preserved(self):
        f = Finding("T", "d", Severity.LOW, Category.TLS, "s", id="custom123")
        self.assertEqual(f.id, "custom123")

    def test_metadata_roundtrip(self):
        f = Finding(
            "T", "d", Severity.HIGH, Category.CRYPTO, "s",
            references=["https://example.com"],
            metadata={"port": 443, "cipher": "RC4"},
        )
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        self.assertEqual(f2.metadata["port"], 443)
        self.assertEqual(f2.references, ["https://example.com"])

    def test_empty_collection_helpers(self):
        col = FindingCollection()
        self.assertEqual(col.severity_counts, {})
        self.assertEqual(col.by_severity(Severity.HIGH), [])
        self.assertEqual(col.sorted_by_severity(), [])

    def test_from_list_empty(self):
        col = FindingCollection.from_list([])
        self.assertEqual(len(col), 0)

    def test_severity_full_ordering(self):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for i in range(len(order) - 1):
            self.assertTrue(order[i] < order[i + 1])


# ===========================================================================
# HTML fallback (no Jinja2)
# ===========================================================================


class HtmlFallbackTests(unittest.TestCase):
    def test_fallback_with_findings(self):
        from plugins.html_report import HtmlReportPlugin

        plugin = HtmlReportPlugin()
        html = plugin._generate_fallback(
            sections={"traffic": {"dns": ["example.com"]}},
            findings_summary={"total": 1, "by_severity": {"high": 1}},
            findings=[{"severity": "high", "title": "Open Port", "description": "Port 80 open"}],
        )
        self.assertIn("Open Port", html)
        self.assertIn("Total: 1", html)
        self.assertIn("Traffic", html)

    def test_fallback_escapes_xss(self):
        from plugins.html_report import HtmlReportPlugin

        plugin = HtmlReportPlugin()
        html = plugin._generate_fallback(
            sections={},
            findings_summary=None,
            findings=[{"severity": "high", "title": "<script>alert(1)</script>", "description": "d"}],
        )
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_sev_color_known(self):
        from plugins.html_report import HtmlReportPlugin

        plugin = HtmlReportPlugin()
        self.assertEqual(plugin._sev_color("critical"), "#dc2626")
        self.assertEqual(plugin._sev_color("high"), "#ea580c")

    def test_sev_color_unknown(self):
        from plugins.html_report import HtmlReportPlugin

        plugin = HtmlReportPlugin()
        self.assertEqual(plugin._sev_color("unknown"), "#6b7280")


if __name__ == "__main__":
    unittest.main()
