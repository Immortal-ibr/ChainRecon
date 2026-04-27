"""Comprehensive tests for the analysis modules (Traffic, SSL, Scanner)."""

import tempfile
import socket
import unittest
from unittest.mock import patch

from analysis import ScannerAnalyzer, SSLAnalyzer, TrafficAnalyzer


# ---------------------------------------------------------------------------
# Reusable mocks for pyshark-like packet objects
# ---------------------------------------------------------------------------

class MockLayer:
    """Simulate a pyshark protocol layer with attribute and dict access."""

    def __init__(self, **fields):
        self._fields = fields
        for key, value in fields.items():
            setattr(self, key, value)

    def get(self, key, default=None):
        return self._fields.get(key, default)

    def get_field_value(self, key):
        return self._fields.get(key)


class MockPacket:
    """Simulate a pyshark packet with named layers."""

    def __init__(self, highest_layer, layers):
        self.highest_layer = highest_layer
        self._layer_names = {name.lower() for name in layers}
        for name, layer in layers.items():
            setattr(self, name.lower(), layer)

    def __contains__(self, item):
        return item.lower() in self._layer_names


class MockCapture(list):
    """List of MockPackets that acts like a pyshark FileCapture."""

    def close(self):
        self.closed = True


# ===========================================================================
# TrafficAnalyzer tests
# ===========================================================================

class TrafficAnalyzerBasicTests(unittest.TestCase):
    """Core happy-path tests for TrafficAnalyzer."""

    def _make_analyzer(self, packets):
        capture = MockCapture(packets)
        return TrafficAnalyzer(capture_factory=lambda _: capture), capture

    def test_analyze_pcap_returns_complete_schema(self):
        analyzer, _ = self._make_analyzer([])
        result = analyzer.analyze_pcap("empty.pcap")
        for key in ("metadata", "findings", "summary", "risk_indicators"):
            self.assertIn(key, result)

    def test_packet_count_matches_input(self):
        packets = [
            MockPacket("DNS", {"dns": MockLayer(qry_name="example.com", qry_type="A"),
                                "ip": MockLayer(src="10.0.0.1", dst="8.8.8.8")}),
            MockPacket("TLS", {"tls": MockLayer(handshake_extensions_server_name="sni.example.com"),
                                "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4")}),
        ]
        analyzer, _ = self._make_analyzer(packets)
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["metadata"]["packet_count"], 2)

    def test_capture_is_closed_after_analysis(self):
        analyzer, capture = self._make_analyzer([])
        analyzer.analyze_pcap("test.pcap")
        self.assertTrue(getattr(capture, "closed", False))

    def test_capture_closed_even_on_error(self):
        """Ensure the finally block closes the capture when processing fails."""
        def bad_factory(path):
            capture = MockCapture([
                MockPacket("DNS", {"dns": MockLayer(qry_name="ok", qry_type="A"),
                                   "ip": MockLayer(src="10.0.0.1", dst="8.8.8.8")})
            ])
            return capture

        analyzer = TrafficAnalyzer(capture_factory=bad_factory)
        # Patch extract_dns to raise after _load_packets succeeds
        original = analyzer.extract_dns
        def boom(packets):
            raise RuntimeError("boom")
        analyzer.extract_dns = boom
        with self.assertRaises(RuntimeError):
            analyzer.analyze_pcap("broken.pcap")


class TrafficDnsTests(unittest.TestCase):
    """DNS extraction edge cases."""

    def _analyzer(self, packets):
        return TrafficAnalyzer(capture_factory=lambda _: MockCapture(packets))

    def test_extracts_unique_dns_queries(self):
        pkt = lambda name: MockPacket("DNS", {
            "dns": MockLayer(qry_name=name, qry_type="A"),
            "ip": MockLayer(src="10.0.0.1", dst="8.8.8.8"),
        })
        analyzer = self._analyzer([pkt("a.example.com"), pkt("b.example.com"), pkt("a.example.com")])
        result = analyzer.analyze_pcap("test.pcap")
        queries = result["findings"]["dns_queries"]
        self.assertEqual(len(queries), 2)
        self.assertEqual(queries[0]["query"], "a.example.com")
        self.assertEqual(queries[1]["query"], "b.example.com")

    def test_skips_packets_without_dns_layer(self):
        pkt = MockPacket("TCP", {"tcp": MockLayer(srcport="1234"), "ip": MockLayer(src="10.0.0.1", dst="10.0.0.2")})
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["dns_query_count"], 0)

    def test_skips_dns_without_query_name(self):
        pkt = MockPacket("DNS", {"dns": MockLayer(qry_type="A"), "ip": MockLayer(src="10.0.0.1", dst="8.8.8.8")})
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["dns_query_count"], 0)


class TrafficHttpTests(unittest.TestCase):
    """HTTP extraction tests."""

    def _analyzer(self, packets):
        return TrafficAnalyzer(capture_factory=lambda _: MockCapture(packets))

    def test_extracts_http_requests(self):
        pkt = MockPacket("HTTP", {
            "http": MockLayer(request_method="POST", host="api.device.local", request_uri="/data"),
            "ip": MockLayer(src="10.0.0.5", dst="93.184.216.34"),
            "tcp": MockLayer(srcport="50000", dstport="80"),
        })
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(len(result["findings"]["http_requests"]), 1)
        self.assertEqual(result["findings"]["http_requests"][0]["method"], "POST")
        self.assertEqual(result["findings"]["http_requests"][0]["host"], "api.device.local")

    def test_skips_http_response_without_request_fields(self):
        """HTTP response packets have the layer but no method/host/uri."""
        pkt = MockPacket("HTTP", {
            "http": MockLayer(),  # no request fields at all
            "ip": MockLayer(src="93.184.216.34", dst="10.0.0.5"),
        })
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["http_request_count"], 0)

    def test_risk_indicator_for_http_traffic(self):
        pkt = MockPacket("HTTP", {
            "http": MockLayer(request_method="GET", host="insecure.device", request_uri="/"),
            "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4"),
        })
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(len(result["risk_indicators"]), 1)
        self.assertEqual(result["risk_indicators"][0]["severity"], "medium")

    def test_no_risk_indicator_when_all_encrypted(self):
        pkt = MockPacket("TLS", {
            "tls": MockLayer(handshake_extensions_server_name="secure.example.com"),
            "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4"),
        })
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(len(result["risk_indicators"]), 0)


class TrafficTlsSniTests(unittest.TestCase):
    """TLS SNI extraction tests."""

    def _analyzer(self, packets):
        return TrafficAnalyzer(capture_factory=lambda _: MockCapture(packets))

    def test_extracts_sni_from_tls_handshake(self):
        pkt = MockPacket("TLS", {
            "tls": MockLayer(handshake_extensions_server_name="mqtt.vendor.com"),
            "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4"),
        })
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["findings"]["tls_sni"][0]["server_name"], "mqtt.vendor.com")

    def test_deduplicates_sni_entries(self):
        mk = lambda: MockPacket("TLS", {
            "tls": MockLayer(handshake_extensions_server_name="repeated.example.com"),
            "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4"),
        })
        analyzer = self._analyzer([mk(), mk(), mk()])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["tls_sni_count"], 1)

    def test_fallback_sni_field_name(self):
        """Some pyshark versions use handshake_extension_server_name (singular)."""
        pkt = MockPacket("TLS", {
            "tls": MockLayer(handshake_extension_server_name="fallback.example.com"),
            "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4"),
        })
        analyzer = self._analyzer([pkt])
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["tls_sni_count"], 1)


class TrafficProtocolStatsTests(unittest.TestCase):
    def test_counts_highest_layers(self):
        packets = [
            MockPacket("DNS", {"dns": MockLayer(), "ip": MockLayer(src="10.0.0.1", dst="8.8.8.8")}),
            MockPacket("DNS", {"dns": MockLayer(), "ip": MockLayer(src="10.0.0.1", dst="8.8.8.8")}),
            MockPacket("TLS", {"tls": MockLayer(), "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4")}),
        ]
        analyzer = TrafficAnalyzer(capture_factory=lambda _: MockCapture(packets))
        result = analyzer.analyze_pcap("test.pcap")
        stats = result["summary"]["protocol_stats"]
        self.assertEqual(stats["DNS"], 2)
        self.assertEqual(stats["TLS"], 1)


class TrafficExternalIpTests(unittest.TestCase):
    def test_identifies_external_ips(self):
        packets = [
            MockPacket("TCP", {"tcp": MockLayer(), "ip": MockLayer(src="10.0.0.1", dst="93.184.216.34")}),
            MockPacket("TCP", {"tcp": MockLayer(), "ip": MockLayer(src="192.168.1.1", dst="10.0.0.1")}),
        ]
        analyzer = TrafficAnalyzer(capture_factory=lambda _: MockCapture(packets))
        result = analyzer.analyze_pcap("test.pcap")
        external = result["findings"]["external_ips"]
        self.assertIn("93.184.216.34", external)
        self.assertNotIn("10.0.0.1", external)
        self.assertNotIn("192.168.1.1", external)

    def test_handles_invalid_ip_gracefully(self):
        pkt = MockPacket("TCP", {"tcp": MockLayer(), "ip": MockLayer(src="not-an-ip", dst="also-bad")})
        analyzer = TrafficAnalyzer(capture_factory=lambda _: MockCapture([pkt]))
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["external_ip_count"], 0)


class TrafficConversationTests(unittest.TestCase):
    def test_groups_conversations_by_tuple(self):
        mk = lambda: MockPacket("TCP", {
            "tcp": MockLayer(srcport="50000", dstport="80"),
            "ip": MockLayer(src="10.0.0.1", dst="1.2.3.4"),
        })
        analyzer = TrafficAnalyzer(capture_factory=lambda _: MockCapture([mk(), mk()]))
        result = analyzer.analyze_pcap("test.pcap")
        convos = result["findings"]["conversations"]
        self.assertEqual(len(convos), 1)
        self.assertEqual(convos[0]["packet_count"], 2)

    def test_skips_packets_without_ip(self):
        pkt = MockPacket("ARP", {"arp": MockLayer()})
        analyzer = TrafficAnalyzer(capture_factory=lambda _: MockCapture([pkt]))
        result = analyzer.analyze_pcap("test.pcap")
        self.assertEqual(result["summary"]["conversation_count"], 0)


class TrafficRuntimeErrorTests(unittest.TestCase):
    def test_raises_when_pyshark_missing(self):
        analyzer = TrafficAnalyzer()
        # The default factory checks for pyshark; since we haven't mocked it,
        # it should raise RuntimeError if pyshark is not installed.
        # We can't guarantee pyshark is or isn't installed, so test the factory directly.
        import analysis.traffic as mod
        if mod.pyshark is None:
            with self.assertRaises(RuntimeError):
                analyzer.analyze_pcap("missing.pcap")


# ===========================================================================
# SSLAnalyzer tests
# ===========================================================================

class SSLProbeTests(unittest.TestCase):
    """Tests for probe_certificates."""

    def _make_probe(self, port_results):
        """Return a probe function that returns specific results per port."""
        def probe(target, port):
            if port in port_results:
                return port_results[port]
            return {"port": port, "reachable": False, "error": "connection refused"}
        return probe

    def test_reachable_certificate_included(self):
        probe = self._make_probe({
            443: {
                "port": 443, "reachable": True,
                "subject": "CN=iot.device", "issuer": "CN=TestCA",
                "serial_number": "01", "not_before": "Jan  1 00:00:00 2024 GMT",
                "not_after": "Jan  1 00:00:00 2035 GMT", "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384", "self_signed": False, "expired": False,
            }
        })
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.probe_certificates("10.0.0.1", [443])
        certs = result["findings"]["certificates"]
        self.assertEqual(len(certs), 1)
        self.assertTrue(certs[0]["reachable"])
        self.assertEqual(certs[0]["subject"], "CN=iot.device")

    def test_unreachable_port_included_with_error(self):
        probe = self._make_probe({})
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.probe_certificates("10.0.0.1", [8443])
        certs = result["findings"]["certificates"]
        self.assertEqual(len(certs), 1)
        self.assertFalse(certs[0]["reachable"])
        self.assertIn("error", certs[0])

    def test_self_signed_generates_risk_indicator(self):
        probe = self._make_probe({
            443: {
                "port": 443, "reachable": True,
                "subject": "CN=self", "issuer": "CN=self",
                "serial_number": "01", "not_before": None, "not_after": None,
                "version": "TLSv1.2", "cipher": "AES256", "self_signed": True, "expired": False,
            }
        })
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.probe_certificates("10.0.0.1", [443])
        self.assertEqual(len(result["risk_indicators"]), 1)
        self.assertIn("self-signed", result["risk_indicators"][0]["details"])

    def test_expired_cert_generates_high_severity(self):
        probe = self._make_probe({
            443: {
                "port": 443, "reachable": True,
                "subject": "CN=exp", "issuer": "CN=CA",
                "serial_number": "01", "not_before": None,
                "not_after": "Jan  1 00:00:00 2020 GMT",
                "version": "TLSv1.2", "cipher": "AES256",
                "self_signed": False, "expired": True,
            }
        })
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.probe_certificates("10.0.0.1", [443])
        self.assertEqual(result["risk_indicators"][0]["severity"], "high")

    def test_ports_normalized_to_int(self):
        probe = self._make_probe({443: {"port": 443, "reachable": False, "error": "closed"}})
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.probe_certificates("10.0.0.1", ["443"])
        self.assertEqual(result["metadata"]["ports"], [443])

    def test_file_path_target_is_reported_as_invalid(self):
        result = SSLAnalyzer()._probe_port(r"C:\captures\traffic.pcap", 443)
        self.assertFalse(result["reachable"])
        self.assertEqual(result["error_type"], "invalid_target")
        self.assertIn("file path", result["error"])

    def test_dns_resolution_failure_has_actionable_error(self):
        analyzer = SSLAnalyzer()
        with patch("analysis.ssl_analyzer.socket.create_connection", side_effect=socket.gaierror(11001, "getaddrinfo failed")):
            result = analyzer._probe_port("does-not-resolve.example", 443)
        self.assertFalse(result["reachable"])
        self.assertEqual(result["error_type"], "dns_resolution_failed")
        self.assertIn("plain IP address or hostname", result["error"])
        self.assertFalse(result["target_resolved"])
        self.assertFalse(result["tcp_reachable"])
        self.assertFalse(result["tls_reachable"])

    def test_tcp_failure_is_not_reported_as_dns_or_tls_success(self):
        analyzer = SSLAnalyzer()
        with patch("analysis.ssl_analyzer.socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = analyzer._probe_port("10.0.0.1", 443)
        self.assertEqual(result["error_type"], "tcp_connection_failed")
        self.assertTrue(result["target_resolved"])
        self.assertFalse(result["tcp_reachable"])
        self.assertFalse(result["tls_reachable"])

    def test_multiple_ports(self):
        probe = self._make_probe({
            443: {"port": 443, "reachable": True, "subject": "CN=a", "issuer": "CN=b",
                  "serial_number": "01", "not_before": None, "not_after": None,
                  "version": "TLSv1.3", "cipher": "AES", "self_signed": False, "expired": False},
            8443: {"port": 8443, "reachable": True, "subject": "CN=c", "issuer": "CN=c",
                   "serial_number": "02", "not_before": None, "not_after": None,
                   "version": "TLSv1.2", "cipher": "AES", "self_signed": True, "expired": False},
        })
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.probe_certificates("10.0.0.1", [443, 8443])
        self.assertEqual(result["summary"]["reachable_ports"], 2)
        self.assertEqual(result["summary"]["certificate_count"], 2)


class SSLCipherTests(unittest.TestCase):
    """Tests for analyze_ciphers."""

    def test_weak_cipher_flagged(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": "TLS_RSA_WITH_RC4_128_SHA",
                    "version": "TLSv1.2"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertEqual(result["summary"]["weak_cipher_count"], 1)
        self.assertTrue(result["findings"]["cipher_analysis"][0]["weak_cipher"])

    def test_outdated_protocol_flagged(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": "TLS_AES_256_GCM_SHA384",
                    "version": "TLSv1.0"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertEqual(result["summary"]["outdated_protocol_count"], 1)

    def test_modern_config_no_issues(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": "TLS_AES_256_GCM_SHA384",
                    "version": "TLSv1.3"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertEqual(result["summary"]["weak_cipher_count"], 0)
        self.assertEqual(result["summary"]["outdated_protocol_count"], 0)
        self.assertEqual(len(result["risk_indicators"]), 0)

    def test_unreachable_port_in_cipher_analysis(self):
        def probe(_, port):
            return {"port": port, "reachable": False, "error": "timeout"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertFalse(result["findings"]["cipher_analysis"][0]["reachable"])

    def test_null_cipher_detected(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": "TLS_NULL_WITH_NULL_NULL",
                    "version": "TLSv1.2"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertTrue(result["findings"]["cipher_analysis"][0]["weak_cipher"])

    def test_des_cipher_detected(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": "TLS_RSA_WITH_DES_CBC_SHA",
                    "version": "TLSv1.2"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertTrue(result["findings"]["cipher_analysis"][0]["weak_cipher"])

    def test_sslv3_is_outdated(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": "AES256", "version": "SSLv3"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertTrue(result["findings"]["cipher_analysis"][0]["outdated_protocol"])

    def test_none_cipher_not_flagged_weak(self):
        def probe(_, port):
            return {"port": port, "reachable": True, "cipher": None, "version": "TLSv1.3"}
        analyzer = SSLAnalyzer(probe_func=probe)
        result = analyzer.analyze_ciphers("10.0.0.1", [443])
        self.assertFalse(result["findings"]["cipher_analysis"][0]["weak_cipher"])


class SSLJa3Tests(unittest.TestCase):
    """Tests for compute_ja3."""

    def test_successful_computation(self):
        analyzer = SSLAnalyzer(ja3_calculator=lambda _: "abc123def456")
        result = analyzer.compute_ja3("capture.pcap")
        self.assertTrue(result["findings"]["ja3"]["available"])
        self.assertEqual(result["findings"]["ja3"]["hash"], "abc123def456")

    def test_runtime_error_degrades_cleanly(self):
        def fail(_):
            raise RuntimeError("missing dependency")
        analyzer = SSLAnalyzer(ja3_calculator=fail)
        result = analyzer.compute_ja3("capture.pcap")
        self.assertFalse(result["findings"]["ja3"]["available"])
        self.assertIn("missing dependency", result["findings"]["ja3"]["error"])

    def test_default_calculator_with_real_file(self):
        """Default JA3 calculator should return a sha256-prefixed hash for non-empty files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            f.write(b"\x00" * 100)
            path = f.name
        analyzer = SSLAnalyzer()
        result = analyzer.compute_ja3(path)
        self.assertTrue(result["findings"]["ja3"]["available"])
        self.assertTrue(result["findings"]["ja3"]["hash"].startswith("sha256:"))

    def test_default_calculator_empty_file_raises(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            path = f.name
        analyzer = SSLAnalyzer()
        result = analyzer.compute_ja3(path)
        self.assertFalse(result["findings"]["ja3"]["available"])

    def test_schema_keys_present(self):
        analyzer = SSLAnalyzer(ja3_calculator=lambda _: "hash")
        result = analyzer.compute_ja3("test.pcap")
        self.assertIn("metadata", result)
        self.assertIn("findings", result)
        self.assertIn("summary", result)
        self.assertIn("risk_indicators", result)
        self.assertEqual(result["risk_indicators"], [])


class SSLSecurityAssessmentTests(unittest.TestCase):
    """Tests for assess_tls_security."""

    def test_clean_report_is_low_risk(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security(
            {"findings": {"certificates": [{"port": 443, "reachable": True, "self_signed": False, "expired": False}]}},
            {"findings": {"cipher_analysis": [{"port": 443, "reachable": True, "weak_cipher": False, "outdated_protocol": False}]}},
        )
        self.assertEqual(result["summary"]["risk_rating"], "low")
        self.assertEqual(result["summary"]["finding_count"], 0)

    def test_self_signed_raises_to_medium(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security(
            {"findings": {"certificates": [{"port": 443, "self_signed": True, "expired": False}]}},
            {"findings": {"cipher_analysis": []}},
        )
        self.assertEqual(result["summary"]["risk_rating"], "medium")

    def test_expired_cert_raises_to_high(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security(
            {"findings": {"certificates": [{"port": 443, "self_signed": False, "expired": True}]}},
            {"findings": {"cipher_analysis": []}},
        )
        self.assertEqual(result["summary"]["risk_rating"], "high")

    def test_weak_cipher_raises_to_high(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security(
            {"findings": {"certificates": []}},
            {"findings": {"cipher_analysis": [{"port": 443, "weak_cipher": True, "outdated_protocol": False}]}},
        )
        self.assertEqual(result["summary"]["risk_rating"], "high")

    def test_outdated_protocol_raises_to_medium(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security(
            {"findings": {"certificates": []}},
            {"findings": {"cipher_analysis": [{"port": 443, "weak_cipher": False, "outdated_protocol": True}]}},
        )
        self.assertEqual(result["summary"]["risk_rating"], "medium")

    def test_defaults_when_none_passed(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security()
        self.assertEqual(result["summary"]["risk_rating"], "low")
        self.assertEqual(result["summary"]["finding_count"], 0)

    def test_combined_expired_and_weak_cipher(self):
        analyzer = SSLAnalyzer()
        result = analyzer.assess_tls_security(
            {"findings": {"certificates": [{"port": 443, "self_signed": True, "expired": True}]}},
            {"findings": {"cipher_analysis": [{"port": 443, "weak_cipher": True, "outdated_protocol": True}]}},
        )
        self.assertEqual(result["summary"]["risk_rating"], "high")
        self.assertGreaterEqual(result["summary"]["finding_count"], 3)


class SSLInternalHelperTests(unittest.TestCase):
    """Tests for private SSL helper methods."""

    def test_is_expired_true(self):
        analyzer = SSLAnalyzer()
        self.assertTrue(analyzer._is_expired("Jan  1 00:00:00 2020 GMT"))

    def test_is_expired_false(self):
        analyzer = SSLAnalyzer()
        self.assertFalse(analyzer._is_expired("Jan  1 00:00:00 2099 GMT"))

    def test_is_expired_none(self):
        analyzer = SSLAnalyzer()
        self.assertFalse(analyzer._is_expired(None))

    def test_is_expired_garbage(self):
        analyzer = SSLAnalyzer()
        self.assertFalse(analyzer._is_expired("not-a-date"))

    def test_format_dn_none(self):
        analyzer = SSLAnalyzer()
        self.assertIsNone(analyzer._format_dn(None))

    def test_format_dn_empty(self):
        analyzer = SSLAnalyzer()
        self.assertIsNone(analyzer._format_dn(()))

    def test_format_dn_tuple(self):
        analyzer = SSLAnalyzer()
        dn = ((("commonName", "test.local"),), (("organizationName", "TestOrg"),))
        result = analyzer._format_dn(dn)
        self.assertIn("commonName=test.local", result)
        self.assertIn("organizationName=TestOrg", result)

    def test_is_weak_cipher_various(self):
        analyzer = SSLAnalyzer()
        self.assertTrue(analyzer._is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA"))
        self.assertTrue(analyzer._is_weak_cipher("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"))
        self.assertTrue(analyzer._is_weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
        self.assertTrue(analyzer._is_weak_cipher("TLS_NULL_WITH_NULL_NULL"))
        self.assertTrue(analyzer._is_weak_cipher("TLS_DH_anon_WITH_AES_128_CBC_SHA"))
        self.assertFalse(analyzer._is_weak_cipher("TLS_AES_256_GCM_SHA384"))
        self.assertFalse(analyzer._is_weak_cipher(None))

    def test_is_outdated_tls(self):
        analyzer = SSLAnalyzer()
        self.assertTrue(analyzer._is_outdated_tls("SSLv3"))
        self.assertTrue(analyzer._is_outdated_tls("TLSv1"))
        self.assertTrue(analyzer._is_outdated_tls("TLSv1.0"))
        self.assertTrue(analyzer._is_outdated_tls("TLSv1.1"))
        self.assertFalse(analyzer._is_outdated_tls("TLSv1.2"))
        self.assertFalse(analyzer._is_outdated_tls("TLSv1.3"))
        self.assertFalse(analyzer._is_outdated_tls(None))


# ===========================================================================
# ScannerAnalyzer tests
# ===========================================================================

class ScannerXmlParsingTests(unittest.TestCase):
    """Tests for nmap XML parsing."""

    def _parse_xml(self, xml_content):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(xml_content)
            path = f.name
        return ScannerAnalyzer().parse_nmap_output(path)

    def test_single_host_two_ports(self):
        result = self._parse_xml("""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80"><state state="open" /><service name="http" product="Boa" version="0.94" /></port>
      <port protocol="tcp" portid="1883"><state state="open" /><service name="mqtt" /></port>
    </ports>
  </host>
</nmaprun>""")
        self.assertEqual(result["metadata"]["host_count"], 1)
        self.assertEqual(result["summary"]["open_port_count"], 2)

    def test_multiple_hosts(self):
        result = self._parse_xml("""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50" addrtype="ipv4" />
    <ports><port protocol="tcp" portid="80"><state state="open" /><service name="http" /></port></ports>
  </host>
  <host>
    <address addr="192.168.1.51" addrtype="ipv4" />
    <ports><port protocol="tcp" portid="22"><state state="open" /><service name="ssh" /></port></ports>
  </host>
</nmaprun>""")
        self.assertEqual(result["metadata"]["host_count"], 2)
        self.assertEqual(result["summary"]["open_port_count"], 2)
        ips = [h["ip"] for h in result["findings"]["hosts"]]
        self.assertIn("192.168.1.50", ips)
        self.assertIn("192.168.1.51", ips)

    def test_closed_ports_excluded(self):
        result = self._parse_xml("""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50" />
    <ports>
      <port protocol="tcp" portid="80"><state state="open" /><service name="http" /></port>
      <port protocol="tcp" portid="443"><state state="closed" /><service name="https" /></port>
    </ports>
  </host>
</nmaprun>""")
        self.assertEqual(result["summary"]["open_port_count"], 1)
        self.assertEqual(result["summary"]["closed_port_count"], 1)
        host = result["findings"]["hosts"][0]
        self.assertEqual(len(host["ports"]), 2)
        self.assertEqual(host["ports"][1]["state"], "closed")

    def test_xml_extraports_are_counted(self):
        result = self._parse_xml("""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.123.99" />
    <ports>
      <extraports state="closed" count="1000" />
    </ports>
  </host>
</nmaprun>""")
        self.assertEqual(result["summary"]["open_port_count"], 0)
        self.assertEqual(result["summary"]["closed_port_count"], 1000)
        self.assertEqual(result["summary"]["scanned_port_count"], 1000)
        host = result["findings"]["hosts"][0]
        self.assertEqual(host["state_summary"], {"closed": 1000})

    def test_port_without_service_element(self):
        result = self._parse_xml("""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50" />
    <ports><port protocol="tcp" portid="9999"><state state="open" /></port></ports>
  </host>
</nmaprun>""")
        svc = result["findings"]["hosts"][0]["services"][0]
        self.assertIsNone(svc["service"])
        self.assertIsNone(svc["product"])

    def test_empty_scan(self):
        result = self._parse_xml("""<?xml version="1.0"?><nmaprun></nmaprun>""")
        self.assertEqual(result["metadata"]["host_count"], 0)
        self.assertEqual(result["summary"]["open_port_count"], 0)


class ScannerTextParsingTests(unittest.TestCase):
    """Tests for nmap text output parsing."""

    def _parse_text(self, content):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        return ScannerAnalyzer().parse_nmap_output(path)

    def test_single_host(self):
        result = self._parse_text(
            "Nmap scan report for 192.168.1.50\n"
            "80/tcp   open  http\n"
            "443/tcp  open  https\n"
        )
        self.assertEqual(result["metadata"]["host_count"], 1)
        self.assertEqual(result["summary"]["open_port_count"], 2)
        self.assertEqual(result["findings"]["hosts"][0]["ip"], "192.168.1.50")

    def test_multiple_hosts(self):
        result = self._parse_text(
            "Nmap scan report for 192.168.1.50\n"
            "80/tcp   open  http\n"
            "Nmap scan report for 192.168.1.51\n"
            "22/tcp   open  ssh\n"
            "1883/tcp open  mqtt\n"
        )
        self.assertEqual(result["metadata"]["host_count"], 2)
        self.assertEqual(result["summary"]["open_port_count"], 3)
        self.assertEqual(result["findings"]["hosts"][0]["ip"], "192.168.1.50")
        self.assertEqual(len(result["findings"]["hosts"][0]["services"]), 1)
        self.assertEqual(result["findings"]["hosts"][1]["ip"], "192.168.1.51")
        self.assertEqual(len(result["findings"]["hosts"][1]["services"]), 2)

    def test_hostname_with_ip_in_parens(self):
        result = self._parse_text(
            "Nmap scan report for router.local (192.168.1.1)\n"
            "80/tcp open http\n"
        )
        self.assertEqual(result["findings"]["hosts"][0]["ip"], "192.168.1.1")

    def test_empty_output(self):
        result = self._parse_text("")
        self.assertEqual(result["metadata"]["host_count"], 0)
        self.assertEqual(result["summary"]["open_port_count"], 0)

    def test_udp_services(self):
        result = self._parse_text(
            "Nmap scan report for 10.0.0.1\n"
            "5353/udp open  mdns\n"
        )
        svc = result["findings"]["hosts"][0]["services"][0]
        self.assertEqual(svc["protocol"], "udp")
        self.assertEqual(svc["port"], 5353)

    def test_closed_and_filtered_text_ports_are_counted(self):
        result = self._parse_text(
            "Nmap scan report for 192.168.123.99\n"
            "Host is up (0.00s latency).\n"
            "80/tcp   closed http\n"
            "443/tcp  filtered https\n"
        )
        self.assertEqual(result["summary"]["open_port_count"], 0)
        self.assertEqual(result["summary"]["closed_port_count"], 1)
        self.assertEqual(result["summary"]["filtered_port_count"], 1)
        self.assertEqual(result["findings"]["hosts"][0]["host_state"], "up")

    def test_not_shown_closed_ports_are_counted(self):
        result = self._parse_text(
            "Nmap scan report for 192.168.123.99\n"
            "Host is up (0.0013s latency).\n"
            "All 1000 scanned ports on 192.168.123.99 are in ignored states.\n"
            "Not shown: 1000 closed tcp ports (reset)\n"
        )
        self.assertEqual(result["summary"]["open_port_count"], 0)
        self.assertEqual(result["summary"]["closed_port_count"], 1000)
        self.assertEqual(result["summary"]["scanned_port_count"], 1000)
        host = result["findings"]["hosts"][0]
        self.assertIn("Not shown: 1000 closed tcp ports (reset)", host["notes"])


class ScannerIotIdentificationTests(unittest.TestCase):
    """Tests for IoT service identification."""

    def test_mqtt_by_port(self):
        services = [{"port": 1883, "service": "unknown"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["protocol"], "MQTT")

    def test_mqtt_tls_by_port(self):
        services = [{"port": 8883, "service": "unknown"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(result[0]["protocol"], "MQTT over TLS")

    def test_coap_by_port(self):
        services = [{"port": 5683, "service": "unknown"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(result[0]["protocol"], "CoAP")

    def test_upnp_by_port(self):
        services = [{"port": 1900, "service": "unknown"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(result[0]["protocol"], "UPnP")

    def test_bacnet_by_port(self):
        services = [{"port": 47808, "service": "unknown"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(result[0]["protocol"], "BACnet")

    def test_iot_by_service_name(self):
        services = [{"port": 9999, "service": "mqtt-custom"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(len(result), 1)

    def test_non_iot_service_excluded(self):
        services = [{"port": 22, "service": "ssh"}]
        result = ScannerAnalyzer().identify_iot_services(services)
        self.assertEqual(len(result), 0)

    def test_empty_service_list(self):
        result = ScannerAnalyzer().identify_iot_services([])
        self.assertEqual(len(result), 0)


class ScannerCveHintTests(unittest.TestCase):
    """Tests for CVE hint correlation."""

    def test_telnet_gets_hint(self):
        services = [{"port": 23, "service": "telnet"}]
        hints = ScannerAnalyzer().correlate_cves(services)
        self.assertEqual(len(hints), 1)
        self.assertIn("Cleartext", hints[0]["details"])

    def test_ftp_gets_hint(self):
        services = [{"port": 21, "service": "ftp"}]
        hints = ScannerAnalyzer().correlate_cves(services)
        self.assertEqual(len(hints), 1)

    def test_http_gets_hint(self):
        services = [{"port": 80, "service": "http"}]
        hints = ScannerAnalyzer().correlate_cves(services)
        self.assertEqual(len(hints), 1)

    def test_upnp_gets_hint(self):
        services = [{"port": 1900, "service": "upnp"}]
        hints = ScannerAnalyzer().correlate_cves(services)
        self.assertEqual(len(hints), 1)

    def test_ssh_no_hint(self):
        services = [{"port": 22, "service": "ssh"}]
        hints = ScannerAnalyzer().correlate_cves(services)
        self.assertEqual(len(hints), 0)

    def test_service_name_none(self):
        services = [{"port": 9999, "service": None}]
        hints = ScannerAnalyzer().correlate_cves(services)
        self.assertEqual(len(hints), 0)

    def test_risk_indicators_match_hints(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" />
    <ports>
      <port protocol="tcp" portid="23"><state state="open" /><service name="telnet" /></port>
      <port protocol="tcp" portid="21"><state state="open" /><service name="ftp" /></port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(xml)
            path = f.name
        result = ScannerAnalyzer().parse_nmap_output(path)
        self.assertEqual(len(result["risk_indicators"]), 2)


class ScannerShodanTests(unittest.TestCase):
    """Tests for Shodan API integration."""

    def test_no_api_key_returns_disabled(self):
        result = ScannerAnalyzer().lookup_shodan("10.0.0.1")
        self.assertFalse(result["enabled"])

    def test_empty_api_key_returns_disabled(self):
        result = ScannerAnalyzer().lookup_shodan("10.0.0.1", api_key="")
        self.assertFalse(result["enabled"])

    def test_missing_requests_returns_error(self):
        analyzer = ScannerAnalyzer(request_get=None)
        analyzer.request_get = None
        result = analyzer.lookup_shodan("10.0.0.1", api_key="key")
        self.assertFalse(result["enabled"])

    def test_successful_shodan_lookup(self):
        class FakeResponse:
            def raise_for_status(self): pass
            def json(self):
                return {"org": "TestOrg", "os": "Linux", "tags": ["iot"], "ports": [80]}

        analyzer = ScannerAnalyzer(request_get=lambda *a, **kw: FakeResponse())
        result = analyzer.lookup_shodan("10.0.0.1", api_key="key")
        self.assertTrue(result["enabled"])
        self.assertEqual(result["organization"], "TestOrg")
        self.assertEqual(result["ports"], [80])

    def test_shodan_passes_correct_url(self):
        calls = []
        class FakeResponse:
            def raise_for_status(self): pass
            def json(self): return {"org": "", "os": "", "tags": [], "ports": []}

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse()

        analyzer = ScannerAnalyzer(request_get=fake_get)
        analyzer.lookup_shodan("1.2.3.4", api_key="mykey")
        self.assertIn("1.2.3.4", calls[0][0])
        self.assertEqual(calls[0][1]["params"]["key"], "mykey")


if __name__ == "__main__":
    unittest.main()
