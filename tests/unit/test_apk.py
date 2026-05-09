"""Tests for analysis.apk_analyzer module."""

import json
import os
import textwrap
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from chainrecon.analysis.apk_analyzer import APKAnalyzer, _load_patterns


class LoadPatternsTests(unittest.TestCase):
    def test_loads_default_patterns(self):
        patterns = _load_patterns()
        self.assertIn("credential_patterns", patterns)
        self.assertIn("iot_sdks", patterns)
        self.assertIn("pinning_indicators", patterns)
        self.assertIn("dangerous_permissions", patterns)

    def test_returns_empty_for_missing_file(self):
        patterns = _load_patterns(Path("/nonexistent/file.yaml"))
        self.assertEqual(patterns, {})


class ManifestParsingTests(unittest.TestCase):
    """Test manifest parsing with a realistic manifest snippet."""

    MANIFEST = textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.iot">
            <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
            <uses-permission android:name="android.permission.INTERNET" />
            <uses-permission android:name="android.permission.CAMERA" />
            <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
            <application
                android:debuggable="true"
                android:allowBackup="true"
                android:usesCleartextTraffic="true"
                android:networkSecurityConfig="@xml/network_security_config">
                <activity android:name=".MainActivity" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                    </intent-filter>
                </activity>
                <service android:name=".MyService" android:exported="false" />
                <receiver android:name=".BootReceiver">
                    <intent-filter>
                        <action android:name="android.intent.action.BOOT_COMPLETED" />
                    </intent-filter>
                </receiver>
                <provider android:name=".DataProvider" android:exported="true" />
            </application>
        </manifest>
    """)

    def _make_decompiled(self, tmp: str):
        """Create a minimal decompiled directory with the test manifest."""
        res = Path(tmp) / "resources"
        res.mkdir(parents=True, exist_ok=True)
        (res / "AndroidManifest.xml").write_text(self.MANIFEST, encoding="utf-8")
        return Path(tmp)

    def test_extract_permissions(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            dec = self._make_decompiled(tmp)
            analyzer = APKAnalyzer(executor=MagicMock())
            manifest = analyzer._parse_manifest(dec)
            perms = analyzer._extract_permissions(manifest)
            names = [p["permission"] for p in perms]
            self.assertIn("android.permission.INTERNET", names)
            self.assertIn("android.permission.CAMERA", names)
            # CAMERA is dangerous
            camera = next(p for p in perms if "CAMERA" in p["permission"])
            self.assertTrue(camera["dangerous"])

    def test_extract_components(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            dec = self._make_decompiled(tmp)
            analyzer = APKAnalyzer(executor=MagicMock())
            manifest = analyzer._parse_manifest(dec)
            comps = analyzer._extract_components(manifest)
            # MainActivity is exported=true
            main = next(c for c in comps if "MainActivity" in c["name"])
            self.assertTrue(main["exported"])
            self.assertEqual(main["type"], "activity")
            # MyService is exported=false
            svc = next(c for c in comps if "MyService" in c["name"])
            self.assertFalse(svc["exported"])
            # BootReceiver has intent-filter, exported not set → implicitly exported
            rcv = next(c for c in comps if "BootReceiver" in c["name"])
            self.assertTrue(rcv["exported"])

    def test_extract_app_flags(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            dec = self._make_decompiled(tmp)
            analyzer = APKAnalyzer(executor=MagicMock())
            manifest = analyzer._parse_manifest(dec)
            flags = analyzer._extract_app_flags(manifest)
            self.assertTrue(flags["debuggable"])
            self.assertTrue(flags["allowBackup"])
            self.assertTrue(flags["usesCleartextTraffic"])
            self.assertEqual(flags["minSdkVersion"], "21")
            self.assertEqual(flags["targetSdkVersion"], "33")

    def test_missing_manifest_returns_empty(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = APKAnalyzer(executor=MagicMock())
            manifest = analyzer._parse_manifest(Path(tmp))
            self.assertIsNone(manifest)
            perms = analyzer._extract_permissions(manifest)
            self.assertEqual(perms, [])


class NetworkSecurityConfigTests(unittest.TestCase):
    CONFIG_XML = textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <network-security-config>
            <domain-config cleartextTrafficPermitted="true">
                <domain includeSubdomains="true">example.com</domain>
            </domain-config>
            <pin-set>
                <pin digest="SHA-256">abc123=</pin>
                <pin digest="SHA-256">def456=</pin>
            </pin-set>
        </network-security-config>
    """)

    def test_parses_cleartext_and_pins(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp) / "res" / "xml"
            res.mkdir(parents=True)
            (res / "network_security_config.xml").write_text(self.CONFIG_XML, encoding="utf-8")
            analyzer = APKAnalyzer(executor=MagicMock())
            result = analyzer._parse_network_security_config(Path(tmp))
            self.assertTrue(result["found"])
            self.assertTrue(result["cleartext_allowed"])
            self.assertEqual(result["pin_count"], 2)

    def test_not_found(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = APKAnalyzer(executor=MagicMock())
            result = analyzer._parse_network_security_config(Path(tmp))
            self.assertFalse(result["found"])


class CredentialScanTests(unittest.TestCase):
    def test_finds_hardcoded_password(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources" / "com" / "example"
            sources.mkdir(parents=True)
            (sources / "Config.java").write_text(
                'public static final String password = "SuperSecret123";',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            creds = analyzer._scan_credentials(Path(tmp))
            self.assertGreater(len(creds), 0)
            self.assertEqual(creds[0]["type"], "Hardcoded Password")

    def test_finds_aws_key(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "Keys.java").write_text(
                'String key = "AKIAIOSFODNN7EXAMPLE";',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            creds = analyzer._scan_credentials(Path(tmp))
            aws = [c for c in creds if "AWS" in c["type"]]
            self.assertGreater(len(aws), 0)

    def test_no_creds_in_clean_source(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "Main.java").write_text(
                'public class Main { public static void main(String[] args) {} }',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            creds = analyzer._scan_credentials(Path(tmp))
            self.assertEqual(creds, [])


class PinningDetectionTests(unittest.TestCase):
    def test_detects_okhttp_pinner(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "Net.java").write_text(
                'CertificatePinner pinner = new CertificatePinner.Builder().build();',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            result = analyzer._check_pinning(Path(tmp))
            self.assertTrue(result["detected"])
            self.assertIn("CertificatePinner", result["indicators"])

    def test_detects_bypass_risk(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "Insecure.java").write_text(
                'TrustManager[] trustAllCerts = new TrustManager[] {};',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            result = analyzer._check_pinning(Path(tmp))
            self.assertIn("trustAllCerts", result["bypass_risk_indicators"])

    def test_no_pinning(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "Clean.java").write_text(
                'public class Clean {}',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            result = analyzer._check_pinning(Path(tmp))
            self.assertFalse(result["detected"])


class SDKDetectionTests(unittest.TestCase):
    def test_detects_firebase(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "App.java").write_text(
                'import com.google.firebase.FirebaseApp;',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            sdks = analyzer._detect_sdks(Path(tmp))
            names = [s["name"] for s in sdks]
            self.assertIn("Firebase", names)

    def test_detects_mqtt(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sources = Path(tmp) / "sources"
            sources.mkdir(parents=True)
            (sources / "MqttHelper.java").write_text(
                'import org.eclipse.paho.client.mqttv3.MqttClient;',
                encoding="utf-8",
            )
            analyzer = APKAnalyzer(executor=MagicMock())
            sdks = analyzer._detect_sdks(Path(tmp))
            names = [s["name"] for s in sdks]
            self.assertIn("MQTT (Eclipse Paho)", names)


class RiskIndicatorTests(unittest.TestCase):
    def test_debuggable_flag_generates_high_risk(self):
        analyzer = APKAnalyzer(executor=MagicMock())
        indicators = analyzer._build_risk_indicators(
            permissions=[],
            components=[],
            app_flags={"debuggable": True},
            net_security={},
            credentials=[],
            pinning={"detected": True},
        )
        titles = [i["title"] for i in indicators]
        self.assertIn("Application is debuggable", titles)

    def test_no_pinning_generates_medium_risk(self):
        analyzer = APKAnalyzer(executor=MagicMock())
        indicators = analyzer._build_risk_indicators(
            permissions=[],
            components=[],
            app_flags={},
            net_security={},
            credentials=[],
            pinning={"detected": False},
        )
        titles = [i["title"] for i in indicators]
        self.assertIn("No certificate pinning detected", titles)

    def test_credentials_generate_risk(self):
        analyzer = APKAnalyzer(executor=MagicMock())
        indicators = analyzer._build_risk_indicators(
            permissions=[],
            components=[],
            app_flags={},
            net_security={},
            credentials=[{"type": "Hardcoded Password", "severity": "high"}],
            pinning={"detected": True},
        )
        cred_ind = [i for i in indicators if "credential" in i["title"]]
        self.assertEqual(len(cred_ind), 1)


class FullAnalyzeTests(unittest.TestCase):
    """Integration test: create a fake APK decompile output and run analyze()."""

    MANIFEST = textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.iot">
            <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
            <uses-permission android:name="android.permission.CAMERA" />
            <application android:debuggable="true" android:usesCleartextTraffic="true">
                <activity android:name=".MainActivity" android:exported="true" />
            </application>
        </manifest>
    """)

    def test_full_analysis_structure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            apk_file = Path(tmp) / "test.apk"
            apk_file.write_bytes(b"PK")  # fake APK

            output = Path(tmp) / "decompiled"
            output.mkdir()
            res = output / "resources"
            res.mkdir()
            (res / "AndroidManifest.xml").write_text(self.MANIFEST, encoding="utf-8")
            sources = output / "sources"
            sources.mkdir()
            (sources / "Config.java").write_text(
                'String password = "secret123";', encoding="utf-8",
            )

            # Mock executor so jadx doesn't actually run
            mock_exec = MagicMock()
            analyzer = APKAnalyzer(executor=mock_exec)

            result = analyzer.analyze(str(apk_file), output_dir=str(output))

            self.assertIn("metadata", result)
            self.assertIn("findings", result)
            self.assertIn("summary", result)
            self.assertIn("risk_indicators", result)
            self.assertIn("permissions", result["findings"])
            self.assertIn("components", result["findings"])
            self.assertIn("credentials", result["findings"])
            self.assertGreater(result["summary"]["risk_indicator_count"], 0)

    def test_apk_not_found_raises(self):
        analyzer = APKAnalyzer(executor=MagicMock())
        with self.assertRaises(FileNotFoundError):
            analyzer.analyze("/nonexistent/app.apk")


if __name__ == "__main__":
    unittest.main()
