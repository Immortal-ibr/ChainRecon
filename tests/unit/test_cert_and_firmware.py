import datetime
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from analysis.cert_analyzer import CertAnalyzer
from analysis.firmware_analyzer import FirmwareAnalyzer


class CertAnalyzerTests(unittest.TestCase):
    def _generate_der(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "device.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChainRecon"),
        ])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("device.local")]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.DER)

    def test_extracts_deduped_certificates_with_protocol_metadata(self):
        der = self._generate_der()
        hex_blob = (b"\x01\x02" + der + b"\x03").hex()
        packet = SimpleNamespace(
            tls=SimpleNamespace(handshake_certificate=hex_blob),
            data=SimpleNamespace(data_data=hex_blob),
        )
        result = CertAnalyzer().analyze([packet])
        self.assertEqual(result["summary"]["total_certs"], 1)
        certificate = result["findings"]["certificates"][0]
        self.assertEqual(certificate["subject_components"]["commonName"], "device.local")
        self.assertEqual(certificate["san"], ["device.local"])
        self.assertEqual(certificate["extracted_from"]["protocol"], "tls")


class FirmwareAnalyzerTests(unittest.TestCase):
    def test_detects_private_keys_and_shadow_files(self):
        analyzer = FirmwareAnalyzer(executor=lambda *args, **kwargs: None, binwalk_path="binwalk")
        with tempfile.TemporaryDirectory() as td:
            image = Path(td) / "firmware.bin"
            image.write_bytes(b"firmware")
            extract_dir = Path(td) / "extract"
            root = extract_dir / "_firmware.bin.extracted"
            (root / "etc").mkdir(parents=True)
            (root / "etc" / "shadow").write_text("root:*:0:0\n", encoding="utf-8")
            (root / "keys").mkdir(parents=True)
            (root / "keys" / "device.key").write_text("-----BEGIN PRIVATE KEY-----\nabc\n", encoding="utf-8")
            (root / "config.txt").write_text("mqtt password=demo\n", encoding="utf-8")
            analyzer._run_binwalk = lambda *_args, **_kwargs: None
            result = analyzer.analyze(str(image), output_dir=str(extract_dir))
        self.assertEqual(result["summary"]["private_key_count"], 1)
        self.assertEqual(result["summary"]["shadow_file_count"], 1)
        self.assertGreaterEqual(result["summary"]["credential_hit_count"], 1)