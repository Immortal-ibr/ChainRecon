"""Certificate extraction and analysis from packet captures.

Extracts X.509 certificates from TLS and DTLS handshakes in pcap files,
checks RSA key sizes, signature algorithms, expiry dates, and basic
key-weakness indicators (small primes, Fermat factorisation proximity).
"""

from __future__ import annotations

import hashlib
import math
import struct
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from utils.logging_config import get_logger

logger = get_logger("cert_analyzer")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


class CertAnalyzer:
    """Extract and analyse certificates found inside a packet capture."""

    def analyze(self, packets: Iterable[Any]) -> Dict[str, Any]:
        packet_list = list(packets)
        logger.info("Scanning %d packets for embedded certificates", len(packet_list))

        raw_certs = self._extract_der_certs(packet_list)
        parsed = self._parse_certs(raw_certs)
        weak = [c for c in parsed if c.get("weaknesses")]

        indicators: List[Dict[str, str]] = []
        for cert in weak:
            for w in cert["weaknesses"]:
                indicators.append({
                    "severity": "high" if "key" in w.lower() or "expired" in w.lower() else "medium",
                    "title": w,
                    "details": f"Subject: {cert.get('subject', 'unknown')}",
                })

        expired = [c for c in parsed if c.get("expired")]
        if expired:
            indicators.append({
                "severity": "high",
                "title": f"{len(expired)} expired certificate(s) found",
                "details": "Expired certificates indicate poor key management.",
            })

        self_signed = [c for c in parsed if c.get("self_signed")]
        if self_signed:
            indicators.append({
                "severity": "medium",
                "title": f"{len(self_signed)} self-signed certificate(s)",
                "details": "Self-signed certs bypass CA trust chain.",
            })

        return {
            "metadata": {
                "packet_count": len(packet_list),
                "certs_found": len(parsed),
                "analyzer": self.__class__.__name__,
            },
            "findings": {
                "certificates": parsed,
                "weak_certificates": weak,
            },
            "summary": {
                "total_certs": len(parsed),
                "weak_count": len(weak),
                "expired_count": len(expired),
                "self_signed_count": len(self_signed),
            },
            "risk_indicators": indicators,
        }

    # ── DER extraction from raw payloads ─────────────────────────────

    def _extract_der_certs(self, packets) -> List[bytes]:
        """Find DER-encoded X.509 certificates in TLS/DTLS handshake payloads."""
        certs: List[bytes] = []
        seen: set = set()

        for pkt in packets:
            raw = self._get_payload(pkt)
            if raw is None or len(raw) < 20:
                continue
            # Scan for the ASN.1 SEQUENCE tag (0x30 0x82) followed by a
            # plausible length that fits inside the payload.
            offset = 0
            while offset < len(raw) - 4:
                idx = raw.find(b"\x30\x82", offset)
                if idx == -1:
                    break
                # Two-byte length after 0x30 0x82
                if idx + 4 > len(raw):
                    break
                cert_len = struct.unpack("!H", raw[idx + 2 : idx + 4])[0] + 4
                if cert_len < 100 or idx + cert_len > len(raw):
                    offset = idx + 1
                    continue
                der = raw[idx : idx + cert_len]
                fingerprint = hashlib.sha256(der).digest()
                if fingerprint not in seen:
                    seen.add(fingerprint)
                    certs.append(der)
                offset = idx + cert_len

        logger.info("Extracted %d unique DER blobs", len(certs))
        return certs

    def _parse_certs(self, der_list: List[bytes]) -> List[Dict[str, Any]]:
        if not _CRYPTO_AVAILABLE:
            logger.warning("cryptography package not installed — skipping cert parsing")
            return [{"raw_sha256": hashlib.sha256(d).hexdigest(), "note": "Install 'cryptography' for full analysis"} for d in der_list]

        results: List[Dict[str, Any]] = []
        for der in der_list:
            try:
                cert = x509.load_der_x509_certificate(der)
            except Exception:
                continue

            info = self._cert_info(cert, der)
            results.append(info)
        return results

    def _cert_info(self, cert, der: bytes) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        expired = cert.not_valid_after_utc < now
        self_signed = subject == issuer

        info: Dict[str, Any] = {
            "subject": subject,
            "issuer": issuer,
            "serial": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "expired": expired,
            "self_signed": self_signed,
            "sha256": hashlib.sha256(der).hexdigest(),
            "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        }

        weaknesses: List[str] = []
        pub = cert.public_key()

        if isinstance(pub, rsa.RSAPublicKey):
            key_size = pub.key_size
            info["key_type"] = "RSA"
            info["key_size"] = key_size
            numbers = pub.public_numbers()
            info["rsa_exponent"] = numbers.e

            if key_size < 2048:
                weaknesses.append(f"RSA key too small ({key_size} bits)")
            if numbers.e < 3:
                weaknesses.append("RSA exponent is dangerously small")

            # Fermat factorisation check (p and q too close)
            if self._fermat_vulnerable(numbers.n):
                weaknesses.append("RSA modulus may be Fermat-factorable (p ≈ q)")

        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["key_type"] = "EC"
            info["key_size"] = pub.key_size
            info["curve"] = pub.curve.name
            if pub.key_size < 256:
                weaknesses.append(f"EC key too small ({pub.key_size} bits)")
        else:
            info["key_type"] = type(pub).__name__

        # Weak signature algorithms
        sig_oid = cert.signature_algorithm_oid.dotted_string
        if "sha1" in str(cert.signature_hash_algorithm).lower() if cert.signature_hash_algorithm else False:
            weaknesses.append("Certificate signed with SHA-1")
        if sig_oid in ("1.2.840.113549.1.1.2", "1.2.840.113549.1.1.4"):
            weaknesses.append("Certificate signed with MD2/MD5")

        if expired:
            weaknesses.append("Certificate has expired")

        info["weaknesses"] = weaknesses
        return info

    @staticmethod
    def _fermat_vulnerable(n: int, iterations: int = 100) -> bool:
        """Quick check if RSA modulus n = p*q where p ≈ q (Fermat attack)."""
        if n < 4:
            return False
        a = math.isqrt(n)
        if a * a == n:
            return True
        for _ in range(iterations):
            a += 1
            b_sq = a * a - n
            b = math.isqrt(b_sq)
            if b * b == b_sq:
                return True
        return False

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _get_payload(pkt) -> Optional[bytes]:
        for layer_name in ("data", "DATA", "tcp", "TCP", "udp", "UDP"):
            layer = getattr(pkt, layer_name, None)
            if layer is None:
                continue
            for field in ("data_data", "payload"):
                raw_hex = getattr(layer, field, None)
                if raw_hex:
                    try:
                        return bytes.fromhex(str(raw_hex).replace(":", ""))
                    except ValueError:
                        continue
        return None
