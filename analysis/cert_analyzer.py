"""Certificate extraction and analysis from packet captures."""

from __future__ import annotations

import hashlib
import math
import struct
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

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

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        from analysis.traffic import TrafficAnalyzer

        packets, capture = TrafficAnalyzer()._load_packets(pcap_path)
        try:
            result = self.analyze(packets)
        finally:
            if hasattr(capture, "close"):
                capture.close()
        result.setdefault("metadata", {})["source"] = pcap_path
        return result

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
                "extraction_sources": sorted({item.get("extracted_from", {}).get("source") for item in parsed if item.get("extracted_from")}),
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

    # -- DER extraction from raw payloads -----------------------------

    def _extract_der_certs(self, packets) -> List[Dict[str, Any]]:
        """Find DER-encoded X.509 certificates in TLS/DTLS/raw payloads."""
        certs: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for packet_index, pkt in enumerate(packets):
            for extracted in self._iter_packet_certificates(pkt):
                fingerprint = hashlib.sha256(extracted["der"]).hexdigest()
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                certs.append({
                    "der": extracted["der"],
                    "sha256": fingerprint,
                    "packet_index": packet_index,
                    "extracted_from": extracted["extracted_from"],
                })

        logger.info("Extracted %d unique DER blobs", len(certs))
        return certs

    def _parse_certs(self, der_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not _CRYPTO_AVAILABLE:
            logger.warning("cryptography package not installed -- skipping cert parsing")
            return [{"raw_sha256": item["sha256"], "note": "Install 'cryptography' for full analysis", "extracted_from": item.get("extracted_from", {})} for item in der_list]

        results: List[Dict[str, Any]] = []
        for item in der_list:
            try:
                cert = x509.load_der_x509_certificate(item["der"])
            except Exception:
                continue

            info = self._cert_info(cert, item["der"], item)
            results.append(info)
        return results

    def _cert_info(self, cert, der: bytes, extracted: Dict[str, Any]) -> Dict[str, Any]:
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
            "sha256": extracted.get("sha256") or hashlib.sha256(der).hexdigest(),
            "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
            "signature_hash": getattr(getattr(cert, "signature_hash_algorithm", None), "name", None),
            "subject_components": self._name_components(cert.subject),
            "issuer_components": self._name_components(cert.issuer),
            "san": self._subject_alt_names(cert),
            "extracted_from": dict(extracted.get("extracted_from") or {}),
            "packet_index": extracted.get("packet_index"),
            "certificate_observed": True,
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
                weaknesses.append("RSA modulus may be Fermat-factorable (p ~ q)")

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

    def _iter_packet_certificates(self, pkt: Any) -> Iterator[Dict[str, Any]]:
        for layer_name, protocol in (("tls", "tls"), ("dtls", "dtls")):
            layer = getattr(pkt, layer_name, None)
            if layer is None:
                continue
            yield from self._extract_from_layer_fields(layer, protocol)
        for protocol, source, raw in self._payload_candidates(pkt):
            yield from self._extract_from_blob(raw, {"protocol": protocol, "source": source})

    def _extract_from_layer_fields(self, layer: Any, protocol: str) -> Iterator[Dict[str, Any]]:
        for field_name in dir(layer):
            lowered = field_name.lower()
            if field_name.startswith("_") or "certificate" not in lowered:
                continue
            value = getattr(layer, field_name, None)
            for item in self._flatten_field_values(value):
                raw = self._decode_hex_blob(item)
                if raw:
                    yield from self._extract_from_blob(raw, {"protocol": protocol, "source": f"{protocol}.{field_name}"})

    def _payload_candidates(self, pkt: Any) -> Iterator[tuple[str, str, bytes]]:
        for layer_name, protocol in (("tls", "tls"), ("dtls", "dtls"), ("tcp", "tcp_reassembled"), ("udp", "dtls"), ("data", "raw")):
            layer = getattr(pkt, layer_name, None)
            if layer is None:
                continue
            for field in ("reassembled_data", "segment_data", "payload", "data_data", "app_data"):
                value = getattr(layer, field, None)
                raw = self._decode_hex_blob(value)
                if raw:
                    yield protocol, f"{layer_name}.{field}", raw

    def _extract_from_blob(self, raw: bytes, extracted_from: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        if len(raw) < 8:
            return
        offset = 0
        while offset < len(raw) - 4:
            idx = raw.find(b"\x30\x82", offset)
            if idx == -1 or idx + 4 > len(raw):
                break
            cert_len = struct.unpack("!H", raw[idx + 2 : idx + 4])[0] + 4
            if cert_len < 100 or idx + cert_len > len(raw):
                offset = idx + 1
                continue
            yield {"der": raw[idx : idx + cert_len], "extracted_from": dict(extracted_from)}
            offset = idx + cert_len

    @staticmethod
    def _flatten_field_values(value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            items: List[Any] = []
            for item in value:
                items.extend(CertAnalyzer._flatten_field_values(item))
            return items
        return [value]

    @staticmethod
    def _decode_hex_blob(value: Any) -> Optional[bytes]:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        cleaned = text.replace(":", "").replace(" ", "")
        if len(cleaned) % 2 != 0:
            return None
        if any(ch not in "0123456789abcdefABCDEF" for ch in cleaned):
            return None
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return None

    @staticmethod
    def _name_components(name) -> Dict[str, Any]:
        components: Dict[str, Any] = {}
        for attribute in name:
            label = getattr(attribute.oid, "_name", None) or attribute.oid.dotted_string
            if label in components:
                existing = components[label]
                if isinstance(existing, list):
                    existing.append(attribute.value)
                else:
                    components[label] = [existing, attribute.value]
            else:
                components[label] = attribute.value
        return components

    @staticmethod
    def _subject_alt_names(cert) -> List[str]:
        if not _CRYPTO_AVAILABLE:
            return []
        try:
            extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except Exception:
            return []
        values: List[str] = []
        for name in extension.value:
            value = getattr(name, "value", None)
            if value is not None:
                values.append(str(value))
        return values

    @staticmethod
    def _fermat_vulnerable(n: int, iterations: int = 100) -> bool:
        """Quick check if RSA modulus n = p*q where p ~ q (Fermat attack)."""
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

    # -- helpers ------------------------------------------------------

