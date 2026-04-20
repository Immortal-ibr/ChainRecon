"""SSL/TLS analysis helpers for ChainRecon."""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from utils.logging_config import get_logger

logger = get_logger("ssl")


class SSLAnalyzer:
    """Collect SSL/TLS posture details from target services."""

    def __init__(self, probe_func=None, ja3_calculator=None, timeout: int = 5):
        self.probe_func = probe_func or self._probe_port
        self.ja3_calculator = ja3_calculator or self._default_ja3_calculator
        self.timeout = timeout

    def probe_certificates(self, target: str, ports: Iterable[int]) -> Dict[str, Any]:
        certificates = []
        normalized_ports = [int(port) for port in ports]
        logger.info("Probing certificates on %s ports %s", target, normalized_ports)
        for port in normalized_ports:
            result = self._safe_probe(target, port)
            if result.get("reachable"):
                certificates.append(
                    {
                        "port": result["port"],
                        "reachable": True,
                        "subject": result.get("subject"),
                        "issuer": result.get("issuer"),
                        "serial_number": result.get("serial_number"),
                        "not_before": result.get("not_before"),
                        "not_after": result.get("not_after"),
                        "version": result.get("version"),
                        "cipher": result.get("cipher"),
                        "self_signed": result.get("self_signed", False),
                        "expired": result.get("expired", False),
                    }
                )
            else:
                certificates.append({"port": port, "reachable": False, "error": result.get("error", "connection failed")})

        return {
            "metadata": {"target": target, "ports": normalized_ports},
            "findings": {"certificates": certificates},
            "summary": {
                "reachable_ports": sum(1 for cert in certificates if cert.get("reachable")),
                "certificate_count": sum(1 for cert in certificates if cert.get("subject")),
            },
            "risk_indicators": [
                {
                    "severity": "high" if cert.get("expired") else "medium",
                    "title": "Certificate issue detected",
                    "details": f"Port {cert['port']} uses an {'expired' if cert.get('expired') else 'self-signed'} certificate.",
                }
                for cert in certificates
                if cert.get("self_signed") or cert.get("expired")
            ],
        }

    def analyze_ciphers(self, target: str, ports: Iterable[int]) -> Dict[str, Any]:
        results = []
        normalized_ports = [int(port) for port in ports]
        for port in normalized_ports:
            result = self._safe_probe(target, port)
            if not result.get("reachable"):
                results.append({"port": port, "reachable": False, "error": result.get("error", "connection failed")})
                continue

            cipher = result.get("cipher")
            version = result.get("version")
            results.append(
                {
                    "port": port,
                    "reachable": True,
                    "cipher": cipher,
                    "protocol": version,
                    "weak_cipher": self._is_weak_cipher(cipher),
                    "outdated_protocol": self._is_outdated_tls(version),
                }
            )

        return {
            "metadata": {"target": target, "ports": normalized_ports},
            "findings": {"cipher_analysis": results},
            "summary": {
                "weak_cipher_count": sum(1 for item in results if item.get("weak_cipher")),
                "outdated_protocol_count": sum(1 for item in results if item.get("outdated_protocol")),
            },
            "risk_indicators": [
                {
                    "severity": "high" if item.get("weak_cipher") else "medium",
                    "title": "TLS configuration weakness",
                    "details": f"Port {item['port']} negotiated {item.get('cipher')} over {item.get('protocol')}.",
                }
                for item in results
                if item.get("weak_cipher") or item.get("outdated_protocol")
            ],
        }

    def compute_ja3(self, pcap_path: str) -> Dict[str, Any]:
        try:
            hash_value = self.ja3_calculator(pcap_path)
            findings = {"available": True, "hash": hash_value}
        except RuntimeError as exc:
            findings = {"available": False, "error": str(exc)}
        return {
            "metadata": {"source": pcap_path},
            "findings": {"ja3": findings},
            "summary": {"ja3_available": findings["available"]},
            "risk_indicators": [],
        }

    def assess_tls_security(
        self,
        certificate_results: Optional[Dict[str, Any]] = None,
        cipher_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        certificate_results = certificate_results or {"findings": {"certificates": []}}
        cipher_results = cipher_results or {"findings": {"cipher_analysis": []}}

        findings = []
        risk_rating = "low"
        for cert in certificate_results["findings"].get("certificates", []):
            if cert.get("self_signed"):
                findings.append({"severity": "medium", "title": "Self-signed certificate", "port": cert["port"]})
                if risk_rating == "low":
                    risk_rating = "medium"
            if cert.get("expired"):
                findings.append({"severity": "high", "title": "Expired certificate", "port": cert["port"]})
                risk_rating = "high"

        for item in cipher_results["findings"].get("cipher_analysis", []):
            if item.get("weak_cipher"):
                findings.append({"severity": "high", "title": "Weak cipher negotiated", "port": item["port"]})
                risk_rating = "high"
            elif item.get("outdated_protocol") and risk_rating != "high":
                findings.append({"severity": "medium", "title": "Outdated TLS protocol", "port": item["port"]})
                risk_rating = "medium"

        return {
            "metadata": {
                "certificate_ports": certificate_results.get("metadata", {}).get("ports", []),
                "cipher_ports": cipher_results.get("metadata", {}).get("ports", []),
            },
            "findings": {"security_findings": findings},
            "summary": {"finding_count": len(findings), "risk_rating": risk_rating},
            "risk_indicators": findings,
        }

    def _safe_probe(self, target: str, port: int) -> Dict[str, Any]:
        try:
            return self.probe_func(target, port)
        except Exception as exc:  # pragma: no cover
            return {"port": port, "reachable": False, "error": str(exc)}

    def _probe_port(self, target: str, port: int) -> Dict[str, Any]:
        # Strip CIDR notation — user may have pasted a subnet like 10.0.0.1/24
        clean_target = target.split("/")[0].strip()
        if not clean_target:
            return {"port": port, "reachable": False, "error": "Empty target"}

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # SNI server_hostname must be a hostname, not an IP address.
        # Passing an IP as server_hostname causes "label empty or too long" on some stacks.
        import ipaddress
        try:
            ipaddress.ip_address(clean_target)
            sni_host = None  # numeric IP — skip SNI
        except ValueError:
            sni_host = clean_target  # hostname — use for SNI

        try:
            with socket.create_connection((clean_target, port), timeout=self.timeout) as tcp_socket:
                with context.wrap_socket(tcp_socket, server_hostname=sni_host) as tls_socket:
                    der_cert = tls_socket.getpeercert(binary_form=True)
                    cipher_info = tls_socket.cipher()
                    version = tls_socket.version()
        except socket.gaierror as exc:
            return {
                "port": port, "reachable": False,
                "error": f"DNS/network error: {exc} — ensure target is a reachable IP or hostname",
            }
        except ssl.SSLError as exc:
            return {"port": port, "reachable": False, "error": f"TLS handshake failed: {exc}"}
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            return {"port": port, "reachable": False, "error": f"Connection failed: {exc}"}

        subject, issuer, serial_number, not_before, not_after = (
            self._parse_der_certificate(der_cert) if der_cert else (None, None, None, None, None)
        )

        return {
            "port": port,
            "reachable": True,
            "subject": subject,
            "issuer": issuer,
            "serial_number": serial_number,
            "not_before": not_before,
            "not_after": not_after,
            "version": version,
            "cipher": cipher_info[0] if cipher_info else None,
            "self_signed": bool(subject and issuer and subject == issuer),
            "expired": self._is_expired(not_after),
        }

    def _parse_der_certificate(self, der_bytes: bytes):
        """Extract fields from a DER-encoded certificate.

        Uses the ``cryptography`` library when available for rich parsing.
        Falls back to ``ssl.DER_cert_to_PEM_cert`` and basic OpenSSL decoding
        when ``cryptography`` is not installed.
        """
        try:
            from cryptography import x509 as _x509

            cert = _x509.load_der_x509_certificate(der_bytes)
            subject = ", ".join(
                f"{attr.oid._name}={attr.value}" for attr in cert.subject
            )
            issuer = ", ".join(
                f"{attr.oid._name}={attr.value}" for attr in cert.issuer
            )
            serial_number = format(cert.serial_number, "X")
            not_before = cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT")
            not_after = cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
            return subject, issuer, serial_number, not_before, not_after
        except Exception:
            pass

        # Fallback: decode via ssl stdlib (limited but works without extras)
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        # stdlib can re-parse PEM to get the dict form
        cert_dict = ssl._ssl._test_decode_cert(pem)  # type: ignore[attr-defined]
        if not cert_dict:
            return None, None, None, None, None
        subject = self._format_dn(cert_dict.get("subject"))
        issuer = self._format_dn(cert_dict.get("issuer"))
        return (
            subject,
            issuer,
            cert_dict.get("serialNumber"),
            cert_dict.get("notBefore"),
            cert_dict.get("notAfter"),
        )

    def _default_ja3_calculator(self, pcap_path: str) -> str:
        """Attempt JA3 computation using pyja3, fall back to file-hash placeholder."""
        try:
            import pyja3  # type: ignore

            with open(pcap_path, "rb") as handle:
                payload = handle.read()
            hashes = pyja3.process_pcap(payload)
            if hashes:
                return hashes[0]
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: SHA-256 digest of the pcap as an opaque fingerprint
        # (not a true JA3 — flagged in output so callers know)
        try:
            with open(pcap_path, "rb") as handle:
                payload = handle.read()
        except OSError as exc:  # pragma: no cover
            raise RuntimeError(str(exc)) from exc
        if not payload:
            raise RuntimeError("JA3 computation requires a non-empty pcap file")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _is_expired(self, not_after: Optional[str]) -> bool:
        if not not_after:
            return False
        try:
            expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        except Exception:
            return False
        return expires_at < datetime.now(timezone.utc)

    def _format_dn(self, dn) -> Optional[str]:
        if not dn:
            return None
        parts = []
        for item in dn:
            for key, value in item:
                parts.append(f"{key}={value}")
        return ", ".join(parts)

    def _is_weak_cipher(self, cipher: Optional[str]) -> bool:
        if not cipher:
            return False
        return any(marker in cipher.upper() for marker in ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"))

    def _is_outdated_tls(self, version: Optional[str]) -> bool:
        return version in {"SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
