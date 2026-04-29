"""Firmware extraction and filesystem inspection for ChainRecon."""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from runners.base import run_subprocess
from utils.logging_config import get_logger
from utils.platform_info import find_tool

logger = get_logger("firmware")


class FirmwareAnalyzer:
    """Extract firmware images with binwalk and inspect the extracted filesystem."""

    _TEXT_EXTENSIONS = {".txt", ".conf", ".cfg", ".ini", ".json", ".xml", ".sh", ".cgi", ".php", ".js", ".py", ".pem", ".crt", ".key"}
    _KEYWORDS = {
        "admin": "default admin credential surface",
        "password": "hardcoded password-like string",
        "token": "token-like material embedded in firmware",
        "secret": "secret-like material embedded in firmware",
        "mqtt": "mqtt configuration present in firmware",
        "webrtc": "webrtc configuration or dependency present",
    }
    _URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    _IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)

    def __init__(self, executor: Optional[Callable] = None, binwalk_path: Optional[str] = None):
        self._executor = executor or run_subprocess
        self._binwalk = binwalk_path or find_tool("binwalk") or "binwalk"

    def analyze(self, firmware_path: str, output_dir: Optional[str] = None, rules: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        image = Path(firmware_path)
        if not image.exists():
            raise FileNotFoundError(f"Firmware image not found: {firmware_path}")

        extract_root = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="chainrecon_firmware_"))
        extract_root.mkdir(parents=True, exist_ok=True)

        extraction_warning = None
        try:
            self._run_binwalk(image, extract_root)
            extracted_paths = self._collect_extracted_paths(extract_root)
        except RuntimeError as exc:
            extraction_warning = str(exc)
            logger.warning("Firmware extraction failed; continuing with direct image scan: %s", exc)
            extracted_paths = [image]
        file_inventory = self._inventory_files(extracted_paths)
        credential_hits = self._scan_text_hits(extracted_paths)
        config_findings = self._scan_config_paths(file_inventory)
        secrets = self._detect_secrets(extracted_paths)
        network_indicators = self._extract_network_indicators(extracted_paths, rules=rules or {})

        risk_indicators: List[Dict[str, str]] = []
        if secrets["private_keys"]:
            risk_indicators.append({
                "severity": "high",
                "title": "Private key material extracted from firmware",
                "details": f"Found {len(secrets['private_keys'])} private key file(s) in extracted firmware.",
            })
        if secrets["shadow_files"]:
            risk_indicators.append({
                "severity": "high",
                "title": "Password database files present",
                "details": "Extracted firmware contains passwd/shadow-style files that should be reviewed for default or weak hashes.",
            })
        if credential_hits:
            risk_indicators.append({
                "severity": "medium",
                "title": "Credential-like strings found in extracted files",
                "details": f"Detected {len(credential_hits)} credential-like hit(s) across extracted firmware files.",
            })
        if network_indicators["urls"] or network_indicators["domains"] or network_indicators["ips"]:
            risk_indicators.append({
                "severity": "medium",
                "title": "Network endpoints embedded in firmware",
                "details": "Extracted firmware contains hardcoded URLs, domains, or IPs that should be reviewed against the device profile.",
            })

        return {
            "metadata": {
                "firmware": str(image.resolve()),
                "extract_root": str(extract_root.resolve()),
                "analyzer": self.__class__.__name__,
                "binwalk_path": self._binwalk,
                "extraction_warning": extraction_warning,
            },
            "findings": {
                "extracted_paths": [str(path) for path in extracted_paths],
                "file_inventory": file_inventory,
                "credential_hits": credential_hits,
                "config_findings": config_findings,
                "private_keys": secrets["private_keys"],
                "certificate_files": secrets["certificate_files"],
                "shadow_files": secrets["shadow_files"],
                "network_indicators": network_indicators,
            },
            "summary": {
                "extracted_path_count": len(extracted_paths),
                "file_count": len(file_inventory),
                "credential_hit_count": len(credential_hits),
                "config_finding_count": len(config_findings),
                "private_key_count": len(secrets["private_keys"]),
                "certificate_file_count": len(secrets["certificate_files"]),
                "shadow_file_count": len(secrets["shadow_files"]),
                "url_count": len(network_indicators["urls"]),
                "ip_count": len(network_indicators["ips"]),
                "domain_count": len(network_indicators["domains"]),
                "firmware_rule_hit_count": len(network_indicators["rule_hits"]),
            },
            "risk_indicators": risk_indicators,
        }

    def _run_binwalk(self, image: Path, extract_root: Path) -> None:
        args = ["--extract", "--matryoshka", "--directory", str(extract_root), str(image)]
        commands = [[self._binwalk, *args]]
        if sys.platform == "win32":
            commands.append([sys.executable, "-m", "binwalk", *args])
        logger.info("Running binwalk extraction on %s", image)
        errors: List[str] = []
        for cmd in commands:
            try:
                result = self._executor(cmd, timeout=900)
            except OSError as exc:
                errors.append(f"{cmd[0]}: {self._friendly_extraction_error(exc)}")
                continue
            returncode = getattr(result, "returncode", 0) if result is not None else 0
            if returncode in (0, None):
                return
            stderr = getattr(result, "stderr", "") or getattr(result, "stdout", "") or ""
            errors.append(f"{cmd[0]} exited {returncode}: {self._friendly_extraction_error(stderr)}")
        details = "; ".join(errors) or "unknown error"
        raise RuntimeError(f"binwalk extraction unavailable; direct firmware image scan continued. Attempts: {details}")

    @staticmethod
    def _friendly_extraction_error(error: Any) -> str:
        text = str(error).strip()
        if "%1 is not a valid Win32 application" in text or "WinError 193" in text:
            return "configured binwalk path is not a runnable executable on this host"
        if "ModuleNotFoundError" in text and "binwalk.core" in text:
            return "Python binwalk package is incomplete or incompatible; install a working binwalk CLI for extraction"
        return text

    def _collect_extracted_paths(self, extract_root: Path) -> List[Path]:
        paths = [path for path in extract_root.iterdir() if path.exists()]
        return sorted(paths) if paths else [extract_root]

    def _inventory_files(self, roots: Iterable[Path]) -> List[Dict[str, Any]]:
        inventory: List[Dict[str, Any]] = []
        for root in roots:
            if root.is_file():
                inventory.append({
                    "path": str(root),
                    "name": root.name,
                    "suffix": root.suffix.lower(),
                    "size": root.stat().st_size,
                })
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                inventory.append({
                    "path": str(path),
                    "name": path.name,
                    "suffix": path.suffix.lower(),
                    "size": path.stat().st_size,
                })
        inventory.sort(key=lambda item: item["path"])
        return inventory

    def _scan_text_hits(self, roots: Iterable[Path]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for path in self._iter_small_text_files(roots):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lower = text.lower()
            for keyword, description in self._KEYWORDS.items():
                if keyword in lower:
                    hits.append({
                        "path": str(path),
                        "keyword": keyword,
                        "description": description,
                    })
        return hits

    def _scan_config_paths(self, inventory: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        interesting = {
            "passwd": "UNIX account database present",
            "shadow": "Password hash database present",
            "dropbear": "Dropbear SSH configuration or binaries present",
            "lighttpd": "Embedded web server configuration present",
            "uhttpd": "OpenWrt web server configuration present",
            "hostapd": "Wireless access-point configuration present",
            "dnsmasq": "Local DNS/DHCP configuration present",
            "cgi-bin": "CGI application directory present",
            "www": "Embedded web UI assets present",
        }
        for item in inventory:
            lowered = item["path"].lower()
            for marker, description in interesting.items():
                if marker in lowered:
                    findings.append({
                        "path": item["path"],
                        "marker": marker,
                        "description": description,
                    })
        return findings

    def _detect_secrets(self, roots: Iterable[Path]) -> Dict[str, List[str]]:
        private_keys: List[str] = []
        certificate_files: List[str] = []
        shadow_files: List[str] = []
        for path in self._iter_small_text_files(roots):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lowered = str(path).lower()
            if "shadow" in lowered or path.name == "passwd":
                shadow_files.append(str(path))
            if "-----begin private key-----" in text.lower() or path.suffix.lower() == ".key":
                private_keys.append(str(path))
            if "-----begin certificate-----" in text.lower() or path.suffix.lower() in {".crt", ".pem"}:
                certificate_files.append(str(path))
        return {
            "private_keys": sorted(set(private_keys)),
            "certificate_files": sorted(set(certificate_files)),
            "shadow_files": sorted(set(shadow_files)),
        }

    def _extract_network_indicators(self, roots: Iterable[Path], *, rules: Dict[str, Any]) -> Dict[str, List[Dict[str, str]] | List[Dict[str, Any]]]:
        urls: Dict[tuple[str, str], Dict[str, str]] = {}
        ips: Dict[tuple[str, str], Dict[str, str]] = {}
        domains: Dict[tuple[str, str], Dict[str, str]] = {}
        rule_hits: List[Dict[str, Any]] = []
        text_cache: List[tuple[Path, str]] = []
        for path in self._iter_small_text_files(roots):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            text_cache.append((path, text))
            for value in self._URL_PATTERN.findall(text):
                urls[(str(path), value)] = {"path": str(path), "value": value}
            for value in self._IP_PATTERN.findall(text):
                ips[(str(path), value)] = {"path": str(path), "value": value}
            for value in self._DOMAIN_PATTERN.findall(text):
                if value.lower() == path.suffix.lower().lstrip("."):
                    continue
                domains[(str(path), value)] = {"path": str(path), "value": value}

        for rule_name, expected in (rules or {}).items():
            candidates = expected if isinstance(expected, list) else [expected]
            for candidate in [str(item) for item in candidates if str(item).strip()]:
                if rule_name == "urls" and any(item["value"] == candidate for item in urls.values()):
                    rule_hits.append({"rule": rule_name, "value": candidate})
                elif rule_name == "ips" and any(item["value"] == candidate for item in ips.values()):
                    rule_hits.append({"rule": rule_name, "value": candidate})
                elif rule_name == "domains" and any(item["value"] == candidate for item in domains.values()):
                    rule_hits.append({"rule": rule_name, "value": candidate})
                elif rule_name == "keywords":
                    for path, text in text_cache:
                        if candidate.lower() in text.lower():
                            rule_hits.append({"rule": rule_name, "value": candidate, "path": str(path)})
                            break

        return {
            "urls": sorted(urls.values(), key=lambda item: (item["value"], item["path"])),
            "ips": sorted(ips.values(), key=lambda item: (item["value"], item["path"])),
            "domains": sorted(domains.values(), key=lambda item: (item["value"], item["path"])),
            "rule_hits": rule_hits,
        }

    def _iter_small_text_files(self, roots: Iterable[Path]) -> Iterable[Path]:
        for root in roots:
            if root.is_file():
                if root.suffix.lower() in self._TEXT_EXTENSIONS or root.stat().st_size <= 2_000_000:
                    yield root
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in self._TEXT_EXTENSIONS and path.stat().st_size > 512_000:
                    continue
                if path.stat().st_size > 2_000_000:
                    continue
                yield path
