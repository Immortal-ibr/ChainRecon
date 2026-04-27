"""Firmware extraction and filesystem inspection for ChainRecon."""

from __future__ import annotations

import re
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

    def __init__(self, executor: Optional[Callable] = None, binwalk_path: Optional[str] = None):
        self._executor = executor or run_subprocess
        self._binwalk = binwalk_path or find_tool("binwalk") or "binwalk"

    def analyze(self, firmware_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        image = Path(firmware_path)
        if not image.exists():
            raise FileNotFoundError(f"Firmware image not found: {firmware_path}")

        extract_root = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="chainrecon_firmware_"))
        extract_root.mkdir(parents=True, exist_ok=True)

        self._run_binwalk(image, extract_root)
        extracted_paths = self._collect_extracted_paths(extract_root)
        file_inventory = self._inventory_files(extracted_paths)
        credential_hits = self._scan_text_hits(extracted_paths)
        config_findings = self._scan_config_paths(file_inventory)
        secrets = self._detect_secrets(extracted_paths)

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

        return {
            "metadata": {
                "firmware": str(image.resolve()),
                "extract_root": str(extract_root.resolve()),
                "analyzer": self.__class__.__name__,
                "binwalk_path": self._binwalk,
            },
            "findings": {
                "extracted_paths": [str(path) for path in extracted_paths],
                "file_inventory": file_inventory,
                "credential_hits": credential_hits,
                "config_findings": config_findings,
                "private_keys": secrets["private_keys"],
                "certificate_files": secrets["certificate_files"],
                "shadow_files": secrets["shadow_files"],
            },
            "summary": {
                "extracted_path_count": len(extracted_paths),
                "file_count": len(file_inventory),
                "credential_hit_count": len(credential_hits),
                "config_finding_count": len(config_findings),
                "private_key_count": len(secrets["private_keys"]),
                "certificate_file_count": len(secrets["certificate_files"]),
                "shadow_file_count": len(secrets["shadow_files"]),
            },
            "risk_indicators": risk_indicators,
        }

    def _run_binwalk(self, image: Path, extract_root: Path) -> None:
        cmd = [self._binwalk, "--extract", "--matryoshka", "--directory", str(extract_root), str(image)]
        logger.info("Running binwalk extraction on %s", image)
        self._executor(cmd, timeout=900)

    def _collect_extracted_paths(self, extract_root: Path) -> List[Path]:
        paths = [path for path in extract_root.iterdir() if path.exists()]
        return sorted(paths) if paths else [extract_root]

    def _inventory_files(self, roots: Iterable[Path]) -> List[Dict[str, Any]]:
        inventory: List[Dict[str, Any]] = []
        for root in roots:
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

    def _iter_small_text_files(self, roots: Iterable[Path]) -> Iterable[Path]:
        for root in roots:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in self._TEXT_EXTENSIONS and path.stat().st_size > 512_000:
                    continue
                if path.stat().st_size > 2_000_000:
                    continue
                yield path