"""APK static analysis module for ChainRecon.

Decompiles an Android APK using JADX then inspects manifests,
source code and resource files for security-relevant findings.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from xml.etree import ElementTree as ET

import yaml

from runners.base import run_subprocess
from utils.logging_config import get_logger
from utils.platform_info import find_tool

try:
    import defusedxml.ElementTree as SafeET
except ImportError:
    SafeET = None

logger = get_logger("apk")

_PATTERNS_FILE = Path(__file__).resolve().parent.parent / "config" / "apk_patterns.yaml"


def _load_patterns(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or _PATTERNS_FILE
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


class APKAnalyzer:
    """Static analysis of Android APK files."""

    def __init__(
        self,
        executor: Optional[Callable] = None,
        jadx_path: Optional[str] = None,
        patterns_path: Optional[Path] = None,
    ):
        self._executor = executor or run_subprocess
        self._jadx = jadx_path or find_tool("jadx") or "jadx"
        self._patterns = _load_patterns(patterns_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, apk_path: str, output_dir: Optional[str] = None, progress_cb=None) -> Dict[str, Any]:
        """Perform full static analysis on an APK.

        Returns a findings dict compatible with the report generator.
        """
        apk = Path(apk_path)
        if not apk.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        # Decompile into a temp or user-specified directory
        if output_dir:
            decompiled = Path(output_dir)
        else:
            decompiled = Path(tempfile.mkdtemp(prefix="chainrecon_apk_"))

        logger.info("Decompiling %s → %s", apk.name, decompiled)
        self._decompile(str(apk), str(decompiled), progress_cb=progress_cb)

        manifest = self._parse_manifest(decompiled)
        permissions = self._extract_permissions(manifest)
        components = self._extract_components(manifest)
        app_flags = self._extract_app_flags(manifest)
        net_security = self._parse_network_security_config(decompiled)
        credentials = self._scan_credentials(decompiled)
        pinning = self._check_pinning(decompiled)
        sdks = self._detect_sdks(decompiled)

        risk_indicators = self._build_risk_indicators(
            permissions, components, app_flags, net_security, credentials, pinning,
        )

        return {
            "metadata": {
                "apk": str(apk),
                "decompiled_dir": str(decompiled),
                "analyzer": self.__class__.__name__,
            },
            "findings": {
                "permissions": permissions,
                "components": components,
                "app_flags": app_flags,
                "network_security_config": net_security,
                "credentials": credentials,
                "pinning": pinning,
                "sdks": sdks,
            },
            "summary": {
                "permission_count": len(permissions),
                "dangerous_permission_count": sum(
                    1 for p in permissions if p.get("dangerous")
                ),
                "exported_component_count": sum(
                    1 for c in components if c.get("exported")
                ),
                "credential_count": len(credentials),
                "sdk_count": len(sdks),
                "pinning_detected": pinning.get("detected", False),
                "risk_indicator_count": len(risk_indicators),
            },
            "risk_indicators": risk_indicators,
        }

    # ------------------------------------------------------------------
    # Decompilation
    # ------------------------------------------------------------------

    def _decompile(self, apk_path: str, output_dir: str, progress_cb=None) -> None:
        # Verify jadx is available only when using the default executor (not mocked)
        if self._executor is run_subprocess:
            jadx_exe = Path(self._jadx)
            if not (jadx_exe.exists() or shutil.which(self._jadx)):
                raise FileNotFoundError(
                    f"JADX not found: '{self._jadx}'.\n"
                    "To fix:\n"
                    "  1. Download jadx from github.com/skylot/jadx/releases\n"
                    "     (get the .zip, e.g. jadx-1.5.5.zip)\n"
                    "  2. Add to config/local.yaml using SINGLE quotes:\n"
                    "       tools:\n"
                    "         jadx: 'C:\\path\\to\\jadx.bat'\n"
                    "  3. Or set env var: CHAINRECON_JADX_PATH=C:\\path\\to\\jadx.bat\n"
                    "  4. Or add jadx/bin to your system PATH"
                )
        cmd = [self._jadx, "-d", output_dir, "--no-debug-info", apk_path]
        logger.debug("Running: %s", " ".join(str(c) for c in cmd))
        if self._executor is run_subprocess:
            # Stream jadx output line-by-line to avoid filling the pipe buffer
            # (large APKs can generate megabytes of progress text which causes
            # subprocess.run(capture_output=True) to deadlock on Windows).
            import subprocess as _sp
            proc = _sp.Popen(
                cmd,
                stdout=_sp.PIPE,
                stderr=_sp.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip()
                if line:
                    logger.debug("jadx: %s", line)
                    if progress_cb is not None:
                        progress_cb(line)
            proc.stdout.close()
            ret = proc.wait(timeout=600)
            if ret not in (0, 1):
                raise RuntimeError(f"jadx exited with code {ret}")
        else:
            self._executor(cmd, timeout=600)

    # ------------------------------------------------------------------
    # Manifest parsing
    # ------------------------------------------------------------------

    def _find_manifest(self, decompiled: Path) -> Optional[Path]:
        for candidate in [
            decompiled / "resources" / "AndroidManifest.xml",
            decompiled / "AndroidManifest.xml",
        ]:
            if candidate.exists():
                return candidate
        # search recursively as a last resort
        results = list(decompiled.rglob("AndroidManifest.xml"))
        return results[0] if results else None

    def _parse_manifest(self, decompiled: Path) -> Optional[ET.Element]:
        manifest_path = self._find_manifest(decompiled)
        if manifest_path is None:
            logger.warning("AndroidManifest.xml not found in decompiled output")
            return None

        text = manifest_path.read_text(encoding="utf-8", errors="replace")
        parser_mod = SafeET if SafeET is not None else ET
        try:
            return parser_mod.fromstring(text)
        except ET.ParseError:
            logger.error("Failed to parse AndroidManifest.xml")
            return None

    def _extract_permissions(self, root: Optional[ET.Element]) -> List[Dict[str, Any]]:
        if root is None:
            return []
        ns = "{http://schemas.android.com/apk/res/android}"
        dangerous = set(self._patterns.get("dangerous_permissions", []))
        perms: List[Dict[str, Any]] = []
        for elem in root.findall("uses-permission"):
            name = elem.get(f"{ns}name") or elem.get("name") or ""
            perms.append({
                "permission": name,
                "dangerous": name in dangerous,
            })
        return perms

    def _extract_components(self, root: Optional[ET.Element]) -> List[Dict[str, Any]]:
        if root is None:
            return []
        ns = "{http://schemas.android.com/apk/res/android}"
        components: List[Dict[str, Any]] = []
        for tag in ("activity", "service", "receiver", "provider"):
            for elem in root.iter(tag):
                name = elem.get(f"{ns}name") or elem.get("name") or ""
                exported_raw = elem.get(f"{ns}exported") or elem.get("exported")
                # If exported is not explicitly set, components with intent-filters
                # are implicitly exported (prior to API 31)
                has_filter = elem.find("intent-filter") is not None
                exported = (
                    exported_raw == "true"
                    if exported_raw is not None
                    else has_filter
                )
                components.append({
                    "type": tag,
                    "name": name,
                    "exported": exported,
                })
        return components

    def _extract_app_flags(self, root: Optional[ET.Element]) -> Dict[str, Any]:
        if root is None:
            return {}
        ns = "{http://schemas.android.com/apk/res/android}"
        app = root.find("application")
        if app is None:
            return {}
        return {
            "debuggable": app.get(f"{ns}debuggable") == "true",
            "allowBackup": app.get(f"{ns}allowBackup") != "false",  # default true
            "usesCleartextTraffic": app.get(f"{ns}usesCleartextTraffic") == "true",
            "networkSecurityConfig": app.get(f"{ns}networkSecurityConfig") or None,
            "minSdkVersion": self._get_sdk(root, "minSdkVersion"),
            "targetSdkVersion": self._get_sdk(root, "targetSdkVersion"),
        }

    @staticmethod
    def _get_sdk(root: ET.Element, attr: str) -> Optional[str]:
        ns = "{http://schemas.android.com/apk/res/android}"
        elem = root.find("uses-sdk")
        if elem is not None:
            return elem.get(f"{ns}{attr}") or elem.get(attr)
        return None

    # ------------------------------------------------------------------
    # Network security config
    # ------------------------------------------------------------------

    def _parse_network_security_config(self, decompiled: Path) -> Dict[str, Any]:
        candidates = list(decompiled.rglob("network_security_config.xml"))
        if not candidates:
            return {"found": False}

        path = candidates[0]
        text = path.read_text(encoding="utf-8", errors="replace")
        parser_mod = SafeET if SafeET is not None else ET
        try:
            root = parser_mod.fromstring(text)
        except ET.ParseError:
            return {"found": True, "parse_error": True}

        cleartext_allowed = False
        pin_sets: List[str] = []
        for domain_config in root.iter("domain-config"):
            ct = domain_config.get("cleartextTrafficPermitted")
            if ct == "true":
                cleartext_allowed = True
        for pin in root.iter("pin"):
            digest = pin.get("digest", "?")
            pin_sets.append(f"{digest}:{(pin.text or '').strip()}")

        return {
            "found": True,
            "cleartext_allowed": cleartext_allowed,
            "pin_count": len(pin_sets),
            "pins": pin_sets,
        }

    # ------------------------------------------------------------------
    # Credential scanning
    # ------------------------------------------------------------------

    def _scan_credentials(self, decompiled: Path) -> List[Dict[str, Any]]:
        patterns = self._patterns.get("credential_patterns", [])
        if not patterns:
            return []

        compiled = []
        for p in patterns:
            try:
                compiled.append((re.compile(p["pattern"]), p["name"], p.get("severity", "medium")))
            except re.error:
                logger.warning("Invalid regex in credential pattern: %s", p.get("name"))

        findings: List[Dict[str, Any]] = []
        source_dir = decompiled / "sources"
        if not source_dir.exists():
            source_dir = decompiled

        for java_file in source_dir.rglob("*.java"):
            try:
                content = java_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for regex, name, severity in compiled:
                for match in regex.finditer(content):
                    findings.append({
                        "type": name,
                        "severity": severity,
                        "file": str(java_file.relative_to(decompiled)),
                        "match": match.group(0)[:120],  # truncate for safety
                    })

        # Also scan XML / properties files
        for ext in ("*.xml", "*.properties", "*.json"):
            for res_file in decompiled.rglob(ext):
                try:
                    content = res_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for regex, name, severity in compiled:
                    for match in regex.finditer(content):
                        findings.append({
                            "type": name,
                            "severity": severity,
                            "file": str(res_file.relative_to(decompiled)),
                            "match": match.group(0)[:120],
                        })

        return findings

    # ------------------------------------------------------------------
    # Certificate pinning detection
    # ------------------------------------------------------------------

    def _check_pinning(self, decompiled: Path) -> Dict[str, Any]:
        present_markers = self._patterns.get("pinning_indicators", {}).get("present", [])
        bypass_markers = self._patterns.get("pinning_indicators", {}).get("bypass_risk", [])

        source_dir = decompiled / "sources"
        if not source_dir.exists():
            source_dir = decompiled

        present_hits: List[str] = []
        bypass_hits: List[str] = []

        for java_file in source_dir.rglob("*.java"):
            try:
                content = java_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for marker in present_markers:
                if marker in content:
                    present_hits.append(marker)
            for marker in bypass_markers:
                if marker in content:
                    bypass_hits.append(marker)

        return {
            "detected": len(present_hits) > 0,
            "indicators": list(set(present_hits)),
            "bypass_risk_indicators": list(set(bypass_hits)),
        }

    # ------------------------------------------------------------------
    # SDK detection
    # ------------------------------------------------------------------

    def _detect_sdks(self, decompiled: Path) -> List[Dict[str, str]]:
        sdk_defs = self._patterns.get("iot_sdks", [])
        if not sdk_defs:
            return []

        source_dir = decompiled / "sources"
        if not source_dir.exists():
            source_dir = decompiled

        # Build a single pass over the file tree
        all_text = ""
        for java_file in source_dir.rglob("*.java"):
            try:
                all_text += java_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

        found: List[Dict[str, str]] = []
        for sdk in sdk_defs:
            for marker in sdk.get("markers", []):
                if marker in all_text:
                    found.append({"name": sdk["name"], "marker": marker})
                    break  # one hit per SDK is enough

        return found

    # ------------------------------------------------------------------
    # Risk indicator aggregation
    # ------------------------------------------------------------------

    def _build_risk_indicators(
        self,
        permissions,
        components,
        app_flags,
        net_security,
        credentials,
        pinning,
    ) -> List[Dict[str, str]]:
        indicators: List[Dict[str, str]] = []

        # Dangerous permissions
        dangerous = [p for p in permissions if p.get("dangerous")]
        if dangerous:
            indicators.append({
                "severity": "medium",
                "title": "Dangerous permissions requested",
                "details": ", ".join(p["permission"] for p in dangerous),
            })

        # Exported components
        exported = [c for c in components if c.get("exported")]
        if exported:
            indicators.append({
                "severity": "medium",
                "title": f"{len(exported)} exported component(s)",
                "details": ", ".join(c["name"] for c in exported[:5]),
            })

        # Debuggable
        if app_flags.get("debuggable"):
            indicators.append({
                "severity": "high",
                "title": "Application is debuggable",
                "details": "android:debuggable is set to true — allows runtime attachment.",
            })

        # Cleartext traffic
        if app_flags.get("usesCleartextTraffic"):
            indicators.append({
                "severity": "high",
                "title": "Cleartext traffic permitted",
                "details": "android:usesCleartextTraffic is true.",
            })

        # Network security config cleartext
        if net_security.get("cleartext_allowed"):
            indicators.append({
                "severity": "high",
                "title": "Network security config allows cleartext",
                "details": "domain-config cleartextTrafficPermitted=true found.",
            })

        # No pinning
        if not pinning.get("detected"):
            indicators.append({
                "severity": "medium",
                "title": "No certificate pinning detected",
                "details": "No CertificatePinner, TrustManager, or pinning config found.",
            })

        # Pinning bypass risk  
        if pinning.get("bypass_risk_indicators"):
            indicators.append({
                "severity": "high",
                "title": "Potential certificate pinning bypass",
                "details": ", ".join(pinning["bypass_risk_indicators"]),
            })

        # Hardcoded credentials
        if credentials:
            indicators.append({
                "severity": "critical" if any(c.get("severity") == "critical" for c in credentials) else "high",
                "title": f"{len(credentials)} hardcoded credential(s) found",
                "details": ", ".join(set(c["type"] for c in credentials)),
            })

        return indicators
