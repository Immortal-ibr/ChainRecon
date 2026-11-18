"""Evidence-led firmware inspection and guided service emulation.

The default extractor uses an offline OCI image with no network or added
capabilities. Host/WSL Binwalk is an explicit trusted-input option.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, cast
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from chainrecon.case_model import Case, Finding, Observation, RunRecord, RunStatus, file_sha256
from chainrecon.elf_inspection import inspect_elf
from chainrecon.utils.redaction import redact_report_data, redact_text
from chainrecon.version import VERSION


TOOLS_IMAGE = "chainrecon/firmware-tools:2.0"
_MAX_FILES = 100_000
_MAX_TEXT_FILE = 2_000_000
_MAX_TOTAL_TEXT = 128_000_000
_MAX_CAPTURE = 64_000
_ELF_MACHINES = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
_SERVICE_NAMES = {"dropbear", "sshd", "telnetd", "uhttpd", "lighttpd", "dnsmasq", "mosquitto", "hostapd", "nginx", "httpd", "miniupnpd", "ftpd"}
_URI_RE = re.compile(rb"(?i)\b(?:https?|mqtts?|rtsps?|coaps?)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
_CREDENTIAL_RE = re.compile(rb"(?i)\b(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*([^\s\"']{3,160})")
_PEM_KEY_RE = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")
_CERT_SUFFIXES = {".crt", ".cer", ".der"}
_ISTG_AREA = {
    "firmware.binary": "ISTG-FW-INFO-004", "firmware.startup": "ISTG-FW-INFO-002",
    "firmware.service": "ISTG-FW-CONF-002", "firmware.account_database": "ISTG-FW-INFO-002",
    "firmware.password_hash_type": "ISTG-FW-CRYPT-001",
    "firmware.private_key": "ISTG-FW-SCRT-003",
    "firmware.credential_string": "ISTG-FW-SCRT-003",
    "firmware.endpoint": "ISTG-FW-INFO-003",
    "firmware.component": "ISTG-FW-CONF-001",
    "firmware.advisory_match": "ISTG-FW-CONF-001",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _result(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)


def _elf_info(header: bytes) -> dict[str, Any] | None:
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] not in (1, 2):
        return None
    endian = "little" if header[5] == 1 else "big"
    prefix = "<" if endian == "little" else ">"
    elf_type, machine = struct.unpack_from(prefix + "HH", header, 16)
    return {
        "class": 32 if header[4] == 1 else 64,
        "endian": endian,
        "machine": _ELF_MACHINES.get(machine, f"machine-{machine}"),
        "machine_id": machine,
        "type": {1: "relocatable", 2: "executable", 3: "shared_or_pie", 4: "core"}.get(elf_type, f"type-{elf_type}"),
    }


def identify_image(image: Path) -> dict[str, Any]:
    """Read bounded file regions and report signatures without executing parsers."""
    size = image.stat().st_size
    with image.open("rb") as handle:
        header = handle.read(min(size, 1024 * 1024))
    signatures: list[dict[str, Any]] = []
    magics = ((b"hsqs", "squashfs"), (b"sqsh", "squashfs"), (b"\x7fELF", "elf"), (b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"PK\x03\x04", "zip"), (b"UBI#", "ubi"))
    seen: set[tuple[str, int]] = set()
    counts: dict[str, int] = {}
    per_type_limit = {"squashfs": 64, "elf": 16, "gzip": 16, "xz": 16, "zip": 16, "ubi": 64}
    with image.open("rb") as handle:
        overlap = b""
        offset = 0
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            block = overlap + chunk
            base = offset - len(overlap)
            for magic, label in magics:
                start = 0
                while True:
                    index = block.find(magic, start)
                    if index < 0:
                        break
                    key = (label, base + index)
                    if key not in seen:
                        signature = {"type": label, "offset": base + index}
                        if label == "squashfs":
                            with image.open("rb") as probe:
                                probe.seek(base + index)
                                superblock = probe.read(48)
                            valid = (len(superblock) == 48 and superblock[:4] == b"hsqs"
                                     and struct.unpack_from("<H", superblock, 28)[0] == 4
                                     and struct.unpack_from("<I", superblock, 12)[0] in {4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576}
                                     and 48 <= struct.unpack_from("<Q", superblock, 40)[0] <= size - (base + index))
                            signature["validated"] = valid
                        elif label == "elf":
                            with image.open("rb") as probe:
                                probe.seek(base + index)
                                signature["validated"] = _elf_info(probe.read(64)) is not None
                        if label in {"squashfs", "elf"} and not signature["validated"]:
                            start = index + len(magic)
                            continue
                        counts[label] = counts.get(label, 0) + 1
                        if counts[label] <= per_type_limit[label]:
                            signatures.append(signature)
                        seen.add(key)
                    start = index + len(magic)
            offset += len(chunk)
            overlap = block[-7:]
    partitions: list[dict[str, Any]] = []
    if len(header) >= 512 and header[510:512] == b"\x55\xaa":
        for number in range(4):
            entry = header[446 + number * 16:462 + number * 16]
            kind = entry[4]
            start_lba, sectors = struct.unpack_from("<II", entry, 8)
            if kind and sectors:
                partitions.append({"number": number + 1, "type_hex": f"0x{kind:02x}", "offset": start_lba * 512, "size": sectors * 512, "extends_past_image": (start_lba + sectors) * 512 > size})
    if header[:4] == b"\x27\x05\x19\x56":
        signatures.append({"type": "uimage", "offset": 0})
    elf = _elf_info(header[:64])
    return {"size": size, "sha256": file_sha256(image), "signatures": sorted(signatures, key=lambda x: x["offset"]), "signature_counts": counts, "signature_truncated": any(counts[key] > per_type_limit[key] for key in counts), "partitions": partitions, "elf": elf}


def _walk_regular(root: Path, warnings: list[str]) -> Iterator[Path]:
    """Never dereference symlinks, including Windows-inaccessible WSL links."""
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=lambda e: warnings.append(f"Directory read failed ({type(e).__name__})")):
        safe_dirs = []
        for name in dirs:
            path = Path(directory) / name
            try:
                if path.is_symlink():
                    warnings.append(f"Skipped directory symlink: {path.relative_to(root).as_posix()}")
                else:
                    safe_dirs.append(name)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1920:
                    warnings.append(f"Skipped WSL directory symlink: {path.relative_to(root).as_posix()}")
                else:
                    warnings.append(f"Could not inspect directory {name}: {type(exc).__name__} ({getattr(exc, 'winerror', '')})")
        dirs[:] = safe_dirs
        for name in files:
            path = Path(directory) / name
            try:
                if path.is_symlink() or not path.is_file():
                    warnings.append(f"Skipped non-regular entry: {path.relative_to(root).as_posix()}")
                    continue
                count += 1
                if count > _MAX_FILES:
                    warnings.append(f"File limit {_MAX_FILES} reached; inventory is partial")
                    return
                yield path
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1920:
                    warnings.append(f"Skipped WSL symlink: {path.relative_to(root).as_posix()}")
                else:
                    warnings.append(f"Could not inspect {path.relative_to(root).as_posix()}: {type(exc).__name__} ({getattr(exc, 'winerror', '')})")


def _safe_child(root: Path, relative: str) -> Path:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(part in ("..", "") for part in parts):
        raise ValueError("Path must stay inside the extracted root")
    child = root
    for part in parts:
        child = child / part
        if child.is_symlink():
            raise ValueError("Path contains an extracted symlink")
    if not child.resolve().is_relative_to(root.resolve()):
        raise ValueError("Path resolves outside the extracted root")
    return child


def _certificate_metadata(data: bytes, suffix: str) -> tuple[list[dict[str, str]], int]:
    """Parse bounded certificate candidates without exposing key material."""
    pem_blocks = _PEM_CERT_RE.findall(data)
    candidates: list[tuple[bytes, bool]] = [(block, True) for block in pem_blocks]
    if not pem_blocks and suffix.lower() in _CERT_SUFFIXES:
        candidates.append((data, False))
    certificates: list[dict[str, str]] = []
    errors = int(b"-----BEGIN CERTIFICATE-----" in data and not pem_blocks)
    for blob, is_pem in candidates:
        try:
            cert = x509.load_pem_x509_certificate(blob) if is_pem else x509.load_der_x509_certificate(blob)
        except ValueError:
            errors += 1
            continue
        before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        certificates.append({
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_before": before.isoformat(),
            "not_valid_after": after.isoformat(),
        })
    return certificates, errors


def _network_indicator(value: bytes) -> dict[str, Any] | None:
    """Keep connection targets, excluding URI paths, user info, and query tokens."""
    try:
        parts = urlsplit(value.decode("ascii"))
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    return {"scheme": parts.scheme.lower(), "host": host, "port": port}


def _matches_rootfs_path(relative: str, suffix: str) -> bool:
    return relative == suffix or relative.endswith("/" + suffix)


def _lua_http_shell_flows(data: bytes) -> list[dict[str, Any]]:
    """Find narrow, same-function LuCI form-value to shell-sink flows.

    This is a static lead, not proof that a route is reachable or exploitable.
    Reassignment and explicit shell quoting suppress this simple rule.
    """
    source = data.decode("utf-8", errors="replace")
    if not re.search(r"require\s*\(\s*['\"]luci\.http['\"]\s*\)", source):
        return []
    routes: dict[str, str] = {}
    for entry in re.finditer(r"entry\s*\(\s*\{(?P<segments>[^}]+)\}\s*,\s*call\s*\(\s*['\"](?P<handler>\w+)['\"]\s*\)", source):
        segments = re.findall(r"['\"]([^'\"]+)['\"]", entry.group("segments"))
        if segments:
            routes[entry.group("handler")] = "/" + "/".join(segments)
    starts = list(re.finditer(r"(?m)^\s*(?:local\s+)?function\s+(?P<name>[\w.:]+)\s*\(", source))
    flows: list[dict[str, Any]] = []
    for index, function in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(source)
        block = source[function.start():end]
        for assignment in re.finditer(
            r"(?m)^\s*(?:local\s+)?(?P<variable>[A-Za-z_]\w*)\s*=\s*"
            r"(?:luci\.)?http\.formvalue\s*\(\s*['\"](?P<parameter>[^'\"]+)['\"]\s*\)",
            block,
        ):
            variable = assignment.group("variable")
            for sink in re.finditer(r"(?m)^(?!\s*--)[^\n]*?\b(?P<sink>io\.popen|os\.execute)\s*\((?P<arguments>[^\n]*)", block[assignment.end():]):
                between = block[assignment.end():assignment.end() + sink.start()]
                if re.search(rf"(?m)^\s*{re.escape(variable)}\s*=", between):
                    break
                arguments = sink.group("arguments")
                if not re.search(rf"\b{re.escape(variable)}\b", arguments):
                    continue
                if re.search(rf"(?:shellquote|quote)\s*\(\s*{re.escape(variable)}\s*\)", arguments):
                    continue
                offset = function.start() + assignment.end() + sink.start()
                flows.append({
                    "parameter": assignment.group("parameter"),
                    "sink": sink.group("sink"),
                    "source_line": source.count("\n", 0, function.start() + assignment.start()) + 1,
                    "line": source.count("\n", 0, offset) + 1,
                    "function": function.group("name"),
                    "route": routes.get(function.group("name").split(".")[-1], ""),
                })
                break
    return flows


class FirmwareEngine:
    def __init__(self, *, image: str = TOOLS_IMAGE, wsl_distro: str = "kali-linux"):
        self.image = image
        self.wsl_distro = wsl_distro

    def _container_cmd(self, mounts: list[tuple[Path, str, str]], args: list[str], *, memory: str = "1g") -> list[str]:
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", memory, "--cpus", "2", "--tmpfs", "/tmp:rw,nosuid,size=256m", "--ulimit", "fsize=1073741824:1073741824"]
        if os.name != "nt":
            cmd.extend(["--user", f"{getattr(os, 'getuid')()}:{getattr(os, 'getgid')()}"])
        for host, container, access in mounts:
            cmd.extend(["--mount", f"type=bind,source={host.resolve()},target={container},readonly={'true' if access == 'ro' else 'false'}"])
        return [*cmd, self.image, *args]

    def _container_ready(self) -> tuple[bool, str]:
        if shutil.which("docker") is None:
            return False, "Docker CLI unavailable; install/start Docker and build the tools image"
        try:
            available = _result(["docker", "image", "inspect", self.image], timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return False, "Could not contact the container engine"
        if available.returncode:
            return False, "Container engine or firmware tools image unavailable; start Docker and build docker/firmware-tools.Dockerfile"
        return True, ""

    def _tool_provenance(self, mode: str) -> dict[str, str]:
        versions = {"chainrecon": VERSION, "python": sys.version.split()[0], "extractor_mode": mode, "tools_image": self.image}
        if mode == "container":
            command = ["docker", "image", "inspect", "--format", "{{.Id}}", self.image]
            key = "tools_image_id"
        elif mode == "trusted-wsl":
            command = ["wsl", "-d", self.wsl_distro, "--", "binwalk", "--version"]
            key = "binwalk_version"
        else:
            command = [shutil.which("binwalk") or "binwalk", "--version"]
            key = "binwalk_version"
        try:
            result = _result(command, timeout=20)
            if result.returncode == 0 and result.stdout.strip():
                versions[key] = result.stdout.strip().splitlines()[0][:200]
        except (OSError, subprocess.TimeoutExpired):
            pass
        return versions

    def _extract(self, source: Path, root: Path, mode: str, warnings: list[str]) -> tuple[RunStatus, str]:
        root.mkdir(parents=True, exist_ok=True)
        if mode == "container":
            ready, reason = self._container_ready()
            if not ready:
                return "needs_input", reason + "; or explicitly select trusted-wsl/host mode"
            cmd = self._container_cmd([(source, "/input/firmware", "ro"), (root, "/output", "rw")], ["binwalk", "--extract", "--matryoshka", "--directory", "/output", "/input/firmware"])
        elif mode == "trusted-wsl":
            if os.name != "nt" or shutil.which("wsl") is None:
                return "needs_input", "Trusted WSL extraction requires Windows with WSL"
            src = _result(["wsl", "-d", self.wsl_distro, "--", "wslpath", "-a", source.as_posix()], timeout=20)
            out = _result(["wsl", "-d", self.wsl_distro, "--", "wslpath", "-a", root.as_posix()], timeout=20)
            if src.returncode or out.returncode:
                return "needs_input", "Could not translate Windows paths into the selected WSL distro"
            cmd = ["wsl", "-d", self.wsl_distro, "--", "binwalk", "--extract", "--matryoshka", "--directory", out.stdout.strip(), src.stdout.strip()]
        elif mode == "trusted-host":
            binwalk = shutil.which("binwalk")
            if not binwalk:
                return "needs_input", "Binwalk CLI unavailable on this host"
            cmd = [binwalk, "--extract", "--matryoshka", "--directory", str(root), str(source)]
        else:
            raise ValueError(f"Unknown extraction mode: {mode}")
        try:
            result = _result(cmd, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "partial", f"Extraction did not complete: {exc}"
        if result.returncode:
            return "partial", f"Extractor exited {result.returncode}: {(result.stderr or result.stdout)[-_MAX_CAPTURE:]}"
        if not any(_walk_regular(root, [])):
            return "partial", "Extractor returned success without regular files"
        return "complete", ""

    def analyze(self, case: Case, evidence_id: str, *, mode: str = "container", advisory_snapshot: str | Path | None = None, progress: Callable[[str], None] | None = None) -> RunRecord:
        ref = case.evidence(evidence_id)
        if ref.kind not in {"firmware", "flash_dump"}:
            raise ValueError(f"Firmware analysis does not accept {ref.kind} evidence")
        started = _now()
        if progress:
            progress("Identifying firmware image")
        source = case.evidence_path(evidence_id)
        advisory_ref = case.add_evidence(advisory_snapshot, kind="other") if advisory_snapshot else None
        advisory_source = case.evidence_path(advisory_ref.id) if advisory_ref else None
        advisory_data: list[dict[str, Any]] = []
        if advisory_source is not None:
            if advisory_source.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Advisory snapshot exceeds the 16 MiB limit")
            snapshot = json.loads(advisory_source.read_text(encoding="utf-8"))
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("advisories"), list):
                raise ValueError("Advisory snapshot must contain an advisories list")
            advisory_data = snapshot["advisories"]
            for advisory_entry in advisory_data:
                if not isinstance(advisory_entry, dict):
                    raise ValueError("Advisory entries must be mappings")
                if not isinstance(advisory_entry.get("id"), str) or not isinstance(advisory_entry.get("component"), str):
                    raise ValueError("Advisory entries require string id and component")
                versions = advisory_entry.get("versions")
                if not isinstance(versions, list) or any(not isinstance(version, str) for version in versions):
                    raise ValueError("Advisory entries require a list of exact version strings")
        run_id = f"run-{uuid.uuid4().hex}"
        run_root = case.root / "runs" / run_id
        run_root.mkdir(parents=True)
        extraction_root = run_root / "extracted"
        warnings: list[str] = []
        image_info = identify_image(source)
        if progress:
            progress(f"Extracting with {mode} mode")
        status, extraction_error = self._extract(source, extraction_root, mode, warnings)
        extraction_completed = status == "complete"
        if extraction_error:
            warnings.append(extraction_error)
        observations: list[Observation] = []
        findings: list[Finding] = []

        def observe(kind: str, summary: str, locator: str, *, confidence: str = "medium", attributes: dict[str, Any] | None = None, source_id: str = evidence_id) -> str:
            level = confidence if confidence in {"low", "medium", "high"} else "medium"
            details = dict(attributes or {})
            if kind in _ISTG_AREA:
                details["istg_area"] = _ISTG_AREA[kind]
            observation = Observation(f"obs-{uuid.uuid4().hex}", kind, summary, source_id, locator, cast(Literal["low", "medium", "high"], level), details)
            observations.append(observation)
            return observation.id

        for partition in image_info["partitions"]:
            observe("firmware.partition", f"MBR partition {partition['number']} ({partition['type_hex']})", f"offset:{partition['offset']}", confidence="high", attributes=partition)
        for signature in image_info["signatures"]:
            observe("firmware.signature", f"{signature['type']} signature", f"offset:{signature['offset']}", confidence="high" if signature.get("validated") else "medium", attributes=signature)
        if image_info["elf"]:
            observe("firmware.elf", f"ELF {image_info['elf']['machine']} image", "offset:0", confidence="high", attributes=image_info["elf"])

        inventory: list[dict[str, Any]] = []
        components: list[dict[str, str]] = []
        text_bytes = 0
        readable = 0
        elf_count = 0
        elf_partial = 0
        certificate_count = 0
        certificate_parse_errors = 0
        certificate_files_skipped_limit = 0
        text_files_skipped_limit = 0
        weak_passwords: list[tuple[str, str, str]] = []
        dropbear_options: dict[str, tuple[str, str]] = {}
        startup_invocations: list[tuple[str, str]] = []
        elf_network_shell_signals: dict[str, set[str]] = {}
        if status in {"complete", "partial"}:
            if progress:
                progress("Inventorying recovered files")
            for path in _walk_regular(extraction_root, warnings):
                relative = path.relative_to(extraction_root).as_posix()
                try:
                    size = path.stat().st_size
                    with path.open("rb") as handle:
                        head = handle.read(4096)
                    item: dict[str, Any] = {"path": relative, "size": size, "sha256": file_sha256(path), "elf": _elf_info(head)}
                    inventory.append(item)
                    if progress and len(inventory) % 250 == 0:
                        progress(f"Inventoried {len(inventory)} files")
                    if item["elf"]:
                        details = inspect_elf(path)
                        item["elf_details"] = details
                        elf_count += 1
                        if details and details["parse_status"] == "partial":
                            elf_partial += 1
                        if size <= 64 * 1024:
                            probe = head if size <= len(head) else path.read_bytes()
                            signals = {name for name in ("socket", "bind", "listen", "accept", "execve") if name.encode() + b"\x00" in probe}
                            if b"/bin/sh\x00" in probe or b"/bin/busybox\x00" in probe:
                                signals.add("shell_path")
                            if {"socket", "bind", "listen", "accept", "execve", "shell_path"} <= signals:
                                elf_network_shell_signals[relative] = signals
                        observe("firmware.binary", f"{item['elf']['machine']} ELF ({item['elf']['type']})", relative, confidence="high", attributes={"sha256": item["sha256"], **item["elf"], **(details or {})})
                    if any(part in relative.lower().split("/") for part in ("init.d", "systemd")) or relative.lower().endswith(("/inittab", "/rc.local")):
                        observe("firmware.startup", "Startup configuration present", relative, attributes={"sha256": item["sha256"]})
                    if path.name.lower() in _SERVICE_NAMES:
                        observe("firmware.service", f"Service executable/configuration: {path.name}", relative, attributes={"sha256": item["sha256"]})
                    if any(_matches_rootfs_path(relative.lower(), name) for name in ("etc/shadow", "etc/passwd")):
                        observe("firmware.account_database", "UNIX account database present", relative, confidence="high", attributes={"sha256": item["sha256"]})
                    certificate_candidate = path.suffix.lower() in _CERT_SUFFIXES or b"-----BEGIN CERTIFICATE-----" in head
                    if size > _MAX_TEXT_FILE:
                        if certificate_candidate:
                            certificate_files_skipped_limit += 1
                            warnings.append(f"Certificate candidate exceeds read limit: {relative}")
                        elif b"\x00" not in head:
                            text_files_skipped_limit += 1
                            warnings.append(f"Text candidate exceeds read limit: {relative}")
                        continue
                    scan_text = b"\x00" not in head and text_bytes + size <= _MAX_TOTAL_TEXT
                    if b"\x00" not in head and not scan_text:
                        text_files_skipped_limit += 1
                        warnings.append(f"Text scan budget reached before reading: {relative}")
                    if not scan_text and not certificate_candidate:
                        continue
                    data = path.read_bytes()
                    if certificate_candidate:
                        certs, errors = _certificate_metadata(data, path.suffix)
                        certificate_count += len(certs)
                        certificate_parse_errors += errors
                        if errors:
                            warnings.append(f"Certificate candidate could not be fully parsed: {relative}")
                        if certs:
                            item["certificates"] = certs
                        for number, cert in enumerate(certs, 1):
                            observe("firmware.certificate", "X.509 certificate present", f"{relative}:certificate:{number}", confidence="high", attributes=cert)
                    if not scan_text:
                        continue
                    text_bytes += len(data)
                    readable += 1
                    if _matches_rootfs_path(relative.lower(), "etc/shadow"):
                        for line_number, row in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                            fields = row.split(":", 2)
                            if len(fields) < 2:
                                continue
                            account, stored = fields[:2]
                            scheme = ("empty" if not stored else "locked" if stored.startswith(("!", "*")) else
                                      "md5-crypt" if stored.startswith("$1$") else
                                      "sha256-crypt" if stored.startswith("$5$") else
                                      "sha512-crypt" if stored.startswith("$6$") else
                                      "yescrypt" if stored.startswith("$y$") else "other")
                            oid = observe("firmware.password_hash_type", f"{account} account: {scheme}", f"{relative}:line:{line_number}", confidence="high", attributes={"account": account, "scheme": scheme})
                            if scheme in {"empty", "md5-crypt"}:
                                weak_passwords.append((account, scheme, oid))
                    if _matches_rootfs_path(relative.lower(), "etc/config/dropbear"):
                        for line_number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                            match = re.match(r"\s*option\s+(PasswordAuth|RootPasswordAuth)\s+['\"]?(on|off|1|0|yes|no)['\"]?\s*$", line, re.I)
                            if match:
                                key, value = match.group(1), match.group(2).lower()
                                oid = observe("firmware.service_option", f"Dropbear {key}: {value}", f"{relative}:line:{line_number}", confidence="high", attributes={"service": "dropbear", "option": key, "value": value})
                                dropbear_options[key.lower()] = (value, oid)
                    if _matches_rootfs_path(relative.lower(), "etc/rc.local"):
                        prefix = relative[:-len("etc/rc.local")]
                        for line_number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                            command_line = line.strip()
                            if not command_line or command_line.startswith("#"):
                                continue
                            match = re.match(r"(?P<executable>/[A-Za-z0-9_./+-]+|[A-Za-z_][\w.-]*)(?:\s|$)", command_line)
                            if not match:
                                continue
                            executable = match.group("executable")
                            name = Path(executable).name
                            if not executable.startswith("/") and name not in {"telnetd", "nc", "ncat", "socat"}:
                                continue
                            port_match = re.search(r"(?:^|\s)-p\s+(\d{1,5})(?:\s|$)", command_line)
                            port = int(port_match.group(1)) if port_match else None
                            oid = observe("firmware.startup_command", f"Boot script invokes {name}", f"{relative}:line:{line_number}", confidence="high", attributes={"executable": executable, "port": port})
                            if executable.startswith("/"):
                                startup_invocations.append((prefix + executable.lstrip("/"), oid))
                            if name == "telnetd":
                                findings.append(Finding(
                                    f"finding-{uuid.uuid4().hex}", "Boot script starts a Telnet daemon", "medium", "candidate", (oid,),
                                    "The startup command invokes Telnet, which does not encrypt sessions; verify boot execution, bind address, and firewall reachability.",
                                    affected_component=relative,
                                    impact="Credentials and commands may be exposed on a reachable plaintext session.",
                                    remediation="Disable Telnet and use an authenticated encrypted management service.",
                                ))
                    if path.suffix.lower() == ".lua":
                        for flow in _lua_http_shell_flows(data):
                            oid = observe("firmware.http_shell_flow", f"HTTP form parameter reaches {flow['sink']} in a LuCI controller", f"{relative}:line:{flow['line']}", confidence="medium", attributes={"parameter": flow["parameter"], "sink": flow["sink"], "source": "luci.http.formvalue", "source_line": flow["source_line"], "route": flow["route"]})
                            findings.append(Finding(
                                f"finding-{uuid.uuid4().hex}", "HTTP parameter reaches shell execution in LuCI controller", "high", "candidate", (oid,),
                                "Static source flow; verify route authentication, runtime reachability, and input handling before disclosure.",
                                affected_component=relative, reproduction=f"Inspect {relative}:line:{flow['line']} and its formvalue source.",
                                impact="Potential command execution if the route accepts attacker-controlled input.",
                                remediation="Avoid shell command construction from request data; use fixed commands and validated arguments.",
                            ))
                    if _PEM_KEY_RE.search(data):
                        oid = observe("firmware.private_key", "Private key material present", relative, confidence="high", attributes={"sha256": item["sha256"]})
                        findings.append(Finding(f"finding-{uuid.uuid4().hex}", "Embedded private key requires reuse and exposure review", "medium", "candidate", (oid,), "Key presence alone does not establish exploitability."))
                    # A generic assignment regex on source code mostly matches
                    # variables and UI field declarations, not embedded secrets.
                    # Keep these weak leads to data/configuration files.
                    if path.suffix.lower() not in {".lua", ".sh", ".js", ".htm", ".html", ".css", ".xml", ".svg"}:
                        for credential_match in list(_CREDENTIAL_RE.finditer(data))[:20]:
                            value = credential_match.group(2)
                            if value.startswith((b"$", b"%")) or value.lower() in {b"true", b"false", b"none", b"null"}:
                                continue
                            keyword = credential_match.group(1).decode("ascii", errors="replace").lower()
                            credential_line = data.count(b"\n", 0, credential_match.start()) + 1
                            observe("firmware.credential_string", f"{keyword}-like assignment (value withheld)", f"{relative}:line:{credential_line}", confidence="low")
                    for uri_match in list(_URI_RE.finditer(data))[:20]:
                        indicator = _network_indicator(uri_match.group())
                        if indicator is None:
                            continue
                        uri_line = data.count(b"\n", 0, uri_match.start()) + 1
                        observe("firmware.endpoint", "Embedded network URI", f"{relative}:line:{uri_line}", confidence="high", attributes=indicator)
                    if any(_matches_rootfs_path(relative, name) for name in ("usr/lib/opkg/status", "lib/opkg/status")):
                        for stanza in data.decode("utf-8", errors="replace").split("\n\n"):
                            package = re.search(r"(?m)^Package:\s*(\S+)", stanza)
                            version = re.search(r"(?m)^Version:\s*(\S+)", stanza)
                            if package and version:
                                components.append({"name": package.group(1), "version": version.group(1), "source": relative})
                except OSError as exc:
                    warnings.append(f"Could not read {relative}: {type(exc).__name__} ({getattr(exc, 'winerror', '')})")
        skipped_count = sum(item.startswith("Skipped ") for item in warnings)
        if status == "complete" and len(warnings) > skipped_count:
            status = "partial"
        if status == "complete" and not inventory:
            status = "partial"
            warnings.append("No regular extracted files were inventoried")
        component_observations: dict[tuple[str, str, str], str] = {}
        for target, startup_oid in startup_invocations:
            if target in elf_network_shell_signals and Path(target).name not in _SERVICE_NAMES:
                binary_oid = observe("firmware.network_shell_binary", "Boot-launched ELF has listening-socket and shell-execution imports", target, confidence="medium", attributes={"indicators": sorted(elf_network_shell_signals[target])})
                findings.append(Finding(
                    f"finding-{uuid.uuid4().hex}", "Boot-launched custom program may expose a shell service", "high", "candidate", (startup_oid, binary_oid),
                    "Static symbol and startup correlation; inspect the binary and confirm runtime behavior, authentication, and reachability before disclosure.",
                    affected_component=target,
                    impact="A reachable shell service could enable unauthorized command execution.",
                    remediation="Remove undocumented shell services and restrict any required management interface.",
                ))
        root_auth = dropbear_options.get("rootpasswordauth")
        password_auth = dropbear_options.get("passwordauth")
        enabled = {"on", "1", "yes"}
        for account, scheme, oid in weak_passwords:
            if account == "root" and root_auth and password_auth and root_auth[0] in enabled and password_auth[0] in enabled:
                findings.append(Finding(
                    f"finding-{uuid.uuid4().hex}", "Root SSH password login uses an MD5-crypt or empty hash", "high", "candidate",
                    (oid, password_auth[1], root_auth[1]),
                    "The image enables Dropbear password and root-password authentication; confirm the service starts and is reachable before disclosure. Hash value is withheld.",
                    affected_component="Dropbear and /etc/shadow",
                    impact="An accessible password login may permit offline or online password attacks.",
                    remediation="Disable root password login and use stronger password storage where supported.",
                ))
            else:
                findings.append(Finding(f"finding-{uuid.uuid4().hex}", f"Review {account} account password storage ({scheme})", "high" if scheme == "empty" else "medium", "candidate", (oid,), "Confirm authentication reachability and account policy before disclosure; password hash value is withheld."))
        for component in components:
            component_observations[(component["name"], component["version"], component["source"])] = observe("firmware.component", f"Package {component['name']} {component['version']}", component["source"], confidence="high", attributes=component)
        if advisory_ref is not None:
            for advisory_number, advisory in enumerate(advisory_data):
                for component in components:
                    if component["name"] == advisory.get("component") and component["version"] in advisory.get("versions", []):
                        oid = observe("firmware.advisory_match", f"{advisory.get('id')} affects an identified package version", f"advisories[{advisory_number}]", confidence="medium", attributes={"advisory_id": advisory.get("id"), "component": component}, source_id=advisory_ref.id)
                        component_oid = component_observations[(component["name"], component["version"], component["source"])]
                        findings.append(Finding(f"finding-{uuid.uuid4().hex}", f"Review {advisory.get('id')} applicability", "medium", "candidate", (component_oid, oid), "Version match requires configuration and exploitability review."))
        inspection = {"image": image_info, "inventory": inventory, "components": components, "extraction_status": status, "warnings": warnings}
        inspection_path = run_root / "inspection.json"
        inspection_path.write_text(json.dumps(inspection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        run_warnings = [item for item in warnings if not item.startswith("Skipped ")]
        if skipped_count:
            run_warnings.insert(0, f"Skipped {skipped_count} symlinks/non-regular entries; paths are in inspection.json")
        run = RunRecord(
            id=run_id, analyzer="firmware", status=status, input_ids=(evidence_id, advisory_ref.id) if advisory_ref else (evidence_id,),
            started_at=started, completed_at=_now(), tool_versions=self._tool_provenance(mode),
            settings={"mode": mode, "source_name": ref.name, "advisory_snapshot_sha256": advisory_ref.sha256 if advisory_ref else None}, warnings=tuple(run_warnings),
            coverage={"image_identified": True, "extraction_completed": extraction_completed, "regular_files": len(inventory), "skipped_non_regular_entries": skipped_count, "elf_files": elf_count, "elf_metadata_partial": elf_partial, "certificates": certificate_count, "certificate_parse_errors": certificate_parse_errors, "certificate_files_skipped_limit": certificate_files_skipped_limit, "text_files_read": readable, "text_files_skipped_limit": text_files_skipped_limit, "text_bytes_read": text_bytes, "advisory_snapshot_loaded": bool(advisory_snapshot)},
            observations=tuple(observations), findings=tuple(findings),
            artifacts=(inspection_path.relative_to(case.root).as_posix(),),
        )
        case.add_run(run)
        if progress:
            progress(f"Firmware run {run.id}: {run.status}; {len(inventory)} files inventoried")
        return run

    def diff(self, case: Case, before_id: str, after_id: str) -> dict[str, Any]:
        before = case.get_run(before_id)
        after = case.get_run(after_id)
        if before["analyzer"] != "firmware" or after["analyzer"] != "firmware":
            raise ValueError("Both runs must be firmware analyses")
        def inventory(run: dict[str, Any]) -> dict[str, str]:
            artifact_name = run["artifacts"][0]
            if artifact_name != f"runs/{run['id']}/inspection.json":
                raise ValueError("Invalid firmware inspection artifact reference")
            artifact = _safe_child(case.root, artifact_name)
            return {item["path"]: item["sha256"] for item in json.loads(artifact.read_text(encoding="utf-8"))["inventory"]}
        left, right = inventory(before), inventory(after)
        return {
            "before": before_id, "after": after_id,
            "added": sorted(right.keys() - left.keys()),
            "removed": sorted(left.keys() - right.keys()),
            "changed": sorted(path for path in left.keys() & right.keys() if left[path] != right[path]),
            "unchanged_count": sum(left[path] == right[path] for path in left.keys() & right.keys()),
        }

    def emulate(self, case: Case, run_id: str, binary: str, *, rootfs: str | None = None, argv: list[str] | None = None, timeout: int = 30) -> dict[str, Any]:
        run = case.get_run(run_id)
        if run["analyzer"] != "firmware":
            raise ValueError("Service emulation requires a firmware run")
        root = case.root / "runs" / run_id / "extracted"
        executable = _safe_child(root, binary)
        if not executable.is_file():
            raise FileNotFoundError(binary)
        selected_root: Path | None = _safe_child(root, rootfs) if rootfs else None
        if selected_root is None:
            for candidate in executable.parents:
                if candidate == root.parent:
                    break
                if (candidate / "etc").is_dir() and any((candidate / name).is_dir() for name in ("lib", "lib64", "usr/lib")):
                    selected_root = candidate
                    break
        if selected_root is None or not selected_root.is_dir() or not executable.is_relative_to(selected_root):
            outcome: dict[str, Any] = {"status": "needs_input", "reason": "Select a matching extracted Linux root filesystem with etc and lib directories", "binary": binary}
            return self._record_emulation(case, run, outcome, binary, "", argv or [], rootfs or "")
        rootfs_relative = selected_root.relative_to(root).as_posix()
        with executable.open("rb") as handle:
            elf = _elf_info(handle.read(64))
        if elf is None or elf["machine"] not in {"arm", "aarch64", "mips"}:
            outcome = {"status": "needs_input", "reason": "Select a supported ARM, AArch64, or MIPS Linux ELF binary", "binary": binary}
            return self._record_emulation(case, run, outcome, binary, "", argv or [], rootfs_relative)
        qemu = {"arm": "qemu-arm-static", "aarch64": "qemu-aarch64-static", "mips": "qemu-mipsel-static" if elf["endian"] == "little" else "qemu-mips-static"}[elf["machine"]]
        ready, reason = self._container_ready()
        if not ready:
            outcome = {"status": "needs_input", "reason": reason, "binary": binary, "architecture": elf}
            return self._record_emulation(case, run, outcome, binary, qemu, argv or [], rootfs_relative)
        inside_binary = executable.relative_to(selected_root).as_posix()
        cmd = self._container_cmd([(selected_root, "/rootfs", "ro")], [qemu, "-L", "/rootfs", f"/rootfs/{inside_binary}", *(argv or [])], memory="512m")
        try:
            result = _result(cmd, timeout=min(max(timeout, 1), 120))
        except (OSError, subprocess.TimeoutExpired) as exc:
            outcome = {"status": "partial", "reason": f"Emulation did not complete: {type(exc).__name__}", "binary": binary, "architecture": elf}
            return self._record_emulation(case, run, outcome, binary, qemu, argv or [], rootfs_relative)
        stderr = redact_text(result.stderr[-_MAX_CAPTURE:])
        outcome = {"status": "complete" if result.returncode == 0 else "partial", "exit_code": result.returncode, "stdout": redact_text(result.stdout[-_MAX_CAPTURE:]), "stderr": stderr, "binary": binary, "architecture": elf, "network": "disabled"}
        if result.returncode and any(term in stderr.lower() for term in ("could not open", "no such file", "error while loading shared libraries")):
            outcome["reason"] = "Loader or shared library unavailable in the selected extracted root filesystem"
        return self._record_emulation(case, run, outcome, binary, qemu, argv or [], rootfs_relative)

    def _record_emulation(self, case: Case, firmware_run: dict[str, Any], outcome: dict[str, Any], binary: str, qemu: str, argv: list[str], rootfs: str) -> dict[str, Any]:
        emulation_id = f"run-{uuid.uuid4().hex}"
        artifact = case.root / "runs" / emulation_id / "emulation.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps(redact_report_data(outcome), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        observation = Observation(f"obs-{uuid.uuid4().hex}", "firmware.emulation", f"Service emulation {outcome['status']}", firmware_run["input_ids"][0], binary, "high", {"qemu": qemu, "exit_code": outcome.get("exit_code")})
        run = RunRecord(
            emulation_id, "firmware_emulation", cast(RunStatus, outcome["status"]), tuple(firmware_run["input_ids"]),
            _now(), _now(), {**self._tool_provenance("container"), "qemu": qemu},
            {"binary": binary, "rootfs": rootfs, "argument_count": len(argv), "network": "disabled"},
            (str(outcome["reason"]),) if outcome.get("reason") else (),
            {"service_process_started": "exit_code" in outcome, "full_device_boot": False},
            (observation,), (), (artifact.relative_to(case.root).as_posix(),),
        )
        case.add_run(run)
        return {**outcome, "run_id": emulation_id}
